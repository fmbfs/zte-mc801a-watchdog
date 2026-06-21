#!/usr/bin/env python3
r"""
\file zte_watchdog.py
\brief Connectivity watchdog for the ZTE MC801A 5G router (firmware B16). FINAL.

\details
The MC801A's cellular WAN intermittently wedges (radio attached, ppp_connected,
but no IP) and the firmware does not auto-recover, requiring a manual toggle in
the admin UI. This daemon pings outbound; on sustained failure it logs into the
router's goform API and performs the same disconnect->reconnect cycle the manual
toggle does, restoring the WAN unattended.

\section auth The authentication scheme (reverse-engineered, verified)
The decisive detail: the login password hash must be UPPERCASE at BOTH stages:

    login_password = SHA256( SHA256(pw).upper() + LD ).upper()

Only this encoding makes the router return result=0 AND issue the `stok`
session cookie via Set-Cookie (HttpOnly). The lowercase variant returns
result=3 -- a partial state that can READ but cannot WRITE (no stok issued),
which is why every write previously failed. No AD is sent on login.

Authenticated writes then carry the captured stok cookie plus:
    AD = md5( md5(wa_inner_version + cr_version) + RD )    (lowercase)
    notCallback = true

\section recovery Recovery action
The fault is a wedged session, so recovery is DISCONNECT_NETWORK followed by
CONNECT_NETWORK (mirroring the manual "toggle off then on").

\section testing What to test (Given-When-Then)
- Given 3 consecutive ping failures and a reachable admin API,
  When a cycle runs, Then exactly one login+reconnect is attempted and logged.
- Given login returns result!=0 / no stok issued,
  When reconnect runs, Then it is reported as an auth failure (distinct from a
  transport failure) and auth-backoff applies.
- Given a reconnect fired < COOLDOWN_SECONDS ago, When ping fails again,
  Then no second reconnect fires (cooldown holds).
- Given > MAX_RECOVERIES_PER_WINDOW recoveries in ROLLING_WINDOW_SECONDS,
  When the threshold is hit again, Then the circuit breaker holds and only logs.
"""

import hashlib
import logging
import os
import subprocess
import sys
import time
from collections import deque
from typing import Optional

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", stream=sys.stdout)
log = logging.getLogger("zte_watchdog")


def env_int(name: str, default: int) -> int:
    r"""\brief Read an integer from the environment, falling back to default."""
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        log.warning("Invalid value for %s, using default %s", name, default)
        return default


ROUTER_IP = os.environ.get("ROUTER_IP", "192.168.0.1")
ROUTER_PASSWORD = os.environ.get("ROUTER_PASSWORD", "")
PING_TARGET = os.environ.get("PING_TARGET", "1.1.1.1")
CHECK_INTERVAL_SECONDS = env_int("CHECK_INTERVAL", 60)
FAIL_THRESHOLD = env_int("FAIL_THRESHOLD", 3)
COOLDOWN_SECONDS = env_int("COOLDOWN", 180)
MAX_RECOVERIES_PER_WINDOW = env_int("MAX_REBOOTS_PER_WINDOW", 8)
ROLLING_WINDOW_SECONDS = env_int("ROLLING_WINDOW_SECONDS", 24 * 3600)
AUTH_MAX_FAILURES = env_int("AUTH_MAX_FAILURES", 4)
RECONNECT_VERIFY_SECONDS = env_int("RECONNECT_VERIFY_SECONDS", 30)

BASE_URL = f"http://{ROUTER_IP}"
GET_URL = f"{BASE_URL}/goform/goform_get_cmd_process"
SET_URL = f"{BASE_URL}/goform/goform_set_cmd_process"
HTTP_TIMEOUT = 8

XHR_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Accept": "application/json, text/javascript, */*; q=0.01",
    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    "Origin": BASE_URL,
    "Referer": f"{BASE_URL}/",
    "X-Requested-With": "XMLHttpRequest",
}


def md5_hex(s: str) -> str:
    return hashlib.md5(s.encode("utf-8")).hexdigest()


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def build_login_password(password: str, ld: str) -> str:
    r"""\brief Uppercase-both-stages SHA256. The encoding that yields result=0 + stok."""
    return sha256_hex(sha256_hex(password).upper() + ld).upper()


def is_reachable() -> bool:
    r"""\brief One ICMP ping with a 2s deadline. True if the target replies."""
    try:
        r = subprocess.run(["ping", "-c", "1", "-W", "2", PING_TARGET],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return r.returncode == 0
    except FileNotFoundError:
        log.error("ping binary not found -- install iputils-ping")
        return False


def get_cmd(s: requests.Session, cmd: str) -> Optional[dict]:
    r"""\brief GET goform values. None if the admin API is unreachable."""
    try:
        r = s.get(GET_URL, params={"isTest": "false", "cmd": cmd, "multi_data": "1"},
                  headers=XHR_HEADERS, timeout=HTTP_TIMEOUT)
        r.raise_for_status()
        return r.json()
    except (requests.RequestException, ValueError) as exc:
        log.error("Admin API unreachable: %s", exc)
        return None


# Recovery outcome codes.
RECOVER_OK = "ok"
RECOVER_AUTH_FAIL = "auth_fail"       # login rejected / no stok -> back off
RECOVER_UNREACHABLE = "unreachable"   # admin API down -> normal cadence
RECOVER_NO_IP = "no_ip"               # commands sent but WAN didn't come up


def login(s: requests.Session) -> str:
    r"""\brief Login (uppercase scheme). Returns 'ok' / 'auth_fail' / 'unreachable'."""
    tokens = get_cmd(s, "wa_inner_version,cr_version,RD,LD")
    if tokens is None:
        return RECOVER_UNREACHABLE
    payload = {"isTest": "false", "goformId": "LOGIN",
               "password": build_login_password(ROUTER_PASSWORD, tokens.get("LD", ""))}
    try:
        r = s.post(SET_URL, data=payload, headers=XHR_HEADERS, timeout=HTTP_TIMEOUT)
        r.raise_for_status()
        result = str(r.json().get("result"))
    except (requests.RequestException, ValueError) as exc:
        log.error("Login POST failed: %s", exc)
        return RECOVER_UNREACHABLE
    # Real success = result 0 AND a stok cookie was issued.
    if result in ("0", "success") and s.cookies.get("stok"):
        log.info("Login OK (result=%s, stok issued)", result)
        return RECOVER_OK
    log.error("Login did not authorise writes (result=%s, stok=%s)",
              result, "yes" if s.cookies.get("stok") else "no")
    return RECOVER_AUTH_FAIL


def write_cmd(s: requests.Session, wa: str, cr: str, goform_id: str) -> bool:
    r"""\brief Authenticated write: fresh RD -> md5 AD -> POST with notCallback + stok."""
    rd_doc = get_cmd(s, "RD")
    if rd_doc is None:
        return False
    ad = md5_hex(md5_hex(wa + cr) + rd_doc.get("RD", ""))
    try:
        r = s.post(SET_URL,
                   data={"isTest": "false", "notCallback": "true", "goformId": goform_id, "AD": ad},
                   headers=XHR_HEADERS, timeout=HTTP_TIMEOUT)
        r.raise_for_status()
        body = r.text.strip()
    except requests.RequestException as exc:
        log.error("%s transport error: %s", goform_id, exc)
        return False
    log.info("%s -> %s", goform_id, body)
    return '"result":"0"' in body or "success" in body


def recover() -> str:
    r"""\brief Full recovery: login -> DISCONNECT -> CONNECT -> verify WAN IP."""
    if not ROUTER_PASSWORD:
        log.error("ROUTER_PASSWORD not set")
        return RECOVER_AUTH_FAIL
    s = requests.Session()
    outcome = login(s)
    if outcome != RECOVER_OK:
        return outcome

    ver = get_cmd(s, "wa_inner_version,cr_version")
    if ver is None:
        return RECOVER_UNREACHABLE
    wa, cr = ver.get("wa_inner_version", ""), ver.get("cr_version", "")

    write_cmd(s, wa, cr, "DISCONNECT_NETWORK")
    time.sleep(3)
    write_cmd(s, wa, cr, "CONNECT_NETWORK")

    deadline = time.time() + RECONNECT_VERIFY_SECONDS
    while time.time() < deadline:
        time.sleep(5)
        st = get_cmd(s, "wan_ipaddr")
        if st and st.get("wan_ipaddr"):
            log.info("WAN is UP: %s", st.get("wan_ipaddr"))
            return RECOVER_OK
    log.warning("Commands accepted but WAN has no IP yet")
    return RECOVER_NO_IP


def main() -> None:
    log.info("Watchdog starting: ping=%s every %ss, threshold=%s, cooldown=%ss, "
             "breaker=%s/%ss, auth_max=%s",
             PING_TARGET, CHECK_INTERVAL_SECONDS, FAIL_THRESHOLD, COOLDOWN_SECONDS,
             MAX_RECOVERIES_PER_WINDOW, ROLLING_WINDOW_SECONDS, AUTH_MAX_FAILURES)

    consecutive = 0
    last_recovery = 0.0
    history: deque = deque()
    auth_failures = 0

    while True:
        if is_reachable():
            if consecutive > 0:
                log.info("Connectivity restored after %s failed checks", consecutive)
            consecutive = 0
            auth_failures = 0
            time.sleep(CHECK_INTERVAL_SECONDS)
            continue

        consecutive += 1
        log.warning("Ping failed (%s/%s)", consecutive, FAIL_THRESHOLD)
        if consecutive < FAIL_THRESHOLD:
            time.sleep(CHECK_INTERVAL_SECONDS)
            continue

        now = time.time()

        if auth_failures >= AUTH_MAX_FAILURES:
            log.error("Auth latch: %s consecutive auth failures -- not retrying login until "
                      "connectivity recovers. Check ROUTER_PASSWORD / scheme.", auth_failures)
            time.sleep(CHECK_INTERVAL_SECONDS)
            continue

        if now - last_recovery < COOLDOWN_SECONDS:
            log.info("In cooldown (%.0fs left), skipping", COOLDOWN_SECONDS - (now - last_recovery))
            time.sleep(CHECK_INTERVAL_SECONDS)
            continue

        while history and now - history[0] > ROLLING_WINDOW_SECONDS:
            history.popleft()
        if len(history) >= MAX_RECOVERIES_PER_WINDOW:
            log.error("Circuit breaker: %s recoveries in %ss -- holding. Manual check needed.",
                      len(history), ROLLING_WINDOW_SECONDS)
            time.sleep(CHECK_INTERVAL_SECONDS)
            continue

        log.warning("Threshold reached -- attempting reconnect")
        outcome = recover()

        if outcome == RECOVER_OK:
            auth_failures = 0
            last_recovery = now
            history.append(now)
            consecutive = 0
            log.info("Recovery succeeded")
            time.sleep(CHECK_INTERVAL_SECONDS)
        elif outcome == RECOVER_AUTH_FAIL:
            auth_failures += 1
            backoff = min(CHECK_INTERVAL_SECONDS * (2 ** auth_failures), 1800)
            log.error("Auth failure (%s/%s) -- backing off %ss", auth_failures, AUTH_MAX_FAILURES, backoff)
            time.sleep(backoff)
        elif outcome == RECOVER_NO_IP:
            # Commands worked but WAN didn't come up yet; count it (cooldown) and wait.
            last_recovery = now
            history.append(now)
            log.info("Reconnect issued; waiting for WAN to settle")
            time.sleep(COOLDOWN_SECONDS)
        else:  # RECOVER_UNREACHABLE
            log.warning("Admin API unreachable -- normal cadence")
            time.sleep(CHECK_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
