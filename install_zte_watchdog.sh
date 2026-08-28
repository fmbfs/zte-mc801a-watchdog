#!/usr/bin/env bash
###############################################################################
# install_zte_watchdog.sh
#
# Installs a persistent systemd service on a Raspberry Pi (or any systemd
# Linux) that watches outbound connectivity and recovers a ZTE MC801A 5G
# router through an escalating, breaker-bounded ladder:
#
#   L1  CONNECT              (re)dial the WAN data session  (no breaker)
#   L2  DISCONNECT/CONNECT   re-dial the cellular WAN      (breaker 8/24h)
#   L3  REBOOT_DEVICE        full soft reboot              (breaker 3/24h)
#
#   Liveness gate: if the router's admin HTTP plane is unreachable for
#   ROUTER_DEAD_THRESHOLD cycles, no goform command can land -> log CRITICAL
#   once, then retry the ladder blind every ADMIN_DEAD_RETRY_EVERY cycles
#   (the attach point for a future Shelly power-cycle). Escalation to L3
#   happens after L3_ESCALATION_THRESHOLD consecutive L2 attempts fail.
#
# Auth (confirmed against MC801A firmware):
#   LOGIN: SHA256(SHA256(password).upper() + LD).upper(), sets `stok` cookie
#   SET  : AD = MD5(MD5(wa_inner_version + cr_version) + RD)   [MD5, per-call]
#
# Logs are categorized in a grep-able second column:
#   journalctl -u zte-watchdog | grep FAULT   -> code/protocol problems only
#   journalctl -u zte-watchdog | grep DETECT  -> observed conditions only
#   (also: LIFECYCLE, HEARTBEAT, ACTION, STATE)
#
# Usage:
#   chmod +x install_zte_watchdog.sh
#   ./install_zte_watchdog.sh          # prompts for the password if unset
#
# Override defaults via env vars, e.g.:
#   ROUTER_IP=192.168.0.1 FAIL_THRESHOLD=2 ./install_zte_watchdog.sh
#
# RUN_TESTS=1 (default) runs the mocked test suite as an install gate; set 0
# to skip. Re-running is safe: code/service are overwritten, config.env reused.
###############################################################################
set -euo pipefail

INSTALL_DIR="/opt/zte-watchdog"
SERVICE_NAME="zte-watchdog"

ROUTER_IP="${ROUTER_IP:-192.168.0.1}"
PING_TARGET="${PING_TARGET:-1.1.1.1}"
CHECK_INTERVAL="${CHECK_INTERVAL:-20}"
FAIL_THRESHOLD="${FAIL_THRESHOLD:-3}"
COOLDOWN="${COOLDOWN:-180}"
L2_MAX_PER_WINDOW="${L2_MAX_PER_WINDOW:-8}"
L2_SETTLE="${L2_SETTLE:-3}"
L3_MAX_PER_WINDOW="${L3_MAX_PER_WINDOW:-3}"
L3_ESCALATION_THRESHOLD="${L3_ESCALATION_THRESHOLD:-3}"
L3_BOOT_WAIT="${L3_BOOT_WAIT:-90}"
ROUTER_DEAD_THRESHOLD="${ROUTER_DEAD_THRESHOLD:-3}"
ADMIN_DEAD_RETRY_EVERY="${ADMIN_DEAD_RETRY_EVERY:-10}"
ROLLING_WINDOW_SECONDS="${ROLLING_WINDOW_SECONDS:-86400}"

# --- MTU guard (path-MTU black-hole detector; see mtu_guard section below) ---
# The goform contract (SET_DEVICE_MTU / mtu / tcp_mss) is confirmed against
# this firmware's own admin bundle, so corrections are live by default.
# Set MTU_GUARD_DRY_RUN=1 to return to detect-and-log-only.
#
# MTU_TARGET IS A PLACEHOLDER -- REPLACE IT WITH YOUR OWN MEASURED CEILING:
#   ping -M do -s N -c 3 8.8.8.8    # bisect N; ceiling = N + 28
#   MTU_TARGET=<ceiling> ./install_zte_watchdog.sh
# It is the size the guard probes for, i.e. "the MTU I expect to be in force
# on a healthy link". It must match your path's real ceiling. Setting it to
# 1500 on a path that cannot carry 1500 makes the guard re-detect a black hole
# every MTU_CHECK_EVERY seconds and re-write the same value until the
# correction breaker trips -- correct MTU, permanent warnings. Measure first.
MTU_GUARD_ENABLED="${MTU_GUARD_ENABLED:-1}"
MTU_GUARD_DRY_RUN="${MTU_GUARD_DRY_RUN:-0}"
MTU_TARGET="${MTU_TARGET:-1360}"   # <-- PLACEHOLDER: measure yours, see above
MTU_FLOOR="${MTU_FLOOR:-1200}"
MTU_CHECK_EVERY="${MTU_CHECK_EVERY:-900}"
MTU_MAX_PER_WINDOW="${MTU_MAX_PER_WINDOW:-4}"

RUN_TESTS="${RUN_TESTS:-1}"

CONFIG_FILE="${INSTALL_DIR}/config.env"

if [[ -z "${ROUTER_PASSWORD:-}" ]]; then
  if [[ -f "${CONFIG_FILE}" ]]; then
    echo "Existing config found at ${CONFIG_FILE}, reusing stored password."
    ROUTER_PASSWORD="$(grep -E '^ROUTER_PASSWORD=' "${CONFIG_FILE}" | cut -d= -f2-)"
    # Reverse exactly what the writer below does: systemd's EnvironmentFile
    # parser strips one layer of matching double quotes and honours \\ and \"
    # escapes inside them. Undo the same transform, or a re-install would
    # re-escape an already-escaped password and change it.
    if [[ "${ROUTER_PASSWORD}" == '"'*'"' && ${#ROUTER_PASSWORD} -ge 2 ]]; then
      ROUTER_PASSWORD="${ROUTER_PASSWORD:1:${#ROUTER_PASSWORD}-2}"
      ROUTER_PASSWORD="${ROUTER_PASSWORD//\\\"/\"}"
      ROUTER_PASSWORD="${ROUTER_PASSWORD//\\\\/\\}"
    fi
  fi
fi
if [[ -z "${ROUTER_PASSWORD:-}" ]]; then
  read -srp "Router admin password: " ROUTER_PASSWORD
  echo
fi

echo "[1/7] Checking system dependencies (python3, venv, pip, ping)..."
missing=""
command -v python3 >/dev/null 2>&1 || missing="${missing} python3"
command -v ping >/dev/null 2>&1 || missing="${missing} iputils-ping"
python3 -c "import venv" >/dev/null 2>&1 || missing="${missing} python3-venv"
if [[ -n "${missing}" ]]; then
  echo "      Installing:${missing} (needs network)"
  sudo apt-get update -qq
  sudo apt-get install -y -qq ${missing} python3-pip
else
  echo "      All system deps already present -- skipping apt (offline-safe)."
fi

echo "[2/7] Creating install directory at ${INSTALL_DIR}..."
sudo mkdir -p "${INSTALL_DIR}"
sudo chown "$(whoami)":"$(whoami)" "${INSTALL_DIR}"

echo "[3/7] Setting up Python virtual environment..."
if [[ ! -x "${INSTALL_DIR}/venv/bin/python" ]]; then
  python3 -m venv "${INSTALL_DIR}/venv"
fi
VENV_PY="${INSTALL_DIR}/venv/bin/python"

# Only hit the network if something is actually missing. This keeps re-installs
# working during an outage -- the very situation the watchdog exists for -- as
# long as 'requests' is already in the venv (it is, after the first install).
need_pip=0
"${VENV_PY}" -c "import requests" >/dev/null 2>&1 || need_pip=1
if [[ "${RUN_TESTS}" == "1" ]]; then
  "${VENV_PY}" -c "import pytest" >/dev/null 2>&1 || need_pip=1
fi

if [[ "${need_pip}" == "1" ]]; then
  pkgs="requests"
  [[ "${RUN_TESTS}" == "1" ]] && pkgs="requests pytest"
  echo "      Installing missing packages (${pkgs}); needs network..."
  if ! "${INSTALL_DIR}/venv/bin/pip" install --quiet --timeout 15 --retries 1 ${pkgs}; then
    if "${VENV_PY}" -c "import requests" >/dev/null 2>&1; then
      echo "      WARNING: pip failed (offline?), but 'requests' is present -- continuing."
      if [[ "${RUN_TESTS}" == "1" ]] && ! "${VENV_PY}" -c "import pytest" >/dev/null 2>&1; then
        echo "      pytest unavailable offline -- skipping the test gate this run."
        RUN_TESTS=0
      fi
    else
      echo "      ERROR: 'requests' is required but pip failed and the network is down."
      echo "      Re-run with connectivity, or pre-install once:"
      echo "        ${INSTALL_DIR}/venv/bin/pip install requests"
      exit 1
    fi
  fi
else
  echo "      All Python deps already present -- skipping pip (offline-safe)."
fi

echo "[4/7] Writing watchdog daemon to ${INSTALL_DIR}/zte_watchdog.py..."

cat > "${INSTALL_DIR}/zte_watchdog.py" << 'PYEOF'
#!/usr/bin/env python3
r"""
\file zte_watchdog.py
\brief Connectivity watchdog for the ZTE MC801A 5G router.

\details
Polls outbound connectivity and, on sustained failure, walks an escalating,
breaker-bounded recovery ladder against the router's undocumented goform
admin API:

  L1  CONNECT              (re)dial the WAN data session   (no breaker; cheap)
  L2  DISCONNECT/CONNECT   re-dial the cellular WAN         (breaker 8/24h)
  L3  REBOOT_DEVICE        full soft reboot                 (breaker 3/24h)

Liveness gate: two independent signals are read each cycle --
  - is_wan_up()          external ICMP reachability (the wider internet)
  - is_admin_plane_up()  the router's own HTTP stack answers at all
If the admin plane is unreachable for ROUTER_DEAD_THRESHOLD cycles, goform
commands are unlikely to land: fire on_admin_plane_dead
(log CRITICAL today -- the attach point for a future Shelly power-cycle).
Escalation to L3 happens after L3_ESCALATION_THRESHOLD consecutive L2 attempts
fail to restore WAN. Any restoration resets the ladder.

Everything lives in this one file on purpose (mirrors the original installer's
single-daemon layout); the OO seams (CircuitBreaker, RecoveryAction Protocol,
pure step()) exist to make the logic testable and to make a future physical
recovery rung an append rather than a rewrite.

\section auth Authentication (confirmed against MC801A firmware)
  LOGIN: login_password = SHA256( SHA256(password).upper() + LD ).upper()
         POST goformId=LOGIN  ->  sets the `stok` session cookie on success.
  SET  : AD = MD5( MD5(wa_inner_version + cr_version) + RD )   [MD5, per-call]
Note the asymmetry: LOGIN is SHA256, AD is MD5. Matches the reverse-engineered
MC801A JavaScript (AD via hex_md5) and the community login scheme.

\warning PROVENANCE / VERIFY
Login (SHA256 + stok), AD (MD5), and DISCONNECT_NETWORK / CONNECT_NETWORK /
REBOOT_DEVICE are validated against a live MC801A (login result=0; DISCONNECT,
CONNECT, and REBOOT all accepted). WIFI_SWITCH was removed: this firmware
rejects it (result=failure) and the Wi-Fi radio is the wrong lever for WAN
recovery anyway. If LOGIN succeeds but every SET is rejected, suspect the AD
scheme (FAULT log lines flag exactly this).

\section logging Log categories (grep-friendly second column)
  LIFECYCLE  start/stop, effective config
  HEARTBEAT  routine "all is well" (DEBUG)
  DETECT     something observed about the world (WAN down, router unreachable)
  ACTION     a recovery action this daemon performed
  STATE      a ladder/escalation transition
  FAULT      a code / config / router-protocol problem (bug, bad scheme, etc.)
Example triage: `journalctl -u zte-watchdog | grep FAULT` shows only problems
in the code or the router protocol; `... | grep DETECT` shows only what the
watchdog observed. The two are never conflated.
"""

from __future__ import annotations

import hashlib
import logging
import os
import subprocess
import sys
import time
from collections import deque
from dataclasses import dataclass, field, replace
from typing import Callable, Deque, Dict, List, Optional, Protocol, runtime_checkable

import requests

# --- logging -----------------------------------------------------------------

class _AlignedFormatter(logging.Formatter):
    r"""
    \brief Render level names as fixed 4-letter labels so every column after
           the "[LEVEL]" bracket lines up.

    \details Standard level names vary in width (INFO=4 .. CRITICAL=8) and read
    ragged. We map each to a 4-char label (all equal width, so alignment is
    automatic) and restore the record afterwards so no other handler sees the
    mutated value.
    """

    _LABELS = {
        "DEBUG": "DEBG",
        "INFO": "INFO",
        "WARNING": "WARN",
        "ERROR": "ERRO",
        "CRITICAL": "CRIT",
    }

    def format(self, record: logging.LogRecord) -> str:
        original = record.levelname
        record.levelname = self._LABELS.get(original, original[:4])
        try:
            return super().format(record)
        finally:
            record.levelname = original


_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(_AlignedFormatter("%(asctime)s [%(levelname)s] %(message)s"))
logging.basicConfig(level=logging.INFO, handlers=[_handler])
log = logging.getLogger("zte_watchdog")

# Category tags. Kept in a fixed-width second column so lines are grep-able:
#   grep FAULT  -> code/protocol problems only
#   grep DETECT -> observations about the world only
TAG_LIFECYCLE = "LIFECYCLE"
TAG_HEARTBEAT = "HEARTBEAT"
TAG_DETECT = "DETECT"
TAG_ACTION = "ACTION"
TAG_STATE = "STATE"
TAG_FAULT = "FAULT"


def _emit(level: int, tag: str, msg: str, *args: object, exc_info: bool = False) -> None:
    r"""
    \brief Emit a categorized log line: "<TAG>    | <message>".

    \param level     logging level (e.g. logging.WARNING).
    \param tag        one of the TAG_* categories.
    \param msg        printf-style message; %-substitutions come from args.
    \param args       message arguments.
    \param exc_info   when True, append the active exception traceback.
    """
    log.log(level, "%-9s | " + msg, tag, *args, exc_info=exc_info)


# --- defaults ----------------------------------------------------------------
#
# Every tunable's default lives HERE and nowhere else in this module: the
# builders below read these names instead of repeating a literal. The
# installer's shell block at the top of install_zte_watchdog.sh is the other
# half of each pair, and the two are kept honest by
# test_installer_defaults_match_daemon_defaults -- which is how a silent
# disagreement (CHECK_INTERVAL was 20 in the installer and 60 here) is caught
# instead of shipped.

#: Seconds between connectivity checks.
DEFAULT_CHECK_INTERVAL_S = 20
#: Consecutive failed checks before the ladder acts.
DEFAULT_FAIL_THRESHOLD = 3
#: Seconds between recovery attempts.
DEFAULT_COOLDOWN_S = 180
#: Failed L2 attempts before escalating to L3.
DEFAULT_L3_ESCALATION_THRESHOLD = 3
#: Cycles of unreachable admin plane before declaring it dead.
DEFAULT_ROUTER_DEAD_THRESHOLD = 3
#: Cycles between blind ladder retries while the admin plane is dead.
DEFAULT_ADMIN_DEAD_RETRY_EVERY = 10
#: Seconds to wait out a soft reboot before probing for readiness.
DEFAULT_L3_BOOT_WAIT_S = 90
#: Seconds between DISCONNECT and CONNECT in an L2 cycle.
DEFAULT_L2_SETTLE_S = 3
#: L2 attempts allowed per rolling window.
DEFAULT_L2_MAX_PER_WINDOW = 8
#: L3 (reboot) attempts allowed per rolling window.
DEFAULT_L3_MAX_PER_WINDOW = 3
#: Rolling window for every circuit breaker, in seconds.
DEFAULT_ROLLING_WINDOW_S = 24 * 3600

#: Top rung of the recovery ladder. escalation_level is 1-based (1=L1, 2=L2,
#: 3=L3), so this is both the ceiling the ladder may climb to and the level
#: the registration gate jumps straight to.
LADDER_TOP_LEVEL = 3

#: Seconds added to a ping's own deadline before the subprocess is killed.
#: `ping -W` bounds the wait for a reply; this bounds the process itself, so a
#: ping that hangs without honouring -W still cannot wedge the poll loop.
_PING_HARD_TIMEOUT_MARGIN_S = 3

#: How much of a router response body to quote in a log line.
_LOG_BODY_CHARS = 200


# --- small helpers -----------------------------------------------------------


def _env_int(name: str, default: int) -> int:
    r"""\brief Read an int from the environment; FAULT-log and fall back if invalid."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        _emit(logging.ERROR, TAG_FAULT, "invalid %s=%r (not an int) -- using default %s", name, raw, default)
        return default


def _sha256_upper(s: str) -> str:
    r"""\brief SHA-256 hex digest, upper-cased (ZTE login convention)."""
    return hashlib.sha256(s.encode("utf-8")).hexdigest().upper()


def _md5_hex(s: str) -> str:
    r"""\brief MD5 hex digest, lower-case (ZTE AD convention)."""
    return hashlib.md5(s.encode("utf-8")).hexdigest()


def icmp_ok(target: str, timeout_s: int = 2) -> bool:
    r"""
    \brief One ICMP echo to `target` with a hard deadline (the WAN-liveness signal).

    \param target     IP/host to ping (e.g. 1.1.1.1).
    \param timeout_s  Per-ping deadline, in seconds.
    \return True if a reply arrived within the deadline.
    """
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout_s), target],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            # -W bounds the wait for a REPLY, not the process: a ping wedged in
            # name resolution or on a stalled interface would block the whole
            # poll loop. Belt and braces, with headroom over -W.
            timeout=timeout_s + _PING_HARD_TIMEOUT_MARGIN_S,
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        _emit(logging.WARNING, TAG_DETECT, "ping to %s exceeded its hard timeout -- treating as down", target)
        return False
    except FileNotFoundError:
        _emit(logging.ERROR, TAG_FAULT, "ping binary not found -- install iputils-ping")
        return False


# --- circuit breaker (shared, one instance per rung) -------------------------


class CircuitBreaker:
    r"""
    \brief Bounds the number of actions within a rolling time window.

    \details The single implementation of "at most N actions per window".
    Each rung owns its own instance with independent state, so the logic is
    reused, not duplicated. Purpose: stop the watchdog from masking a deeper
    fault (signal, carrier, hardware) by acting forever.

    \note Not thread-safe; the watchdog is single-threaded.
    """

    def __init__(self, max_actions: int, window_seconds: int, name: str) -> None:
        r"""
        \param max_actions     Maximum actions permitted inside the window.
        \param window_seconds  Rolling window length, in seconds.
        \param name            Log label (e.g. "L2", "L3").
        """
        self._max = max_actions
        self._window = window_seconds
        self._name = name
        self._events: Deque[float] = deque()

    @property
    def name(self) -> str:
        r"""\brief The breaker's log label."""
        return self._name

    def _prune(self, now: float) -> None:
        r"""\brief Drop events aged out of the window. \param now epoch seconds."""
        while self._events and now - self._events[0] > self._window:
            self._events.popleft()

    def allow(self, now: float) -> bool:
        r"""
        \brief Check whether another action is permitted (read-only).

        \param now  Current epoch time, in seconds.
        \return True if the in-window count is strictly below the maximum.
        """
        self._prune(now)
        return len(self._events) < self._max

    def record(self, now: float) -> None:
        r"""\brief Commit one action to the window. \param now epoch seconds."""
        self._events.append(now)

    def remaining(self, now: float) -> int:
        r"""\brief Actions still permitted this window. \param now epoch seconds."""
        self._prune(now)
        return max(0, self._max - len(self._events))


# --- ZTE router API (all device wire-format lives here) ----------------------

# goform SET payloads (device-specific; see PROVENANCE). DISCONNECT/CONNECT/
# REBOOT are standard ZTE goformIds. NOTE: WIFI_SWITCH was dropped -- on this
# MC801A it is rejected (result=failure) and, being the Wi-Fi radio toggle, is
# the wrong lever anyway: WAN recovery is CONNECT_NETWORK, not Wi-Fi.
RECOVERY_PAYLOADS: Dict[str, Dict[str, str]] = {
    "DISCONNECT": {"goformId": "DISCONNECT_NETWORK"},
    "CONNECT": {"goformId": "CONNECT_NETWORK"},
    "REBOOT": {"goformId": "REBOOT_DEVICE"},
}

#: CONFIRMED against MC801A firmware. Recovered from the router's own admin
#: bundle (/js/service.js), which builds the request as:
#:     n.goformId="SET_DEVICE_MTU", n.mtu=e.mtuValue, n.tcp_mss=e.mssValue
#: The GET side uses the same field names (cmd="...,mtu,tcp_mss,...").
#: Because that bundle IGNORES the SET result for this command, set_mtu()
#: confirms by reading the value back rather than trusting the response.
MTU_PAYLOAD_TEMPLATE: Dict[str, str] = {
    "goformId": "SET_DEVICE_MTU",
    "mtu": "{mtu}",
    "tcp_mss": "{mss}",
}

#: modem_main_state values that mean "attached and usable". Confirmed healthy
#: value on this firmware: modem_init_complete. Others are ZTE-common states
#: seen across MC-series builds; anything outside this set is treated as
#: unregistered, which is the safe direction (it escalates rather than stalls).
_MODEM_STATES_REGISTERED = frozenset({
    "modem_init_complete", "modem_connected", "modem_online",
})

#: network_type values that mean "no network". The router shows "Limited
#: Service" in its own UI for this condition.
_NETWORK_TYPES_UNREGISTERED = frozenset({
    "limited service", "no service", "noservice", "no_service",
    "limited_service", "searching", "unknown", "",
})

#: Every goform request, read or write, carries this. It was repeated at four
#: call sites before it was named.
_GOFORM_BASE_PARAMS: Dict[str, str] = {"isTest": "false"}

# Router "result" values that mean success. Firmware builds differ ("0" vs
# "success"); raw values are always logged so a mismatch is visible as FAULT.
_OK_RESULTS = frozenset({"0", "success"})


class ZteRouterApi:
    r"""
    \brief Stateful goform client: log in once, reuse the `stok` cookie.

    \note The requests.Session is injectable so tests mock every HTTP call and
          never touch hardware.
    """

    def __init__(
        self,
        router_ip: str,
        password: str,
        *,
        session: Optional[requests.Session] = None,
        http_timeout_s: int = 8,
    ) -> None:
        r"""
        \param router_ip      Admin IP of the router (e.g. 192.168.0.1).
        \param password        Plain admin password (hashed before sending).
        \param session         Injectable requests.Session (tests pass a mock).
        \param http_timeout_s  Per-request timeout, in seconds.
        """
        self._ip = router_ip
        self._password = password
        self._timeout = http_timeout_s
        self._base = f"http://{router_ip}"
        self._get_url = f"{self._base}/goform/goform_get_cmd_process"
        self._set_url = f"{self._base}/goform/goform_set_cmd_process"
        self._session = session or requests.Session()
        self._session.headers.update(
            {
                "Referer": f"{self._base}/index.html",  # ZTE checks Referer/Origin
                "Origin": self._base,
                "X-Requested-With": "XMLHttpRequest",
            }
        )
        self._logged_in = False

    def _get(self, cmd: str) -> Optional[dict]:
        r"""
        \brief GET goform_get_cmd_process and parse JSON.

        \details Transport failures are DETECT (router/net unreachable);
        non-JSON replies are FAULT (our assumption about the API shape is wrong).

        \param cmd  Comma-separated field list (e.g. "LD").
        \return Parsed dict, or None on failure.
        """
        try:
            resp = self._session.get(
                self._get_url,
                params={**_GOFORM_BASE_PARAMS, "cmd": cmd, "multi_data": "1"},
                timeout=self._timeout,
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            _emit(logging.WARNING, TAG_DETECT, "goform GET cmd=%s unreachable: %s", cmd, exc)
            return None
        try:
            return resp.json()
        except ValueError as exc:
            _emit(
                logging.ERROR, TAG_FAULT,
                "goform GET cmd=%s returned non-JSON (API-shape assumption wrong?): %s | body[:200]=%r",
                cmd, exc, resp.text[:_LOG_BODY_CHARS],
            )
            return None

    def _compute_ad(self) -> Optional[str]:
        r"""
        \brief Fetch fresh version/RD tokens and compute the MD5 AD challenge.

        \return AD hex string, or None if tokens could not be fetched.
        """
        tokens = self._get("wa_inner_version,cr_version,RD")
        if not tokens:
            return None
        missing = [k for k in ("wa_inner_version", "RD") if k not in tokens]
        if missing:
            _emit(logging.ERROR, TAG_FAULT, "AD tokens missing %s (firmware field names changed?)", missing)
            return None
        inner = _md5_hex(tokens.get("wa_inner_version", "") + tokens.get("cr_version", ""))
        return _md5_hex(inner + tokens.get("RD", ""))

    def _post_set(self, payload: Dict[str, str]) -> bool:
        r"""
        \brief POST a goform SET command with a fresh AD.

        \details Distinguishes:
          - transport error  -> DETECT (router unreachable)
          - HTTP 4xx/5xx      -> FAULT  (stok/AD likely rejected)
          - result != ok      -> FAULT  (wrong AD scheme? raw result logged)
          - non-JSON body     -> FAULT  (API-shape assumption wrong)

        \param payload  Form fields including goformId (see RECOVERY_PAYLOADS).
        \return True if the router reported success.
        """
        goform_id = payload.get("goformId", "?")
        ad = self._compute_ad()
        if ad is None:
            return False
        body = {**_GOFORM_BASE_PARAMS, "AD": ad, **payload}
        try:
            resp = self._session.post(self._set_url, data=body, timeout=self._timeout)
        except requests.RequestException as exc:
            _emit(logging.WARNING, TAG_DETECT, "goform SET %s unreachable: %s", goform_id, exc)
            self._logged_in = False  # force re-login next time
            return False
        if resp.status_code >= 400:
            _emit(
                logging.ERROR, TAG_FAULT,
                "goform SET %s HTTP %s (stok/AD rejected? session expired?)", goform_id, resp.status_code,
            )
            self._logged_in = False
            return False
        try:
            result = str(resp.json().get("result", "")).lower()
        except ValueError as exc:
            _emit(logging.ERROR, TAG_FAULT, "goform SET %s returned non-JSON: %s | body[:200]=%r",
                  goform_id, exc, resp.text[:_LOG_BODY_CHARS])
            return False
        if result in _OK_RESULTS:
            _emit(logging.DEBUG, TAG_ACTION, "goform SET %s ok (result=%s)", goform_id, result)
            return True
        _emit(
            logging.ERROR, TAG_FAULT,
            "goform SET %s rejected result=%s -- likely modem busy/transitional state, "
            "stale stok (post-reboot), or command not accepted now; "
            "if EVERY SET is rejected suspect the AD scheme (expected MD5(MD5(ver)+RD))",
            goform_id, result,
        )
        # A rejected SET is often a stale session (the router rebooted, or the
        # single allowed login expired). The original re-authenticated before
        # every action; we cache login, so drop the cache here to force a fresh
        # login next time instead of looping on a dead stok.
        self._logged_in = False
        return False

    def login(self) -> bool:
        r"""
        \brief Perform the SHA256 login and capture the `stok` cookie.

        \return True on success; the session then carries a valid stok cookie.
        """
        ld_tokens = self._get("LD")
        if not ld_tokens or "LD" not in ld_tokens:
            _emit(logging.WARNING, TAG_DETECT, "could not fetch LD nonce (router unreachable or field renamed)")
            return False
        ld = ld_tokens["LD"]
        login_password = _sha256_upper(_sha256_upper(self._password) + ld)
        try:
            resp = self._session.post(
                self._set_url,
                data={**_GOFORM_BASE_PARAMS, "goformId": "LOGIN", "password": login_password},
                timeout=self._timeout,
            )
            resp.raise_for_status()
            result = str(resp.json().get("result", "")).lower()
        except requests.RequestException as exc:
            _emit(logging.WARNING, TAG_DETECT, "login request unreachable: %s", exc)
            return False
        except ValueError as exc:
            _emit(logging.ERROR, TAG_FAULT, "login returned non-JSON (API-shape wrong?): %s", exc)
            return False
        if result in _OK_RESULTS:
            self._logged_in = True
            _emit(logging.INFO, TAG_ACTION, "router login succeeded (result=%s)", result)
            return True
        _emit(
            logging.ERROR, TAG_FAULT,
            "login rejected result=%s (wrong password, or wrong hash scheme for this firmware? "
            "expected SHA256(SHA256(pw).upper()+LD).upper())", result,
        )
        return False

    def ensure_login(self) -> bool:
        r"""\brief Log in only if not already authenticated. \return True if usable."""
        if self._logged_in:
            return True
        return self.login()

    def is_admin_plane_up(self) -> bool:
        r"""
        \brief Probe whether the router's admin HTTP stack answers at all.

        \details The second liveness signal, distinguishing "WAN down but
        router alive" (goform recovery worth trying) from "router wedged"
        (no goform can land).

        "Up" means the goform API itself answered: HTTP < 400 AND a JSON body.
        A bare `status < 500` would call a 403 auth wall, a captive portal, or
        the router serving an HTML error page "alive" -- inverting the very
        diagnosis this probe exists to make, and burning L2/L3 breaker budget
        on a router that cannot accept a single goform.

        \return True if the goform API replied within the timeout.
        """
        try:
            resp = self._session.get(
                self._get_url,
                params={**_GOFORM_BASE_PARAMS, "cmd": "LD", "multi_data": "1"},
                timeout=self._timeout,
            )
            if resp.status_code >= 400:
                _emit(logging.WARNING, TAG_DETECT,
                      "admin plane probe HTTP %s (auth wall or router error page)", resp.status_code)
                return False
            try:
                resp.json()
            except ValueError:
                _emit(logging.WARNING, TAG_DETECT,
                      "admin plane probe returned non-JSON (captive portal / error page?) body[:80]=%r",
                      resp.text[:80])
                return False
            return True
        except requests.RequestException as exc:
            # Never swallow this silently: when the probe fails for hours we
            # need to know WHY (connect refused vs timeout vs stale keep-alive).
            _emit(logging.WARNING, TAG_DETECT,
                  "admin plane probe failed: %s: %s", type(exc).__name__, exc)
            # Drop the connection pool: a poisoned keep-alive socket would
            # otherwise keep failing every cycle on a router that is alive.
            try:
                self._session.close()
            except Exception:  # noqa: BLE001 - close() must never mask the probe result
                pass
            self._logged_in = False
            return False

    # recovery primitives ----------------------------------------------------

    def disconnect_network(self) -> bool:
        r"""\brief L2: drop the cellular WAN session. \return True on success."""
        return self._post_set(RECOVERY_PAYLOADS["DISCONNECT"])

    def connect_network(self) -> bool:
        r"""\brief L2: re-dial the cellular WAN session. \return True on success."""
        return self._post_set(RECOVERY_PAYLOADS["CONNECT"])

    def is_registered(self) -> Optional[bool]:
        r"""
        \brief Whether the modem holds a usable network registration.

        \details Distinguishes two failures the recovery ladder must treat
        differently:

          - DATA SESSION WEDGED -- registered on the carrier, but the PDN is
            stuck. DISCONNECT/CONNECT (L2) is the correct, cheap fix.
          - NO REGISTRATION ("Limited Service") -- the modem is not attached to
            any network. There is no session to re-dial, so L2 can only fail;
            only a reboot (L3) has ever recovered this.

        Field semantics were confirmed against this firmware in a HEALTHY state:

            modem_main_state = "modem_init_complete"
            ppp_status       = "ppp_connected"
            network_type     = "LTE"
            signalbar        = "5"
            network_provider = "<your operator>"
            rssi/rsrp/rscp   = ""      <-- EMPTY EVEN WHEN HEALTHY

        That last line is why signal-strength fields are deliberately NOT used
        as evidence: they are blank on a perfectly working link, so treating
        blank as "no service" would fire constantly.

        \return True registered, False not registered, None if unreadable
                (never guess -- an unreadable router is the liveness gate's
                problem, not this probe's).
        """
        data = self._get("modem_main_state,network_type,signalbar,network_provider")
        if not data:
            return None

        state = str(data.get("modem_main_state", "")).strip().lower()
        net = str(data.get("network_type", "")).strip().lower()
        bars = str(data.get("signalbar", "")).strip()

        if state and state not in _MODEM_STATES_REGISTERED:
            _emit(logging.WARNING, TAG_DETECT,
                  "modem_main_state=%r indicates no usable registration", data.get("modem_main_state"))
            return False
        if net in _NETWORK_TYPES_UNREGISTERED:
            _emit(logging.WARNING, TAG_DETECT,
                  "network_type=%r -- modem is not attached to a network", data.get("network_type"))
            return False
        # signalbar is "5" when healthy; "0"/"" alongside a live admin plane
        # means the radio has nothing. Only trusted when it parses as a number,
        # so a firmware that stops populating it cannot cause false positives.
        if bars.isdigit() and int(bars) == 0:
            _emit(logging.WARNING, TAG_DETECT, "signalbar=0 -- no radio coverage")
            return False
        return True

    def read_mtu(self) -> Optional[int]:
        r"""
        \brief Read the router's currently configured WAN MTU.

        \return MTU in bytes, or None if unreadable / non-numeric.
        """
        data = self._get("mtu,tcp_mss")
        if not data:
            return None
        try:
            return int(str(data.get("mtu", "")).strip())
        except (TypeError, ValueError):
            _emit(logging.ERROR, TAG_FAULT, "router returned non-numeric mtu=%r", data.get("mtu"))
            return None

    def set_mtu(self, mtu: int, mss: int) -> bool:
        r"""
        \brief Write WAN MTU and TCP MSS, then confirm by reading the value back.

        \details The SET result is deliberately NOT trusted as the sole signal.
        The router's own admin bundle ignores it for this command --

            ENABLE_PIN:      function t(e){return e&&"success"===e.result?...}
            SET_DEVICE_MTU:  function t(e){return e||fi}

        -- so this firmware may answer without the "result" field that
        _post_set() keys on, which would make a successful write look like a
        failure. Read-back is authoritative: the router either reports the new
        MTU or it does not.

        \param mtu  WAN MTU in bytes.
        \param mss  TCP MSS in bytes (conventionally mtu - 40).
        \return True if the router reports the requested MTU after the write.
        """
        payload = {k: v.format(mtu=mtu, mss=mss) for k, v in MTU_PAYLOAD_TEMPLATE.items()}
        posted = self._post_set(payload)
        readback = self.read_mtu()
        if readback == mtu:
            if not posted:
                _emit(logging.INFO, TAG_ACTION,
                      "SET_DEVICE_MTU reported no/unknown result but read-back confirms mtu=%s "
                      "-- treating as success (this firmware's own UI ignores the result too)", mtu)
            return True
        _emit(logging.ERROR, TAG_FAULT,
              "MTU write not reflected: asked for %s, router reports %r "
              "(the admin UI warns MTU may only be changeable while the modem is disconnected)",
              mtu, readback)
        return False

    def reboot_device(self) -> bool:
        r"""\brief L3: full soft reboot of the router. \return True on success."""
        ok = self._post_set(RECOVERY_PAYLOADS["REBOOT"])
        if ok:
            # The router is about to restart: the current stok will be invalid.
            # Drop the cached login so the next action re-authenticates.
            self._logged_in = False
        return ok


# --- recovery ladder ---------------------------------------------------------


@runtime_checkable
class RecoveryAction(Protocol):
    r"""
    \brief Uniform interface for one rung of the recovery ladder.

    \var name  Short label used in logs (e.g. "L2:DISCONNECT_CONNECT").

    A future physical rung (Shelly power-cycle) implements this same Protocol
    and is appended to the ladder -- no redesign.
    """

    name: str

    def available(self, now: float) -> bool:  # pragma: no cover - protocol stub
        r"""
        \brief Whether this rung can act right now (breaker budget remaining).

        \details Read-only; lets the loop pick the highest actionable rung and
        fall back to a cheaper one instead of spinning on an exhausted rung.

        \param now  Current epoch time, in seconds.
        \return True if attempt() would do real work (not be breaker-skipped).
        """
        ...

    def attempt(self, now: float) -> bool:  # pragma: no cover - protocol stub
        r"""
        \brief Perform one recovery attempt.

        \param now  Current epoch time, in seconds.
        \return True if the command(s) were issued. "Issued" != "connectivity
                confirmed"; the poll loop confirms restoration next cycle.
        """
        ...


class ConnectRecovery:
    r"""
    \brief L1: cheapest rung -- (re)dial the WAN data session. No breaker.

    \details This is the software equivalent of flipping the router UI's data
    toggle from OFF to ON: a single CONNECT_NETWORK. After a WAN drop (or a
    reboot, which leaves the data session OFF), this is usually all that is
    needed. If a plain connect does not restore WAN, L2 escalates to a full
    disconnect+reconnect, then L3 reboots.
    """

    name = "L1:CONNECT"

    def __init__(self, api: ZteRouterApi) -> None:
        r"""\param api  Router client (auto-login on demand)."""
        self._api = api

    def available(self, now: float) -> bool:
        r"""\brief L1 has no breaker: always actionable. \return True."""
        return True

    def attempt(self, now: float) -> bool:
        r"""\brief Log in if needed, then issue CONNECT_NETWORK. \param now epoch seconds. \return success."""
        if not self._api.ensure_login():
            return False
        return self._api.connect_network()


class DisconnectReconnectRecovery:
    r"""\brief L2: re-dial the WAN. The everyday recovery. Breaker-gated."""

    name = "L2:DISCONNECT_CONNECT"

    def __init__(self, api: ZteRouterApi, breaker: CircuitBreaker,
                 *, settle_s: float = 3.0, sleep: Callable[[float], None] = time.sleep) -> None:
        r"""
        \param api       Router client.
        \param breaker   This rung's own breaker instance (e.g. 8 / 24h).
        \param settle_s  Pause between DISCONNECT and CONNECT, in seconds. The
                         modem needs a beat to finish tearing down the session;
                         issuing CONNECT too soon is rejected ("failure").
        \param sleep     Injectable sleep (tests pass a no-op).
        """
        self._api = api
        self._breaker = breaker
        self._settle_s = settle_s
        self._sleep = sleep

    def available(self, now: float) -> bool:
        r"""\brief Whether the L2 breaker still has budget. \return breaker.allow(now)."""
        return self._breaker.allow(now)

    def attempt(self, now: float) -> bool:
        r"""
        \brief DISCONNECT, wait for the modem to settle, then CONNECT.

        \param now  Current epoch time, in seconds.
        \return True if both goform commands were issued successfully.
        """
        if not self._breaker.allow(now):
            # Defensive: step() pre-checks available(), so this is unreachable
            # in normal flow -- kept as a guard, logged quietly to avoid noise.
            _emit(logging.DEBUG, TAG_STATE, "%s breaker tripped -- skipped", self.name)
            return False
        ok = False
        if self._api.ensure_login():
            # Disconnect is best-effort: if the session is already down (e.g.
            # after a reboot), DISCONNECT may return failure, but that must not
            # block the CONNECT that actually brings the WAN back.
            self._api.disconnect_network()
            self._sleep(self._settle_s)  # let the modem finish the teardown
            ok = self._api.connect_network()
        self._breaker.record(now)  # an attempt counts, success or not
        return ok


class SoftRebootRecovery:
    r"""
    \brief L3: full soft reboot via REBOOT_DEVICE. Last software resort.

    \details Repurposes the router's own reboot as the top software rung: it
    clears wedged modem/firmware state that a WAN re-dial (L2) cannot. Kept
    the rarest action (tighter breaker) because power-cycling a 5G CPE many
    times a day masks a deeper fault.
    """

    name = "L3:REBOOT_DEVICE"

    def __init__(
        self,
        api: ZteRouterApi,
        breaker: CircuitBreaker,
        *,
        boot_wait_s: float = 90.0,
        readiness_probe: Optional[Callable[[], bool]] = None,
        readiness_ceiling_s: float = 180.0,
        readiness_poll_s: float = 5.0,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        r"""
        \param api                 Router client.
        \param breaker             This rung's own breaker (e.g. 3/24h).
        \param boot_wait_s         Minimum floor to wait after reboot, seconds.
        \param readiness_probe     Optional; when it returns True the router is
                                   back and the wait ends early (>= boot_wait_s).
        \param readiness_ceiling_s Hard cap on total wait, seconds.
        \param readiness_poll_s    Interval between readiness probes, seconds.
        \param sleep               Injectable sleep (tests pass a no-op).
        """
        self._api = api
        self._breaker = breaker
        self._boot_wait_s = boot_wait_s
        self._probe = readiness_probe
        self._ceiling_s = readiness_ceiling_s
        self._poll_s = readiness_poll_s
        self._sleep = sleep

    def available(self, now: float) -> bool:
        r"""\brief Whether the L3 breaker still has budget. \return breaker.allow(now)."""
        return self._breaker.allow(now)

    def _wait_for_boot(self) -> None:
        r"""\brief Sleep the floor, then poll readiness up to the ceiling."""
        self._sleep(self._boot_wait_s)
        if self._probe is None:
            return
        waited = self._boot_wait_s
        while waited < self._ceiling_s:
            if self._probe():
                _emit(logging.INFO, TAG_STATE, "router readiness confirmed after ~%.0fs SWITCHING TO normal polling", waited)
                return
            self._sleep(self._poll_s)
            waited += self._poll_s
        _emit(logging.WARNING, TAG_DETECT, "readiness ceiling (%.0fs) reached, router still not confirmed up", self._ceiling_s)

    def attempt(self, now: float) -> bool:
        r"""
        \brief Issue REBOOT_DEVICE if the breaker allows, then wait for boot.

        \param now  Current epoch time, in seconds.
        \return True if the reboot command was issued successfully.
        """
        if not self._breaker.allow(now):
            # Defensive: step() pre-checks available() and owns the latched
            # "software exhausted" CRITICAL, so this is unreachable in normal
            # flow. FUTURE SHELLY SEAM #2 attaches at the step() latch.
            _emit(logging.DEBUG, TAG_STATE, "%s breaker tripped -- skipped", self.name)
            return False
        issued = self._api.ensure_login() and self._api.reboot_device()
        self._breaker.record(now)  # an attempt counts, success or not
        if issued:
            _emit(logging.WARNING, TAG_ACTION, "REBOOT_DEVICE issued SWITCHING TO boot wait")
            self._wait_for_boot()
        return issued


# --- state / config / deps ---------------------------------------------------


# --- MTU guard: path-MTU black-hole detection and correction -----------------
#
# WHY THIS IS NOT A LADDER RUNG
#
# step() returns early whenever is_wan_up() is true, and is_wan_up() is a
# 56-byte ICMP echo. During a path-MTU black hole that probe SUCCEEDS every
# cycle -- small packets pass -- so the ladder is never consulted even though
# every TLS handshake on the LAN is failing. The guard therefore attaches to
# the HAPPY path of step(), not to deps.ladder. The two subsystems are
# orthogonal: the ladder owns "WAN is down", the guard owns "WAN is up but
# lying about its packet size".
#
# FAILURE SIGNATURE (what a black hole looks like from the LAN)
#   HTTP  (port 80, small responses)     works
#   QUIC  (UDP 443; Google, Anthropic)   works  -- does its own MTU probing
#   HTTPS (TCP 443, everything else)     fails  -- ERR_CONNECTION_CLOSED
#   Wired + Windows clients              work   -- OS PMTU blackhole detection
#   Android clients                      fail   -- no blackhole detection
#   Path ceiling: some value below 1500, specific to your carrier's path.
#                 Bisect it; do not copy a number from anyone else.
#
# The intermediate hop drops oversized packets WITHOUT the ICMP
# "fragmentation needed" reply that RFC 1191 PMTUD depends on -- hence
# "black hole": nothing tells the sender to back off.
#
# STRATEGY
#   DETECT   small probe must pass AND target-sized probe must fail.
#            Both failing is an ordinary outage: left to the ladder.
#   MEASURE  binary-search the true ceiling between MTU_FLOOR and 1500.
#   CORRECT  write ceiling (MTU) and ceiling-40 (MSS), then re-probe.
#
# BOUNDS
#   MTU_FLOOR      never write below it, whatever the search says.
#   CircuitBreaker a flapping carrier path must not become a rewrite loop.
#   Corrections only run when the small probe passes, so a plain outage can
#   never be misread as a shrinking path and drive MTU to the floor.


#: ICMP payload size for the "is the link alive at all" probe. 56 matches the
#: ladder's own icmp_ok(), so both subsystems agree on what "WAN up" means.
SMALL_PROBE_PAYLOAD = 56

#: IPv4 header (20) + ICMP header (8). payload + this == on-the-wire size.
_ICMP_OVERHEAD = 28

#: TCP MSS is MTU minus IPv4 (20) and TCP (20) headers.
_MSS_OVERHEAD = 40

# MTU guard defaults. Same rule as the block near the top: one definition each,
# read by both MtuGuardConfig's field defaults and build_deps()'s env fallbacks.

#: PLACEHOLDER -- swap for YOUR measured path ceiling (installer: MTU_TARGET).
#: See the MTU_TARGET block at the top of install_zte_watchdog.sh.
DEFAULT_MTU_TARGET = 1360
#: Never write an MTU below this, whatever the search returns.
DEFAULT_MTU_FLOOR = 1200
#: Upper bound of the search: standard Ethernet.
DEFAULT_MTU_CEILING = 1500
#: Seconds between MTU checks.
DEFAULT_MTU_CHECK_EVERY_S = 900
#: MTU corrections allowed per rolling window.
DEFAULT_MTU_MAX_PER_WINDOW = 4


def icmp_ok_sized(
    target: str,
    total_size: int,
    timeout_s: int = 2,
    *,
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> bool:
    r"""
    \brief One DF-set ICMP echo of an exact on-the-wire size.

    \details Mirrors `ping -M do -s <payload>`: the don't-fragment bit forces
    routers to drop rather than fragment, which is what makes this a path-MTU
    probe rather than a reachability probe.

    \param target      IP to ping (an IP, never a hostname -- DNS is itself a
                       casualty of a black hole and would confound the result).
    \param total_size  Desired on-the-wire packet size in bytes (payload + 28).
    \param timeout_s   Per-ping deadline, in seconds.
    \param runner      Injectable subprocess.run (tests pass a fake).
    \return True if a reply arrived within the deadline at that exact size.
    """
    payload = max(0, total_size - _ICMP_OVERHEAD)
    try:
        result = runner(
            ["ping", "-M", "do", "-s", str(payload), "-c", "1", "-W", str(timeout_s), target],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout_s + _PING_HARD_TIMEOUT_MARGIN_S,
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        _emit(logging.WARNING, TAG_DETECT,
              "sized ping (%sB) to %s exceeded its hard timeout -- treating as blocked",
              total_size, target)
        return False
    except FileNotFoundError:
        _emit(logging.ERROR, TAG_FAULT, "ping binary not found -- install iputils-ping")
        return False


@dataclass
class MtuGuardConfig:
    r"""\brief Tuning parameters for the MTU guard."""

    #: Seconds between MTU checks. Far coarser than the ladder's interval: a
    #: black hole is a config/carrier-path event, not a flapping condition,
    #: and each check costs two pings.
    check_every_s: int = DEFAULT_MTU_CHECK_EVERY_S
    #: The MTU we expect to be in force on a healthy link. PLACEHOLDER --
    #: this must be YOUR measured path ceiling, set via MTU_TARGET. A value
    #: the path cannot carry makes every check re-detect a black hole.
    target_mtu: int = DEFAULT_MTU_TARGET
    #: Never write an MTU below this, whatever the search returns.
    mtu_floor: int = DEFAULT_MTU_FLOOR
    #: Upper bound of the search (standard Ethernet).
    mtu_ceiling: int = DEFAULT_MTU_CEILING
    #: Search granularity, in bytes. 4 lands well inside TCP's tolerance while
    #: bounding the search to ~7 probes across the 1200..1500 range.
    search_step: int = 4
    #: When True, measure and log but never issue a goform SET.
    dry_run: bool = False


@dataclass
class MtuGuardState:
    r"""\brief State the guard carries between checks."""

    last_check_time: float = 0.0
    #: Latched so a persistent, uncorrectable black hole logs CRITICAL once
    #: rather than every check.
    blackhole_announced: bool = False
    #: Last ceiling found by measure_path_mtu(), for logging and diffing.
    last_measured_mtu: Optional[int] = None


class MtuGuard:
    r"""
    \brief Detects path-MTU black holes and rewrites the router's MTU to match
           the measured path ceiling.

    \details Collaborators are injected so the whole class is testable without
    hardware: `probe` stands in for sized ICMP, `write_mtu` for the goform SET.
    """

    name = "MTU_GUARD"

    def __init__(
        self,
        probe: Callable[[int], bool],
        write_mtu: Callable[[int, int], bool],
        breaker: "CircuitBreaker",
        cfg: MtuGuardConfig,
    ) -> None:
        r"""
        \param probe      (total_size) -> bool; DF-set ICMP at that exact size.
        \param write_mtu  (mtu, mss) -> bool; issues the router-side write.
        \param breaker    Bounds corrections per rolling window.
        \param cfg        Tuning parameters.
        """
        self._probe = probe
        self._write = write_mtu
        self._breaker = breaker
        self._cfg = cfg

    # detection ---------------------------------------------------------------

    def detect_blackhole(self) -> Optional[bool]:
        r"""
        \brief Classify the link with two probes.

        \details GIVEN the link may be healthy, black-holed, or simply down
                 WHEN a small probe and a target-sized probe are sent
                 THEN return True (black hole), False (healthy), or None
                      (link down -- not ours to judge; the ladder owns that).

        \return True black hole, False healthy, None link down / inconclusive.
        """
        if not self._probe(SMALL_PROBE_PAYLOAD + _ICMP_OVERHEAD):
            # Both this guard and the ladder would see this; the ladder acts.
            _emit(logging.DEBUG, TAG_HEARTBEAT,
                  "small probe failed -- link down, deferring to recovery ladder")
            return None
        if self._probe(self._cfg.target_mtu):
            _emit(logging.DEBUG, TAG_HEARTBEAT, "MTU probe ok at %sB", self._cfg.target_mtu)
            return False
        _emit(logging.WARNING, TAG_DETECT,
              "path-MTU black hole: %sB probe blocked while %sB passes "
              "(TLS handshakes will fail; QUIC and plain HTTP will not)",
              self._cfg.target_mtu, SMALL_PROBE_PAYLOAD + _ICMP_OVERHEAD)
        return True

    # measurement -------------------------------------------------------------

    def measure_path_mtu(self) -> Optional[int]:
        r"""
        \brief Binary-search the largest packet size that traverses the path.

        \details GIVEN a path whose ceiling is unknown
                 WHEN sizes between mtu_floor and mtu_ceiling are probed
                 THEN return the largest size that passes, rounded down to
                      search_step, or None if even the floor is blocked.

        The floor is a hard bound: a link that cannot pass mtu_floor is broken
        in a way lowering MTU will not fix, and writing an ever-smaller value
        would only mask it.

        \return Measured ceiling in bytes, or None if the floor itself fails.
        """
        lo, hi = self._cfg.mtu_floor, self._cfg.mtu_ceiling
        if not self._probe(lo):
            _emit(logging.ERROR, TAG_FAULT,
                  "even the %sB floor is blocked -- not an MTU problem; refusing to lower further", lo)
            return None
        best = lo
        while lo <= hi:
            mid = ((lo + hi) // 2 // self._cfg.search_step) * self._cfg.search_step
            if mid <= best:
                break
            if self._probe(mid):
                best = mid
                lo = mid + self._cfg.search_step
            else:
                hi = mid - self._cfg.search_step
        _emit(logging.INFO, TAG_DETECT, "measured path MTU ceiling: %sB", best)
        return best

    # correction --------------------------------------------------------------

    def correct(self, now: float) -> bool:
        r"""
        \brief Measure the path and write the result to the router.

        \details GIVEN a confirmed black hole
                 WHEN the breaker still has budget
                 THEN measure the true ceiling, write MTU and MSS, and re-probe
                      to confirm the correction took effect.

        \param now  Current epoch time, in seconds.
        \return True if the correction was written AND confirmed by re-probe.
        """
        if not self._breaker.allow(now):
            _emit(logging.WARNING, TAG_STATE,
                  "MTU correction budget spent (%s/24h) SWITCHING TO observe-only",
                  self._breaker.name)
            return False

        measured = self.measure_path_mtu()
        if measured is None:
            return False

        mss = measured - _MSS_OVERHEAD
        if self._cfg.dry_run:
            _emit(logging.WARNING, TAG_ACTION,
                  "DRY RUN -- would write MTU=%s MSS=%s (set MTU_GUARD_DRY_RUN=0 once the "
                  "goform contract is captured; see MTU_PAYLOAD_TEMPLATE)", measured, mss)
            return False

        self._breaker.record(now)
        _emit(logging.WARNING, TAG_ACTION, "SWITCHING TO MTU write: MTU=%s MSS=%s", measured, mss)
        if not self._write(measured, mss):
            _emit(logging.ERROR, TAG_ACTION,
                  "MTU write did not complete (see FAULT lines above)")
            return False

        if self._probe(measured):
            _emit(logging.INFO, TAG_ACTION,
                  "MTU corrected to %s and confirmed by re-probe SWITCHING TO normal polling", measured)
            return True
        _emit(logging.ERROR, TAG_FAULT,
              "MTU written as %s but re-probe still blocked -- the write may not have "
              "applied, or the path shrank mid-correction", measured)
        return False

    # per-cycle entry point ---------------------------------------------------

    def check(self, state: MtuGuardState, now: float) -> MtuGuardState:
        r"""
        \brief One guard cycle. Rate-limited; safe to call every poll cycle.

        \details GIVEN the watchdog's happy path runs every check_interval_s
                 WHEN check_every_s has not yet elapsed
                 THEN return the state untouched, spending no probes.

        \param state  Current guard state (not mutated; a new one is returned).
        \param now    Current epoch time, in seconds.
        \return The next guard state.
        """
        if now - state.last_check_time < self._cfg.check_every_s:
            return state

        s = MtuGuardState(
            last_check_time=now,
            blackhole_announced=state.blackhole_announced,
            last_measured_mtu=state.last_measured_mtu,
        )

        verdict = self.detect_blackhole()
        if verdict is None:
            return s
        if verdict is False:
            if s.blackhole_announced:
                _emit(logging.INFO, TAG_STATE,
                      "path MTU healthy again SWITCHING TO normal polling")
            s.blackhole_announced = False
            return s

        corrected = self.correct(now)
        s.last_measured_mtu = self._cfg.target_mtu if corrected else s.last_measured_mtu
        if corrected:
            s.blackhole_announced = False
        elif not s.blackhole_announced:
            _emit(logging.CRITICAL, TAG_STATE,
                  "path-MTU black hole present and not corrected -- HTTPS will fail for "
                  "clients without PMTU blackhole detection (Android in particular)")
            s.blackhole_announced = True
        return s


@dataclass(frozen=True)
class WatchdogConfig:
    r"""\brief Immutable tuning parameters for the poll loop."""

    check_interval_s: int
    fail_threshold: int
    cooldown_s: int
    l3_escalation_threshold: int
    router_dead_threshold: int
    admin_dead_retry_every: int

    @staticmethod
    def from_env() -> "WatchdogConfig":
        r"""\brief Build config from the environment (EnvironmentFile=config.env)."""
        return WatchdogConfig(
            check_interval_s=_env_int("CHECK_INTERVAL", DEFAULT_CHECK_INTERVAL_S),
            fail_threshold=_env_int("FAIL_THRESHOLD", DEFAULT_FAIL_THRESHOLD),
            cooldown_s=_env_int("COOLDOWN", DEFAULT_COOLDOWN_S),
            l3_escalation_threshold=_env_int(
                "L3_ESCALATION_THRESHOLD", DEFAULT_L3_ESCALATION_THRESHOLD),
            router_dead_threshold=_env_int(
                "ROUTER_DEAD_THRESHOLD", DEFAULT_ROUTER_DEAD_THRESHOLD),
            admin_dead_retry_every=_env_int(
                "ADMIN_DEAD_RETRY_EVERY", DEFAULT_ADMIN_DEAD_RETRY_EVERY),
        )


@dataclass
class WatchdogState:
    r"""\brief Everything the poll loop carries between cycles."""

    consecutive_failures: int = 0
    escalation_level: int = 1  # 1=L1, 2=L2, 3=L3 (the ceiling we may climb to)
    consecutive_l2_failures: int = 0
    router_dead_streak: int = 0
    admin_dead_announced: bool = False
    last_action_time: float = 0.0
    exhausted: bool = False  # latch: software recovery spent (quiesce, log once)
    #: MTU-guard state. Lives here (not in a module global) so the happy path
    #: can carry it across cycles -- see the note in step().
    mtu: MtuGuardState = field(default_factory=MtuGuardState)
    #: Latch so the "no registration" finding is announced once per episode.
    unregistered_announced: bool = False


@dataclass
class WatchdogDeps:
    r"""
    \brief Injected collaborators, so step() can be tested with fakes.

    \var is_wan_up            () -> bool  external connectivity signal.
    \var is_admin_plane_up    () -> bool  router-HTTP-alive signal.
    \var ladder               [L1, L2, L3] recovery rungs, cheapest first.
    \var on_admin_plane_dead  (now) -> None  fired when the router is wedged.
    \var is_registered        () -> Optional[bool] carrier-registration signal.
    \var mtu_guard            optional MtuGuard; None disables the check.
    """

    is_wan_up: Callable[[], bool]
    is_admin_plane_up: Callable[[], bool]
    #: () -> True registered / False not registered / None unknown.
    #: When False, L2 cannot help and the ladder jumps straight to L3.
    is_registered: Callable[[], Optional[bool]]
    ladder: List[RecoveryAction]
    on_admin_plane_dead: Callable[[float], None]
    #: Optional path-MTU guard, consulted on the HAPPY path (see step()).
    mtu_guard: Optional["MtuGuard"] = None


# --- pure per-cycle decision -------------------------------------------------


def step(state: WatchdogState, deps: WatchdogDeps, cfg: WatchdogConfig, now: float) -> WatchdogState:
    r"""
    \brief Decide and act for exactly one poll cycle. Pure w.r.t. `state`.

    \param state  Current state (not mutated; a new state is returned).
    \param deps   Injected signals/actions.
    \param cfg    Tuning parameters.
    \param now    Current epoch time, in seconds.
    \return The next state.
    """
    s = replace(state)

    # happy path: WAN up
    if deps.is_wan_up():
        if s.consecutive_failures or s.escalation_level > 1:
            _emit(logging.INFO, TAG_STATE, "connectivity restored (was level %s after %s failed checks) SWITCHING TO normal polling",
                  s.escalation_level, s.consecutive_failures)
        else:
            _emit(logging.DEBUG, TAG_HEARTBEAT, "ping ok")
        # "Reachable" is not "usable": a path-MTU black hole passes small ICMP
        # and kills every TLS handshake, so the ladder above never fires. The
        # guard is rate-limited internally (MTU_CHECK_EVERY), so calling it on
        # every happy cycle costs nothing between checks.
        #
        # NOTE: mtu state must be threaded through explicitly. This branch
        # deliberately returns a FRESH WatchdogState to reset the ladder, which
        # would otherwise wipe the guard's rate-limit timestamp and announce
        # latch on every single cycle.
        mtu_state = s.mtu
        if deps.mtu_guard is not None:
            mtu_state = deps.mtu_guard.check(mtu_state, now)
        return WatchdogState(last_action_time=s.last_action_time, mtu=mtu_state)

    # WAN down: count, bail until sustained. After the threshold the "/N"
    # ratio is meaningless, so switch to a sustained-outage line with elapsed
    # time instead of an ever-growing "(417/3 consecutive)".
    s.consecutive_failures += 1
    if s.consecutive_failures <= cfg.fail_threshold:
        _emit(logging.WARNING, TAG_DETECT, "WAN unreachable (%s/%s consecutive)",
              s.consecutive_failures, cfg.fail_threshold)
    else:
        elapsed_min = (s.consecutive_failures * cfg.check_interval_s) // 60
        _emit(logging.WARNING, TAG_DETECT, "WAN still unreachable (sustained: %s checks, ~%smin)",
              s.consecutive_failures, elapsed_min)
    if s.consecutive_failures < cfg.fail_threshold:
        return s

    # LIVENESS GATE: is the admin plane even reachable? The hook is latched to
    # the crossing (== threshold) so it fires once per dead episode, not every
    # cycle. The per-cycle DETECT line stays as the liveness pulse.
    if not deps.is_admin_plane_up():
        s.router_dead_streak += 1
        # Same reasoning as the WAN counter above: once the threshold is passed
        # the "/N" ratio is meaningless, so report elapsed time. The form is
        # keyed off the ANNOUNCEMENT latch, not the streak: a flapping admin
        # plane resets the streak, and keying off it would replay the "(1/3)
        # (2/3) (3/3)" preamble on every flap.
        if not s.admin_dead_announced:
            _emit(logging.ERROR, TAG_DETECT, "router admin plane unreachable (%s/%s) -- no goform recovery possible",
                  s.router_dead_streak, cfg.router_dead_threshold)
        else:
            dead_min = (s.router_dead_streak * cfg.check_interval_s) // 60
            _emit(logging.ERROR, TAG_DETECT, "router admin plane still dead (sustained: %s checks, ~%smin)",
                  s.router_dead_streak, dead_min)
        # One CRITICAL per outage, not per streak crossing: without this latch a
        # flapping admin plane re-fires the hook every few cycles.
        if s.router_dead_streak >= cfg.router_dead_threshold and not s.admin_dead_announced:
            s.admin_dead_announced = True
            deps.on_admin_plane_dead(now)
        # A failed probe is evidence, not proof, that no goform can land: the
        # probe itself can fail on a live router (stale socket, transient 5xx,
        # HTTP stack busy). Retrying the ladder every Nth cycle keeps a path
        # out of the hole instead of counting forever until a human intervenes.
        if cfg.admin_dead_retry_every <= 0 or s.router_dead_streak % cfg.admin_dead_retry_every != 0:
            return s
        _emit(logging.WARNING, TAG_STATE,
              "admin plane dead for %s cycles SWITCHING TO blind ladder retry",
              s.router_dead_streak)
    elif s.router_dead_streak:
        if s.admin_dead_announced:
            _emit(logging.INFO, TAG_DETECT, "router admin plane reachable again SWITCHING TO ladder")
        s.router_dead_streak = 0

    # REGISTRATION GATE: the admin plane answers, so ask the modem whether it
    # is attached to a network at all. Two different faults hide behind one
    # symptom ("no internet"):
    #
    #   ppp_connected but no route  -> data session wedged   -> L2 re-dials it
    #   Limited Service / no attach -> nothing to re-dial     -> only L3 helps
    #
    # Without this gate the second case still reaches L3 eventually, but only
    # after L3_ESCALATION_THRESHOLD failed L2 attempts spaced a cooldown apart
    # -- roughly ten minutes of guaranteed-useless DISCONNECT/CONNECT calls,
    # each burning L2 breaker budget that a real session fault might need later.
    registered = deps.is_registered()
    if registered is False:
        if not s.unregistered_announced:
            _emit(logging.ERROR, TAG_STATE,
                  "modem has no network registration (Limited Service) -- L2 cannot re-dial "
                  "a session that does not exist SWITCHING TO ceiling L3 (REBOOT_DEVICE)")
            s.unregistered_announced = True
        s.escalation_level = LADDER_TOP_LEVEL
    elif registered is True and s.unregistered_announced:
        _emit(logging.INFO, TAG_DETECT, "modem registered again")
        s.unregistered_announced = False
    # registered is None: unreadable. Say nothing and let the ladder proceed
    # normally -- an unreadable router is the liveness gate's concern.

    # EXHAUSTION LATCH: at the top of the ladder with both breaker-gated rungs
    # spent, more software attempts cannot help. Log CRITICAL once, then quiesce
    # (keep polling for restoration) until a breaker frees up or WAN returns.
    l2, l3 = deps.ladder[1], deps.ladder[2]
    exhausted_now = (s.escalation_level >= LADDER_TOP_LEVEL
                     and not l2.available(now) and not l3.available(now))
    if exhausted_now:
        if not s.exhausted:
            _emit(logging.CRITICAL, TAG_STATE,
                  "software recovery EXHAUSTED (L2 and L3 budgets spent in window) -- "
                  "physical intervention needed; still polling for restoration")
            s.exhausted = True
        return s
    s.exhausted = False  # a breaker freed up: resume acting

    # global cooldown between recovery actions
    remaining = cfg.cooldown_s - (now - s.last_action_time)
    if remaining > 0:
        _emit(logging.INFO, TAG_STATE, "threshold hit but in cooldown (%.0fs remaining) SWITCHING TO wait", remaining)
        return s

    # Select the highest rung within the current ceiling that still has budget,
    # falling back to a cheaper one (L1 has no breaker, so it is always the
    # floor). This keeps useful work flowing instead of spinning on a spent rung.
    chosen_idx = 0
    for i in range(s.escalation_level - 1, -1, -1):
        if deps.ladder[i].available(now):
            chosen_idx = i
            break
    action = deps.ladder[chosen_idx]

    _emit(logging.WARNING, TAG_ACTION, "ceiling L%s SWITCHING TO %s", s.escalation_level, action.name)
    issued = action.attempt(now)
    s.last_action_time = now
    if issued:
        _emit(logging.INFO, TAG_ACTION, "%s completed SWITCHING TO awaiting effect", action.name)
    else:
        _emit(logging.ERROR, TAG_ACTION, "%s did not complete (see FAULT/DETECT lines above)", action.name)

    # Raise the ceiling for next time. Accounting is based on what actually ran:
    # only a real L2 attempt counts toward the L2->L3 escalation; a spent L2
    # breaker (fell back to L1) unlocks L3 directly.
    if s.escalation_level == 1:
        s.escalation_level = 2
        _emit(logging.INFO, TAG_STATE, "SWITCHING TO ceiling L2 (DISCONNECT/CONNECT)")
    elif s.escalation_level == 2:
        if chosen_idx == 1:
            s.consecutive_l2_failures += 1
        if s.consecutive_l2_failures >= cfg.l3_escalation_threshold or not l2.available(now):
            s.escalation_level = LADDER_TOP_LEVEL
            _emit(logging.WARNING, TAG_STATE, "SWITCHING TO ceiling L3 (REBOOT_DEVICE)")
    # ceiling 3 stays; the exhaustion latch above bounds it.

    return s


# --- wiring + loop -----------------------------------------------------------


def build_deps(cfg: WatchdogConfig) -> WatchdogDeps:
    r"""
    \brief Assemble the real (non-test) dependency graph from the environment.

    \param cfg  Loaded configuration.
    \return Fully wired WatchdogDeps.
    """
    router_ip = os.environ.get("ROUTER_IP", "192.168.0.1")
    password = os.environ.get("ROUTER_PASSWORD", "")
    ping_target = os.environ.get("PING_TARGET", "1.1.1.1")
    boot_wait_s = float(_env_int("L3_BOOT_WAIT", DEFAULT_L3_BOOT_WAIT_S))
    l2_settle_s = float(_env_int("L2_SETTLE", DEFAULT_L2_SETTLE_S))
    l2_max = _env_int("L2_MAX_PER_WINDOW", DEFAULT_L2_MAX_PER_WINDOW)
    l3_max = _env_int("L3_MAX_PER_WINDOW", DEFAULT_L3_MAX_PER_WINDOW)
    window_s = _env_int("ROLLING_WINDOW_SECONDS", DEFAULT_ROLLING_WINDOW_S)

    if not password:
        _emit(logging.ERROR, TAG_FAULT, "ROUTER_PASSWORD empty -- authentication will fail; set it in config.env")

    api = ZteRouterApi(router_ip, password)

    ladder: List[RecoveryAction] = [
        ConnectRecovery(api),
        DisconnectReconnectRecovery(api, CircuitBreaker(l2_max, window_s, "L2"), settle_s=l2_settle_s),
        SoftRebootRecovery(
            api,
            CircuitBreaker(l3_max, window_s, "L3"),
            boot_wait_s=boot_wait_s,
            readiness_probe=lambda: api.is_admin_plane_up() and icmp_ok(ping_target),
        ),
    ]

    def on_admin_plane_dead(now: float) -> None:
        r"""
        \brief Fired when the router's admin HTTP is wedged (log-only today).

        \details FUTURE SHELLY SEAM #1: the router answers nothing over HTTP,
        so L1/L2/L3 are all useless. A physical power-cycle (Shelly Plug S)
        would attach here -- cutting mains needs no cooperation from the router.
        """
        _emit(
            logging.CRITICAL, TAG_STATE,
            "admin plane unreachable -- no software recovery possible; manual power-cycle of the router needed",
        )

    mtu_guard: Optional[MtuGuard] = None
    if _env_int("MTU_GUARD_ENABLED", 1):
        mtu_cfg = MtuGuardConfig(
            check_every_s=_env_int("MTU_CHECK_EVERY", DEFAULT_MTU_CHECK_EVERY_S),
            target_mtu=_env_int("MTU_TARGET", DEFAULT_MTU_TARGET),
            mtu_floor=_env_int("MTU_FLOOR", DEFAULT_MTU_FLOOR),
            dry_run=bool(_env_int("MTU_GUARD_DRY_RUN", 0)),
        )
        mtu_guard = MtuGuard(
            probe=lambda size: icmp_ok_sized(ping_target, size),
            write_mtu=api.set_mtu,
            breaker=CircuitBreaker(
                _env_int("MTU_MAX_PER_WINDOW", DEFAULT_MTU_MAX_PER_WINDOW),
                window_s, "MTU"),
            cfg=mtu_cfg,
        )
        _emit(logging.INFO, TAG_LIFECYCLE,
              "MTU guard: target=%sB floor=%sB every=%ss dry_run=%s",
              mtu_cfg.target_mtu, mtu_cfg.mtu_floor, mtu_cfg.check_every_s, mtu_cfg.dry_run)
        if mtu_cfg.dry_run:
            _emit(logging.WARNING, TAG_LIFECYCLE,
                  "MTU guard is in DRY RUN -- it will detect and measure but never write. "
                  "Re-install with MTU_GUARD_DRY_RUN=0 to enable corrections")
    else:
        _emit(logging.INFO, TAG_LIFECYCLE, "MTU guard disabled (MTU_GUARD_ENABLED=0)")

    _emit(logging.INFO, TAG_LIFECYCLE, "wired: router=%s ping=%s L2=%s/24h L3=%s/24h boot_wait=%.0fs",
          router_ip, ping_target, l2_max, l3_max, boot_wait_s)

    return WatchdogDeps(
        is_wan_up=lambda: icmp_ok(ping_target),
        is_admin_plane_up=api.is_admin_plane_up,
        is_registered=api.is_registered,
        ladder=ladder,
        on_admin_plane_dead=on_admin_plane_dead,
        mtu_guard=mtu_guard,
    )


def main() -> None:
    r"""\brief Entrypoint: load config, wire deps, run the poll loop forever."""
    cfg = WatchdogConfig.from_env()
    _emit(logging.INFO, TAG_LIFECYCLE, "starting: interval=%ss threshold=%s cooldown=%ss L3-after=%s L2-fails admin-dead-after=%s cycles",
          cfg.check_interval_s, cfg.fail_threshold, cfg.cooldown_s, cfg.l3_escalation_threshold, cfg.router_dead_threshold)
    deps = build_deps(cfg)
    state = WatchdogState()
    consecutive_faults = 0
    # NOTE ON CADENCE: check_interval_s is the SLEEP between cycles, not a
    # period. step() runs synchronously and a single cycle can block far longer
    # than the interval -- worst case is an L3 reboot: ~24s of HTTP plus the
    # boot wait (L3_BOOT_WAIT floor, readiness ceiling 180s) = ~205s. That is
    # deliberate (there is nothing to poll while the router reboots), but it
    # means "interval=20s" is a floor, not a guarantee. Elapsed time in the
    # DETECT lines is derived from the cycle COUNT, so it under-reports during
    # an L3 episode.
    while True:
        cycle_started = time.time()
        try:
            state = step(state, deps, cfg, time.time())
            consecutive_faults = 0
        except Exception:  # noqa: BLE001 - guard: a bug must not kill the daemon
            consecutive_faults += 1
            _emit(
                logging.ERROR, TAG_FAULT,
                "unhandled exception in poll cycle (#%s consecutive) -- this is a CODE bug, not a detected condition",
                consecutive_faults, exc_info=True,
            )
        # Subtract the work already done so a slow cycle does not stack its
        # duration on top of a full interval.
        elapsed = time.time() - cycle_started
        if elapsed > cfg.check_interval_s:
            _emit(logging.DEBUG, TAG_HEARTBEAT, "cycle took %.0fs (> interval %ss)", elapsed, cfg.check_interval_s)
        time.sleep(max(0.0, cfg.check_interval_s - elapsed))


if __name__ == "__main__":
    main()
PYEOF

echo "[4b/7] Writing test suite to ${INSTALL_DIR}/test_zte_watchdog.py..."
cat > "${INSTALL_DIR}/test_zte_watchdog.py" << 'PYTESTEOF'
r"""
\file test_zte_watchdog.py
\brief GWT tests for zte_watchdog. Every HTTP call and sleep is mocked; no
       hardware is touched. Run: python -m pytest test_zte_watchdog.py -q

Grouped by unit, each test names Given-When-Then and (in the section headers)
what is tested and why.
"""

import hashlib
import logging
import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import List
from unittest.mock import MagicMock, patch

import pytest
import requests

import zte_watchdog

from zte_watchdog import (
    CircuitBreaker,
    DisconnectReconnectRecovery,
    SoftRebootRecovery,
    WatchdogConfig,
    WatchdogDeps,
    WatchdogState,
    ConnectRecovery,
    ZteRouterApi,
    icmp_ok,
    step,
    # MTU guard
    MtuGuard,
    MtuGuardConfig,
    MtuGuardState,
    SMALL_PROBE_PAYLOAD,
    _ICMP_OVERHEAD,
    icmp_ok_sized,
)

# =====================================================================
# CircuitBreaker -- the shared safety property (allow/record/prune)
# =====================================================================


def test_given_fewer_than_max_in_window_when_allow_then_true():
    cb = CircuitBreaker(3, 100, "T")
    cb.record(1000.0)
    cb.record(1000.0)
    assert cb.allow(1000.0) is True


def test_given_max_reached_in_window_when_allow_then_false():
    cb = CircuitBreaker(2, 100, "T")
    cb.record(1000.0)
    cb.record(1000.0)
    assert cb.allow(1000.0) is False


def test_given_events_older_than_window_when_allow_then_pruned_and_true():
    cb = CircuitBreaker(1, 100, "T")
    cb.record(1000.0)
    assert cb.allow(1000.0) is False        # within window: blocked
    assert cb.allow(1101.0) is True         # 101s > 100s window: aged out


def test_given_partial_window_when_remaining_then_counts_only_live_events():
    cb = CircuitBreaker(3, 100, "T")
    cb.record(1000.0)                        # ages out at t=1101
    cb.record(1080.0)                        # still live
    assert cb.remaining(1101.0) == 2


# =====================================================================
# ZteRouterApi -- auth on the wire (SHA256 login / MD5 AD), liveness.
# Why: prove the confirmed scheme is actually sent, and that transport vs
# protocol failures are handled (and, via logs, categorized) distinctly.
# =====================================================================


def _resp(json_body, status=200, text=""):
    r = MagicMock()
    r.status_code = status
    r.json.return_value = json_body
    r.text = text
    r.raise_for_status.return_value = None
    return r


def _sha_upper(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest().upper()


def _session():
    s = MagicMock(spec=requests.Session)
    s.headers = {}
    return s


def test_given_ld_nonce_when_login_then_posts_expected_sha256_hash():
    s = _session()
    s.get.return_value = _resp({"LD": "ABCDEF"})
    s.post.return_value = _resp({"result": "0"})

    api = ZteRouterApi("192.168.0.1", "s3cret", session=s)
    assert api.login() is True

    expected = _sha_upper(_sha_upper("s3cret") + "ABCDEF")
    _, kwargs = s.post.call_args
    assert kwargs["data"]["goformId"] == "LOGIN"
    assert kwargs["data"]["password"] == expected


def test_given_authenticated_when_disconnect_then_sends_md5_ad_and_succeeds():
    s = _session()
    s.get.return_value = _resp({"wa_inner_version": "BD_V1", "cr_version": "", "RD": "RANDOM"})
    s.post.return_value = _resp({"result": "0"})

    api = ZteRouterApi("192.168.0.1", "pw", session=s)
    assert api.disconnect_network() is True

    inner = hashlib.md5("BD_V1".encode()).hexdigest()
    expected_ad = hashlib.md5((inner + "RANDOM").encode()).hexdigest()
    _, kwargs = s.post.call_args
    assert kwargs["data"]["goformId"] == "DISCONNECT_NETWORK"
    assert kwargs["data"]["AD"] == expected_ad


def test_given_set_times_out_when_reboot_then_false_and_session_invalidated():
    s = _session()
    s.get.return_value = _resp({"wa_inner_version": "v", "cr_version": "", "RD": "R"})
    s.post.side_effect = requests.Timeout("boom")

    api = ZteRouterApi("192.168.0.1", "pw", session=s)
    api._logged_in = True
    assert api.reboot_device() is False
    assert api._logged_in is False  # transport error forces re-login next time


def test_given_http_error_status_when_set_then_false_and_invalidated():
    s = _session()
    s.get.return_value = _resp({"wa_inner_version": "v", "cr_version": "", "RD": "R"})
    s.post.return_value = _resp({}, status=403)  # stok/AD rejected

    api = ZteRouterApi("192.168.0.1", "pw", session=s)
    api._logged_in = True
    assert api.connect_network() is False
    assert api._logged_in is False


def test_given_result_rejected_when_login_then_false():
    s = _session()
    s.get.return_value = _resp({"LD": "X"})
    s.post.return_value = _resp({"result": "1"})  # bad password / wrong scheme

    api = ZteRouterApi("192.168.0.1", "pw", session=s)
    assert api.login() is False


def test_given_set_result_rejected_when_disconnect_then_session_invalidated():
    # A HTTP-200 rejection (e.g. stale stok after a reboot) must drop the
    # cached login so the next action re-authenticates -- restoring the
    # original's per-action fresh auth. This is the regression fix.
    s = _session()
    s.get.return_value = _resp({"wa_inner_version": "v", "cr_version": "", "RD": "R"})
    s.post.return_value = _resp({"result": "failure"}, status=200)
    api = ZteRouterApi("192.168.0.1", "pw", session=s)
    api._logged_in = True
    assert api.disconnect_network() is False
    assert api._logged_in is False


def test_given_reboot_ok_when_reboot_then_session_invalidated():
    # After a successful REBOOT_DEVICE the router restarts and the stok dies;
    # the cached login must be dropped so post-boot commands re-authenticate.
    s = _session()
    s.get.return_value = _resp({"wa_inner_version": "v", "cr_version": "", "RD": "R"})
    s.post.return_value = _resp({"result": "0"}, status=200)
    api = ZteRouterApi("192.168.0.1", "pw", session=s)
    api._logged_in = True
    assert api.reboot_device() is True
    assert api._logged_in is False


def test_given_connection_error_when_probe_admin_plane_then_false():
    s = _session()
    s.get.side_effect = requests.ConnectionError("no route")
    api = ZteRouterApi("192.168.0.1", "pw", session=s)
    assert api.is_admin_plane_up() is False


def test_given_http_reply_when_probe_admin_plane_then_true():
    s = _session()
    s.get.return_value = _resp({"LD": "x"}, status=200)
    api = ZteRouterApi("192.168.0.1", "pw", session=s)
    assert api.is_admin_plane_up() is True


def test_given_auth_wall_403_when_probe_admin_plane_then_false():
    # A 403 is the router refusing us, not the router being alive for goform.
    s = _session()
    s.get.return_value = _resp({}, status=403)
    api = ZteRouterApi("192.168.0.1", "pw", session=s)
    assert api.is_admin_plane_up() is False


def test_given_html_error_page_200_when_probe_admin_plane_then_false():
    # Captive portal / router error page: HTTP 200 but not the goform API.
    s = _session()
    r = _resp(None, status=200, text="<html>error</html>")
    r.json.side_effect = ValueError("no json")
    s.get.return_value = r
    api = ZteRouterApi("192.168.0.1", "pw", session=s)
    assert api.is_admin_plane_up() is False


def test_given_probe_transport_error_when_probe_then_session_pool_dropped():
    s = _session()
    s.get.side_effect = requests.ConnectionError("refused")
    api = ZteRouterApi("192.168.0.1", "pw", session=s)
    api._logged_in = True
    assert api.is_admin_plane_up() is False
    assert api._logged_in is False
    s.close.assert_called_once()


def test_given_hanging_ping_when_icmp_ok_then_false_not_blocked():
    with patch("zte_watchdog.subprocess.run",
               side_effect=subprocess.TimeoutExpired(cmd="ping", timeout=5)):
        assert icmp_ok("1.1.1.1") is False


def test_given_ping_when_icmp_ok_then_a_hard_timeout_is_passed():
    with patch("zte_watchdog.subprocess.run") as run:
        run.return_value = MagicMock(returncode=0)
        icmp_ok("1.1.1.1", timeout_s=2)
        assert run.call_args.kwargs["timeout"] > 2


# =====================================================================
# Recovery rungs -- breaker gating, order, record-once semantics.
# =====================================================================


def _api_all_ok():
    api = MagicMock()
    api.ensure_login.return_value = True
    api.connect_network.return_value = True
    api.disconnect_network.return_value = True
    api.connect_network.return_value = True
    api.reboot_device.return_value = True
    return api


def test_given_l1_when_attempt_then_login_then_connect():
    api = _api_all_ok()
    assert ConnectRecovery(api).attempt(1000.0) is True
    api.ensure_login.assert_called_once()
    api.connect_network.assert_called_once()


def test_given_l2_breaker_tripped_when_attempt_then_no_goform_call():
    api = _api_all_ok()
    br = CircuitBreaker(1, 86400, "L2")
    br.record(1000.0)
    assert DisconnectReconnectRecovery(api, br, sleep=lambda _s: None).attempt(1000.0) is False
    api.disconnect_network.assert_not_called()


def test_given_l2_attempt_when_it_runs_then_breaker_records_exactly_once():
    api = _api_all_ok()
    br = CircuitBreaker(8, 86400, "L2")
    DisconnectReconnectRecovery(api, br, sleep=lambda _s: None).attempt(1000.0)
    assert br.remaining(1000.0) == 7


def test_given_l2_disconnect_fails_when_attempt_then_connect_still_runs():
    # After a reboot the session is already down; DISCONNECT may fail, but the
    # CONNECT (the OFF->ON that brings WAN back) must still run and decide L2.
    api = _api_all_ok()
    api.disconnect_network.return_value = False   # already disconnected
    br = CircuitBreaker(8, 86400, "L2")
    l2 = DisconnectReconnectRecovery(api, br, settle_s=0.0, sleep=lambda _s: None)
    assert l2.attempt(1000.0) is True             # connect succeeded -> L2 ok
    api.connect_network.assert_called_once()


def test_given_l2_when_attempt_then_disconnect_then_settle_then_connect():
    # The modem needs a beat: DISCONNECT must be followed by a settle sleep
    # before CONNECT, or the CONNECT is rejected ("failure").
    api = _api_all_ok()
    order: list = []
    api.disconnect_network.side_effect = lambda: (order.append("disc"), True)[1]
    api.connect_network.side_effect = lambda: (order.append("conn"), True)[1]
    br = CircuitBreaker(8, 86400, "L2")
    l2 = DisconnectReconnectRecovery(api, br, settle_s=3.0,
                                     sleep=lambda s: order.append(f"sleep{s}"))
    assert l2.attempt(1000.0) is True
    assert order == ["disc", "sleep3.0", "conn"]


def test_given_l2_redial_fails_when_attempt_then_still_records_the_attempt():
    api = _api_all_ok()
    api.connect_network.return_value = False
    br = CircuitBreaker(8, 86400, "L2")
    assert DisconnectReconnectRecovery(api, br, sleep=lambda _s: None).attempt(1000.0) is False
    assert br.remaining(1000.0) == 7


def test_given_l3_breaker_tripped_when_attempt_then_no_reboot():
    api = _api_all_ok()
    br = CircuitBreaker(1, 86400, "L3")
    br.record(1000.0)
    l3 = SoftRebootRecovery(api, br, boot_wait_s=0.0, sleep=lambda _s: None)
    assert l3.attempt(1000.0) is False
    api.reboot_device.assert_not_called()


def test_given_l3_ok_when_attempt_then_reboot_then_boot_wait_floor():
    api = _api_all_ok()
    calls: list = []
    br = CircuitBreaker(3, 86400, "L3")
    l3 = SoftRebootRecovery(api, br, boot_wait_s=1.0, readiness_probe=lambda: True, sleep=calls.append)
    assert l3.attempt(1000.0) is True
    api.reboot_device.assert_called_once()
    assert calls and calls[0] == 1.0  # floor slept before probing


# =====================================================================
# step() -- liveness gate, escalation ladder, cooldown, reset.
# =====================================================================


@dataclass
class FakeAction:
    name: str
    result: bool = True
    is_available: bool = True
    calls: List[float] = field(default_factory=list)

    def available(self, now: float) -> bool:
        return self.is_available

    def attempt(self, now: float) -> bool:
        self.calls.append(now)
        return self.result


def _cfg(**over):
    base = dict(check_interval_s=60, fail_threshold=3, cooldown_s=180,
                l3_escalation_threshold=3, router_dead_threshold=3,
                admin_dead_retry_every=10)
    base.update(over)
    return WatchdogConfig(**base)


def _deps(wan_up, admin_up, dead_calls, avail=(True, True, True), registered=True):
    r"""
    \brief Build injected deps for step() tests.

    \param registered  Carrier-registration signal: True (attached),
                       False (Limited Service), or None (unreadable).
                       Defaults to True so tests written before the
                       registration gate keep exercising the normal ladder.
    """
    l1 = FakeAction("L1", is_available=avail[0])
    l2 = FakeAction("L2", is_available=avail[1])
    l3 = FakeAction("L3", is_available=avail[2])
    deps = WatchdogDeps(
        is_wan_up=lambda: wan_up,
        is_admin_plane_up=lambda: admin_up,
        is_registered=lambda: registered,
        ladder=[l1, l2, l3],
        on_admin_plane_dead=lambda now: dead_calls.append(now),
    )
    return deps, (l1, l2, l3)


def test_given_wan_up_when_step_then_ladder_resets_to_level_1():
    deps, _ = _deps(True, True, [])
    start = WatchdogState(consecutive_failures=9, escalation_level=3, consecutive_l2_failures=5)
    out = step(start, deps, _cfg(), 1000.0)
    assert out.escalation_level == 1
    assert out.consecutive_failures == 0
    assert out.consecutive_l2_failures == 0


def test_given_wan_down_below_threshold_when_step_then_only_counts():
    deps, rungs = _deps(False, True, [])
    out = step(WatchdogState(consecutive_failures=0), deps, _cfg(), 1000.0)
    assert out.consecutive_failures == 1
    assert all(not r.calls for r in rungs)


def test_given_admin_plane_dead_reaching_threshold_when_step_then_hook_fires():
    dead: list = []
    deps, rungs = _deps(False, False, dead)
    out = step(WatchdogState(consecutive_failures=3, router_dead_streak=2), deps, _cfg(), 1000.0)
    assert out.router_dead_streak == 3
    assert dead == [1000.0]
    assert all(not r.calls for r in rungs)


def test_given_admin_plane_stays_dead_when_step_then_hook_fires_only_once():
    # crossing fires once (streak == threshold); staying dead does not re-fire.
    dead: list = []
    deps, _ = _deps(False, False, dead)
    st = WatchdogState(consecutive_failures=3, router_dead_streak=2)
    st = step(st, deps, _cfg(), 1000.0)   # streak 2->3 == threshold: fire
    st = step(st, deps, _cfg(), 1060.0)   # streak 3->4 > threshold: silent
    st = step(st, deps, _cfg(), 1120.0)   # streak 4->5 > threshold: silent
    assert dead == [1000.0]


def test_given_admin_plane_dead_off_retry_cycle_when_step_then_no_action():
    # streak 4..9 with retry_every=10: still counting, ladder untouched.
    deps, rungs = _deps(False, False, [])
    out = step(WatchdogState(consecutive_failures=5, router_dead_streak=4),
               deps, _cfg(cooldown_s=0), 1000.0)
    assert out.router_dead_streak == 5
    assert all(not r.calls for r in rungs)


def test_given_admin_plane_dead_on_retry_cycle_when_step_then_ladder_retried():
    # streak reaching a multiple of retry_every: try the ladder blind, because
    # a failed probe is not proof that no goform can land.
    deps, (l1, l2, l3) = _deps(False, False, [])
    out = step(WatchdogState(consecutive_failures=12, router_dead_streak=9),
               deps, _cfg(cooldown_s=0), 1000.0)
    assert out.router_dead_streak == 10
    assert l1.calls == [1000.0]


def test_given_retry_disabled_when_admin_plane_dead_then_never_retries():
    deps, rungs = _deps(False, False, [])
    st = WatchdogState(consecutive_failures=12, router_dead_streak=9)
    st = step(st, deps, _cfg(cooldown_s=0, admin_dead_retry_every=0), 1000.0)
    assert st.router_dead_streak == 10
    assert all(not r.calls for r in rungs)


def test_given_admin_plane_back_up_when_step_then_streak_resets_and_ladder_runs():
    deps, (l1, l2, l3) = _deps(False, True, [])
    out = step(WatchdogState(consecutive_failures=20, router_dead_streak=17),
               deps, _cfg(cooldown_s=0), 1000.0)
    assert out.router_dead_streak == 0
    assert l1.calls == [1000.0]


def test_given_flapping_admin_plane_when_step_then_hook_fires_only_once():
    # Regression: a streak that resets on every flap must not re-announce.
    dead: list = []
    deps, _ = _deps(False, False, dead)
    up_deps, _ = _deps(False, True, dead)
    st = WatchdogState(consecutive_failures=5)
    for i in range(6):                      # 3 dead cycles, 1 up, repeat
        st = step(st, deps, _cfg(cooldown_s=0), 1000.0 + i * 60)
        st = step(st, deps, _cfg(cooldown_s=0), 1030.0 + i * 60)
        st = step(st, deps, _cfg(cooldown_s=0), 1045.0 + i * 60)
        st = step(st, up_deps, _cfg(cooldown_s=0), 1050.0 + i * 60)
    assert len(dead) == 1


def test_given_announced_dead_when_step_then_log_drops_the_ratio(caplog):
    deps, _ = _deps(False, False, [])
    st = WatchdogState(consecutive_failures=5, router_dead_streak=20,
                       admin_dead_announced=True)
    with caplog.at_level(logging.ERROR):
        step(st, deps, _cfg(cooldown_s=0), 1000.0)
    msgs = [r.getMessage() for r in caplog.records]
    assert any("still dead" in m for m in msgs)
    assert not any("/3)" in m for m in msgs)


def test_given_l3_spent_but_l2_free_when_step_then_falls_back_to_l2():
    deps, (l1, l2, l3) = _deps(False, True, [], avail=(True, True, False))
    out = step(WatchdogState(consecutive_failures=3, escalation_level=3),
               deps, _cfg(cooldown_s=0), 1000.0)
    assert l2.calls == [1000.0]        # fell back from spent L3 to L2
    assert not l3.calls
    assert out.exhausted is False


def test_given_l2_and_l3_spent_at_ceiling_when_step_then_quiesce_and_latch():
    deps, (l1, l2, l3) = _deps(False, True, [], avail=(True, False, False))
    out = step(WatchdogState(consecutive_failures=5, escalation_level=3),
               deps, _cfg(cooldown_s=0), 1000.0)
    assert out.exhausted is True
    assert not (l1.calls or l2.calls or l3.calls)   # quiesced, no action


def test_given_already_exhausted_when_step_then_stays_quiesced():
    deps, (l1, l2, l3) = _deps(False, True, [], avail=(True, False, False))
    st = WatchdogState(consecutive_failures=9, escalation_level=3, exhausted=True)
    out = step(st, deps, _cfg(cooldown_s=0), 1000.0)
    assert out.exhausted is True
    assert not (l1.calls or l2.calls or l3.calls)


def test_given_exhausted_then_wan_restored_when_step_then_latch_clears():
    deps, _ = _deps(True, True, [])   # WAN back
    out = step(WatchdogState(consecutive_failures=9, escalation_level=3, exhausted=True),
               deps, _cfg(), 1000.0)
    assert out.exhausted is False
    assert out.escalation_level == 1


def test_given_ceiling_2_but_l2_spent_when_step_then_l1_runs_and_unlocks_l3():
    deps, (l1, l2, l3) = _deps(False, True, [], avail=(True, False, True))
    out = step(WatchdogState(consecutive_failures=3, escalation_level=2),
               deps, _cfg(cooldown_s=0), 1000.0)
    assert l1.calls == [1000.0]        # fell back to L1 (L2 spent)
    assert not l2.calls
    assert out.consecutive_l2_failures == 0   # L1 ran, not counted as L2 failure
    assert out.escalation_level == 3          # spent L2 unlocks L3 ceiling


def test_given_sustained_failure_admin_up_when_step_then_l1_fires_and_arms_l2():
    deps, (l1, l2, l3) = _deps(False, True, [])
    out = step(WatchdogState(consecutive_failures=2, escalation_level=1), deps, _cfg(), 1000.0)
    assert l1.calls == [1000.0]
    assert not l2.calls and not l3.calls
    assert out.escalation_level == 2


def test_given_repeated_l2_failures_when_step_then_escalates_to_l3():
    deps, (l1, l2, l3) = _deps(False, True, [])
    out = step(WatchdogState(consecutive_failures=3, escalation_level=2, consecutive_l2_failures=2),
               deps, _cfg(cooldown_s=0), 1000.0)
    assert l2.calls == [1000.0]
    assert out.consecutive_l2_failures == 3
    assert out.escalation_level == 3


def test_given_inside_cooldown_when_step_then_no_action():
    deps, (l1, l2, l3) = _deps(False, True, [])
    out = step(WatchdogState(consecutive_failures=3, escalation_level=2, last_action_time=950.0),
               deps, _cfg(cooldown_s=180), 1000.0)
    assert not (l1.calls or l2.calls or l3.calls)

# =============================================================================
# MTU guard
# =============================================================================

SMALL = SMALL_PROBE_PAYLOAD + _ICMP_OVERHEAD


class _FakeBreaker:
    r"""\brief Minimal CircuitBreaker stand-in with observable calls."""

    def __init__(self, allowed=True):
        self.name = "MTU"
        self._allowed = allowed
        self.records = []

    def allow(self, now):
        return self._allowed

    def record(self, now):
        self.records.append(now)


def _guard(path_ceiling, *, dry_run=False, breaker=None, write=None, **cfg_kw):
    r"""
    \brief Build a guard whose fake path passes any probe <= path_ceiling.

    \param path_ceiling  Largest size the simulated path will carry.
    \param dry_run       Whether the guard is in observe-only mode.
    \param breaker       Injected breaker (defaults to always-allow).
    \param write         Injected write_mtu (defaults to a MagicMock -> True).
    """
    cfg = MtuGuardConfig(dry_run=dry_run, **cfg_kw)
    probe = MagicMock(side_effect=lambda size: size <= path_ceiling)
    writer = write if write is not None else MagicMock(return_value=True)
    return MtuGuard(probe, writer, breaker or _FakeBreaker(), cfg), probe, writer


# --- icmp_ok_sized -----------------------------------------------------------


def test_given_total_size_when_probing_then_df_bit_and_correct_payload_are_passed():
    runner = MagicMock(return_value=subprocess.CompletedProcess([], 0))
    assert icmp_ok_sized("1.1.1.1", 1360, runner=runner) is True
    argv = runner.call_args[0][0]
    assert "-M" in argv and argv[argv.index("-M") + 1] == "do"
    # 1360 on the wire == 1332 payload + 28 bytes of IPv4/ICMP header.
    assert argv[argv.index("-s") + 1] == "1332"


def test_given_nonzero_exit_when_probing_then_false():
    runner = MagicMock(return_value=subprocess.CompletedProcess([], 1))
    assert icmp_ok_sized("1.1.1.1", 1400, runner=runner) is False


def test_given_hanging_ping_when_probing_then_false_not_blocked():
    runner = MagicMock(side_effect=subprocess.TimeoutExpired(cmd="ping", timeout=5))
    assert icmp_ok_sized("1.1.1.1", 1400, runner=runner) is False


def test_given_ping_when_probing_then_a_hard_timeout_is_passed():
    runner = MagicMock(return_value=subprocess.CompletedProcess([], 0))
    icmp_ok_sized("1.1.1.1", 1360, timeout_s=2, runner=runner)
    assert runner.call_args.kwargs["timeout"] > 2


# --- detect_blackhole --------------------------------------------------------


def test_given_path_carries_target_mtu_when_detecting_then_healthy():
    guard, _, _ = _guard(path_ceiling=1500, target_mtu=1360)
    assert guard.detect_blackhole() is False


def test_given_small_passes_but_target_blocked_when_detecting_then_blackhole():
    guard, _, _ = _guard(path_ceiling=1300, target_mtu=1360)
    assert guard.detect_blackhole() is True


def test_given_link_fully_down_when_detecting_then_none_so_ladder_owns_it():
    guard, _, _ = _guard(path_ceiling=0, target_mtu=1360)
    assert guard.detect_blackhole() is None


def test_given_link_down_when_detecting_then_large_probe_is_not_wasted():
    guard, probe, _ = _guard(path_ceiling=0, target_mtu=1360)
    guard.detect_blackhole()
    probe.assert_called_once_with(SMALL)


# --- measure_path_mtu --------------------------------------------------------


def test_given_ceiling_of_1360_when_measuring_then_finds_1360():
    guard, _, _ = _guard(path_ceiling=1360, mtu_floor=1200, mtu_ceiling=1500, search_step=4)
    assert guard.measure_path_mtu() == 1360


def test_given_ceiling_below_floor_when_measuring_then_none_and_no_write():
    guard, _, writer = _guard(path_ceiling=1100, mtu_floor=1200)
    assert guard.measure_path_mtu() is None
    writer.assert_not_called()


def test_given_full_range_when_measuring_then_probe_count_stays_bounded():
    guard, probe, _ = _guard(path_ceiling=1360, mtu_floor=1200, mtu_ceiling=1500, search_step=4)
    guard.measure_path_mtu()
    # log2(300/4) ~= 6.2, plus the floor probe; 12 is generous headroom.
    assert probe.call_count <= 12


def test_given_measured_value_when_measuring_then_it_is_step_aligned():
    guard, _, _ = _guard(path_ceiling=1357, mtu_floor=1200, mtu_ceiling=1500, search_step=4)
    assert guard.measure_path_mtu() % 4 == 0


# --- correct -----------------------------------------------------------------


def test_given_blackhole_when_correcting_then_writes_measured_mtu_and_mss():
    writer = MagicMock(return_value=True)
    guard, _, _ = _guard(path_ceiling=1360, write=writer, mtu_floor=1200, mtu_ceiling=1500)
    assert guard.correct(now=100.0) is True
    writer.assert_called_once_with(1360, 1320)


def test_given_dry_run_when_correcting_then_measures_but_never_writes():
    writer = MagicMock(return_value=True)
    guard, _, _ = _guard(path_ceiling=1360, dry_run=True, write=writer)
    assert guard.correct(now=100.0) is False
    writer.assert_not_called()


def test_given_dry_run_when_correcting_then_breaker_budget_is_not_spent():
    breaker = _FakeBreaker()
    guard, _, _ = _guard(path_ceiling=1360, dry_run=True, breaker=breaker)
    guard.correct(now=100.0)
    assert breaker.records == []


def test_given_breaker_tripped_when_correcting_then_no_probe_and_no_write():
    breaker = _FakeBreaker(allowed=False)
    writer = MagicMock(return_value=True)
    guard, probe, _ = _guard(path_ceiling=1360, breaker=breaker, write=writer)
    assert guard.correct(now=100.0) is False
    writer.assert_not_called()
    probe.assert_not_called()


def test_given_correction_runs_when_it_completes_then_breaker_records_exactly_once():
    breaker = _FakeBreaker()
    guard, _, _ = _guard(path_ceiling=1360, breaker=breaker)
    guard.correct(now=100.0)
    assert len(breaker.records) == 1


def test_given_write_rejected_by_router_when_correcting_then_false():
    writer = MagicMock(return_value=False)
    guard, _, _ = _guard(path_ceiling=1360, write=writer)
    assert guard.correct(now=100.0) is False


def test_given_write_accepted_but_path_still_blocked_when_correcting_then_false():
    r"""The router reported success but the probe disagrees -- trust the probe."""
    cfg = MtuGuardConfig(dry_run=False, mtu_floor=1200, mtu_ceiling=1500)
    shrunk = {"yes": False}

    def flaky(size):
        # Passes during measurement; the write flips the path to a lower
        # ceiling, so the confirming re-probe must fail.
        return size <= (1200 if shrunk["yes"] else 1360)

    def write(mtu, mss):
        shrunk["yes"] = True
        return True

    guard = MtuGuard(flaky, write, _FakeBreaker(), cfg)
    assert guard.correct(now=100.0) is False


# --- check (rate limiting and latching) --------------------------------------


def test_given_interval_not_elapsed_when_checking_then_no_probes_are_spent():
    guard, probe, _ = _guard(path_ceiling=1300, check_every_s=900)
    state = MtuGuardState(last_check_time=1000.0)
    out = guard.check(state, now=1100.0)
    probe.assert_not_called()
    assert out is state


def test_given_interval_elapsed_when_checking_then_probes_run():
    guard, probe, _ = _guard(path_ceiling=1500, check_every_s=900)
    guard.check(MtuGuardState(last_check_time=0.0), now=1000.0)
    assert probe.call_count >= 1


def test_given_uncorrectable_blackhole_when_checking_repeatedly_then_announced_once():
    guard, _, _ = _guard(path_ceiling=1300, dry_run=True, check_every_s=0, target_mtu=1360)
    s = guard.check(MtuGuardState(), now=1000.0)
    assert s.blackhole_announced is True
    s2 = guard.check(s, now=2000.0)
    assert s2.blackhole_announced is True  # still latched, not re-announced


def test_given_previously_announced_when_path_recovers_then_latch_clears():
    guard, _, _ = _guard(path_ceiling=1500, check_every_s=0, target_mtu=1360)
    s = guard.check(MtuGuardState(blackhole_announced=True), now=1000.0)
    assert s.blackhole_announced is False


def test_given_link_down_when_checking_then_latch_is_left_untouched():
    r"""An outage must not clear a black-hole latch it says nothing about."""
    guard, _, _ = _guard(path_ceiling=0, check_every_s=0)
    s = guard.check(MtuGuardState(blackhole_announced=True), now=1000.0)
    assert s.blackhole_announced is True


def test_given_any_check_when_it_runs_then_timestamp_advances():
    guard, _, _ = _guard(path_ceiling=1500, check_every_s=0)
    s = guard.check(MtuGuardState(last_check_time=0.0), now=1234.0)
    assert s.last_check_time == 1234.0

# --- set_mtu read-back verification ------------------------------------------


def _api_for_mtu(set_json, get_json):
    r"""\brief Build an api whose SET returns set_json and GET returns get_json."""
    sess = MagicMock()
    sess.get.return_value = _resp(get_json)
    sess.post.return_value = _resp(set_json)
    api = ZteRouterApi("10.0.0.1", "pw", session=sess)
    api._logged_in = True
    return api, sess


def test_given_set_ok_and_readback_matches_when_set_mtu_then_true():
    api, sess = _api_for_mtu({"result": "success"},
                             {"wa_inner_version": "v", "cr_version": "c", "RD": "r",
                              "mtu": "1360", "tcp_mss": "1320"})
    assert api.set_mtu(1360, 1320) is True


def test_given_set_result_missing_but_readback_matches_when_set_mtu_then_true():
    r"""This firmware's own UI ignores the SET result for SET_DEVICE_MTU."""
    api, _ = _api_for_mtu({},
                          {"wa_inner_version": "v", "cr_version": "c", "RD": "r",
                           "mtu": "1360", "tcp_mss": "1320"})
    assert api.set_mtu(1360, 1320) is True


def test_given_set_ok_but_readback_differs_when_set_mtu_then_false():
    api, _ = _api_for_mtu({"result": "success"},
                          {"wa_inner_version": "v", "cr_version": "c", "RD": "r",
                           "mtu": "1500", "tcp_mss": "1460"})
    assert api.set_mtu(1360, 1320) is False


def test_given_set_mtu_when_posting_then_uses_confirmed_goform_contract():
    api, sess = _api_for_mtu({"result": "success"},
                             {"wa_inner_version": "v", "cr_version": "c", "RD": "r",
                              "mtu": "1360", "tcp_mss": "1320"})
    api.set_mtu(1360, 1320)
    body = sess.post.call_args.kwargs["data"]
    assert body["goformId"] == "SET_DEVICE_MTU"
    assert body["mtu"] == "1360"
    assert body["tcp_mss"] == "1320"


def test_given_non_numeric_mtu_when_reading_then_none_not_crash():
    api, _ = _api_for_mtu({}, {"mtu": "--", "tcp_mss": "1320"})
    assert api.read_mtu() is None


def test_given_unreachable_router_when_reading_mtu_then_none():
    sess = MagicMock()
    sess.get.side_effect = requests.ConnectionError("boom")
    api = ZteRouterApi("10.0.0.1", "pw", session=sess)
    assert api.read_mtu() is None



# --- registration gate (Limited Service) -------------------------------------


def test_given_unregistered_modem_when_step_then_skips_l2_and_fires_l3():
    r"""GIVEN the modem holds no registration
        WHEN the threshold is reached
        THEN L3 runs immediately, because there is no session for L2 to re-dial."""
    deps, (l1, l2, l3) = _deps(False, True, [], registered=False)
    cfg = _cfg()
    s = WatchdogState(consecutive_failures=cfg.fail_threshold - 1)
    step(s, deps, cfg, now=10_000.0)
    assert l3.calls == [10_000.0]
    assert not l2.calls and not l1.calls


def test_given_unregistered_when_step_repeatedly_then_announced_once():
    deps, _ = _deps(False, True, [], registered=False)
    cfg = _cfg()
    s = WatchdogState(consecutive_failures=cfg.fail_threshold - 1)
    s = step(s, deps, cfg, now=10_000.0)
    assert s.unregistered_announced is True
    s = step(s, deps, cfg, now=10_000.0 + cfg.cooldown_s + 1)
    assert s.unregistered_announced is True


def test_given_registration_returns_when_step_then_latch_clears():
    deps, _ = _deps(False, True, [], registered=True)
    cfg = _cfg()
    s = WatchdogState(consecutive_failures=cfg.fail_threshold - 1,
                      unregistered_announced=True)
    s = step(s, deps, cfg, now=10_000.0)
    assert s.unregistered_announced is False


def test_given_registration_unreadable_when_step_then_ladder_behaves_normally():
    r"""None means "cannot tell". Guessing either way would be worse than
        letting the ordinary ladder proceed."""
    deps, (l1, l2, l3) = _deps(False, True, [], registered=None)
    cfg = _cfg()
    s = WatchdogState(consecutive_failures=cfg.fail_threshold - 1)
    step(s, deps, cfg, now=10_000.0)
    assert l1.calls == [10_000.0] and not l3.calls


def test_given_registered_modem_when_step_then_normal_l1_first_escalation():
    deps, (l1, l2, l3) = _deps(False, True, [], registered=True)
    cfg = _cfg()
    s = WatchdogState(consecutive_failures=cfg.fail_threshold - 1)
    step(s, deps, cfg, now=10_000.0)
    assert l1.calls == [10_000.0] and not l3.calls


# --- ZteRouterApi.is_registered ----------------------------------------------


def _api_reg(fields):
    sess = MagicMock()
    sess.get.return_value = _resp(fields)
    api = ZteRouterApi("10.0.0.1", "pw", session=sess)
    api._logged_in = True
    return api


_HEALTHY = {
    "wa_inner_version": "v", "cr_version": "c", "RD": "r",
    "modem_main_state": "modem_init_complete",
    "network_type": "LTE",
    "signalbar": "5",
    "network_provider": "ExampleNet",
}


def test_given_healthy_capture_when_is_registered_then_true():
    r"""Exact field values captured from this firmware while working."""
    assert _api_reg(dict(_HEALTHY)) is not None
    assert _api_reg(dict(_HEALTHY)).is_registered() is True


def test_given_limited_service_network_type_when_is_registered_then_false():
    f = dict(_HEALTHY, network_type="Limited Service")
    assert _api_reg(f).is_registered() is False


def test_given_zero_signal_bars_when_is_registered_then_false():
    f = dict(_HEALTHY, signalbar="0")
    assert _api_reg(f).is_registered() is False


def test_given_unknown_modem_state_when_is_registered_then_false():
    f = dict(_HEALTHY, modem_main_state="modem_undetected")
    assert _api_reg(f).is_registered() is False


def test_given_empty_signal_fields_when_is_registered_then_still_true():
    r"""rssi/rsrp/rscp are EMPTY on this firmware even when healthy, so blank
        signal data must never be read as loss of service."""
    f = dict(_HEALTHY, rssi="", rsrp="", rscp="")
    assert _api_reg(f).is_registered() is True


def test_given_unreadable_router_when_is_registered_then_none_not_false():
    sess = MagicMock()
    sess.get.side_effect = requests.ConnectionError("boom")
    api = ZteRouterApi("10.0.0.1", "pw", session=sess)
    assert api.is_registered() is None


def test_given_non_numeric_signalbar_when_is_registered_then_not_treated_as_zero():
    f = dict(_HEALTHY, signalbar="--")
    assert _api_reg(f).is_registered() is True


# ---------------------------------------------------------------------------
# installer <-> daemon default drift
#
# Each tunable's default is necessarily written twice -- once in bash at the
# top of install_zte_watchdog.sh, once as a DEFAULT_* constant in the daemon --
# because they are two languages in one file and cannot share a literal. This
# test is the bridge: it parses the installer's shell defaults and asserts they
# equal the daemon's constants, so the pair can only drift loudly.
#
# It caught CHECK_INTERVAL being 20 in the installer and 60 in the daemon.
# ---------------------------------------------------------------------------

_INSTALLER_TO_CONSTANT = {
    "CHECK_INTERVAL": "DEFAULT_CHECK_INTERVAL_S",
    "FAIL_THRESHOLD": "DEFAULT_FAIL_THRESHOLD",
    "COOLDOWN": "DEFAULT_COOLDOWN_S",
    "L2_SETTLE": "DEFAULT_L2_SETTLE_S",
    "L2_MAX_PER_WINDOW": "DEFAULT_L2_MAX_PER_WINDOW",
    "L3_MAX_PER_WINDOW": "DEFAULT_L3_MAX_PER_WINDOW",
    "L3_ESCALATION_THRESHOLD": "DEFAULT_L3_ESCALATION_THRESHOLD",
    "L3_BOOT_WAIT": "DEFAULT_L3_BOOT_WAIT_S",
    "ROUTER_DEAD_THRESHOLD": "DEFAULT_ROUTER_DEAD_THRESHOLD",
    "ADMIN_DEAD_RETRY_EVERY": "DEFAULT_ADMIN_DEAD_RETRY_EVERY",
    "ROLLING_WINDOW_SECONDS": "DEFAULT_ROLLING_WINDOW_S",
    "MTU_TARGET": "DEFAULT_MTU_TARGET",
    "MTU_FLOOR": "DEFAULT_MTU_FLOOR",
    "MTU_CHECK_EVERY": "DEFAULT_MTU_CHECK_EVERY_S",
    "MTU_MAX_PER_WINDOW": "DEFAULT_MTU_MAX_PER_WINDOW",
}

_SHELL_DEFAULT_RE = re.compile(
    r'^(?P<key>[A-Z0-9_]+)="\$\{(?P=key):-(?P<val>[^}]*)\}"', re.MULTILINE)


def _find_installer():
    r"""\brief Locate install_zte_watchdog.sh, or None when running from /opt.

    \details The installer copies only the daemon and this test file into
    INSTALL_DIR, so at service-install time there is nothing to compare
    against and the check is skipped. Run from a git checkout it always fires.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    for d in (here, os.path.dirname(here), os.getcwd()):
        cand = os.path.join(d, "install_zte_watchdog.sh")
        if os.path.isfile(cand):
            return cand
    return None


def test_installer_defaults_match_daemon_defaults():
    installer = _find_installer()
    if installer is None:
        pytest.skip("install_zte_watchdog.sh not alongside the tests (installed copy)")
    with open(installer, encoding="utf-8") as fh:
        shell = {m.group("key"): m.group("val")
                 for m in _SHELL_DEFAULT_RE.finditer(fh.read())}

    missing = [k for k in _INSTALLER_TO_CONSTANT if k not in shell]
    assert not missing, f"installer no longer defines: {missing}"

    drift = []
    for key, const in _INSTALLER_TO_CONSTANT.items():
        daemon_value = getattr(zte_watchdog, const)
        if int(shell[key]) != daemon_value:
            drift.append(f"{key}: installer={shell[key]} {const}={daemon_value}")
    assert not drift, "installer and daemon defaults disagree -- " + "; ".join(drift)


def test_given_every_mtu_env_knob_when_mapped_then_the_table_is_complete():
    r"""The drift table must cover every MTU_* knob the installer writes."""
    covered = {k for k in _INSTALLER_TO_CONSTANT if k.startswith("MTU_")}
    assert covered == {"MTU_TARGET", "MTU_FLOOR", "MTU_CHECK_EVERY", "MTU_MAX_PER_WINDOW"}


PYTESTEOF

echo "[5/7] Writing config to ${CONFIG_FILE} (mode 600)..."
# The password is the only free-form value here. systemd's EnvironmentFile
# parser strips one layer of matching quotes, so a password that BEGINS and ENDS
# with a quote character would silently lose them. Always emit it double-quoted
# with \\ and \" escaped -- systemd's documented unquoting rules -- so the
# round-trip is exact for every printable password.
_pw_esc="${ROUTER_PASSWORD//\\/\\\\}"
_pw_esc="${_pw_esc//\"/\\\"}"
ROUTER_PASSWORD_ESCAPED="\"${_pw_esc}\""
cat > "${CONFIG_FILE}" << EOF
ROUTER_IP=${ROUTER_IP}
ROUTER_PASSWORD=${ROUTER_PASSWORD_ESCAPED}
PING_TARGET=${PING_TARGET}
CHECK_INTERVAL=${CHECK_INTERVAL}
FAIL_THRESHOLD=${FAIL_THRESHOLD}
COOLDOWN=${COOLDOWN}
L2_MAX_PER_WINDOW=${L2_MAX_PER_WINDOW}
L2_SETTLE=${L2_SETTLE}
L3_MAX_PER_WINDOW=${L3_MAX_PER_WINDOW}
L3_ESCALATION_THRESHOLD=${L3_ESCALATION_THRESHOLD}
L3_BOOT_WAIT=${L3_BOOT_WAIT}
ROUTER_DEAD_THRESHOLD=${ROUTER_DEAD_THRESHOLD}
ADMIN_DEAD_RETRY_EVERY=${ADMIN_DEAD_RETRY_EVERY}
ROLLING_WINDOW_SECONDS=${ROLLING_WINDOW_SECONDS}
MTU_GUARD_ENABLED=${MTU_GUARD_ENABLED}
MTU_GUARD_DRY_RUN=${MTU_GUARD_DRY_RUN}
MTU_TARGET=${MTU_TARGET}
MTU_FLOOR=${MTU_FLOOR}
MTU_CHECK_EVERY=${MTU_CHECK_EVERY}
MTU_MAX_PER_WINDOW=${MTU_MAX_PER_WINDOW}
EOF
chmod 600 "${CONFIG_FILE}"

if [[ "${RUN_TESTS}" == "1" ]]; then
  echo "[6/7] Running mocked test suite (no hardware touched)..."
  ( cd "${INSTALL_DIR}" && "${INSTALL_DIR}/venv/bin/python" -m pytest test_zte_watchdog.py -q )
else
  echo "[6/7] Skipping tests (RUN_TESTS=0)."
fi

echo "[7/7] Installing and starting systemd service..."
sudo tee "/etc/systemd/system/${SERVICE_NAME}.service" > /dev/null << EOF
[Unit]
Description=ZTE MC801A connectivity watchdog (L1/L2/L3 ladder)
After=network-online.target
Wants=network-online.target
# RestartSec must stay BELOW StartLimitIntervalSec or the rate limiter can
# never trip and a hard-failing daemon (bad config, missing venv) respawns
# forever. 5 starts per 120s is enough to survive transient boot races.
StartLimitIntervalSec=120
StartLimitBurst=5

[Service]
Type=simple
EnvironmentFile=${CONFIG_FILE}
ExecStart=${INSTALL_DIR}/venv/bin/python3 ${INSTALL_DIR}/zte_watchdog.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Hardening. The daemon needs exactly two things: outbound HTTP to the router
# on the LAN, and the ping binary. Everything else is denied. ping needs
# CAP_NET_RAW on kernels without net.ipv4.ping_group_range coverage, so that
# one capability is kept and all others dropped.
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
CapabilityBoundingSet=CAP_NET_RAW
AmbientCapabilities=CAP_NET_RAW
RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_UNIX
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable "${SERVICE_NAME}.service"
sudo systemctl restart "${SERVICE_NAME}.service"

echo ""
echo "Done. The watchdog is running as a persistent systemd service."
echo ""
echo "  Status:        systemctl status ${SERVICE_NAME}"
echo "  Live logs:     journalctl -u ${SERVICE_NAME} -f"
echo "  Only faults:   journalctl -u ${SERVICE_NAME} | grep FAULT"
echo "  Only detects:  journalctl -u ${SERVICE_NAME} | grep DETECT"
echo "  Run tests:     ( cd ${INSTALL_DIR} && venv/bin/python -m pytest test_zte_watchdog.py -q )"
echo "  Stop:          sudo systemctl stop ${SERVICE_NAME}"
echo "  Disable:       sudo systemctl disable ${SERVICE_NAME}"
echo "  Reconfigure:   edit ${CONFIG_FILE} then: sudo systemctl restart ${SERVICE_NAME}"
