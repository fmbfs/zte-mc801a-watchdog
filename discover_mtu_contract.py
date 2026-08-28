#!/usr/bin/env python3
r"""
\file discover_mtu_contract.py
\brief Recover the goform contract for writing WAN MTU/MSS on a ZTE MC801A,
       without a proxy in the path.

\details
mitmproxy works but needs a browser, a CA install and a manual UI click. The
router already ships everything required: its admin UI is plain JavaScript
served from the device, and that JS contains the exact goformId and field
names it posts. So instead of observing a request, read the code that builds
it.

Three passes, cheapest first:

  1. READ   probe goform_get_cmd_process for MTU-ish field names. Whatever the
            GET side calls a field, the SET side almost always calls the same
            thing -- this alone usually names the parameter.
  2. CRAWL  fetch the admin UI's JS bundles and regex out every goformId whose
            surrounding context mentions mtu/mss. This names the command.
  3. REPORT print a ready-to-paste MTU_PAYLOAD_TEMPLATE.

Nothing is written to the router. This script is read-only by construction:
it issues GETs and one login, never a goform SET.

\par Usage
    sudo /opt/zte-watchdog/venv/bin/python discover_mtu_contract.py

Credentials are read from /opt/zte-watchdog/config.env so nothing is retyped
and no password appears in shell history or argv.
"""

from __future__ import annotations

import hashlib
import re
import sys
from typing import Dict, List, Optional, Set, Tuple

import requests

CONFIG_PATH = "/opt/zte-watchdog/config.env"

#: GET fields worth asking for. The router answers with only those it knows,
#: so over-asking is free and under-asking hides the answer.
CANDIDATE_GET_FIELDS: List[str] = [
    "mtu", "MTU", "wan_mtu", "WAN_MTU", "mtu_size", "ipv4_mtu",
    "mss", "MSS", "tcp_mss", "wan_mss", "mss_size",
    "pdp_type", "apn_mtu", "ppp_mtu", "dial_mode",
]

#: JS paths the MC801A serves. Not all exist on every build; misses are skipped.
CANDIDATE_JS_PATHS: List[str] = [
    "/js/config.js",
    "/js/app.js",
    "/js/main.js",
    "/js/common.js",
    "/js/base.js",
    "/js/service.js",
    "/js/lib.js",
    "/js/index.js",
    "/js/controller/router.js",
    "/js/controller/advance.js",
    "/js/controller/wan.js",
    "/js/model/router.js",
    "/index.html",
]

_GOFORM_RE = re.compile(r"""goformId\s*[:=]\s*['"]([A-Z0-9_]+)['"]""")
_MTU_HINT_RE = re.compile(r"\b(mtu|mss)\b", re.IGNORECASE)


def load_config(path: str) -> Dict[str, str]:
    r"""
    \brief Parse the watchdog's EnvironmentFile.

    \param path  Path to config.env.
    \return Mapping of key to value, with systemd's one layer of quoting undone.
    """
    cfg: Dict[str, str] = {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                if len(val) >= 2 and val[0] == '"' and val[-1] == '"':
                    val = val[1:-1].replace('\\"', '"').replace("\\\\", "\\")
                cfg[key.strip()] = val
    except OSError as exc:
        sys.exit(f"cannot read {path}: {exc}\nRun with sudo, or pass --ip/--password.")
    return cfg


def login(session: requests.Session, base: str, password: str) -> bool:
    r"""
    \brief SHA256 login, identical to the watchdog's scheme.

    \param session   Session that will carry the stok cookie.
    \param base      http://<router-ip>
    \param password  Plain admin password.
    \return True on success.
    """
    try:
        ld = session.get(
            f"{base}/goform/goform_get_cmd_process",
            params={"isTest": "false", "cmd": "LD", "multi_data": "1"},
            timeout=8,
        ).json().get("LD", "")
    except Exception as exc:  # noqa: BLE001 - discovery tool, report and stop
        print(f"  ! could not fetch LD nonce: {exc}")
        return False

    hashed = hashlib.sha256(
        (hashlib.sha256(password.encode()).hexdigest().upper() + ld).encode()
    ).hexdigest().upper()

    try:
        resp = session.post(
            f"{base}/goform/goform_set_cmd_process",
            data={"isTest": "false", "goformId": "LOGIN", "password": hashed},
            timeout=8,
        )
        ok = str(resp.json().get("result", "")).lower() in ("0", "success")
    except Exception as exc:  # noqa: BLE001
        print(f"  ! login request failed: {exc}")
        return False
    print("  login:", "ok" if ok else f"REJECTED ({resp.text[:80]})")
    return ok


def probe_get_fields(session: requests.Session, base: str) -> Dict[str, str]:
    r"""
    \brief Ask the router for every candidate field and keep what it returns.

    \details Fields are requested one at a time: a single unknown name in a
    multi_data batch can make the whole reply empty on some builds, which
    would look like "none of these exist".

    \param session  Authenticated session.
    \param base     http://<router-ip>
    \return Mapping of field name to the value the router reported.
    """
    found: Dict[str, str] = {}
    for field in CANDIDATE_GET_FIELDS:
        try:
            data = session.get(
                f"{base}/goform/goform_get_cmd_process",
                params={"isTest": "false", "cmd": field, "multi_data": "1"},
                timeout=6,
            ).json()
        except Exception:  # noqa: BLE001 - a miss is expected and uninteresting
            continue
        val = data.get(field)
        if val not in (None, ""):
            found[field] = str(val)
            print(f"  + {field} = {val}")
    return found


def crawl_js(session: requests.Session, base: str) -> Tuple[Set[str], List[str]]:
    r"""
    \brief Fetch admin-UI JS and extract goformIds near MTU/MSS references.

    \param session  Authenticated session.
    \param base     http://<router-ip>
    \return (goformIds seen near an MTU/MSS mention, raw context snippets).
    """
    ids: Set[str] = set()
    snippets: List[str] = []
    for path in CANDIDATE_JS_PATHS:
        try:
            resp = session.get(f"{base}{path}", timeout=8)
            if resp.status_code != 200 or not resp.text:
                continue
        except Exception:  # noqa: BLE001
            continue
        body = resp.text
        if not _MTU_HINT_RE.search(body):
            continue
        print(f"  . {path} ({len(body)} bytes) mentions mtu/mss")
        for m in _MTU_HINT_RE.finditer(body):
            lo = max(0, m.start() - 400)
            hi = min(len(body), m.end() + 400)
            window = body[lo:hi]
            for gid in _GOFORM_RE.findall(window):
                ids.add(gid)
            if "goformId" in window:
                snippets.append(f"--- {path} @ {m.start()} ---\n{window}\n")
    return ids, snippets


def main() -> None:
    r"""\brief Run all three passes and print a paste-ready payload template."""
    cfg = load_config(CONFIG_PATH)
    ip = cfg.get("ROUTER_IP", "192.168.0.1")
    password = cfg.get("ROUTER_PASSWORD", "")
    if not password:
        sys.exit("ROUTER_PASSWORD missing from config.env")

    base = f"http://{ip}"
    session = requests.Session()
    session.headers.update({
        "Referer": f"{base}/index.html",
        "Origin": base,
        "X-Requested-With": "XMLHttpRequest",
    })

    print(f"\n[1/3] Logging in to {ip} ...")
    if not login(session, base, password):
        sys.exit("login failed -- check ROUTER_PASSWORD in config.env")

    print("\n[2/3] Probing goform GET for MTU/MSS field names ...")
    fields = probe_get_fields(session, base)
    if not fields:
        print("  (none -- the GET side may not expose MTU on this firmware)")

    print("\n[3/3] Crawling admin-UI JavaScript for the SET command ...")
    ids, snippets = crawl_js(session, base)
    if ids:
        print(f"\n  goformIds found near mtu/mss: {sorted(ids)}")
    else:
        print("  (no goformId found near an mtu/mss reference)")

    print("\n" + "=" * 70)
    print("RESULT")
    print("=" * 70)

    mtu_field = next((f for f in fields if "mtu" in f.lower()), None)
    mss_field = next((f for f in fields if "mss" in f.lower()), None)
    best_id = None
    for gid in sorted(ids):
        if "MTU" in gid or "WAN" in gid or "MSS" in gid:
            best_id = gid
            break
    if best_id is None and ids:
        best_id = sorted(ids)[0]

    if best_id and mtu_field:
        print("\nPaste into MTU_PAYLOAD_TEMPLATE in /opt/zte-watchdog/zte_watchdog.py:\n")
        print("MTU_PAYLOAD_TEMPLATE: Dict[str, str] = {")
        print(f'    "goformId": "{best_id}",')
        print(f'    "{mtu_field}": "{{mtu}}",')
        print(f'    "{mss_field or "mss"}": "{{mss}}",')
        print("}")
        print("\nThen:  sudo systemctl restart zte-watchdog")
        print("Re-install with MTU_GUARD_DRY_RUN=0 once you have confirmed it.")
    else:
        print("\nNot enough to build the payload automatically.")
        print(f"  MTU field from GET : {mtu_field or 'NOT FOUND'}")
        print(f"  MSS field from GET : {mss_field or 'NOT FOUND'}")
        print(f"  goformId candidates: {sorted(ids) or 'NONE'}")
        print("\nThis is a real possibility, not a script failure: the MC801A's")
        print("own UI warns 'The setting can only be changed when the modem is")
        print("disconnected', so MTU may not be writable through goform at all.")
        print("If so, keep MTU_GUARD_DRY_RUN=1 -- detection still tells you")
        print("exactly what to set by hand, which is most of the value.")

    if snippets:
        print("\n" + "-" * 70)
        print("CONTEXT (for manual inspection if the above is inconclusive)")
        print("-" * 70)
        for s in snippets[:5]:
            print(s[:1200])


if __name__ == "__main__":
    main()
