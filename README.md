# zte-mc801a-watchdog

A small, dependency-light watchdog daemon that automatically recovers a **ZTE MC801A** 5G router from the two ways its cellular link fails in practice: a wedged WAN session, and a **path-MTU black hole** that leaves the link "up" while silently killing HTTPS.

On firmware `MC801AV1.0.0B16`, the modem periodically ends up *attached to the network but with no WAN IP* (`ppp_connected`, `wan_ipaddr=''`) and stays that way until you manually toggle the connection in the admin UI. This daemon detects the outage by pinging out, then logs into the router's undocumented `goform` API and escalates through a bounded recovery ladder.

> **Unofficial.** Not affiliated with or endorsed by ZTE. It talks to an undocumented HTTP API that may change between firmware versions. Use at your own risk.

---

## Install (Raspberry Pi / any systemd Linux)

```bash
git clone https://github.com/<you>/zte-mc801a-watchdog.git
cd zte-mc801a-watchdog
chmod +x install_zte_watchdog.sh
./install_zte_watchdog.sh          # prompts for the router admin password
```

`install_zte_watchdog.sh` is the whole product: the daemon and its test suite are embedded in it as heredocs, so there is exactly one file to keep in sync. It creates a venv under `/opt/zte-watchdog`, writes `config.env` (mode 600), runs the mocked test suite as an install gate, and installs + starts a hardened systemd unit.

```bash
ROUTER_IP=192.168.0.1 FAIL_THRESHOLD=2 ./install_zte_watchdog.sh   # override any default
RUN_TESTS=0 ./install_zte_watchdog.sh                              # skip the test gate
```

Re-running is safe: code and service are overwritten, the stored password is reused, and `apt`/`pip` are skipped entirely when everything is already present — so a re-install works during the very outage the watchdog exists for.

Logs are categorised in a grep-able second column:

```bash
journalctl -u zte-watchdog -f
journalctl -u zte-watchdog | grep FAULT    # code/protocol problems only
journalctl -u zte-watchdog | grep DETECT   # observed conditions only
```

**A healthy watchdog is a silent one.** The per-cycle successes — `ping ok`, and
the MTU guard's `MTU probe ok at NNNNB` — are logged at `DEBUG`, so at the
default `INFO` an untroubled daemon writes nothing after its three startup
lines. That is the pass signal, not a sign the checks aren't running.

To watch them actually happen, raise the level:

```bash
LOG_LEVEL=DEBUG ./install_zte_watchdog.sh
# or, without reinstalling:
sudo sed -i 's/^LOG_LEVEL=.*/LOG_LEVEL=DEBUG/' /opt/zte-watchdog/config.env
sudo systemctl restart zte-watchdog
```

Accepts `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` in any case, or a bare
number. An unrecognised value falls back to `INFO` and logs one `FAULT` line —
a typo in a log setting should never stop the watchdog from starting. The level
in force is echoed at startup: `LIFECYCLE | log level: DEBUG (LOG_LEVEL)`.

---

## How it works

### The recovery ladder (WAN down)

Ping a public IP every `CHECK_INTERVAL` seconds. After `FAIL_THRESHOLD` consecutive failures, escalate:

| Rung | Action | Breaker |
|---|---|---|
| **L1** | `CONNECT_NETWORK` — (re)dial the data session | none |
| **L2** | `DISCONNECT_NETWORK` → `CONNECT_NETWORK` | `L2_MAX_PER_WINDOW` per rolling window |
| **L3** | `REBOOT_DEVICE` — full soft reboot | `L3_MAX_PER_WINDOW` per rolling window |

Escalation to L3 happens after `L3_ESCALATION_THRESHOLD` consecutive failed L2 attempts. An L3 that fails arms exactly one L2 re-dial before another reboot is considered: a reboot costs ~8 minutes (boot floor + readiness ceiling + cooldown) and a re-dial ~40s, and on 2026-09-20 three consecutive failed reboots were followed by a single L2 that restored the link in 39 seconds. When both breaker-gated rungs are spent, the daemon logs `CRITICAL` once and keeps polling for restoration instead of looping — software has run out of options, and a power-cycle (e.g. a smart plug) is the fallback.

**Liveness gate.** If the router's admin HTTP plane is unreachable, no `goform` command can land at all, so the ladder is pointless. That case is logged once as `CRITICAL` and then retried blind every `ADMIN_DEAD_RETRY_EVERY` cycles — a failed probe is evidence, not proof, that the router is gone.

### The registration gate (which fault is this?)

Two different faults look identical from outside — "no internet" — but need opposite responses:

- **Wedged data session**: the modem is registered on the carrier, `ppp_connected`, but there is no route. There *is* a session to re-dial, so **L2 is the correct, cheap fix**.
- **No registration** ("Limited Service" / not attached): there is no session to re-dial, so every L2 attempt is guaranteed to fail. **Only L3 has ever recovered this.**

Before running the ladder, the daemon reads `modem_main_state`, `network_type` and `signalbar` and jumps straight to L3 when the modem holds no usable registration for `REGISTRATION_GATE_STREAK` consecutive checks. The streak matters: registration flaps, and on 2026-09-20 a single 22s `NO_SERVICE` sample was enough to pin the ladder at ceiling L3 for 28 minutes while the modem was already back on LTE with full bars. Without the gate the second case still reaches L3 eventually — but only after `L3_ESCALATION_THRESHOLD` failed L2 attempts a cooldown apart, several minutes of useless `DISCONNECT`/`CONNECT` calls, each burning L2 breaker budget that a real session fault might need later.

An unreadable router returns "unknown", never a guess: that is the liveness gate's problem, not this probe's.

> **Do not use signal strength as evidence of service loss.** On this firmware `rssi`, `rsrp` and `rscp` are **empty strings even on a perfectly healthy link**. Treating blank as "no service" would fire constantly. The gate uses `signalbar` only when it parses as a number, so a firmware build that stops populating it cannot cause false positives.

---

## Path-MTU black holes (the part most people are missing)

This is the failure that costs the most time to identify, because it does not look like a network fault at all. **It presents as broken Wi-Fi**, and no standard advice finds it.

### Symptom

- Full signal, router says connected, `ping` works fine.
- **HTTPS is dead** — pages hang or fail with `ERR_CONNECTION_CLOSED`.
- **Google, YouTube and plain HTTP work**, which makes it look like "the internet is fine, this one site is broken". (Google's properties negotiate over QUIC/UDP, which does its own MTU probing; plain HTTP responses are small enough to fit.)
- **Android phones break while Windows PCs and wired clients are fine.** Windows and most desktop stacks implement PMTU *blackhole detection* (RFC 4821 style probing) and quietly back off; Android does not.

That last asymmetry is the tell. If one class of device on the LAN works and another doesn't, the problem is packet size, not the link.

### Diagnosis

Ping with fragmentation forbidden (`-M do`) and bisect the payload size:

```bash
ping -M do -s 1472 -c 3 8.8.8.8    # 1472 + 28 = 1500, the Ethernet default
ping -M do -s 1400 -c 3 8.8.8.8
ping -M do -s 1300 -c 3 8.8.8.8
```

A blocked size fails with `Frag needed and DF set` or, in a true black hole, just silently times out while smaller sizes succeed. Bisect until you find the largest `-s N` that still gets replies. Then:

```
path MTU = N + 28        # 20 B IPv4 header + 8 B ICMP header
TCP MSS  = MTU - 40      # 20 B IPv4 header + 20 B TCP header
```

Two probes distinguish this from an ordinary outage: a **small** ping must pass **and** a **large** one must fail. Both failing is just a dead link.

### Root cause

Somewhere in the carrier's path, a hop forwards packets smaller than its MTU and **drops oversized ones without sending the ICMP "fragmentation needed" reply** that RFC 1191 Path MTU Discovery depends on. Nothing ever tells the sender to use smaller packets, so it keeps retransmitting the same too-large segment forever — hence *black hole*. A TLS handshake's certificate exchange is one of the first things on a connection big enough to hit it, which is why HTTPS dies while pings live.

### Fix

Set the router's WAN MTU to the measured ceiling, and TCP MSS to MTU − 40.

> **The working value is carrier-specific — measure your own.** It depends on your operator's tunnelling and can change. Do not copy a number out of this README, a forum post, or `config.env.example`: run the bisection above on your own link and use what you find. Every MTU value shipped in this repo is a **placeholder**, not a recommendation.

Then hand it to the installer, which is the one setting most people need to change:

```bash
MTU_TARGET=<your measured ceiling> ./install_zte_watchdog.sh
```

`MTU_TARGET` is the size the guard probes for — "the MTU I expect to be in force on a healthy link" — so it has to match what your path can actually carry. **Setting it too high is not the safe direction.** Leave it at 1500 on a path that cannot carry 1500 and every check re-detects a black hole, re-measures, and rewrites the same correct value until the correction breaker trips: right MTU, permanent warnings. Measure first, then set it.

### What the daemon does about it

The MTU guard is **not** a rung of the recovery ladder, and that is the design point. `step()` returns early while `is_wan_up()` is true, and `is_wan_up()` is a 56-byte ICMP echo — which succeeds throughout a black hole. The ladder would never fire. So the guard hooks the **happy path** instead, rate-limited to one check every `MTU_CHECK_EVERY` seconds:

1. **Detect** — small probe passes *and* `MTU_TARGET`-sized probe fails.
2. **Measure** — binary-search the true ceiling between `MTU_FLOOR` and 1500.
3. **Correct** — write MTU and MSS via `goform`, then **re-probe** to confirm.

Bounds that keep it safe: `MTU_FLOOR` is a hard floor the search will never write below; a circuit breaker (`MTU_MAX_PER_WINDOW`) stops a flapping carrier path from becoming a rewrite loop; and corrections only run while the small probe passes, so a plain outage can never be misread as a shrinking path and drive the MTU to the floor. Set `MTU_GUARD_DRY_RUN=1` to detect and measure without ever writing — detection alone still tells you exactly what to set by hand, which is most of the value.

---

## Reverse-engineered `goform` protocol (the useful bit)

This is what cost the most time to work out, documented here so you don't have to repeat it. All requests go to `http://<router>/goform/goform_get_cmd_process` (reads) and `.../goform_set_cmd_process` (writes).

**Login** — the keystone detail is that the password hash must be **uppercase at both stages**:

```
GET  cmd=wa_inner_version,cr_version,RD,LD
password = SHA256( SHA256(pw).upper() + LD ).upper()
POST goformId=LOGIN, password=<above>          # no AD field needed
  -> {"result":"0"}  AND  Set-Cookie: stok=...   (success)
```

The lowercase variant returns `{"result":"3"}`, which authenticates *reads* but **does not issue the `stok` cookie**, so every *write* silently fails with `{"result":"failure"}`. That mismatch is the trap.

**Authenticated writes** carry the `stok` cookie (captured automatically from the login response) plus an `AD` anti-CSRF token computed with **lowercase** MD5, using a freshly fetched `RD` per command:

```
GET  cmd=wa_inner_version,cr_version,RD          # fresh RD each time
AD = md5( md5(wa_inner_version + cr_version) + RD )   # lowercase hex
POST goformId=<CMD>, AD=<above>, notCallback=true
```

**Recovery commands:** `CONNECT_NETWORK`, `DISCONNECT_NETWORK`, `REBOOT_DEVICE`.

**MTU/MSS:**

```
POST goformId=SET_DEVICE_MTU, mtu=<bytes>, tcp_mss=<bytes>
GET  cmd=mtu,tcp_mss                              # same field names on the read side
```

This contract was recovered from the router's **own** `/js/service.js`, not from a proxy capture — see the discovery tool below. One detail matters: that bundle **ignores the SET result** for this command —

```js
ENABLE_PIN:      function t(e){return e&&"success"===e.result?…}
SET_DEVICE_MTU:  function t(e){return e||fi}
```

— so the firmware may answer without the `result` field, making a successful write look like a failure. `set_mtu()` therefore treats **read-back as authoritative**: the router either reports the new MTU or it does not. (The admin UI also warns that MTU may only be changeable while the modem is disconnected; if the read-back doesn't take, that is the first thing to suspect.)

**Handy read-only fields:** `wan_ipaddr`, `modem_main_state`, `ppp_status`, `network_type`, `signalbar`, `network_provider`, `mtu`, `tcp_mss`.

---

## `discover_mtu_contract.py` — recovering the contract yourself

A read-only tool that works out the MTU `goform` contract **from the router's own admin JavaScript**. No mitmproxy, no browser, no CA install, no manual UI click. The admin UI is plain JS served from the device, and that JS contains the exact `goformId` and field names it posts — so instead of observing a request, read the code that builds it.

```bash
sudo /opt/zte-watchdog/venv/bin/python discover_mtu_contract.py
```

Three passes, cheapest first:

1. **READ** — probe `goform_get_cmd_process` for MTU-ish field names one at a time (a single unknown name in a `multi_data` batch can blank the whole reply). Whatever the GET side calls a field, the SET side almost always calls the same thing.
2. **CRAWL** — fetch the admin JS bundles and regex out every `goformId` appearing near an `mtu`/`mss` mention. This names the command.
3. **REPORT** — print a ready-to-paste `MTU_PAYLOAD_TEMPLATE`, plus raw context snippets if the result is inconclusive.

It is read-only by construction: GETs and one login, never a `goform` SET. Credentials come from `/opt/zte-watchdog/config.env`, so no password is retyped or lands in shell history or `argv`.

The approach should generalise to other ZTE CPEs that share this admin-bundle structure — point it at a different model and it will name that model's command. If it finds nothing, that is a real answer rather than a script failure: some builds genuinely do not expose MTU through `goform`, in which case keep `MTU_GUARD_DRY_RUN=1` and apply the measured value by hand.

---

## Configuration

All settings are environment variables, stored in `/opt/zte-watchdog/config.env` (mode 600, gitignored, **never commit it**). See `config.env.example` for the full annotated set.

| Variable | Default | Meaning |
|---|---|---|
| `ROUTER_IP` | `192.168.0.1` | Router admin IP |
| `ROUTER_PASSWORD` | *(required)* | Router admin password |
| `PING_TARGET` | `1.1.1.1` | Address used to detect connectivity |
| `CHECK_INTERVAL` | `20` | Seconds between checks |
| `FAIL_THRESHOLD` | `3` | Consecutive failures before acting |
| `COOLDOWN` | `180` | Seconds between recovery attempts, measured from when the previous attempt *finished*. L3 blocks for the whole boot wait, so this is time after the router is back (or the readiness ceiling gave up), not time since the reboot was issued. |
| `ATTRIBUTION_WINDOW` | `90` | Seconds after a rung *finishes* within which a recovery is still credited to it. Past this the ladder is only sitting out its cooldown, so a link that returns is logged as **not** the ladder's doing (external or manual). Diagnostic only: it changes no recovery behaviour. |
| `SESSION_MAX_AGE` | `300` | Seconds a cached router login is trusted before re-authenticating |
| `L2_MAX_PER_WINDOW` | `8` | L2 breaker cap per window |
| `L2_SETTLE` | `15` | Seconds between `DISCONNECT` and `CONNECT` |
| `L3_MAX_PER_WINDOW` | `3` | L3 (reboot) breaker cap per window |
| `L3_ESCALATION_THRESHOLD` | `2` | Failed L2 attempts before escalating to L3 |
| `REGISTRATION_GATE_STREAK` | `3` | Consecutive unregistered readings before the registration gate jumps to L3 |
| `L3_BOOT_WAIT` | `90` | Seconds to wait out a reboot |
| `ROUTER_DEAD_THRESHOLD` | `3` | Cycles of unreachable admin plane before `CRITICAL` |
| `ADMIN_DEAD_RETRY_EVERY` | `10` | Cycles between blind ladder retries while admin is dead |
| `ROLLING_WINDOW_SECONDS` | `86400` | Breaker window |
| `LOG_LEVEL` | `INFO` | `DEBUG` adds per-cycle heartbeats; bad values fall back to `INFO` |
| `MTU_GUARD_ENABLED` | `1` | Enable the path-MTU guard |
| `MTU_GUARD_DRY_RUN` | `0` | `1` = detect and measure, never write |
| `MTU_TARGET` | *(placeholder — measure yours)* | Size the guard probes for; must match your path's real ceiling |
| `MTU_FLOOR` | `1200` | Hard floor; never write below this |
| `MTU_CHECK_EVERY` | `900` | Seconds between MTU checks |
| `MTU_MAX_PER_WINDOW` | `4` | MTU-correction breaker cap per window |
| `TCP_CHECK_ENABLED` | `1` | Also require a TCP handshake, not just ICMP |
| `TCP_CHECK_TARGETS` | `1.1.1.1:443,8.8.8.8:443,9.9.9.9:443` | `host:port` list; WAN is down only if *every* target refuses |
| `TCP_CHECK_TIMEOUT` | `4` | Per-target connect timeout, in seconds |

---

## Tests

The daemon ships with a mocked test suite (no hardware touched) that runs as an install gate. To run it by hand:

```bash
cd /opt/zte-watchdog && venv/bin/python -m pytest test_zte_watchdog.py -q
```

One of them is worth knowing about. Every tunable's default is necessarily
written twice — once in the installer's shell block, once as a `DEFAULT_*`
constant in the daemon — because they are two languages sharing one file and
cannot share a literal. `test_installer_defaults_match_daemon_defaults` parses
the shell defaults back out of `install_zte_watchdog.sh` and asserts they equal
the daemon's constants, so the pair can only drift loudly.

It needs to find the installer, which is not one of the two files copied into
`/opt/zte-watchdog`. So the installer exports its own absolute path as
`ZTE_INSTALLER_PATH` when it runs the gate, and the test reads that first —
which keeps the check live at install time, where it matters most. Running the
suite from a checkout works without the variable, since the installer is right
there. It skips only in the leftover case: a standalone run of the installed
copy with no pointer set.

Everything else has exactly one definition: change `DEFAULT_MTU_TARGET` or its
`MTU_TARGET` shell counterpart and both the dataclass default and the
environment fallback follow.

---

## Notes

- Tested only against `MC801AV1.0.0B16`. Other firmware builds may differ — especially the login hash case, the recovery command names, and whether `SET_DEVICE_MTU` exists at all.
- If a drop is a deeper modem hang that neither a re-dial nor a soft reboot clears, the breakers stop the loop and log it; a hardware power-cycle (a smart plug triggered on ping failure) is the robust fallback. The `on_admin_plane_dead` hook is the attach point for that.

## License

MIT — see [LICENSE](LICENSE).
