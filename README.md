# zte-mc801a-watchdog

A small, dependency-light watchdog daemon that automatically recovers a **ZTE MC801A** 5G router when its cellular WAN session wedges and the firmware fails to re-dial on its own.

On firmware `MC801AV1.0.0B16`, the modem periodically ends up *attached to the network but with no WAN IP* (`ppp_connected`, `wan_ipaddr=''`) and stays that way until you manually toggle the connection off and on in the admin UI. This daemon detects the outage by pinging out, then logs into the router's undocumented `goform` API and performs the same disconnect → reconnect cycle automatically.

> **Unofficial.** Not affiliated with or endorsed by ZTE. It talks to an undocumented HTTP API that may change between firmware versions. Use at your own risk.

---

## How it works

1. Ping a public IP (default `1.1.1.1`) every 60s.
2. After `FAIL_THRESHOLD` consecutive failures, log into the router and issue `DISCONNECT_NETWORK` then `CONNECT_NETWORK`.
3. Verify the WAN got an IP again; otherwise back off and retry within guardrails.

Guardrails: a cooldown between recoveries, a circuit breaker (max N recoveries per rolling window, then it holds and logs instead of looping), and an auth-backoff latch so a wrong credential doesn't hammer the router.

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

**Recovery commands:** `DISCONNECT_NETWORK` then `CONNECT_NETWORK`.

**Handy read-only fields:** `wan_ipaddr`, `modem_main_state`, `ppp_status`, `network_type`.

---

## Install (Raspberry Pi / any systemd Linux)

```bash
git clone https://github.com/<you>/zte-mc801a-watchdog.git
cd zte-mc801a-watchdog
chmod +x install.sh
./install.sh           # prompts for the router admin password
```

The installer creates a venv under `/opt/zte-watchdog`, writes `config.env` (mode 600), and installs + starts a systemd service.

Manual one-shot test (recovers the WAN immediately if it's down):

```bash
cd /opt/zte-watchdog
set -a; source config.env; set +a
./venv/bin/python3 -c "from zte_watchdog import recover; print(recover())"
```

Logs: `journalctl -u zte-watchdog -f`

---

## Configuration

All settings are environment variables (see `config.env.example`). The important ones:

| Variable | Default | Meaning |
|---|---|---|
| `ROUTER_IP` | `192.168.0.1` | Router admin IP |
| `ROUTER_PASSWORD` | *(required)* | Router admin password |
| `PING_TARGET` | `1.1.1.1` | Address used to detect connectivity |
| `CHECK_INTERVAL` | `60` | Seconds between pings |
| `FAIL_THRESHOLD` | `3` | Consecutive failures before acting |
| `COOLDOWN` | `180` | Seconds between recovery attempts |
| `MAX_REBOOTS_PER_WINDOW` | `8` | Circuit-breaker cap per window |
| `ROLLING_WINDOW_SECONDS` | `86400` | Circuit-breaker window |

---

## Notes

- Only the cellular-WAN wedge is handled. If a future drop is a deeper modem hang that a soft reconnect can't clear, the circuit breaker stops the loop and logs it; a hardware power-cycle (a smart plug on a ping-failure trigger) is the robust fallback for that case.
- Tested only against `MC801AV1.0.0B16`. Other firmware builds may differ, especially the login hash case and the recovery command names.

## License

MIT — see [LICENSE](LICENSE).
