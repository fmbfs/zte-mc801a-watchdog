#!/usr/bin/env bash
###############################################################################
# install.sh - install the ZTE MC801A watchdog as a systemd service.
#
#   ./install.sh                 # prompts for the router admin password
#   ROUTER_IP=192.168.0.1 ./install.sh   # override defaults via env vars
#
# Re-running is safe; it refreshes the script/service and reuses an existing
# config.env password if present.
###############################################################################
set -euo pipefail

INSTALL_DIR="/opt/zte-watchdog"
SERVICE_NAME="zte-watchdog"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${INSTALL_DIR}/config.env"

ROUTER_IP="${ROUTER_IP:-192.168.0.1}"
PING_TARGET="${PING_TARGET:-1.1.1.1}"
CHECK_INTERVAL="${CHECK_INTERVAL:-60}"
FAIL_THRESHOLD="${FAIL_THRESHOLD:-3}"
COOLDOWN="${COOLDOWN:-180}"
MAX_REBOOTS_PER_WINDOW="${MAX_REBOOTS_PER_WINDOW:-8}"
ROLLING_WINDOW_SECONDS="${ROLLING_WINDOW_SECONDS:-86400}"
AUTH_MAX_FAILURES="${AUTH_MAX_FAILURES:-4}"
RECONNECT_VERIFY_SECONDS="${RECONNECT_VERIFY_SECONDS:-30}"

if [[ -z "${ROUTER_PASSWORD:-}" && -f "${CONFIG_FILE}" ]]; then
  ROUTER_PASSWORD="$(grep -E '^ROUTER_PASSWORD=' "${CONFIG_FILE}" | cut -d= -f2-)"
  [[ -n "${ROUTER_PASSWORD}" ]] && echo "Reusing stored password from ${CONFIG_FILE}."
fi
if [[ -z "${ROUTER_PASSWORD:-}" ]]; then
  read -srp "Router admin password: " ROUTER_PASSWORD; echo
fi

echo "[1/5] Installing dependencies..."
sudo apt-get update -qq
sudo apt-get install -y -qq python3 python3-venv python3-pip iputils-ping

echo "[2/5] Creating ${INSTALL_DIR}..."
sudo mkdir -p "${INSTALL_DIR}"
sudo chown "$(whoami)":"$(whoami)" "${INSTALL_DIR}"

echo "[3/5] Python venv + deps..."
python3 -m venv "${INSTALL_DIR}/venv"
"${INSTALL_DIR}/venv/bin/pip" install --quiet --upgrade pip requests
cp "${SRC_DIR}/zte_watchdog.py" "${INSTALL_DIR}/zte_watchdog.py"

echo "[4/5] Writing ${CONFIG_FILE} (mode 600)..."
cat > "${CONFIG_FILE}" << EOF
ROUTER_IP=${ROUTER_IP}
ROUTER_PASSWORD=${ROUTER_PASSWORD}
PING_TARGET=${PING_TARGET}
CHECK_INTERVAL=${CHECK_INTERVAL}
FAIL_THRESHOLD=${FAIL_THRESHOLD}
COOLDOWN=${COOLDOWN}
MAX_REBOOTS_PER_WINDOW=${MAX_REBOOTS_PER_WINDOW}
ROLLING_WINDOW_SECONDS=${ROLLING_WINDOW_SECONDS}
AUTH_MAX_FAILURES=${AUTH_MAX_FAILURES}
RECONNECT_VERIFY_SECONDS=${RECONNECT_VERIFY_SECONDS}
EOF
chmod 600 "${CONFIG_FILE}"

echo "[5/5] Installing systemd service..."
sed "s|EnvironmentFile=.*|EnvironmentFile=${CONFIG_FILE}|; \
     s|ExecStart=.*|ExecStart=${INSTALL_DIR}/venv/bin/python3 ${INSTALL_DIR}/zte_watchdog.py|" \
     "${SRC_DIR}/systemd/zte-watchdog.service" | sudo tee "/etc/systemd/system/${SERVICE_NAME}.service" > /dev/null

sudo systemctl daemon-reload
sudo systemctl enable "${SERVICE_NAME}.service"
sudo systemctl restart "${SERVICE_NAME}.service"

echo
echo "Done. Status: systemctl status ${SERVICE_NAME} | Logs: journalctl -u ${SERVICE_NAME} -f"
