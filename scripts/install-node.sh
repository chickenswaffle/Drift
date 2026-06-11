#!/usr/bin/env bash
#
# install-node.sh — one-command DRIFT mesh node setup for Raspberry Pi / Debian
#
#   curl -sSL https://get.driftmsg.io/node | bash
#
# Detects a Raspberry Pi (or any Debian/Ubuntu ARM box), installs Python 3.11,
# Tor, and the DRIFT relay into a venv, then registers a systemd service
# (drift-node) that starts on boot and exposes the node as a Tor onion service.
# Prompts for a bootstrap peer and prints the node's .onion address when done.
#
# Tested targets: Pi Zero W, Pi Zero 2 W, Pi 3, Pi 4, and generic Debian/Ubuntu
# ARM. Safe to re-run: it updates an existing install in place.
#
set -euo pipefail

# --------------------------------------------------------------------------- #
# Pretty output
# --------------------------------------------------------------------------- #
BOLD=$'\033[1m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'; RESET=$'\033[0m'
say()  { printf '%s\n' "${BOLD}⬡ ${*}${RESET}"; }
ok()   { printf '%s\n' "${GREEN}✓ ${*}${RESET}"; }
warn() { printf '%s\n' "${YELLOW}⚠ ${*}${RESET}"; }
die()  { printf '%s\n' "${RED}✗ ${*}${RESET}" >&2; exit 1; }

# --------------------------------------------------------------------------- #
# Configuration (override via env)
# --------------------------------------------------------------------------- #
DRIFT_USER="${DRIFT_USER:-${SUDO_USER:-$(id -un)}}"
INSTALL_DIR="${DRIFT_INSTALL_DIR:-/opt/drift-node}"
REPO_URL="${DRIFT_REPO_URL:-https://github.com/chickenswaffle/Drift.git}"
SERVICE_NAME="drift-node"
NODE_PORT="${DRIFT_NODE_PORT:-8765}"

# --------------------------------------------------------------------------- #
# Privilege + platform checks
# --------------------------------------------------------------------------- #
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    command -v sudo >/dev/null 2>&1 || die "please run as root or install sudo"
    SUDO="sudo"
fi

say "DRIFT mesh node installer"

if [ -r /proc/device-tree/model ] && grep -qi "raspberry pi" /proc/device-tree/model 2>/dev/null; then
    MODEL="$(tr -d '\0' < /proc/device-tree/model)"
    ok "detected: ${MODEL}"
else
    warn "not a Raspberry Pi — continuing (Debian/Ubuntu ARM assumed)"
fi

command -v apt-get >/dev/null 2>&1 || die "this installer needs apt-get (Debian/Ubuntu)"

# --------------------------------------------------------------------------- #
# System dependencies
# --------------------------------------------------------------------------- #
say "installing system packages (python3, venv, tor, git) …"
export DEBIAN_FRONTEND=noninteractive
$SUDO apt-get update -qq
$SUDO apt-get install -y -qq python3 python3-venv python3-pip git tor >/dev/null

# Python 3.11+ is required by DRIFT. If the distro python is older, fall back to
# the deadsnakes-free approach of whatever python3.11 is available.
PYTHON="python3"
if command -v python3.11 >/dev/null 2>&1; then
    PYTHON="python3.11"
fi
PYVER="$($PYTHON -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
case "$PYVER" in
    3.1[1-9]|3.[2-9][0-9]) ok "python ${PYVER}" ;;
    *) warn "python ${PYVER} found; DRIFT needs >=3.11 — attempting anyway" ;;
esac

# --------------------------------------------------------------------------- #
# Enable the tor control port so the node can publish an onion service
# --------------------------------------------------------------------------- #
say "configuring tor control port …"
TORRC="/etc/tor/torrc"
if [ -f "$TORRC" ] && ! grep -q "^ControlPort 9051" "$TORRC"; then
    printf '\n# Added by DRIFT install-node.sh\nControlPort 9051\nCookieAuthentication 1\n' \
        | $SUDO tee -a "$TORRC" >/dev/null
    $SUDO systemctl restart tor || warn "could not restart tor — start it manually"
fi
# Let the node's user read tor's auth cookie.
$SUDO usermod -aG debian-tor "$DRIFT_USER" 2>/dev/null || true

# --------------------------------------------------------------------------- #
# Fetch / update the code
# --------------------------------------------------------------------------- #
say "installing DRIFT into ${INSTALL_DIR} …"
$SUDO mkdir -p "$INSTALL_DIR"
$SUDO chown "$DRIFT_USER" "$INSTALL_DIR"
if [ -d "$INSTALL_DIR/.git" ]; then
    git -C "$INSTALL_DIR" pull --ff-only || warn "git pull failed — using existing checkout"
else
    git clone --depth 1 "$REPO_URL" "$INSTALL_DIR"
fi

# --------------------------------------------------------------------------- #
# Virtualenv + dependencies
# --------------------------------------------------------------------------- #
say "creating virtualenv + installing relay dependencies …"
$PYTHON -m venv "$INSTALL_DIR/.venv"
# shellcheck disable=SC1091
"$INSTALL_DIR/.venv/bin/pip" install --quiet --upgrade pip
"$INSTALL_DIR/.venv/bin/pip" install --quiet -e "$INSTALL_DIR[relay,tor]"
ok "dependencies installed"

# --------------------------------------------------------------------------- #
# Bootstrap peer
# --------------------------------------------------------------------------- #
BOOTSTRAP_PEER="${DRIFT_PEERS:-}"
if [ -z "$BOOTSTRAP_PEER" ] && [ -t 0 ]; then
    printf '\n%s' "Bootstrap peer URL (a relay/onion to join, blank to skip): "
    read -r BOOTSTRAP_PEER || true
fi

# --------------------------------------------------------------------------- #
# systemd service
# --------------------------------------------------------------------------- #
say "registering systemd service '${SERVICE_NAME}' …"
$SUDO tee "/etc/systemd/system/${SERVICE_NAME}.service" >/dev/null <<UNIT
[Unit]
Description=DRIFT mesh node (federated relay over Tor)
After=network-online.target tor.service
Wants=network-online.target

[Service]
Type=simple
User=${DRIFT_USER}
WorkingDirectory=${INSTALL_DIR}
Environment=DRIFT_NODE_PORT=${NODE_PORT}
Environment=DRIFT_PEERS=${BOOTSTRAP_PEER}
Environment=DRIFT_NODE_ADDRESS_FILE=${INSTALL_DIR}/node_address.txt
ExecStart=${INSTALL_DIR}/.venv/bin/python -m relay.node
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

$SUDO systemctl daemon-reload
$SUDO systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || true
$SUDO systemctl restart "$SERVICE_NAME"
ok "service started and enabled on boot"

# --------------------------------------------------------------------------- #
# Report the onion address
# --------------------------------------------------------------------------- #
say "waiting for the node to publish its onion address …"
ADDR_FILE="${INSTALL_DIR}/node_address.txt"
ONION=""
for _ in $(seq 1 30); do
    if [ -s "$ADDR_FILE" ]; then ONION="$(cat "$ADDR_FILE")"; break; fi
    sleep 2
done

echo
if [ -n "$ONION" ]; then
    ok "DRIFT mesh node is live"
    printf '%s\n' "  ${BOLD}.onion address:${RESET} ${ONION}"
    printf '%s\n' "  share it:  ${BOLD}drift chat <name> --relay ws://${ONION}${RESET}"
else
    warn "node started but no onion address yet — check: journalctl -u ${SERVICE_NAME} -f"
fi
echo
ok "done. manage with: systemctl {status,restart,stop} ${SERVICE_NAME}"
