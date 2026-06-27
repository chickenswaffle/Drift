#!/bin/bash -e
#
# Install the DRIFT mesh node into the image rootfs.
#
# Runs on the build host (cwd = this step dir) with ${ROOTFS_DIR} pointing at
# the chroot. `on_chroot` runs commands inside the target filesystem under qemu.

INSTALL_DIR="/opt/drift-node"
SERVICE_USER="drift-node"

# Which DRIFT revision to bake in. build.sh writes these into files/; default to
# upstream main for a bare `pi-gen` invocation.
DRIFT_REF="main"
DRIFT_REPO_URL="https://github.com/chickenswaffle/Drift.git"
if [ -f files/drift-build.env ]; then
	# shellcheck disable=SC1091
	. files/drift-build.env
fi

# --------------------------------------------------------------------------- #
# 1. systemd units + first-boot provisioning script into the image
# --------------------------------------------------------------------------- #
install -m 644 files/drift-node.service      "${ROOTFS_DIR}/etc/systemd/system/drift-node.service"
install -m 644 files/drift-firstboot.service "${ROOTFS_DIR}/etc/systemd/system/drift-firstboot.service"
install -m 755 files/drift-firstboot.sh      "${ROOTFS_DIR}/usr/local/sbin/drift-firstboot"

# --------------------------------------------------------------------------- #
# 2. Operator config template, dropped on the FAT boot partition so it can be
#    edited on any computer after flashing, before first power-on.
#    Bookworm mounts the boot partition at /boot/firmware.
# --------------------------------------------------------------------------- #
install -d "${ROOTFS_DIR}/boot/firmware"
install -m 644 files/drift-node.conf "${ROOTFS_DIR}/boot/firmware/drift-node.conf"

# --------------------------------------------------------------------------- #
# 3. Build the node inside the chroot
# --------------------------------------------------------------------------- #
on_chroot << EOF
set -e

# Dedicated, login-less service account — the node never runs as the login user.
if ! id -u "${SERVICE_USER}" >/dev/null 2>&1; then
    adduser --system --group --home "${INSTALL_DIR}" --no-create-home "${SERVICE_USER}"
fi

# Enable the tor control port so the node can publish an ephemeral onion service
# (cookie auth; the service account is added to debian-tor to read the cookie).
if ! grep -q '^ControlPort 9051' /etc/tor/torrc; then
    printf '\n# Added by DRIFT pi image\nControlPort 9051\nCookieAuthentication 1\n' >> /etc/tor/torrc
fi
adduser "${SERVICE_USER}" debian-tor || true

# Fetch DRIFT and install into an isolated venv. Raspberry Pi OS ships a
# piwheels index (/etc/pip.conf), so cryptography / PyNaCl / argon2-cffi resolve
# to prebuilt ARM wheels instead of compiling from source.
rm -rf "${INSTALL_DIR}/src"
git clone --depth 1 --branch "${DRIFT_REF}" "${DRIFT_REPO_URL}" "${INSTALL_DIR}/src"
python3 -m venv "${INSTALL_DIR}/.venv"
"${INSTALL_DIR}/.venv/bin/pip" install --upgrade pip wheel
"${INSTALL_DIR}/.venv/bin/pip" install -e "${INSTALL_DIR}/src[relay,tor]"

# Writable state dir (onion address, etc). Everything else stays read-only.
mkdir -p "${INSTALL_DIR}/state"
chown -R "${SERVICE_USER}:${SERVICE_USER}" "${INSTALL_DIR}"

# Boot ordering: tor and the node start on boot; firstboot applies operator
# config once, before the node.
systemctl enable tor.service
systemctl enable drift-firstboot.service
systemctl enable drift-node.service
EOF
