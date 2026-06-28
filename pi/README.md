# DRIFT mesh-node Raspberry Pi image

A flashable Raspberry Pi OS image that boots straight into a **DRIFT mesh node**
— a lightweight, always-on federated relay reachable over Tor as an onion
service (`relay.node`). Flash it, drop in a config file, power on. No screen, no
keyboard, no manual install.

> This is for running **infrastructure** (a relay/mesh node), not for chatting.
> To *use* DRIFT as a messenger, install the client — see the repo
> [`README.md`](../README.md). To set a node up on a Pi that already runs
> Raspberry Pi OS, the `curl | bash` installer in
> [`scripts/install-node.sh`](../scripts/install-node.sh) is simpler than
> reflashing.

---

## What's in the image

- Raspberry Pi OS **Lite, Bookworm** (armhf — runs on Pi Zero W, Zero 2 W, 3, 4, 5)
- `tor` with its control port enabled, so the node publishes an **ephemeral
  onion service** with no router/port-forward config
- DRIFT installed in an isolated venv at `/opt/drift-node`, run by a dedicated,
  login-less `drift-node` system account
- A hardened `drift-node.service` (systemd) that starts on boot
- A one-shot `drift-firstboot.service` that applies operator config from the
  boot partition, then disables itself

SSH is enabled but **no default password is baked in** — add a `userconf.txt`
(Raspberry Pi Imager does this under its advanced options) if you want to log in.

---

## Build it

Requires Docker. The build runs entirely in a container, so it works on Linux or
macOS.

```bash
pi/build.sh
# → pi/deploy/drift-node-YYYY-MM-DD-*.img.xz
```

Knobs (all optional):

| Env var          | Default                     | Meaning                                  |
|------------------|-----------------------------|------------------------------------------|
| `DRIFT_REF`      | `main`                      | DRIFT git ref baked into the image       |
| `DRIFT_REPO_URL` | upstream GitHub             | repo cloned into the image               |
| `PI_GEN_REF`     | `bookworm`                  | pinned pi-gen branch                     |

Under the hood `build.sh` clones the official Raspberry Pi OS image builder
([`pi-gen`](https://github.com/RPi-Distro/pi-gen)), layers our
[`stage-drift`](stage-drift) on top of Lite, and exports a single compressed
image. ARM Python wheels (`cryptography`, `PyNaCl`, `argon2-cffi`) come from
Raspberry Pi OS's bundled **piwheels** index, so nothing is compiled from
source.

CI also builds it: the **Pi node image** workflow
([`.github/workflows/pi-image.yml`](../.github/workflows/pi-image.yml)) runs on
demand and attaches the image to published releases.

---

## Flash it

Use [Raspberry Pi Imager](https://www.raspberrypi.com/software/) ("Use custom"
→ select the `.img.xz`) or `dd` / [balenaEtcher](https://etcher.balena.io/).

---

## Configure it (headless)

After flashing, the SD card's small **boot partition** (`bootfs`) mounts on any
computer. Edit `drift-node.conf` there before first power-on:

```ini
# drift-node.conf  (on the boot partition)
DRIFT_PEERS=ws://abc123…xyz.onion      # a relay/onion to join the mesh
DRIFT_NODE_PORT=8765                    # optional
WIFI_SSID=my-network                    # optional (else Ethernet / Imager wifi)
WIFI_PSK=my-password
```

Everything is optional — with no edits the node still boots, publishes an onion
address, and waits for peers.

---

## First boot

1. Power on with Ethernet or configured Wi-Fi.
2. Tor bootstraps and the node publishes its onion address (give it a minute or
   two on first boot).
3. The address is saved to `/opt/drift-node/state/node_address.txt`. Read it via
   SSH, then hand it to peers:

   ```bash
   cat /opt/drift-node/state/node_address.txt
   drift chat <name> --relay ws://<that-address>.onion
   ```

Manage the service like any other:

```bash
systemctl status drift-node
journalctl -u drift-node -f
```

---

## Known limitations

- **First-boot onion timing.** If Tor hasn't finished bootstrapping when the
  node starts, the node serves locally without an onion and does not retry until
  restarted. On a fresh boot it usually wins the race; if `node_address.txt`
  stays empty, `systemctl restart drift-node` once Tor is up.
- **Build needs piwheels.** The chroot install pulls ARM wheels from
  piwheels.org; an offline build would fall back to compiling `cryptography`
  (Rust) from source, which is slow on armhf and not currently provisioned.
- **armv6 build time.** Building under QEMU emulation for the Pi Zero's armv6 is
  slow (tens of minutes). This is the image *build*, not runtime.
- DRIFT is **pre-alpha and unaudited** — see the security notice in the repo
  README before relying on a node for anything high-stakes.
