# DRIFT Desktop (Tauri + React)

The desktop client for DRIFT (Phase 13c). A thin native shell over the
**existing, audited Python core** — no new cryptography lives here.

## Architecture

```
┌──────────────────────────┐        ┌──────────────────────────────┐
│  Tauri window (Rust)      │  JSON  │  Python sidecar              │
│  src-tauri/src/main.rs    │ ◀────▶ │  python -m drift.sidecar     │
│   • spawns the sidecar    │  RPC   │   • wraps drift.storage +    │
│   • `rpc` command         │ stdio  │     drift.transport.Session  │
│   • forwards events       │        │   • the real crypto/transport│
└───────────┬──────────────┘        └──────────────────────────────┘
            │ invoke / events
┌───────────▼──────────────┐
│  React UI (src/)          │
│   onboarding · contacts · │
│   live 1:1 chat           │
└──────────────────────────┘
```

The UI talks only to a small RPC surface (`status`, `init`, `whoami`,
`contacts_add/list`, `safety_number`, `chat_open/send/close`, `lock/unlock`).
Incoming messages and transport status arrive as `sidecar` events. This is the
same seam the CLI and TUI use — see `drift/sidecar.py`.

**Why a Python sidecar?** It reuses 100% of the already-audited crypto instead
of standing up a second implementation today. Per `docs/app-plan.md`, the
sidecar is later swapped for a native Rust `drift-core` **under the same UI**,
with no UI rewrite.

## Prerequisites

- **Node 18+** and **npm**
- **Rust** (stable) + Cargo — `https://rustup.rs`
- **Python 3.11+** with DRIFT installed (`pip install -e ".[dev]"` from repo root)
- Platform Tauri deps: see <https://tauri.app/start/prerequisites/>
  (macOS: Xcode CLT; Linux: webkit2gtk, etc.)

## Run in development

From the repo root, with the Python env active:

```bash
# 1. install JS deps (once)
cd apps/desktop
npm install

# 2. point the shell at your Python interpreter (recommended: the project venv)
export DRIFT_PYTHON="$PWD/../../.venv/bin/python"   # or just rely on `python3`
export DRIFT_REPO="$PWD/../.."                        # repo root for the sidecar

# 3. (optional) run a local relay in another terminal
#    NOTE: a WebSocket backend is required — install one if missing:
#      pip install wsproto
python -m uvicorn relay.server:app --host 127.0.0.1 --port 8765 --ws wsproto

# 4. launch the app (starts Vite + the Tauri window)
npm run tauri dev
```

The default relay is `ws://127.0.0.1:8765` (override with `$DRIFT_RELAY_URL` on
the sidecar). `127.0.0.1` rather than `localhost` on purpose — on dual-stack
hosts `localhost` can resolve to IPv6 `::1`, which an IPv4-only relay won't
answer.

## Build a self-contained installer

A packaged install bundles a **frozen sidecar** (PyInstaller), so end users need
**no Python**. Two steps:

```bash
# 1. freeze the sidecar → src-tauri/binaries/drift-sidecar-<triple>[.exe]
python sidecar/build_sidecar.py

# 2. build the installer, merging the release config that adds the externalBin
cd apps/desktop
npm run tauri build -- --config src-tauri/tauri.conf.release.json
```

The base `tauri.conf.json` (used by `tauri dev`) has **no** `externalBin`, so dev
keeps using the Python fallback; `tauri.conf.release.json` adds it only for
packaged builds. At runtime the shell prefers the bundled `drift-sidecar` next
to the executable and falls back to system Python only in dev (see
`sidecar_command()` in `src-tauri/src/main.rs`).

Output: `.dmg` (macOS, unsigned), `.deb`/`.AppImage` (Linux), `.exe` (Windows).
**Windows binaries can't be cross-compiled from macOS/Linux** — each target
builds on its own OS.

**macOS builds are unsigned and un-notarized** (no Apple Developer certificate
yet): Gatekeeper will warn on first open. Verify the download's SHA-256 against
the checksum on the release page before opening. Updater artifacts are still
minisign-verified by the app itself once installed.

### CI / releases

`.github/workflows/desktop-app.yml` builds all three on native runners. On a
published GitHub release it attaches the versioned installers **and** uploads the
Windows installer under a stable name, so the website download button has a
permanent URL:

```
https://github.com/chickenswaffle/Drift/releases/latest/download/DRIFT-Setup-Windows-x64.exe
```

Trigger it manually (`workflow_dispatch`) to produce artifacts without a release.

### Icons

`src-tauri/icons/` is generated from `assets/icon-source.png` via
`npm run tauri icon assets/icon-source.png`. Replace the source and re-run to
rebrand.

## Status

Phase 13c, first cut. Implemented: identity onboarding, contact add/list,
safety numbers (backend), live 1:1 chat over the relay. Not yet wired into the
UI: Tor transport, the vault lock/unlock + duress flow, groups/rooms, mobile
Lockdown equivalent. See `docs/app-plan.md` §5 for the sub-phase roadmap.
