# AGENTS.md

This file provides guidance to AI coding agents working with code in this repository.

## Project overview

DRIFT is a terminal-first, end-to-end encrypted messenger with rotating stealth addresses. No accounts, no phone numbers — identity is a locally-generated keypair. The design goal is to hide both message content *and* metadata (who talks to whom, when).

The project is **pre-alpha**. The phased roadmap matters: each phase is a discrete milestone, and code should not anticipate later phases unless explicitly scoped.

### Phase status

Current release: **`v0.15.0`**. No phase is in progress right now.

- **Phase 0 — transport** ✅ complete: X25519 ECDH → HKDF → XChaCha20-Poly1305, wired to the relay transport.
- **Phase 1 — stealth addresses + TUI** ✅ complete: rotating one-time addressing and the Textual TUI.
- **Phase 2 — Double Ratchet** ✅ complete: forward-secret message encryption.
- **Phase 3 — Tor + sealed sender** ✅ complete: route over Tor automatically and hide the sender from the relay.
- **Phase 4 — relay federation** ✅ complete: federated relays gossiping opaque blobs, each backed by a short (30s) in-memory replay buffer (no durable mailbox).
- **Phase 5 — panic / duress vault** ✅ complete: panic key + duress decoy vault (`crypto/panic.py`).
- **Phase 6 — fuzzy message detection** ✅ complete: FMD privacy dial (`crypto/fmd.py`).
- **Phase 7 — multi-device** ⏭️ skipped for now.
- **Phase 8 — group messaging** ✅ complete: pairwise ratchets, ≤10 members (`crypto/groups.py`).
- **Phase 9 — one-click Codespaces launch** ✅ complete: `.devcontainer/` + README badge.
- **Phase 10 — WITNESS** ✅ complete: live, signed, hash-chained proof of relay blindness (`relay/witness.py`, `/witness/*` + `/cannot-see`, `drift witness verify|subscribe`). See `docs/witness.md`.
- **Phase 11 — sovereign rooms** ✅ complete: cryptographic chatrooms with no server-side representation — a room is a shared secret derived from its name, posted to rotating stealth addresses. Three tiers (open/invite/dark), optional federation shards (`crypto/rooms.py`, `transport/room_session.py`, `drift room …`). Encrypted but **not** forward-secret — see DESIGN.md §12.
- **Phase 12 — Lockdown Mode** ✅ complete (`v0.15.0`): a high-paranoia TUI mode (Ctrl+K, or `drift chat --lockdown`) with an obfuscated composer (display noise, paste disabled) and purged in-memory history, so a shoulder-surfer or seized-while-open device sees no draft or scrollback (`ui/app.py`).
- **Gauntlet** ✅ complete (`v0.15.0`): a standalone 10-probe adversarial test harness (`scripts/gauntlet.py`) that spins up the relay in-process and fires red-team probes at the core privacy/crypto invariants (relay blindness, stealth unlinkability, forward secrecy, burn replay, sealed-sender opacity, WITNESS chain integrity, forged-message rejection, panic isolation, OTPK consumption, FMD rate).
- **X3DH asynchronous key agreement** ✅ complete (`v0.14.0`): the Signal X3DH handshake replaces the deterministic ratchet bootstrap, closing the last H3 audit residual. Users publish a signed prekey + one-time prekeys to the relay (`/prekeys/*`, sealed at rest); the initiator fetches the bundle, runs `DH1..DH4 → HKDF`, and the recipient's signed prekey seeds the Double Ratchet. One-time prekeys are consumed once and deleted, so a later full key compromise can't decrypt past opening bursts. The relay-side one-time prekey pool **auto-replenishes mid-session** — a recipient who stays online while senders drain it tops the pool back up in the background once it dips below the low watermark, so it never silently falls back to weaker OTPK-less handshakes. The old deterministic bootstrap remains only as a visibly-warned fallback (`crypto/x3dh.py`, `transport/session.py`, `drift prekeys`).

- **Audit M1–M3, M5 + lows L1, L3** ✅ resolved (`v0.14.1`): scan/spend privilege separation (the stealth message key now folds in an `ECDH(spend, R)` so the private spend key is required to decrypt, not just the scan key — `crypto/stealth.py`); single-use burn tokens with nonce + timestamp and relay-side replay dedup (`crypto/burn.py`, `relay/server.py`); relay-specific beacon lookup hash bound to the relay pubkey via `GET /beacon/pubkey` (`crypto/beacon.py`); safety number now commits to both scan **and** spend keys, invalidating old numbers (`storage.py`); bounded seen-address dedup and `/send` size+addr validation. See `docs/audit-2026-06.md`. **L2** (wipe single-shot tell) and **L4** (spend key reused as Ed25519 seed) are documented in DESIGN.md and deferred — both need an on-disk format/migration change.

**Backlog:** L2 / L4 (deferred, need format migration). The **Raspberry Pi image** build pipeline now lives in `pi/` — a `pi-gen` stage (`pi/stage-drift/`) that layers the `relay.node` onion mesh node onto Raspberry Pi OS Lite (Bookworm/armhf), headless first-boot provisioning from a boot-partition `drift-node.conf`, a `build.sh` wrapper, and a `pi-image` CI workflow. It produces a flashable image but none has been cut to a release yet; see `pi/README.md`.

## Development setup

```bash
pip install -e ".[dev]"          # installs drift + relay + dev tools
```

## Commands

```bash
# Tests
pytest tests/unit/ -v                          # all unit tests
pytest tests/unit/test_crypto.py -v            # single test file
pytest tests/unit/test_crypto.py::TestAEAD -v # single test class
pytest tests/ -v --cov=drift                   # with coverage

# Lint / type-check (mirrors CI)
ruff check drift/ relay/ tests/
mypy drift/

# Run the reference relay (one terminal)
python -m relay.server                         # ws://localhost:8765

# Run the CLI
drift init
drift add <name> <contact-code>
drift chat <name>
```

## Architecture

Layers are intentionally decoupled — `crypto/` knows nothing about networks; `transport/` knows nothing about message content; `ui/` knows nothing about crypto.

```
drift/          Python package (client)
  crypto/       All cryptographic operations — keypair gen, ECDH, HKDF, AEAD,
                stealth addressing, Double Ratchet
  transport/    Network layer (relay-backed; Phase 3: Tor)
  relay/        Relay-protocol client stub (currently empty)
  ui/           Textual TUI — component-tree app in app.py (see its module docstring)
  storage.py    Local persistence model — identity + contacts under ~/.config/drift/;
                the seam the UI talks to instead of crypto
  cli.py        Typer CLI; a thin view over drift.storage
relay/          Reference relay server — FastAPI + in-memory mailbox
tests/
  unit/         Pure unit tests against drift.crypto (no network)
  integration/  (empty — planned for Phase 1+)
```

### Cryptographic identity (`drift/crypto/__init__.py`)

An `Identity` has two X25519 keypairs:
- **scan key** — others use the public half to derive one-time addresses *to* you; you use the private half to scan for incoming mail
- **spend key** — private half unlocks a detected message

Contact codes encode both public keys: `drift:<scan_pub_b58>.<spend_pub_b58>`

Phase 0 encryption: `X25519 ECDH → HKDF-SHA256 → XChaCha20-Poly1305`. The `encrypt`/`decrypt` functions in `drift.crypto` return `nonce (24 bytes) || ciphertext+tag`.

### Stealth addresses (`drift/crypto/stealth.py`)

Implemented (Phase 1). Every message derives a unique one-time address via `A_once = spend_point(spend_pub) + SHA256(ECDH(r, scan_pub))·G`. Only the recipient — using their private scan key — can detect it via a constant-time compare. The elliptic-curve point addition that X25519 doesn't expose natively is done with libsodium's ed25519 group operations (Elligator map to a curve point, `crypto_core_ed25519_add`, scalar mult).

### Relay (`relay/server.py`)

Intentionally dumb: routes opaque ciphertext, never reads content. Clients subscribe over WebSocket at `/ws/{addr}` and senders POST to `/send`. There is no durable mailbox — the relay keeps a short (30s) in-memory replay buffer per channel so a late-joining socket can catch up, and Phase 4 federation gossips the same opaque blobs between relays (`relay/federation.py`). Both are RAM-only; nothing is persisted to Redis or disk.

## Iron rules

- **Never implement crypto primitives from scratch.** Use `PyNaCl` / `cryptography` (libsodium bindings). PRs that roll their own curve math will be closed.
- Always let `InvalidTag` propagate on decrypt failure — a tampered message must be rejected, not silently dropped.
- Identity files are saved `chmod 0o600` — never relax this.
- **The panic/duress vault and FMD are live security systems — don't touch them blind.** The panic key + duress decoy vault (`crypto/panic.py`) and the fuzzy message detection privacy dial (`crypto/fmd.py`) are deliberately subtle: a careless change can silently leak real contacts from a decoy unlock or widen the FMD false-positive rate in ways that deanonymize users. Read `crypto/panic.py` and `crypto/fmd.py` in full before modifying either, or anything that calls into them.
