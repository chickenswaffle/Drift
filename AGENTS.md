# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

DRIFT is a terminal-first, end-to-end encrypted messenger with rotating stealth addresses. No accounts, no phone numbers — identity is a locally-generated keypair. The design goal is to hide both message content *and* metadata (who talks to whom, when).

The project is **pre-alpha**. The phased roadmap matters: each phase is a discrete milestone, and code should not anticipate later phases unless explicitly scoped.

### Phase status

Current release: **`v0.11.1`**. No phase is in progress right now.

- **Phase 0 — transport** ✅ complete: X25519 ECDH → HKDF → XChaCha20-Poly1305, wired to the relay transport.
- **Phase 1 — stealth addresses + TUI** ✅ complete: rotating one-time addressing and the Textual TUI.
- **Phase 2 — Double Ratchet** ✅ complete: forward-secret message encryption.
- **Phase 3 — Tor + sealed sender** ✅ complete: route over Tor automatically and hide the sender from the relay.
- **Phase 4 — relay federation** ✅ complete: Redis-backed mailbox + federated relays.
- **Phase 5 — panic / duress vault** ✅ complete: panic key + duress decoy vault (`crypto/panic.py`).
- **Phase 6 — fuzzy message detection** ✅ complete: FMD privacy dial (`crypto/fmd.py`).
- **Phase 7 — multi-device** ⏭️ skipped for now.
- **Phase 8 — group messaging** ✅ complete: pairwise ratchets, ≤10 members (`crypto/groups.py`).
- **Phase 9 — one-click Codespaces launch** ✅ complete: `.devcontainer/` + README badge.

**Backlog (none currently active):** X3DH asynchronous key agreement; M1–M5 audit findings; Phase 10 (Raspberry Pi image); Phase 11 (public rooms).

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

Implemented (Phase 1). Every message derives a unique one-time address via `A_once = spend_point(spend_pub) + SHA256(ECDH(r, scan_pub))·G`. Only the recipient — using their private scan key — can detect it via a constant-time compare. The elliptic-curve point addition that X25519 doesn't expose natively is done with libsodium's ed25519 group operations (Elligator map to a curve point, `crypto_core_ed25519_add`, scalar mult). Note: the module docstring still self-describes as a placeholder and is stale relative to the implementation.

### Relay (`relay/server.py`)

Intentionally dumb: routes opaque ciphertext, never reads content. Phase 0 uses an in-memory `defaultdict` mailbox keyed by address hex. Clients subscribe over WebSocket at `/ws/{addr}` and senders POST to `/send`. The relay queues undelivered messages and drains them on subscribe. Phase 4 will replace this with Redis + relay federation.

## Iron rules

- **Never implement crypto primitives from scratch.** Use `PyNaCl` / `cryptography` (libsodium bindings). PRs that roll their own curve math will be closed.
- Always let `InvalidTag` propagate on decrypt failure — a tampered message must be rejected, not silently dropped.
- Identity files are saved `chmod 0o600` — never relax this.
- **The panic/duress vault and FMD are live security systems — don't touch them blind.** The panic key + duress decoy vault (`crypto/panic.py`) and the fuzzy message detection privacy dial (`crypto/fmd.py`) are deliberately subtle: a careless change can silently leak real contacts from a decoy unlock or widen the FMD false-positive rate in ways that deanonymize users. Read `crypto/panic.py` and `crypto/fmd.py` in full before modifying either, or anything that calls into them.
