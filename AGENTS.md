# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

DRIFT is a terminal-first, end-to-end encrypted messenger with rotating stealth addresses. No accounts, no phone numbers — identity is a locally-generated keypair. The design goal is to hide both message content *and* metadata (who talks to whom, when).

The project is **pre-alpha, Phase 0 in progress**. The phased roadmap matters: each phase is a discrete milestone, and code should not anticipate later phases unless explicitly scoped.

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
  crypto/       All cryptographic operations — keypair gen, ECDH, HKDF, AEAD
  transport/    Network layer (Phase 0: stub; Phase 3: Tor)
  relay/        Relay-protocol client stub (currently empty)
  ui/           Textual TUI (Phase 0 placeholder — app.py not yet created)
  cli.py        Typer CLI; config lives in ~/.config/drift/
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

Phase 1 placeholder. The protocol math is fully documented in the file. The key insight: every message derives a unique one-time address via `A_once = spend_pub + SHA256(ECDH(r, scan_pub))·G`. Only the recipient — using their private scan key — can detect it. Implementing this requires elliptic-curve point addition, which X25519 doesn't expose natively; the file notes `ristretto255` or `pure25519` as viable options.

### Relay (`relay/server.py`)

Intentionally dumb: routes opaque ciphertext, never reads content. Phase 0 uses an in-memory `defaultdict` mailbox keyed by address hex. Clients subscribe over WebSocket at `/ws/{addr}` and senders POST to `/send`. The relay queues undelivered messages and drains them on subscribe. Phase 4 will replace this with Redis + relay federation.

## Iron rules

- **Never implement crypto primitives from scratch.** Use `PyNaCl` / `cryptography` (libsodium bindings). PRs that roll their own curve math will be closed.
- Always let `InvalidTag` propagate on decrypt failure — a tampered message must be rejected, not silently dropped.
- Identity files are saved `chmod 0o600` — never relax this.
