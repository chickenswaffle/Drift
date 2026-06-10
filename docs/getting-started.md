# Getting started with DRIFT

## Prerequisites

- Python 3.11 or newer
- pip
- Git

## Install (development)

```bash
git clone https://github.com/YOUR_USERNAME/drift.git
cd drift
pip install -e ".[dev]"
```

This installs the `drift` CLI command plus all dev dependencies.

## Your first run

### 1. Generate an identity

```bash
drift init
```

You'll see something like:

```
╭─────────────────────── ✓  Identity generated ───────────────────────╮
│ drift:aV9k7Hk2···Q2x.7Hk2p9L···4fX                                  │
╰─ Share this contact code with people who want to message you ────────╯

Keys are stored in: /home/you/.config/drift/identity.json
They never leave this machine.
```

### 2. Add a contact

Send your contact code to a friend. When they send you theirs:

```bash
drift add alice drift:THEIR_CODE_HERE
```

### 3. Verify (important!)

Compare a short safety number **out of band** — over a phone call or in person.
This confirms you have each other's real keys, not an attacker's.

```bash
drift verify alice
# Shows a short word string — should match on both sides
```

If they don't match, stop. Someone may be intercepting your key exchange.

### 4. Chat

```bash
drift chat alice
```

> **Phase 0 note:** The chat UI is not yet implemented. See `drift/ui/` to contribute.

## Run a local relay (for testing)

```bash
# Install relay dependencies
pip install -e ".[relay]"

# Start the relay
python -m relay.server
```

The relay starts on `ws://localhost:8765` by default.
Point clients at it with `drift chat alice --relay ws://localhost:8765`.

## Run tests

```bash
pytest tests/unit/ -v
```

## Project layout

```
drift/
├── drift/
│   ├── cli.py          # all CLI commands
│   ├── crypto/         # keys, AEAD, stealth addresses (Phase 1)
│   │   ├── __init__.py # core: keypairs, encrypt/decrypt, identity
│   │   └── stealth.py  # placeholder for Phase 1 rotating addresses
│   ├── transport/      # WebSocket client, Tor (Phase 3)
│   ├── relay/          # relay protocol client
│   └── ui/             # Textual terminal UI
├── relay/
│   └── server.py       # reference relay (FastAPI + WebSockets)
├── docs/
│   └── getting-started.md   ← you are here
├── tests/
│   └── unit/
│       └── test_crypto.py
├── DESIGN.md           # full protocol specification
├── CONTRIBUTING.md
└── SECURITY.md
```
