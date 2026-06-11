# DRIFT

[![CI](https://github.com/chickenswaffle/Drift/actions/workflows/ci.yml/badge.svg)](https://github.com/chickenswaffle/Drift/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-v0.7.0-blue)](https://github.com/chickenswaffle/Drift/releases/tag/v0.7.0)
[![Phase](https://img.shields.io/badge/phase-4%20%E2%80%94%20Federation-brightgreen)](#project-status)

> A terminal-first, end-to-end encrypted messenger with rotating, unlinkable receiving addresses.

No phone numbers. No accounts. No central authority that can read or hand over your messages.

```
$ drift init
  ✓ keys generated locally — they never leave this machine
  Your contact code: drift:aV9k7Hk2···Q2x

$ drift add bob drift:7Hk2p9L···4fX
$ drift verify bob
  river-amber-tiger-92  ·  matches? [y/N]

$ drift chat bob
  bob › hey, did it work?
  you › flawlessly
```

---

## How it works (the short version)

Every message you receive lands at a **fresh, random address** that the relay cannot link to you or to any of your other messages. Your identity is a keypair you generate locally — nothing more. The relay is a dumb bulletin board of opaque ciphertext with a TTL; it sees nothing useful and holds nothing useful.

Full protocol design: [`DESIGN.md`](DESIGN.md)

---

## What DRIFT defends against

- Passive network surveillance (ISP, nation-state wire-tapping)
- A malicious, compromised, or subpoenaed relay server
- Later device or key theft (forward secrecy + post-compromise security)
- Traffic analysis — who talks to whom and when
- Infrastructure takedown — no single server to kill

## What DRIFT does NOT defend against

- **A compromised endpoint.** Malware on your machine reads the screen. No messenger fixes this.
- **A truly global passive adversary.** We raise the cost enormously; we don't claim to fully solve it.
- **User error** — sharing keys carelessly, screenshotting chats, getting phished.

Being precise here is what separates a serious tool from snake oil.

---

## Project status

🧪 **Alpha — Phases 0–4 complete.** Usable end-to-end, but not yet independently audited; not ready for high-stakes production use.

| Phase | Goal | Status |
|-------|------|--------|
| 0 | Basic E2E encryption — X25519 + XChaCha20 | ✅ Complete (`v0.1.0`) |
| 1 | Stealth rotating addresses + TUI | ✅ Complete (`v0.3.0`) |
| 2 | Double Ratchet (forward secrecy) | ✅ Complete (`v0.4.3`) |
| 3 | Tor transport + sealed sender | ✅ Complete (`v0.6.0`) |
| 4 | Federated relays + Pi Zero mesh nodes | ✅ Complete (`v0.7.0`) |
| 5 | Panic key, decoy volumes, FMD | 📋 Planned |

---

## Getting started (development)

**Requirements:** Python 3.11+, pip

```bash
git clone https://github.com/chickenswaffle/Drift.git
cd drift
pip install -e ".[dev]"

# run the reference relay (in one terminal)
python -m relay.server

# run the client (in another terminal)
drift init
drift chat <contact-code>
```

Full setup guide: [`docs/getting-started.md`](docs/getting-started.md)

---

## Architecture

```
drift/
├── drift/
│   ├── crypto/        # key generation, stealth addresses, AEAD, ratchet
│   ├── transport/     # WebSocket client, Tor bootstrap
│   ├── relay/         # relay protocol client
│   └── ui/            # Textual TUI
├── relay/             # reference relay server (FastAPI + Redis)
├── docs/              # protocol specs, threat model, contributor guide
└── tests/
```

---

## Contributing

Read [`CONTRIBUTING.md`](CONTRIBUTING.md) before opening a PR.

The iron rule: **never implement crypto primitives from scratch.** We compose vetted libraries (`PyNaCl`, `cryptography`) — we do not reimplement Curve25519 by hand. PRs that roll their own crypto will be closed.

Security issues: see [`SECURITY.md`](SECURITY.md).

---

## License

MIT — see [`LICENSE`](LICENSE)

---

> ⚠️ **Security notice:** DRIFT has not been independently audited. Do not use it for anything where your safety depends on it until a formal audit has been completed and published. We will announce audit results here.
