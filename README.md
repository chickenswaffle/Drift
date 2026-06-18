```
██████╗ ██████╗ ██╗███████╗████████╗
██╔══██╗██╔══██╗██║██╔════╝╚══██╔══╝
██║  ██║██████╔╝██║█████╗     ██║   
██║  ██║██╔══██╗██║██╔══╝     ██║   
██████╔╝██║  ██║██║██║        ██║   
╚═════╝ ╚═╝  ╚═╝╚═╝╚═╝        ╚═╝
```
*No accounts. No phone numbers. No server that can read your messages.*

# DRIFT

[![CI](https://github.com/chickenswaffle/Drift/actions/workflows/ci.yml/badge.svg)](https://github.com/chickenswaffle/Drift/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-v0.13.0-blue)](https://github.com/chickenswaffle/Drift/releases/tag/v0.13.0)
[![Phase](https://img.shields.io/badge/phase-11%20%E2%80%94%20Sovereign%20Rooms-brightgreen)](#project-status)

> A terminal-first, end-to-end encrypted messenger with rotating, unlinkable receiving addresses.

No phone numbers. No accounts. No central authority that can read or hand over your messages.

## Try it in your browser

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/chickenswaffle/Drift)

Click to launch a fully configured DRIFT environment in your browser — no installation required.

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

## Verifiable privacy

Most messengers ask you to *trust* that the server doesn't log. DRIFT's relays
let you **verify** it. Every 60 seconds a relay generates and signs a
hash-chained *blindness certificate* recording what it provably cannot know
about the traffic it just routed — zero sender identities, zero recipient
identities, zero readable contents, zero linked conversations. The certificates
form a tamper-evident transparency log: a relay can't rewrite its past without
its private key, and it can't silently start logging without breaking a chain
anyone can watch.

```bash
drift witness verify ws://localhost:8765      # check a relay's full 24-hour chain
drift witness subscribe ws://localhost:8765   # live canary — alerts the instant the chain breaks
```

There's also a plain-English `/cannot-see` page rendering the current
certificate — the page a surveillance request lands on. Full spec, threat model,
and how to verify with just `openssl`/`hashlib`: [`docs/witness.md`](docs/witness.md).

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

🧪 **Alpha — Phases 0–6, 8, the WITNESS proof layer, and Sovereign Rooms complete.** Usable end-to-end, but not yet independently audited; not ready for high-stakes production use.

| Phase | Goal | Status |
|-------|------|--------|
| 0 | Basic E2E encryption — X25519 + XChaCha20 | ✅ Complete (`v0.1.0`) |
| 1 | Stealth rotating addresses + TUI | ✅ Complete (`v0.3.0`) |
| 2 | Double Ratchet (forward secrecy) | ✅ Complete (`v0.4.3`) |
| 3 | Tor transport + sealed sender | ✅ Complete (`v0.6.0` + `v0.7.1`) |
| 4 | Federated relays + Pi Zero mesh nodes | ✅ Complete (`v0.7.0`) |
| 5 | Panic key (duress passphrase) + FMD privacy dial | ✅ Complete (`v0.8.0`; FMD dial wired end-to-end in `v0.11.0`) |
| 6 | Beacon — ephemeral discoverable handles | ✅ Complete (`v0.9.0`) |
| 8 | Group messaging (pairwise ratchets, ≤10 members) | ✅ Complete (`v0.11.0`) |
| 10 | WITNESS — verifiable proof of relay blindness | ✅ Complete (`v0.12.0`) |
| 11 | Sovereign Rooms — cryptographic chatrooms with no server-side representation, rotating stealth addresses, three security tiers (open/invite/dark), and optional federation sharding | ✅ Complete (`v0.13.0`) |

**Protocol upgrades** — cryptographic hardening that spans the whole stack rather than a single phase:

- **X3DH key agreement** ✅ `v0.14.0` — forward-secret handshake, eliminates deterministic bootstrap

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

> **Behavior change (v0.10.0):** `drift lock` now prompts for your unlock passphrase (it re-seals your identity *and* contacts into the vault before shredding the plaintext). In prior versions `drift lock` took no passphrase and left contacts on disk.

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
>
> ⚠️ **The panic key protects you while DRIFT is locked. While unlocked, your identity file is readable on disk — lock DRIFT (`drift lock` or close the app) before handing over a device.**
