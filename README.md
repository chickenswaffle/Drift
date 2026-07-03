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
[![Version](https://img.shields.io/badge/version-v0.20.0-blue)](https://github.com/chickenswaffle/Drift/releases/tag/v0.20.0)
[![Protocol](https://img.shields.io/badge/protocol-DRIFT--P%2F1%20draft-brightgreen)](PROTOCOL.md) [![Site](https://img.shields.io/badge/site-driftmsg.io-00aa2a?style=flat&labelColor=0a0a0a)](https://chickenswaffle.github.io/DRIFT-Site/)

> A terminal-first, end-to-end encrypted messenger with rotating, unlinkable receiving addresses and a hybrid post-quantum handshake.

No phone numbers. No accounts. No central authority that can read or hand over your messages. Session setup is **hybrid post-quantum by default** (ML-KEM-768 + X25519, PQXDH-style) — traffic recorded today can't be decrypted by a future quantum computer.

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

## The Drift Protocol

The wire protocol has a name and a versioned specification: **DRIFT-P/1**, in
[`PROTOCOL.md`](PROTOCOL.md) — identity, stealth addressing, sealed sender,
the envelope format, X3DH + Double Ratchet framing, beacons/invites, burns,
FMD, rooms/groups, and WITNESS, each with its wire layout and its honest
limits. If you want to build a compatible client or relay, start there.

**Open-core stance:** the protocol, this client, and the reference relay are
MIT and stay that way — a security tool you can't read is a security tool you
can't trust. Anything we ever charge for will live *above* the protocol
(operated relays, monitoring, enterprise tooling), never inside it. Details:
[`docs/open-core.md`](docs/open-core.md).

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

Want to attack it yourself? The **Gauntlet** spins up a relay in-process and
fires 11 adversarial probes at DRIFT's privacy and crypto invariants (relay
blindness, stealth unlinkability, forward secrecy, sealed sender, the WITNESS
chain, panic isolation, PQ downgrade resistance, …) with a live pass/fail
report:

```bash
python scripts/gauntlet.py
```

---

## Security engineering

Claims are cheap; gates are not. Every push runs:

- **657 unit tests** plus the **11-probe adversarial gauntlet** — the red-team
  suite is a CI job, so a privacy invariant can't regress silently.
- **Supply-chain audits** — `pip-audit` (Python) and `cargo audit` (RustSec)
  fail the build on known-vulnerable dependency versions.
- **Cross-implementation test vectors** — the Rust core (`drift-core/`) must
  reproduce the Python reference **bit-for-bit** against committed vectors
  (`tests/vectors/`); both sides assert in CI. The Rust core zeroizes all
  secret material on drop.
- **No new cryptography, ever** — X25519/Ed25519/XChaCha20-Poly1305/HKDF/
  Argon2id/ML-KEM-768 all come from vetted libraries (`cryptography`, PyNaCl/
  libsodium, the dalek/RustCrypto crates). The relay's open endpoints are
  rate-limited against floods and prekey-pool draining without logging a
  single client IP.

---

## What DRIFT defends against

- Passive network surveillance (ISP, nation-state wire-tapping)
- A malicious, compromised, or subpoenaed relay server
- Later device or key theft (forward secrecy + post-compromise security)
- **"Harvest now, decrypt later"** — the handshake is hybrid ML-KEM-768 + X25519, so recorded ciphertext stays sealed even against a future quantum computer (the ongoing ratchet remains classical — same honest tradeoff as Signal's PQXDH)
- Traffic analysis of *who talks to whom* — sealed sender + onion transport hide the social graph
- Traffic analysis of *when and how much you send* — as of v0.15.0 (PR #15), **cover traffic** masks activity with Poisson-scheduled dummy envelopes and a uniform on-the-wire message size, on an off/low/high dial (1:1 chats today; group/room cover is future work)
- Infrastructure takedown — no single server to kill

## What DRIFT does NOT defend against

- **A compromised endpoint.** Malware on your machine reads the screen. No messenger fixes this.
- **A truly global passive adversary.** We raise the cost enormously; we don't claim to fully solve it.
- **User error** — sharing keys carelessly, screenshotting chats, getting phished.

Being precise here is what separates a serious tool from snake oil.

---

## Project status

🧪 **Alpha — Phases 0–6, 8, the WITNESS proof layer, Sovereign Rooms, and Lockdown Mode complete.** Usable end-to-end, but not yet independently audited; not ready for high-stakes production use.

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
| 12 | Lockdown Mode — endpoint hardening against software keyloggers, screen scrapers, and shoulder-surfing | ✅ Complete (`v0.15.0`) |
| 13 | GUI app — desktop (Tauri) shipped; native iOS/Android + shared Rust core designed | 🚧 Desktop shipped (`v0.17.0`+, [`apps/desktop/`](apps/desktop/)) — installers on the [releases page](https://github.com/chickenswaffle/Drift/releases/latest); mobile designed in [`docs/app-plan.md`](docs/app-plan.md) |

**Protocol upgrades** — cryptographic hardening that spans the whole stack rather than a single phase:

- **X3DH key agreement** ✅ `v0.14.0` — forward-secret handshake, eliminates deterministic bootstrap
- **The Drift Protocol spec** ✅ `v0.20.0` — the wire protocol, versioned as [DRIFT-P/1](PROTOCOL.md)
- **Hybrid post-quantum handshake** ✅ — PQXDH-style ML-KEM-768 + X25519, on by default, unstrippable by design ([PROTOCOL.md §5](PROTOCOL.md))

**Recent additions** (`v0.20.0` — desktop):

- **Security score** — a clickable `SEC n/N` posture chip; every red item states its threat and most carry a one-click fix.
- **Lockdown Mode (desktop)** — OS-level screen-capture shield (macOS/Windows), blur-on-unfocus, per-chat no-copy, clipboard guard.
- **WITNESS live canary** — the relay's blindness chain re-verified in-app every 60 s; a break goes loud.
- **Cipher X-ray** — any message's *actual* wire envelope (one-time address, opaque blob) next to its decrypted layers.
- **Tor, bundled** — desktop routes over Tor with no system tor installed; safety-number randomart; disappearing invite codes; remote burn.

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

Full setup guide: [`docs/getting-started.md`](docs/getting-started.md) ·
Run your own relay: [`docs/relay-setup.md`](docs/relay-setup.md)

---

## Architecture

```
drift/
├── drift/
│   ├── crypto/        # keys, stealth addresses, AEAD, ratchet, X3DH+ML-KEM
│   ├── transport/     # WebSocket client, Tor bootstrap
│   ├── relay/         # relay protocol client
│   └── ui/            # Textual TUI
├── relay/             # reference relay server (FastAPI, RAM-only by design)
├── drift-core/        # shared Rust core — bit-for-bit parity with Python
├── apps/desktop/      # Tauri + React desktop app
├── docs/              # protocol specs, threat model, contributor guide
└── tests/             # unit tests + cross-implementation vectors
```

---

## Contributing

Read [`CONTRIBUTING.md`](CONTRIBUTING.md) before opening a PR.

The iron rule: **never implement crypto primitives from scratch.** We compose vetted libraries (`PyNaCl`, `cryptography`) — we do not reimplement Curve25519 by hand. PRs that roll their own crypto will be closed.

Security issues: see [`SECURITY.md`](SECURITY.md).

---

## License

**Code:** MIT — see [`LICENSE`](LICENSE). Free forever, by design: a security
tool you can't read is a security tool you can't trust.

**Names:** "DRIFT", "Drift Protocol", and the wordmark are trademarks of the
project — the code license does not cover them. Forks are welcome; calling a
fork "DRIFT" is not. See [`TRADEMARKS.md`](TRADEMARKS.md).

**Open-core:** anything we ever charge for lives *above* the protocol
(operated relays, monitoring, enterprise tooling) in separate repositories —
never inside this one. See [`docs/open-core.md`](docs/open-core.md).

---

> ⚠️ **Security notice:** DRIFT has not been independently audited. Do not use it for anything where your safety depends on it until a formal audit has been completed and published. We will announce audit results here.
>
> ⚠️ **The panic key protects you while DRIFT is locked. While unlocked, your identity file is readable on disk — lock DRIFT (`drift lock` or close the app) before handing over a device.**
