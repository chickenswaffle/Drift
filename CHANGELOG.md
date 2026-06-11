# Changelog

All notable changes to DRIFT are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
DRIFT uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- **Header lock indicator** — a prominent boxed padlock left of the security
  pills that tracks the live channel state: 🔓 dim red (unsecured), 🔒 green
  (E2E + ratchet active), 🔒⁺ green with a cyan superscript (maximum security,
  once Tor lands in Phase 3).
- **Lock watermark** behind the message pane — a large, very dim block padlock
  on a layer beneath the messages; open when unsecured, closed when secured,
  closed-with-a-cross at maximum security. Never obscures message text.

### Changed
- Replaced the 👻 ghost on the STEALTH pill (and in the crypto ticker) with ⬡,
  matching the hexagon motif already used elsewhere in the UI.

---

## [0.4.4] — 2026-06-11

Delivery-reliability fix for two parties on the firehose.

### Fixed
- **Reliable two-party delivery on the firehose** — messages are no longer
  lost when one peer hits send a moment before the other's socket finishes
  subscribing, or opens the chat slightly later. The relay's old
  `delivered == 0` mailbox never fired (the sender is itself a live subscriber
  on the shared channel, so something was always "delivered"), so any message
  sent before the recipient connected vanished. Replaced it with a short
  (30 s), bounded, TTL'd replay buffer that the relay hands to each new
  subscriber. `/health` now reports `recent` instead of `queued`.
- **Idempotent receipt** — the session deduplicates incoming messages by
  one-time address, so a replayed envelope (late join / reconnect) is dropped
  before it reaches the ratchet rather than advancing past its key and
  surfacing as a spurious `InvalidTag`.

---

## [0.4.3] — 2026-06-11

Phase 2 polish: TUI visual upgrade, real scannable QR codes, and the
`DRIFT_CONFIG` two-identity isolation fix.

### Added
- **ASCII art DRIFT logo** in the header bar (`LogoBox` widget).
- **Security pill indicators** — always-visible E2E / RATCHET / STEALTH / TOR
  status chips; TOR is honestly dimmed until Phase 3.
- **Crypto event ticker** (`CryptoTicker`) — streams non-secret transport
  events (one-time address digest, ratchet step, key-erase) to a live feed.
- **Session info panel** (Ctrl+G) — displays contact name, safety number,
  your contact code, and a scannable QR; toggles without leaving the chat.
- **Real scannable QR codes** via the optional `segno` dependency
  (`pip install drift-messenger[qr]`); falls back to a decorative block-art
  QR when `segno` is not installed.
- **Message status glyphs** — outgoing lines show `◌` (sending) → `✓` (sent)
  → `✗` (failed) as the session worker confirms delivery.
- **Keyboard shortcut help bar** pinned at the bottom of the TUI.
- `segno>=1.6` added as an optional `[qr]` dependency in `pyproject.toml`.
- `DRIFT_CONFIG` environment variable respected everywhere; no path is
  hardcoded outside `drift/storage.py`.

### Changed
- Session info panel rebound from Ctrl+I (collides with Tab) to **Ctrl+G**
  for universal terminal compatibility.
- `VERSION` in `app.py` now derives from `drift.__version__` instead of a
  hardcoded string.

### Fixed
- `drift whoami` now uses `print()` instead of `console.print()` — Rich
  hard-wraps at 80 columns when piped, corrupting the 95-character contact
  code. Output is guaranteed single-line.

---

## [0.4.2] — 2026-06-11

Contact isolation, relay stability, and the lazy-initiator handshake fix.

### Added
- **`DRIFT_CONFIG` environment variable** — set to any directory to run a
  completely separate identity in that terminal (e.g.
  `DRIFT_CONFIG=/tmp/drift_alice drift chat bob`).

### Fixed
- **Per-identity contact storage** — contacts are now stored under
  `~/.config/drift/contacts/<scan_pub_b58>.json`, keyed by the identity's
  public scan key. Previously all identities on one machine shared a single
  `contacts.json`, causing cross-contamination.
- **Relay hot-reload dropped connections** — `uvicorn reload=True` restarts
  the server process on every file save, killing every live WebSocket.
  Autoreload is now opt-in via `DRIFT_RELAY_RELOAD=1`; the default is a
  stable long-running process.
- **Lazy ratchet initiator** — whoever sends the first message in a
  conversation now becomes the ratchet initiator on demand (`init_sender`).
  The previous scheme fixed the initiator by static spend-key comparison,
  which meant the key-order responder could not open a conversation —
  `send()` raised `RatchetError: no sending chain yet`.

---

## [0.4.1] — 2026-06-10

Storage refactor and UI foundation — the `drift.storage` model seam.

### Added
- `drift/storage.py` — single source of truth for on-disk state (identity +
  contacts). The CLI and TUI are now thin views over this module; neither
  re-implements file I/O or key handling directly.
- **Textual TUI foundation** (`drift/ui/app.py`) — component-tree chat UI
  with `DriftApp`, `Sidebar`, `MessagePane`, `InputBar`, and `PillButton`
  widgets; session runs in a `@work` background worker.

### Changed
- `drift/cli.py` refactored to delegate all persistence to `drift.storage`;
  no longer carries its own `CONFIG_DIR`.
- CLAUDE.md updated to reflect Phase 2 completion and Phase 3 as next.
- Version aligned to `0.4.x` across `pyproject.toml`, `drift/__init__.py`,
  and the TUI.

---

## [0.4.0] — 2026-06-10

**Phase 2 — Double Ratchet message encryption.**

### Added
- **Double Ratchet** (`drift/crypto/ratchet.py`) — per-message forward
  secrecy and post-compromise security. Every message uses a fresh symmetric
  key derived from a KDF chain; each DH ratchet step replaces the root secret
  with new randomness.
- `Header` — 40-byte serialisable ratchet header carried in every envelope
  alongside the stealth address fields.
- `init_sender` / `init_receiver` / `ratchet_encrypt` / `ratchet_decrypt` —
  public ratchet API consumed by `drift.transport.session`.
- Out-of-order message handling via a skipped-message-keys cache (bounded to
  prevent abuse).
- Integration tests covering bidirectional exchange, rotating addresses,
  `InvalidTag` on tampering, and the lazy-initiator regression.

### Changed
- `Session` now bootstraps the ratchet from a deterministic shared root
  secret (`HKDF(ECDH(spend_keys))`); no extra handshake round-trip.
- Envelopes carry a `hdr` field (Base64 ratchet header); the relay forwards
  it untouched.

---

## [0.3.0] — 2026-06-10

**Phase 1 — Textual TUI and storage model.**

### Added
- **Textual TUI** (`drift/ui/app.py`) — hacker-aesthetic terminal UI with
  sidebar contact list, message pane, input bar, and slash commands
  (`/clear`, `/add`, `/verify`, `/help`).
- `drift chat [name]` CLI command opens the TUI (or falls back to headless
  `--no-tui` mode for CI / TTY-less environments).
- `drift contacts`, `drift verify` CLI commands.
- `AddContactModal` and `HelpModal` overlays.

---

## [0.2.0] — 2026-06-10

**Phase 1 — Stealth rotating addresses.**

### Added
- **Stealth address derivation** (`drift/crypto/stealth.py`) — every message
  lands at a unique one-time address: `A_once = spend_point + SHA256(ECDH(r,
  scan_pub))·G`. Only the recipient, scanning with their private scan key, can
  detect it.
- Ed25519 group operations via libsodium (`crypto_core_ed25519_add`, Elligator
  map) — no custom curve math; `PyNaCl` bindings throughout.
- `scan_for_message` — constant-time recipient detection.
- `derive_one_time_address` — ephemeral keypair + stealth derivation for
  senders.
- Shared firehose channel `drift-stealth-v1`: all clients subscribe to one
  relay channel and scan locally, so the relay never learns the recipient.

### Changed
- Relay `/send` endpoint now carries optional `R` (ephemeral pub) and `addr`
  (one-time address) fields; forwarded opaquely.
- `Session` subscribes to `STEALTH_CHANNEL` instead of an identity-derived
  address.

---

## [0.1.0] — 2026-06-10

**Phase 0 — Basic E2E encryption, reference relay, and CLI.**

### Added
- **Cryptographic identity** (`drift/crypto/__init__.py`) — two X25519
  keypairs (scan + spend); identity serialised to JSON at `chmod 0o600`.
- **Contact codes** — `drift:<scan_pub_b58>.<spend_pub_b58>` encoding;
  `Identity.parse_contact_code` / `Identity.contact_code()`.
- **AEAD encryption** — `X25519 ECDH → HKDF-SHA256 → XChaCha20-Poly1305`;
  output is `nonce (24 bytes) || ciphertext+tag`. `InvalidTag` always
  propagates — tampered messages are rejected, never silently dropped.
- **Reference relay** (`relay/server.py`) — FastAPI + in-memory
  `defaultdict` mailbox; routes opaque ciphertext, never inspects content;
  24-hour message TTL.
- **CLI** (`drift/cli.py`) — `drift init`, `drift whoami`, `drift add`,
  `drift chat` via Typer.
- **Transport layer** (`drift/transport/`) — `RelayClient` WebSocket client;
  `Envelope` dataclass; `Session` context-manager API.
- Safety number derivation — short out-of-band verification phrase symmetric
  across both parties.
- Unit tests for AEAD, keypairs, HKDF, and identity round-trips.

---

[Unreleased]: https://github.com/chickenswaffle/Drift/compare/v0.4.4...HEAD
[0.4.4]: https://github.com/chickenswaffle/Drift/compare/v0.4.3...v0.4.4
[0.4.3]: https://github.com/chickenswaffle/Drift/compare/v0.4.2...v0.4.3
[0.4.2]: https://github.com/chickenswaffle/Drift/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/chickenswaffle/Drift/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/chickenswaffle/Drift/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/chickenswaffle/Drift/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/chickenswaffle/Drift/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/chickenswaffle/Drift/releases/tag/v0.1.0
