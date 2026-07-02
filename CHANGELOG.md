# Changelog

All notable changes to DRIFT are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
DRIFT uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Planned
- **Phase 13 — native mobile + shared Rust core (design).** The remaining
  Phase 13 scope (`docs/app-plan.md`): native iOS/Android apps and a shared Rust
  `drift-core` that the desktop app's Python sidecar is later swapped out for.
  The plan confronts the mobile threat-model tensions head-on — notably
  push-free-by-default delivery, to avoid leaking timing metadata to APNs/FCM.

### Added
- **Desktop app (`apps/desktop/`) — Phase 13c, first cut.** A native desktop
  client (Tauri + React) for people who don't live in a terminal. It adds **no
  cryptography**: a new `drift.sidecar` module exposes the existing, audited
  Python core (`drift.storage` + `drift.transport.Session`) over JSON-RPC on
  stdio, and the Tauri shell spawns it as a child, bridging the UI's `rpc` calls
  and streaming incoming messages back as events. Implemented end-to-end:
  identity onboarding, contact add/list, and live 1:1 chat over the relay (full
  X3DH + Double Ratchet + stealth addressing, verified by a two-party
  round-trip). Per `docs/app-plan.md`, the Python sidecar is a deliberate bridge
  — it reuses the proven crypto now and is later replaced by native `drift-core`
  under the same UI. Tor, the vault/duress flow, and groups/rooms are not yet
  wired into the GUI. See `apps/desktop/README.md`.
- **Self-contained installers + one-click download.** The sidecar is frozen with
  PyInstaller (`apps/desktop/sidecar/`) and bundled as a Tauri `externalBin`, so
  the installer needs **no system Python**. A `desktop-app` GitHub Actions
  workflow builds Windows `.exe`, macOS `.dmg` (unsigned), and Linux
  `.deb`/`.AppImage` on native runners (Windows can't be cross-compiled), and on
  a release uploads the Windows installer under a stable name
  (`DRIFT-Setup-Windows-x64.exe`). The DRIFT website gains a **"download for
  Windows"** button next to the Codespaces launcher pointing at the latest
  release. App icons are generated from `assets/icon-source.png`.
- **Raspberry Pi node image (`pi/`).** A flashable Raspberry Pi OS image that
  boots straight into a DRIFT mesh node (`relay.node`) reachable as a Tor onion
  service — no screen, keyboard, or manual install. Built with the official
  `pi-gen` builder: a custom `stage-drift` layers the node, an isolated venv,
  Tor with its control port enabled, and a dedicated login-less `drift-node`
  service account onto Raspberry Pi OS Lite (Bookworm/armhf — Pi Zero W through
  Pi 5). Headless configuration is read once from a `drift-node.conf` on the
  boot partition (bootstrap peer, port, optional Wi-Fi) by a one-shot
  first-boot service that then disables itself. `pi/build.sh` runs the whole
  build in Docker; a `pi-image` GitHub Actions workflow builds on demand and
  attaches the image to releases. Complements the existing
  `scripts/install-node.sh` (which sets a node up on an already-running Pi).
  See `pi/README.md`.

---

## [0.18.0] — 2026-07-01

**Nothing lingers — disappearing contact codes, disappearing messages, panic
lock, and a hardened shell.** The theme of this release: everything can
disappear — the code you share, the messages you send, the whole identity.
**No new cryptography**: every feature is a thin wrapper over the existing,
internally reviewed primitives (beacon, burn, vault, cover).

### Added
- **Disappearing contact codes (`driftinvite:`).** Mint a one-time code
  instead of sharing your permanent one: it resolves to your contact code
  exactly once, then burns, and dies on its own at the timer (10 m / 1 h /
  24 h dial) regardless. Under the hood an invite *is* a beacon whose handle
  is 128 random bits instead of a memorable name — same signing, same
  encryption, same relay endpoints, so a relay can't even tell an invite from
  a handle beacon. One-time works by the *redeemer* deleting the beacon on
  first resolve via the existing idempotent `DELETE /beacon/{hash}` (on a
  blind relay, deletion authority = resolution authority); expiry is the hard
  guarantee and one-time is best-effort — the UI says exactly that. New
  `drift.crypto.invite` + `drift.transport.beacon_http` (shared by CLI and
  sidecar); sidecar `invite_create` / `invite_resolve` / `invite_extinguish`;
  desktop InviteModal with live countdown and extinguish; the add-contact box
  transparently redeems `driftinvite:` codes with an unverified warning. Live
  invites are tracked in memory only — a disappearing code leaves no trace on
  disk. Relay `BEACON_MAX_TTL` is now env-overridable (default 24 h; clients
  still clamp guessable human handles to 10 minutes themselves).
- **Disappearing messages + burn, in the GUI.** The burn machinery
  (`crypto/burn.py`) finally has a surface: hover **burn** on your latest
  sent line, or **burn conversation** in the header (two-click confirm) — the
  peer's client verifies the tombstone's HMAC before deleting, and the UI
  erases only on that verified event. Plus a per-conversation **expiry dial**
  (off / 5 m / 1 h / 1 d): lines vanish from your screen on schedule, with an
  honesty banner — it's a client-side display timer, your peer keeps their
  copy unless you burn, and honest relays hold nothing past 30 seconds either
  way.
- **Panic lock.** Tray item + global **Ctrl/Cmd+Shift+L** (works with the
  window hidden): closes every session and shreds the plaintext working copy
  instantly, no passphrase. The sealed `vault.bin` persists — unlock restores
  it — at the deliberate cost of anything changed since the last unlock.
- **Verify-before-add.** "› check first" in the add-contact box shows the
  safety number a code would produce *before* saving anything.
- **Remove contact.** Hover `×` in the sidebar; closes any live session
  first. (`storage.remove_contact`, sidecar `contacts_remove`.)
- **Onboarding vault.** "Generate + seal with a passphrase" (with optional
  duress wipe/decoy) at first run — the sidecar's `init` always supported it;
  now the UI offers it.
- **Cover-traffic dial** in Settings (off / low / high): Poisson-scheduled
  decoy envelopes on newly opened 1:1 chats, so a wire-watcher can't tell
  when you're really talking.
- **The hermetic sidecar smoke test, for real.**
  `tests/integration/test_sidecar_e2e.py` spawns two actual
  `python -m drift.sidecar` subprocesses with isolated `$DRIFT_CONFIG` homes
  against the in-process relay and drives the wire protocol end to end:
  init → invite create/resolve/one-time/extinguish → chat_open →
  send/receive → burn-reaches-peer. Plus `tests/unit/test_sidecar.py`
  (dispatch, error hygiene, validation, locks) and `tests/unit/test_invite.py`.

### Security (desktop shell hardening)
- **CSP enabled** (was `null`): `script-src 'self'` with a stricter release
  overlay — the injection backstop a messenger rendering remote strings
  should have had. `style-src` keeps `'unsafe-inline'` for the accent inline
  styles; that's the documented trade.
- **RPC allowlist in the Rust shell**: the single `rpc` command now rejects
  any method not on the UI's list, so a compromised webview can't probe the
  sidecar surface.
- **Per-conversation locks in the sidecar**: requests dispatch as concurrent
  tasks, and close/rotate/leave could previously pull a session out from
  under an in-flight send on the same conversation.
- **Clipboard hygiene**: clicking a message line no longer silently copies
  its plaintext (explicit hover **copy** button instead), and an opt-in
  setting clears DRIFT-copied codes from the clipboard after 30 s (best
  effort, only if the clipboard still holds them).
- **Error hygiene**: unexpected sidecar exceptions return a generic message
  instead of their repr; contact/room names dropped from stderr logs (the
  shell inherits them); range/type validation on `fmd_set`, `group_create`,
  `init` duress mode.
- **Honest wording**: the sidecar's "audited core" comments now say
  "internally reviewed" — SECURITY.md is the source of truth (no independent
  audit yet). Unsigned-macOS note added to SECURITY.md + the desktop README.

### Changed
- Versions unified at 0.18.0 across the desktop app, Python package, and
  README (previously 0.17.0 / 0.15.5 / 0.15.0).

---

## [0.17.0] — 2026-07-01

**Desktop app — channels, rooms, groups, a CRT overhaul, and updates that
actually arrive.** A large desktop round on `apps/desktop/`. No protocol or wire
changes and **no new cryptography**: every feature is a thin wrapper over the
existing, audited core — the sidecar (`drift/sidecar.py`) now exposes the same
sovereign rooms / broadcast channels / groups the CLI and TUI already use. The
terminal/CRT aesthetic is kept and extended (no emoji anywhere).

### Added
- **Broadcast channels.** Create a channel and share its name as an invite code
  without contacting anyone first — you post, anyone with the name reads
  (`channel_create`/`channel_join`, a `kind="channel"` invite room). Subscribers
  are read-only; the composer says so.
- **Sovereign rooms.** Open / invite / dark tiers, invite tokens, and
  `driftroom:` descriptors for dark rooms (`room_create`/`room_join`/`room_invite`).
  A persistent honest banner states rooms are **encrypted but not forward-secret**
  and that sender tags are pseudonyms, not identities.
- **Rolling invite codes.** `room_rotate` re-derives a room/channel's key under a
  fresh, unguessable name — old subscribers and tokens are locked out until they
  get the new code. Because the relay is blind it cannot deny an individual
  reader, so rotation *is* the honest revoke; the manage sheet says this plainly.
- **Groups (≤10).** Create a forward-secret group from your contacts and truly
  **accept/deny** members via an explicit roster (`group_create`/`group_add`/
  `group_remove`, pairwise composition — DESIGN.md §11).
- **Vault self-serve.** Set a passphrase (and optional duress passphrase, wipe or
  decoy) from Settings to seal your identity and enable lock — no CLI required
  (`vault_create`).
- **Command palette (Ctrl/Cmd-K).** Fuzzy-jump to any conversation and run
  actions (new channel/room/group, lock, settings).
- **Restructured navigation.** A grouped, collapsible sidebar — channels, rooms,
  groups, contacts — each with its own create affordance and a per-conversation
  accent color, plus animated view transitions and a richer empty state.
- **Settings pane.** A panel (sidebar → `settings`) hosting verification, the FMD
  dial, the vault, notifications, and the updater.
- **Contact verification.** Generate and compare a contact's **safety number**
  (`safety_number` RPC) to confirm no one is in the middle — a core parity item
  from `docs/app-plan.md` §13c.
- **Vault lock / unlock (panic/duress).** Seal the identity behind its passphrase
  from the sidebar (`lock`) or the tray, and unseal it on a dedicated lock screen
  (`unlock`). The UI treats the real, decoy, and wipe passphrases **identically** —
  same text, same timing, same transition — so an onlooker cannot tell which slot
  opened. Shown only when a sealed vault exists.
- **Metadata-privacy (FMD) dial.** Set the false-positive detection rate
  (`fmd_get`/`fmd_set`) via an off / low / high control, with an honest note on
  the anonymity-set ↔ scanning-cost trade-off. Never changed silently.
- **Native desktop integration.** A system-tray icon (show/hide, lock vault,
  quit); native OS notifications on incoming messages when the window isn't
  focused — the alert names the **contact only, never the message**, consistent
  with the app-plan's push stance; window size/position persisted across
  restarts; and a single-instance guard so a second launch focuses the running
  window instead of spawning a second sidecar.
- **In-chat polish.** Per-message timestamps, live connection/handshake state in
  the chat header (from `chat_event`), and click-to-copy on any message.

### Changed
- **Auto-update is on by default.** The launch update check was opt-in *and off*,
  so fresh installs never learned about new versions. It is now opt-*out*: a quiet
  check runs on every launch unless the user turns it off. Nothing downloads or
  installs without an explicit click, and the cross-platform signing/publishing
  pipeline (`desktop-app.yml`, Windows/macOS/Linux) is unchanged.

---

## [0.15.0] — 2026-06-19

**UX polish, Lockdown Mode, and QR contact exchange.** A feature-and-experience
release — no protocol or wire changes, fully interoperable with `0.14.1`. Adds a
high-paranoia endpoint-hardening mode, in-terminal QR codes for sharing contact
codes, and a pass of first-run and in-chat UX improvements.

### Added
- **Lockdown Mode (Phase 12).** A toggleable high-paranoia TUI state — `Ctrl+K`
  engages it; `drift chat --lockdown` / `-L` starts pre-engaged. While engaged,
  every keystroke appends the real character to a private buffer and re-scrambles
  the *entire* on-screen input with fresh random `0x21–0x7E` noise (none matching
  the real character at any position), so a software keylogger or screen scraper
  sees only noise; the real buffer is never rendered. Scrollback history is wiped
  from memory and does not return on disengage, paste is ignored entirely, a bold-
  red `🔒 LOCKDOWN` pill appears in the header, and the pane border flashes red on
  engage. The crypto path is identical to normal mode. **Threat model:** defeats
  software keyloggers, screen scrapers, shoulder-surfing, and clipboard sniffers;
  hardware keyloggers and OS-level memory forensics are explicitly out of scope.
  (`drift/ui/app.py`, `drift/cli.py`.)
- **QR contact exchange.** `drift init` now renders a scannable QR of your contact
  code automatically after the identity and "what to do next" panels — first run
  is exactly when you need to share it. New `drift whoami --qr` flag appends a
  terminal QR after the existing pipe-safe one-line output. `drift add` now prints
  a styled confirmation echoing a recognisable code fragment (first 8 + last 4
  chars) on success. QR rendering uses a lazy `segno` import with a graceful
  fallback when the `[qr]` extra is not installed. (`drift/cli.py`,
  `drift/ui/app.py`.)
- **Interactive welcome screen.** The static Rich banner + `console.input` prompt
  is replaced by a lightweight Textual app: arrow keys (↑/↓, wrapping) and number
  keys (1–7) navigate, Enter or mouse click fires the selection, with a `▶` cursor
  and primary-color highlight. Non-interactive/pipe paths are unchanged.
- **Empty states, chat splash, and onboarding.** Richer sidebar empty-state hint
  with `[A]`/`[+]` hotkeys; a `_SplashPane` (wordmark + tagline + `[C]`/`[A]`/`[?]`
  action hints) on launch that clears when a conversation opens; and a numbered
  "what to do next" panel printed after `drift init`.

### Changed
- **Input bar & contact list affordances.** Input placeholder now reads
  `type a message · /help for commands · /beacon to go discoverable`; the active
  contact gets a `▌` cyan left-edge accent and a `●` primary-green unread dot.
- **System messages and send feedback.** `write_system` renders as a centered Rich
  rule (`─── text ───`) in dim text so infrastructure events read as infrastructure;
  sent-line glyphs now animate `⟳` (sending) → `✓` (ACK, primary green) / `✗`
  (failed, red).

### Fixed
- Added an explicit `strict=True` to a `zip()` in the obfuscated-input test to
  satisfy ruff `B905`. (`tests/unit/test_ui.py`.)

### Documentation
- Corrected the cover-traffic claims in `DESIGN.md` and the README defense list:
  cover traffic is **planned (Phase 4), not yet implemented**, and is no longer
  described as currently running.

---

## [0.14.1] — 2026-06-18

> ⚠ **v0.14.1 is a wire-breaking protocol change. Existing sessions with
> pre-v0.14.1 clients will fail to decrypt. Both parties must upgrade.**

**Audit findings M1–M3, M5 + lows L1, L3 — scan/spend privilege separation, burn
token replay, beacon hash, safety number scope.** A correctness-and-honesty
release closing the remaining medium audit findings and two straightforward lows.
No new primitives (project iron rule). See `docs/audit-2026-06.md` (Resolution
update — 2026-06-18) and the updated DESIGN.md.

> **Breaking / migration.** Two changes are wire/format breaking and require both
> peers on ≥ `0.14.1`:
> - **M1** changes the stealth message-key derivation, so a `0.14.1` client and an
>   older client can no longer exchange messages in either direction.
> - **M5** changes every safety number — **re-verify your contacts out of band**.

### Security
- **M1 — scan/spend privilege separation.** The stealth message key is now
  `HKDF(ECDH(scan, R) ‖ ECDH(spend, R))`. Detection (the one-time address) still
  uses the scan key alone, but decryption now requires the private *spend* key:
  `scan_for_message` returns a `ScanResult` (ownership confirmed + intermediate),
  and `derive_message_key_with_spend` completes the key. A scan-only device can
  filter mail without being able to read it. (`drift/crypto/stealth.py`,
  `drift/transport/session.py`.)
- **M2 — single-use burn tokens.** Tokens are now `nonce.timestamp.mac` with a
  fresh `os.urandom(16)` nonce and a MAC-bound timestamp. The relay rejects replayed
  nonces (bounded LRU) and tokens older than 300 s; clients re-verify the MAC and
  freshness. Closes the replay hole and the stable per-conversation fingerprint.
  (`drift/crypto/burn.py`, `relay/server.py`.)
- **M3 — relay-specific beacon lookup hash.** `lookup_hash` now binds the relay's
  long-term Ed25519 pubkey: `SHA256(prefix ‖ relay_pubkey ‖ handle)`. A table built
  against one relay is useless against another. Clients fetch the key from the new
  `GET /beacon/pubkey` (alias of `/witness/pubkey`). (`drift/crypto/beacon.py`,
  `relay/server.py`, `drift/cli.py`, `drift/ui/app.py`.)
- **M5 — safety number binds the spend key.** Now
  `SHA256("drift-safety-v1" ‖ sorted([scan‖spend, …]))` — a spend-key swap no longer
  passes `drift verify`. Invalidates existing safety numbers (re-verify).
  (`drift/storage.py`, `drift/cli.py`, `drift/ui/app.py`.)

### Changed
- **L1** — the per-session seen-address dedup is now bounded (cap 4096, oldest
  evicted) instead of an unbounded set. (`drift/transport/session.py`.)
- **L3** — `/send` caps the sealed blob at 64 KiB base64 (`413`) and validates that
  `addr` decodes to 32 bytes (`400`). (`relay/server.py`.)

### Deferred (documented in DESIGN.md, not fixed — need a format/migration change)
- **L2** — duress *wipe* is single-shot and distinguishable across repeated unlocks.
- **L4** — the Ed25519 signing key is derived from the spend key (coupled compromise).

---

## [0.14.0] — 2026-06-17

**X3DH asynchronous key agreement — closes the H3 audit residual, retires the
deterministic ratchet bootstrap.** The opening burst of every conversation is now
forward-secret against a *full* later key compromise (previously only the sender's
key was protected): the recipient publishes one-time prekeys it deletes after a
single use, so the very first message's keys can't be reconstructed once that
prekey is gone.

### Added — crypto (`drift/crypto/x3dh.py`)
- **`PreKeyBundle` / `PreKeyPrivates`** — the publishable bundle (Ed25519 identity
  key, X25519 spend pub, signed prekey + signature, one-time prekeys) and its
  vault-sealed private halves, with rotation (weekly signed prekey, 24h previous
  grace) and replenishment (top up when fewer than 3 one-time prekeys remain).
- **`x3dh_send` / `x3dh_receive` / `verify_prekey_bundle`** — the Signal X3DH
  handshake to spec: `DH1..DH4`, `master = HKDF(F ‖ DH…)`, the sender's ephemeral
  discarded immediately, the recipient's one-time prekey consumed once. Ed25519,
  X25519 and HKDF all from `cryptography` (the Ed25519 key loaded from the
  identity's existing signing seed, so there is still one identity key).

### Added — relay (`relay/server.py`)
- **`POST/GET /prekeys/{addr}`, `/replenish`, `/status`** — publish a bundle, fetch
  it while **atomically consuming one one-time prekey** (null when exhausted —
  weaker but valid X3DH), top up, and a non-consuming status. Bundles expire after
  30 days. The relay stores only public keys and learns nothing about content.

### Added — CLI (`drift/cli.py`)
- **`drift init`** now generates and publishes a prekey bundle (best-effort, with
  `--relay`); **`drift prekeys`** shows signed-prekey validity, one-time prekeys
  remaining on the relay, and last-replenished time (`--publish` to re-upload).

### Changed — session bootstrap (`drift/transport/session.py`)
- The 1:1 bootstrap runs X3DH when the peer has published a bundle: the initiator
  fetches and verifies it, runs the handshake, and seeds the Double Ratchet on the
  recipient's signed prekey; the X3DH header rides sealed inside opening-chain
  envelopes. The X3DH-receive path is **transactional** — a one-time prekey is
  burned and the ratchet swapped only after the bootstrap message authenticates,
  preserving the H1 anti-corruption guarantee.
- **Graceful degradation:** with no bundle on the relay (old client / expired) the
  sender falls back to the legacy deterministic bootstrap and the UI shows a
  one-time amber `⚠ legacy bootstrap` warning in the crypto ticker. Group and room
  sessions stay on the legacy bootstrap.

### Storage
- Prekey privates are sealed in the duress vault alongside the identity/contacts
  and shredded on lock/decoy/wipe (the H4 pattern).

### Docs
- `DESIGN.md` §4 rewritten around X3DH; `docs/audit-2026-06.md` records the H3
  residual as closed; `AGENTS.md` moves X3DH from backlog to complete.

---

## [0.12.0] — 2026-06-16

**Phase 10 — WITNESS: live cryptographic proof of relay blindness.** DRIFT's
privacy claims become mathematically verifiable rather than policy-based. Every
60 seconds a relay generates and signs a hash-chained *blindness certificate*
attesting what it provably cannot know about the traffic it just routed; if a
relay is ever compelled to start logging, the chain breaks and clients detect it.

### Added — relay (`relay/witness.py`, `relay/server.py`)
- **`WitnessCertificate`** — a signed (`drift-witness-v1`) document carrying the
  routed-message count, four structural zero-knowledge counters (sender /
  recipient identities, contents, linked conversations), a Merkle root over the
  period's routed envelopes, and the SHA256 of the previous certificate. Signed
  over canonical JSON; the chain hash covers the signature too.
- **`WitnessChain`** — seals one certificate per 60-second period into a bounded
  24-hour deque (1440 certs), rooted at a fixed genesis hash. Relay mints a
  long-term **Ed25519** identity on first start (`relay_identity.json`,
  `chmod 600`) that signs every certificate; corrupt/empty files fail loud rather
  than silently resetting the chain.
- **Merkle tree** — a direct ~20-line binary SHA256 construction (no library);
  empty periods commit to `SHA256("empty-period")`.
- **`verify_chain` / `verify_chain_report`** — independent checks for signature
  validity, hash-chain continuity, period coverage (missing-window detection),
  and the structural zero claim.
- **Endpoints** — `GET /witness/current`, `/witness/chain?limit=N`,
  `/witness/verify`, `/witness/pubkey` (base58 key + human fingerprint), and
  **`/cannot-see`** — a striking, terminal-styled HTML page rendering the current
  certificate in plain English (the page a surveillance request lands on).

### Added — client (`drift/cli.py`)
- **`drift witness verify <relay>`** — fetches and verifies a relay's full
  24-hour chain (every signature, chain continuity, period coverage), pinning the
  relay's published key; prints a clear pass/fail report that pinpoints a gap or
  reset.
- **`drift witness subscribe <relay>`** — the canary watcher: a dot per good
  period, a loud `⚠ CHAIN BREAK DETECTED` the instant the chain breaks.

### Docs
- **`docs/witness.md`** — what WITNESS proves and doesn't, the compelled-relay
  threat model, the Merkle construction, how to verify with just `openssl`/
  `hashlib`, and a precise "what this means for legal demands" section.
- **DESIGN.md** §6 gains a WITNESS subsection; README gains a "Verifiable privacy"
  section.

### Crypto note
Ed25519 (`cryptography`) for relay signing, SHA256 (`hashlib`) for the Merkle
tree and chain hashes. No new primitives.

---

## [0.11.0] — 2026-06-15

A combined release with one headline feature and two riders. **Phase 8 — group
messaging** lands; the **FMD privacy dial** is wired end to end (closes audit
M4); and a **TUI polish** pass lifts the terminal UI. Full suite: **384 passing**
(ruff + mypy clean).

### Added — Phase 8: group messaging (pairwise composition, ≤10 members)
A group is not a new cryptographic construction: every member keeps an
independent pairwise Double Ratchet with every other member, a message is
encrypted once per recipient and sent to that recipient's own stealth address,
and the group id is encrypted *inside* the payload — so the relay sees N-1
unlinkable envelopes, never a "group". Tradeoffs (O(n) bandwidth → Phase 8b
sender-keys, eventual-consistency membership, forward-but-not-retroactive
removal) are documented in DESIGN.md §11.
- **`drift.crypto.groups`** — `GroupId` (random, member-independent), `GroupState`,
  `ContactInfo`, capacity-checked `create_group`/`add_member`/`remove_member`,
  Ed25519-signed `MembershipChange` (reuses the identity signing key, no new
  primitive), and the group-payload frame that rides inside the ratchet.
- **`GroupSession`** — one firehose subscription, one pairwise channel per member,
  `send_to_group` (N-1 stealth envelopes), and fan-in receive by trial-decryption
  across members' ratchets (safe: `ratchet_decrypt` rolls back on miss). In-band
  `add_member`/`remove_member` announce signed membership changes.
- **CLI** `drift group create|add|remove|list`; `drift chat <name>` routes to a
  group when the name is one. **UI** prefixes each group message with its sender,
  shows membership changes as system lines, and a `⬡ GROUP · N members` indicator.
- Group state is sealed into the duress vault like contacts (audit H4) — a locked
  device holds no plaintext group membership.

### Added — FMD (Fuzzy Message Detection) privacy dial, wired end to end (closes audit M4)
`drift privacy --fmd-rate` previously set a value that touched nothing on the
wire. FMD is now real, **off by default** (wire format + contact code byte-for-byte
unchanged when off).
- Detection key rides as an optional 3rd contact-code segment
  `drift:<scan>.<spend>.<fmd>`, **derived deterministically from the spend key**
  (`derive_fmd_key` / `Identity.fmd_keypair`) — no new stored secret to vault-seal.
- Senders attach an `fmd_flag` bound to the one-time stealth address only for FMD
  recipients; the relay can opt into pre-filtering (forwards matches + the scheme's
  `2^-k` false positives; unflagged traffic fails open; classic subscribers get the
  whole firehose). DESIGN.md §5 states the cost plainly: the relay learns a
  *probabilistic, p-sized* guess it cannot resolve to true matches without the key.

### Added — TUI polish
- Fuzzy command palette (`Ctrl+P`), live relay-latency sparkline, numeric `1–9`
  contact jump, rounded titled panels with live status subtitles, an animated Tor
  bootstrap spinner, and contact accent bars.

### Changed
- Extracted the per-peer crypto (Double Ratchet + sealed-sender bootstrap) into a
  shared **`PairwiseRatchet`**, composed by both `Session` (one peer) and
  `GroupSession` (one per member), so the audited bootstrap logic lives in one
  place.
- `parse_contact_code` accepts the optional FMD segment (2-segment codes still
  valid); DESIGN.md gains the Phase 8 (§11) and current-state FMD (§5) sections.

---

## [0.10.0] — 2026-06-12

Security hardening: the four high-severity findings from the June 2026 audit
(`docs/audit-2026-06.md`), each fixed with a regression test. Full suite: 336
passing.

### Fixed
- **H1 — ratchet state corruption from forged messages.** `ratchet_decrypt` is
  now transactional: it runs on a snapshot and commits the advanced root/chain
  keys and DH-ratchet step only on a successful authenticated decrypt. A forged
  or tampered message (including one naming a fresh DH key, which previously
  turned the ratchet before the body was authenticated and permanently desynced
  the session) now leaves the ratchet byte-for-byte unchanged.
- **H2 — unauthenticated `/burn` denial-of-service.** A conversation-scope burn
  no longer makes the relay wipe the shared firehose replay buffer (an
  unauthenticated, channel-wide DoS). The relay deletes only the single blob
  whose one-time address is explicitly named; conversation erasure is delivered
  end-to-end via the token-verified tombstone. Documented in DESIGN.md "Burn
  requests".
- **H3 — forward-secrecy gap in the ratchet bootstrap.** The initiator folds a
  fresh single-use ephemeral (private half discarded immediately, never derived
  from the long-term key) into the bootstrap root, carried to the peer in the
  sealed envelope of every bootstrap-chain message. The opening burst is now
  forward-secret against compromise of the sender's long-term key. The
  recipient-key residual (fundamental without interactive prekeys/X3DH) is
  documented exactly in DESIGN.md §4.
- **H4 — duress/decoy deniability defeated by a plaintext contact list.**
  Contacts are now sealed in the vault alongside the identity. `drift lock` takes
  the passphrase, re-seals the identity + contacts (preserving the duress slot),
  and shreds the plaintext identity *and* contacts files; a decoy unlock shreds
  any prior identity's contacts, so the real contact graph leaves no trace on
  disk. `PAYLOAD_SIZE` raised to 16 KiB so a real address book fits within the
  indistinguishable fixed-length padding. DESIGN.md §8 documents the new
  guarantee and remaining honest limits.

### Changed
- `drift lock` now requires your unlock passphrase (prompted if omitted) because
  it re-seals the current identity + contacts into the vault before shredding the
  plaintext; it refuses without shredding on a wrong passphrase.

---

## [0.5.0] — 2026-06-11

Burn requests: signed message and conversation erasure across relay and both clients.

### Added
- **Burn requests** — a signed control message that erases messages from the
  relay buffer and both clients.
  - `drift/crypto/burn.py` — HMAC-SHA256 token generation and constant-time
    verification; tokens are bound to the conversation's static ECDH output
    via HKDF with `info=b"drift-burn-v1"` (domain-separated from ratchet keys).
  - `POST /burn` relay endpoint — validates token shape (64 hex chars), deletes
    matching blobs from the replay buffer, and broadcasts a tombstone (including
    token) to live subscribers so both clients update immediately.  Server logs
    record only `"burn request processed"` — no token or content details.
  - `Session.burn_conversation()` / `Session.burn_last_message()` — initiate a
    burn from the transport layer; the relay echoes the tombstone back to all
    subscribers.  Incoming tombstones are verified before the `on_burn` hook
    fires; unverified tombstones are silently dropped.
  - TUI slash commands: `/burn` (full conversation), `/burn last` (last sent
    message), `/burn Nm` / `/burn Ns` (scheduled auto-burn), `/burn cancel`.
  - Help modal updated with burn command reference and the honest UX note:
    *"Burn requests are best-effort — a non-compliant client can ignore them."*
  - 29 new unit tests covering token generation/verification, relay validation,
    relay buffer mutation, and all TUI burn paths.
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
- AGENTS.md updated to reflect Phase 2 completion and Phase 3 as next.
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

[Unreleased]: https://github.com/chickenswaffle/Drift/compare/v0.10.0...HEAD
[0.10.0]: https://github.com/chickenswaffle/Drift/compare/v0.5.0...v0.10.0
[0.5.0]: https://github.com/chickenswaffle/Drift/compare/v0.4.4...v0.5.0
[0.4.4]: https://github.com/chickenswaffle/Drift/compare/v0.4.3...v0.4.4
[0.4.3]: https://github.com/chickenswaffle/Drift/compare/v0.4.2...v0.4.3
[0.4.2]: https://github.com/chickenswaffle/Drift/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/chickenswaffle/Drift/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/chickenswaffle/Drift/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/chickenswaffle/Drift/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/chickenswaffle/Drift/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/chickenswaffle/Drift/releases/tag/v0.1.0
