# DRIFT app plan — Phase 13 (native mobile + desktop on a shared Rust core)

**Status:** 📋 Planned — design only. No code in this phase yet.
**Form factor:** iOS + Android (native) and Windows/macOS/Linux desktop (Tauri).
**Core strategy:** one **shared Rust core** (`drift-core`), the protocol/crypto
implemented once and exposed to every UI via FFI. The Python package remains the
**reference implementation** and the source of conformance test vectors.

> This document is a *plan*, not a spec. It exists to make the big decisions
> explicit and to confront — honestly, up front — the places where a phone app
> is in genuine tension with DRIFT's metadata-privacy threat model (§1 of
> `DESIGN.md`). A mobile messenger that pretends those tensions don't exist is
> exactly the snake oil this project refuses to be.

---

## 1. Goal & non-goals

**Goal.** Make DRIFT usable by people who do not live in a terminal, on the
devices they actually carry, **without weakening the protocol's guarantees** —
or, where a platform forces a trade-off, surfacing that trade-off as an explicit,
user-visible choice rather than a silent downgrade.

**In scope (v1 of the app):**

- 1:1 chat with the full pairwise guarantees: X3DH handshake, Double Ratchet
  forward secrecy, rotating stealth addresses, sealed sender, Tor transport.
- Local identity generation, contact add/verify (safety numbers, QR), the
  panic/duress vault, and a mobile-appropriate Lockdown equivalent.
- Desktop reaches parity with the TUI feature set first; mobile follows.

**Explicitly NOT in scope for v1 (deferred, named so we don't pretend):**

- Groups, Sovereign Rooms, Beacon — land after 1:1 is solid on all targets.
- Multi-device sync (still Phase 7, still skipped — the app is single-device per
  identity until that phase is actually designed).
- Push notifications that compromise metadata privacy. See §5.2 — this is the
  hardest problem and v1 ships the honest, lower-convenience answer.
- An app-store "anonymous accounts" story beyond what the protocol already does.

---

## 2. Why a shared Rust core (decision record)

DESIGN.md §9 already names Rust as the hardened path (`x25519-dalek`,
`ed25519-dalek`, `chacha20poly1305`, `arti`). Three options were weighed:

| Option | Verdict |
|--------|---------|
| **Shared Rust core + FFI** | ✅ Chosen. Protocol/crypto written once, one audited surface, native UIs. Desktop (Tauri) links it directly; mobile binds via UniFFI. Biggest upfront lift, lowest long-term divergence risk. |
| Reuse Python on-device (Briefcase/BeeWare/Chaquopy) | ❌ Ships CPython on the phone — heavy, poor iOS background story, sluggish stealth scanning on low-end hardware. |
| Reimplement per platform (Swift + Kotlin) | ❌ Three copies of the protocol (Python + Swift + Kotlin) kept in lockstep by hand — the most likely way to introduce a subtle, fatal divergence. |

**The iron rule still holds inside the core.** `drift-core` *composes* vetted
crates; it does not hand-roll curve math. The one delicate spot is stealth
addressing, which needs ed25519 group operations (point add, Elligator) that
`x25519-dalek` doesn't expose — handled with `curve25519-dalek`'s group API, the
direct analogue of the libsodium `crypto_core_ed25519_*` calls the Python core
uses today. No new primitives; same construction, different binding.

---

## 3. Architecture

```
drift/                      ← existing Python package — stays the REFERENCE impl
                              (+ source of cross-impl test vectors)

drift-core/                 ← NEW: Rust workspace, the one protocol/crypto impl
  crypto/                     keypairs, X25519 ECDH, HKDF, XChaCha20-Poly1305,
                              Ed25519, Double Ratchet, X3DH, stealth, FMD,
                              sealed sender, burn tokens, panic/duress vault
  transport/                  relay WebSocket client, federation, Arti (Tor)
  storage/                    encrypted identity + contact vault (platform
                              keystore-wrapped)
  ffi/                        UniFFI interface (.udl) → Swift + Kotlin bindings
                              (Tauri links the crate natively, no UniFFI needed)

apps/
  desktop/   (Tauri)          Rust shell + web UI; links drift-core directly
  ios/       (Swift/SwiftUI)  imports drift-core.xcframework via UniFFI
  android/   (Kotlin/Compose) imports drift-core .aar via UniFFI
```

**Layering mirrors the Python rule** (`crypto` knows nothing about networks;
`transport` knows nothing about message content; UI knows nothing about crypto).
The UI layers talk only to a small, audited `drift-core` API surface — roughly
`Identity`, `Contact`, `Session`, `Chat`, `Vault` — never to raw key material.

### 3.1 Crypto mapping (Python → Rust crate)

| DRIFT primitive (Python module) | Rust crate |
|---|---|
| X25519 ECDH (`crypto/__init__.py`) | `x25519-dalek` |
| Ed25519 sign/verify | `ed25519-dalek` |
| XChaCha20-Poly1305 AEAD | `chacha20poly1305` (XChaCha variant) |
| HKDF-SHA256 | `hkdf` + `sha2` |
| Argon2id vault KDF (`crypto/panic.py`) | `argon2` |
| Double Ratchet (`crypto/ratchet.py`) | composed on the above (no off-the-shelf crate; port the construction) |
| X3DH (`crypto/x3dh.py`) | composed on `x25519-dalek` + `hkdf` |
| Stealth addresses (`crypto/stealth.py`) | `curve25519-dalek` group ops (point add, Elligator) |
| Tor transport (`transport/tor.py`) | `arti-client` (embedded Tor, daemonless) |

---

## 4. The big platform tensions (confront these first)

These are the parts where "just port it" is a lie. Each is called out with the
threat-model cost and the v1 stance.

### 4.1 Tor on mobile
iOS/Android forbid a long-lived background tor daemon the way a Pi has one.
**Stance:** embed **Arti** (`arti-client`) inside `drift-core` — daemonless,
in-process, the same library DESIGN.md already earmarks. Bootstrap is slower and
battery-costlier than on desktop; surface a clear "connecting over Tor" state
rather than hiding it.

### 4.2 Push notifications — the hardest problem ⚠️
This is the central tension and deserves bluntness. DRIFT's whole point is that
**no third party learns who talks to whom or when.** Apple Push Notification
service (APNs) and Firebase Cloud Messaging (FCM) are exactly such third parties,
and on iOS especially, reliable background delivery effectively requires them.

There is **no way** to get Signal-grade "instant notification while the app is
closed" without leaking *some* timing/metadata to Apple/Google. We will not
pretend otherwise. The plan:

- **v1 (honest default):** **no APNs/FCM.** Delivery happens while the app is
  foregrounded or during OS-granted background windows (BackgroundTasks /
  WorkManager). Messages are not lost — the relay's replay buffer and the node
  mesh hold ciphertext briefly — but notifications are **best-effort, delayed**,
  not instant. The UI states this plainly.
- **Opt-in later (v2, never default):** a *metadata-minimising* push path —
  e.g. content-free "you have mail" wakeups via a privacy-preserving relay, or
  integration with a self-hosted UnifiedPush distributor on Android. Each option
  is documented with exactly what it reveals before a user turns it on.

This single decision is the difference between "a private messenger" and "a
messenger that quietly tells Apple when you're being contacted." It ships honest.

### 4.3 Stealth scanning on battery
Scanning rotating addresses is continuous work; on a phone that's a battery and
wakeup cost. **Stance:** an adaptive scan cadence (active when foregrounded,
backed off in OS background windows), reusing the FMD privacy dial
(`crypto/fmd.py`) so the false-positive/efficiency trade-off stays a *user*
choice, not a silent one. Never widen FMD's rate to save battery without consent
— that erodes the anonymity set (see the iron rule in AGENTS.md).

### 4.4 Key storage
**Stance:** the encrypted identity/contact vault stays the unit of storage; its
*unlock key* is wrapped by the platform keystore — iOS Keychain / Secure Enclave,
Android Keystore (StrongBox where available), OS keychain on desktop. Biometric
gating optional. The on-disk vault format stays compatible with the Python
reference (same Argon2id + two-slot panic construction) so a vault is portable
and the duress guarantee is preserved.

### 4.5 Panic/duress vault & Lockdown on mobile
The duress passphrase (`crypto/panic.py`) ports as-is into `drift-core` — it is
pure crypto. The **UI affordance** differs: a phone needs a duress *unlock*
gesture and must respect the same constant-work, no-tell-on-disk property. The
TUI "Lockdown Mode" (Phase 12) becomes a mobile equivalent: screenshot/recording
blocking (`FLAG_SECURE` on Android, screenshot suppression on iOS), app-switcher
preview masking, paste suppression. **Same threat model, same honest limits** —
defeats shoulder-surfing and casual capture, not a compromised OS.

### 4.6 Cover traffic
Cover traffic (`crypto/cover.py`, v0.15.0) is battery-hostile if run at desktop
intensity on a phone. **Stance:** keep the off/low/high dial, default lower on
mobile, and document the battery↔metadata trade-off at each setting.

---

## 5. Sub-phase breakdown

Each sub-phase is independently shippable and has a hard exit criterion. Nothing
proceeds until the previous parity gate is green against the Python reference.

| Sub-phase | Deliverable | Exit criterion |
|---|---|---|
| **13a — core extraction** | `drift-core` Rust workspace: crypto + transport ported, no UI, no FFI | Cross-impl test vectors pass: Rust core and Python reference interoperate on the wire (encrypt/decrypt, X3DH, ratchet, stealth detect) |
| **13b — FFI surface** | UniFFI `.udl` + generated Swift/Kotlin bindings; Tauri crate link | A headless smoke app on each platform completes init + send + receive against a live relay |
| **13c — desktop (Tauri)** | Full desktop GUI to TUI parity | A desktop↔TUI conversation works end-to-end incl. verify, panic, lockdown |
| **13d — Android** | Kotlin/Compose app, 1:1 chat, vault in Keystore, Arti transport | Android↔desktop conversation over Tor; background-window delivery works |
| **13e — iOS** | Swift/SwiftUI app, 1:1 chat, vault in Keychain/SE, Arti transport | iOS↔Android conversation over Tor; BackgroundTasks delivery works |
| **13f — hardening pass** | Mobile Lockdown, duress UX, cover-traffic dial, accessibility, store-readiness review | Gauntlet (`scripts/gauntlet.py`) extended with app-core probes; all green |

Groups/Rooms/Beacon on the app are a **Phase 13g+ backlog**, explicitly after
1:1 is proven on every target.

---

## 6. Cross-implementation parity & testing

The single largest risk of a second implementation is **silent divergence** from
the Python reference. Mitigations, in priority order:

1. **Shared test vectors.** Export deterministic vectors from the Python core
   (handshake transcripts, ratchet chains, stealth address derivations, vault
   blobs) and assert the Rust core reproduces them bit-for-bit. These live in the
   repo and run in CI for *both* implementations.
2. **Wire interop tests.** A CI job runs the Python relay and exchanges real
   messages Python↔Rust in both directions.
3. **Extend the Gauntlet.** `scripts/gauntlet.py` already fires 10 adversarial
   probes at the invariants; add core-level probes the Rust build must also pass
   (relay blindness, stealth unlinkability, forward secrecy, sealed-sender
   opacity, panic isolation).
4. **No crypto merges without review.** Same rule as today: PRs that hand-roll
   primitives in Rust are closed.

---

## 7. Security review gates

- `drift-core` gets its own audit pass before any app ships to a store, on the
  same standard as `docs/audit-2026-06.md`.
- Threat-model deltas introduced by the platforms (push, keystore, background
  execution, screenshot surfaces) are documented in DESIGN.md *before* the
  sub-phase that introduces them, not after.
- The README security notice ("not independently audited") extends verbatim to
  the apps until a formal app-core audit is published.

---

## 8. The honesty section (carry into the app's store listing)

What the app **preserves** from the threat model: end-to-end content secrecy,
forward secrecy, rotating-address recipient unlinkability, sealed sender, Tor
transport, the panic/duress vault, no accounts, no phone numbers.

What a phone app **erodes or complicates**, stated plainly:

- **Notifications cost metadata.** Instant background push means trusting
  Apple/Google with timing. v1 chooses delayed, push-free delivery to avoid
  that; users who opt into convenience later will see exactly what it reveals.
- **The endpoint is still the weakest link** — more so on mobile, where the OS,
  the keyboard, and the app store are all third parties. No protocol fixes a
  compromised phone.
- **App-store presence is itself metadata.** Installing DRIFT is observable;
  that's a different exposure than `pip install` on a laptop. Worth saying.

Build it honest, build it in the open — and let "no notification leak by default"
be the thing that distinguishes DRIFT's app from every other "private" messenger.

---

## 9. Decisions

**Decided (with the maintainer):**

- **Desktop ships first, via a Python-sidecar bridge — not a Rust-core port.**
  Rather than block the desktop GUI on 13a (the full Rust core), the desktop app
  (`apps/desktop/`) is a Tauri + React shell over a **Python sidecar**
  (`drift.sidecar`, JSON-RPC on stdio) that wraps the existing audited
  `drift.storage` + `drift.transport.Session`. This ships a working app on the
  proven crypto now; the sidecar is later swapped for native `drift-core` under
  the *same* UI, with no UI rewrite. Trade-off accepted: the installer bundles a
  Python runtime until that swap. This re-orders §5 — 13c (desktop) lands before
  13a (core extraction); 13a/13b become prerequisites for the *mobile* targets,
  where shipping CPython is not acceptable (see §2).
- **Desktop UI stack:** React + Vite + TypeScript inside Tauri.
- **Repo layout:** monorepo — `apps/desktop/` lives in this repo beside `drift/`
  (and `drift-core/` will too), for lockstep CI.
- **Form factor:** desktop (Windows/Linux + unsigned macOS `.dmg`) and Android
  first; signed iOS later (needs the paid Apple Developer Program).

**Decided since (13a):**

- **Vector format & location — DECIDED: JSON under `tests/vectors/`, shared by
  both impls.** `scripts/export_vectors.py` exports them from the Python
  reference; `tests/unit/test_vectors.py` (Python) and
  `drift-core/crypto/tests/vectors.rs` (Rust) both assert conformance, and both
  run in CI. Vectors are the compatibility contract — regenerated only on a
  deliberate, reviewed protocol change.

**Still open (needed before the FFI surface / the mobile targets):**

- **Minimum OS targets** — iOS 16+/Android 9+ assumed for Secure Enclave /
  StrongBox and BackgroundTasks; confirm.
- **UnifiedPush** as the Android opt-in push path (v2) — research spike needed.
- **Stealth/FMD Elligator parity in Rust** — porting `stealth`/`fmd` needs
  libsodium's exact `crypto_core_ed25519_from_uniform` (Elligator 2 + cofactor
  clear); the plan is to bind libsodium (`libsodium-sys`) so the group ops are
  byte-identical to the reference rather than hand-roll field math (which would
  break the iron rule). This is the remaining 13a crypto work.

**Done since:**

- **13a — core extraction (started).** `drift-core/` Cargo workspace; the
  `drift-crypto` crate ports base58, HKDF, the AEAD envelope,
  identity/Ed25519/ECDH, sealed sender, the full Double Ratchet, X3DH, burn
  tokens, and the Argon2id vault, each proven **bit-for-bit** against
  `tests/vectors/`. It composes vetted crates only (dalek + RustCrypto +
  argon2) — the iron rule holds inside the Rust core. Stealth + FMD remain
  (see "Still open"). The 13a exit criterion (Rust↔Python wire interop for
  encrypt/decrypt, X3DH, ratchet) is met for everything except stealth detect,
  which is gated on the Elligator parity above.

- **Sidecar packaging** — `drift.sidecar` is frozen with PyInstaller
  (`apps/desktop/sidecar/build_sidecar.py`) and bundled as a Tauri `externalBin`,
  so the desktop installer needs no system Python. The `desktop-app` CI workflow
  builds Windows/macOS/Linux installers on native runners and publishes a
  stable-named Windows installer for the website's one-click download button.
