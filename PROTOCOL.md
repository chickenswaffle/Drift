# The Drift Protocol — Specification, version 1 (draft)

**Wire identifier:** `DRIFT-P/1` · **Status:** draft — this document is
normative for interoperating implementations, but the protocol itself is
**pre-audit**: treat it as stable-in-shape, not stable-in-guarantee, until an
independent audit is published (see `SECURITY.md`).

The Drift Protocol is a metadata-minimizing, end-to-end-encrypted messaging
protocol in which the transport infrastructure — the *relay* — is a blind,
replaceable bulletin board. It composes established, audited cryptographic
constructions (X25519, Ed25519, XChaCha20-Poly1305, SHA-256/HKDF, X3DH, the
Double Ratchet, Monero-style dual-key stealth addressing, Fuzzy Message
Detection) into one design rule:

> **Every property is enforced by cryptography on the endpoints, never by
> policy on the server.** If a guarantee depends on the relay behaving, it is
> not a guarantee of this protocol — and where a best-effort mechanism exists
> anyway (burns, one-time invites), this spec says "best-effort" out loud.

The reference implementation is the Python package in this repository
(`drift/crypto/`, `drift/transport/`, `relay/`). Where this document and the
reference implementation disagree, the implementation is currently
authoritative and the document has a bug — file it.

The iron rule for implementers: **never implement the primitives yourself.**
Compose vetted libraries (the reference uses PyNaCl / `cryptography`).

---

## 1. Identity

An identity is two X25519 keypairs, generated locally, never registered
anywhere:

| keypair | private use | public use |
|---|---|---|
| **scan** | detect incoming mail on the firehose | part of the contact code |
| **spend** | complete message-key derivation, X3DH identity (IK) | part of the contact code |

The split exists so a *scan-only* device (a filtering watcher) can detect that
mail arrived without gaining the ability to read it (§3).

**Contact code** (the only "address" a user ever shares):

```
drift:<b58(scan_pub)>.<b58(spend_pub)>
```

An optional FMD extension appends detection sub-keys (§7). There are no
usernames, phone numbers, or server-side accounts to enumerate.

**Safety number.** Both peers derive the same short fingerprint from the two
identities; comparing it out-of-band authenticates the key exchange. Clients
SHOULD render it both as digits and as deterministic randomart, and MAY record
a local, non-cryptographic "verified" attestation bit.

## 2. Envelope — the only thing a relay ever sees

All traffic to a relay is one JSON envelope shape (HTTP POST `/send`,
WebSocket fan-out to subscribers of the shared firehose channel
`drift-stealth-v1`):

```
{
  "to":  "drift-stealth-v1",         // shared channel — routing reveals nothing
  "ct":  base64(sealed_blob),        // opaque bytes (§4)
  "ts":  unix_seconds,
  "addr": base64(one_time_addr),     // 32 bytes, used exactly once (§3)
  "fmd":  base64(flag)               // OPTIONAL detection flag (§7)
  "ttl_seconds": int                 // OPTIONAL longer replay retention (rooms)
}
```

A relay observes: a one-time address that will never recur, an opaque blob, a
coarse timestamp. It cannot see sender, recipient identity, conversation
membership, or content. Relays retain envelopes only briefly (reference: 30 s
replay window; rooms may request more via `ttl_seconds`, capped server-side).

## 3. Stealth addressing (recipient unlinkability)

Sender, holding an ephemeral X25519 keypair `(r, R)` and the recipient's
`(scan_pub, spend_pub)`:

```
s_scan  = ECDH(r, scan_pub)
s_spend = ECDH(r, spend_pub)
A_once  = spend_point(spend_pub) + SHA256(s_scan)·G     // the one-time address
msg_key = HKDF(s_scan ‖ s_spend, info="drift-v2-msg")
```

Receiver, for each envelope on the firehose:

```
s_scan = ECDH(scan_priv, R)
ours iff  spend_point(my_spend_pub) + SHA256(s_scan)·G == addr
```

Detection needs only the scan private key; **decryption additionally requires
the spend private key** (`msg_key` folds in `s_spend`). Two different messages
to the same recipient share nothing an observer can correlate.

Implementations MUST dedup accepted one-time addresses within a bounded window
(the relay replays recent traffic to reconnecting sockets) and MUST NOT record
an address as seen until the message authenticates.

## 4. Sealed sender — the blob layout

The ephemeral key and ratchet header would let a relay link a sender's
messages, so both are sealed. `ct` decodes as:

```
sealed_blob = R (32) ‖ u32_be(len) ‖ sealed_header ‖ ratchet_ciphertext
```

- `R` — the one clear value; the recipient needs it to derive `s_scan`.
- `sealed_header` — XChaCha20-Poly1305 of the *inner payload* under
  `HKDF(msg_key, info="drift-sealed-sender-v1")`, with the one-time address as
  associated data (a blob cannot be replayed onto a different address).
- `ratchet_ciphertext` — the Double Ratchet AEAD output (§5).

**Inner payload framing** (what `sealed_header` protects), one flag byte then:

| flag | layout | meaning |
|---|---|---|
| `0` | ratchet header (40) | steady state |
| `1` | fs_pub (32) ‖ header (40) | legacy bootstrap (peer had no prekey bundle) |
| `2` | X3DH header (73) ‖ header (40) | X3DH bootstrap — the default |

Ratchet header: `dh(32) ‖ pn(4 BE) ‖ n(4 BE)`.
X3DH header: `IK_A(32) ‖ EK_A(32) ‖ spk_id(4 BE) ‖ otpk_flag(1) ‖ otpk_id(4 BE)`.

## 5. Content encryption — hybrid PQXDH / X3DH + Double Ratchet

- **Bootstrap:** X3DH (Signal's extended triple DH) against the responder's
  published prekey bundle — identity DH key, signed prekey (Ed25519-signed),
  and consumable one-time prekeys. The bundle's identity key MUST equal the
  spend key from the saved contact code (relay-substitution guard).
  Responders replenish one-time prekeys when the relay pool runs low. Peers
  without a bundle fall back to flag-`1` legacy bootstrap (reduced forward
  secrecy for opening messages — clients MUST surface this).
- **Hybrid post-quantum bootstrap (PQXDH-style, the default):** the bundle
  additionally carries an **ML-KEM-768** encapsulation key (FIPS 203),
  Ed25519-signed like the signed prekey and rotated on the same cadence. The
  initiator encapsulates and derives
  `SK = HKDF(F ‖ DH1 ‖ DH2 ‖ DH3 [‖ DH4] ‖ SS_pq, info="drift-pqxdh-v1")`
  — hybrid, so the handshake is never weaker than classic X3DH, and traffic
  recorded today cannot be decrypted by a future quantum computer. The wire
  header appends `pq_prekey_id(4) ‖ kem_ct(1088)` to the classic X3DH header
  (transport frame flag `3`). Rules:
  - a bundle *offering* a PQ prekey whose signature is missing or invalid
    MUST be rejected outright — never silently downgraded to classic;
  - a bundle with no PQ fields at all is a pre-PQ peer: classic X3DH is
    permitted but clients MUST surface the downgrade;
  - hybrid and classic derivations use distinct `info` strings
    (`drift-pqxdh-v1` / `drift-x3dh-v1`) — disjoint KDF domains.
- **Steady state:** the Double Ratchet (DH ratchet + symmetric chains) gives
  per-message forward secrecy and post-compromise security. Message keys are
  erased after use. **Honesty:** the ratchet's ongoing DH steps remain X25519
  — post-compromise security against a quantum adversary is future work (the
  same tradeoff Signal ships with PQXDH).
- Either peer may speak first; whoever does becomes initiator.
- A message that fails authentication is dropped *per-envelope* (with a
  tamper event) — a forged inbound MUST NOT tear down a live session.

## 6. Cover traffic (traffic-shape privacy)

At level `low`/`high` a session emits dummy envelopes on a Poisson schedule
(uniform random 32-byte address + uniform random blob — indistinguishable on
the wire) and pads real plaintexts *inside* the AEAD to one uniform wire size,
so ciphertext length stops leaking message length. Padding:
`0xFF ‖ u16_be(real_len) ‖ message ‖ zeros`; receivers strip it regardless of
their own setting.

## 7. Fuzzy Message Detection (the privacy dial)

With FMD enabled, envelopes carry a detection flag
(`u(32) ‖ y(32) ‖ flag_bits`) bound to the one-time address. A relay holding
the recipient's *detection* key can pre-filter — but at false-positive rate
`p` (client-chosen, powers of two): the relay's view of "your" messages is
poisoned with decoys. `p` trades bandwidth against anonymity-set size. Flags
carry no content; FMD off means no flag and no overhead.

## 8. Beacons and one-time invites (discoverability without a directory)

A **beacon** binds `handle → contact_code` for a bounded TTL, stored on a
relay that cannot read it:

- index key: `SHA256(prefix ‖ relay_pubkey ‖ handle)` — binding the relay's
  Ed25519 key makes precomputed handle tables relay-specific;
- payload: XChaCha20-Poly1305 under a key derived from the handle (+ relay
  pubkey), Ed25519-signed by the identity inside; the relay sees only
  ciphertext and an opaque index.

A **one-time invite** (`driftinvite:…`) is exactly a beacon whose handle is
128 random bits: unguessable, so its TTL may be longer (reference: ≤24 h vs
≤10 min for human handles). The redeemer deletes the beacon on first resolve —
deletion authority ≈ resolution authority on a blind relay. Expiry is the hard
guarantee; one-shot redemption is **best-effort** (a hostile relay or a
federation replica keeps the sealed blob until expiry — useless without the
exact code).

## 9. Burn requests (best-effort remote erasure)

Both peers derive `burn_shared` from their static spend keys. A burn token is

```
<nonce_hex(32)> . <unix_ts> . <hmac_sha256_hex(64)>
```

MAC'd over scope (`"message"` with the target's one-time address, or
`"conversation"`) with freshness and single-use nonce semantics. The relay
deletes matching envelopes it still holds and re-broadcasts the tombstone;
receiving clients verify the HMAC **before** erasing locally. Honest relays
hold nothing past the replay window anyway; a compromised peer endpoint can
obviously keep copies. Best-effort, and labeled so in every UI.

## 10. Groups and rooms

- **Groups (≤10):** pairwise composition — one independent Double Ratchet per
  other member, one ciphertext per recipient to that recipient's own stealth
  address. The relay sees N−1 unrelated envelopes; the group id exists only
  *inside* payloads. Membership changes are in-band signed messages;
  bandwidth is O(n) by design (sender-keys is future work).
- **Sovereign rooms:** a room is purely a shared secret derived from its name
  (`derive_room_secret`) — **no server-side room object exists**. Three
  tiers: `open` (name is the secret), `invite` (unguessable descriptor),
  `dark` (descriptor + separate posting secret; read/write split). Room
  traffic uses the same envelope shape with rotating addresses; senders are
  pseudonymous 4-char session tags, not identities. Rooms are shared-key, not
  ratcheted — no forward secrecy inside a room, stated in the UI.

## 11. WITNESS — verifiable relay blindness

Every 60 s a relay signs a certificate: counts of what it provably cannot
know (sender identities: 0, recipient identities: 0, readable contents: 0,
linked conversations: 0), a Merkle root over the period's envelopes, and the
previous certificate's hash — an unbroken, Ed25519-signed hash chain. The
chain is canonical JSON (sorted keys); `cert_hash = SHA256(canonical bytes)`.

Anyone can verify: signatures, chain continuity (no resets), period coverage
(no dark windows), and the zero-knowledge claims — `GET /witness/pubkey`,
`/witness/chain`, `/witness/current`. A relay cannot rewrite its past without
its key, and cannot silently start logging without breaking a chain anyone
watches. WITNESS proves the relay's *software state*, not its hardware.

## 12. Local at-rest protection (endpoint, not wire)

Not part of the wire protocol, but normative for conforming clients:
Argon2id-sealed vault with **two slots** — the real passphrase and an optional
duress passphrase that wipes or opens a decoy, indistinguishable to an
observer (same KDF path, same timing, same "unlocked" response). Panic lock
shreds the working copy without any passphrase.

## 13. Versioning and negotiation

`DRIFT-P/1` is this document. The envelope's channel string
(`drift-stealth-v1`), HKDF info strings (`drift-v2-msg`,
`drift-sealed-sender-v1`), and the inner-framing flag byte are the version
anchors: a breaking change bumps them, and mixed-version peers simply fail to
detect/decrypt rather than downgrade. There is deliberately **no in-band
version negotiation** — negotiation is a downgrade-attack surface.

## 14. Extensions

DRIFT-P is deliberately small; everything else — including commercial
services — attaches through extensions. An extension is an optional protocol
layered on the core, identified as:

- `drift-ext/<name>/<version>` — **registered extensions**, specified openly
  in this repository (the first: `drift-ext/witness/1`, §11 — WITNESS is
  optional for relays and advertised as an extension);
- `x-<vendor>-<name>/<version>` — **vendor extensions**, specified and
  operated by whoever owns them. They may be proprietary.

Relays advertise what they speak:

```
GET /capabilities → {"protocol": "DRIFT-P/1", "extensions": ["drift-ext/witness/1", …]}
```

Clients MUST treat unknown extensions as absent and continue on the core
protocol — extensions are additive, never load-bearing for security.

**Conformance rules (normative).** An extension, open or proprietary, MUST
NOT:

1. alter envelope semantics (§2) or attach sender-, recipient-, or
   conversation-linkable metadata to an envelope;
2. gate *core* message delivery on payment, identity, or token possession;
3. weaken any guarantee of §1–§12.

The sanctioned pattern for privileged service tiers is **per-connection**
authorization (e.g. a signed bearer token presented when subscribing, granting
rate/retention/priority tiers); **per-envelope** privilege markers are
non-conforming, because they put a distinguisher on the wire. An
implementation shipping a non-conforming extension may not claim DRIFT-P
compatibility (see `TRADEMARKS.md`).

## 15. What this protocol does NOT provide

- protection of a compromised endpoint (malware reads screens);
- perfect timing privacy against a truly global passive adversary (cover
  traffic raises cost; it does not solve this);
- forward secrecy inside rooms (shared-key by design, §10);
- guaranteed remote deletion (§9 is best-effort and says so);
- anything at all if users skip safety-number verification.

---

*The Drift Protocol specification is © the DRIFT contributors and released
under the repository's MIT license. "DRIFT", "Drift Protocol", and "DRIFT-P"
are trademarks of the project — the code license does not cover them (see
`TRADEMARKS.md`); stewardship stance in `docs/open-core.md`.*
