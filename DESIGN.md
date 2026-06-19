# DRIFT — design document

> Working codename: **DRIFT** (because your addresses *drift* and rotate, never anchoring to you). Rename it to whatever you like before launch.

A terminal-first, end-to-end encrypted messenger with rotating, unlinkable receiving addresses. No phone numbers, no accounts, no central authority that can read or hand over your messages.

This document is the blueprint. It's written so a beginner can follow the reasoning and a contributor can pick up any single layer and build it.

---

## 1. What we are actually defending against (threat model)

Security claims mean nothing without saying *against whom*. Here's the honest scope.

DRIFT is designed to defeat:

- **Passive network surveillance** — an ISP or nation-state tapping the wire learns nothing about message content.
- **A malicious, compromised, or subpoenaed relay** — the server has no plaintext, no contact graph, and no way to link addresses to people. If it's seized, there's nothing useful to seize.
- **Later device or key theft** — past messages stay safe (forward secrecy), and the conversation self-heals after a compromise (post-compromise security).
- **Traffic analysis** — who-talks-to-whom is obscured by sealed sender and onion transport. Timing and volume would be covered by cover traffic, which is *planned but not yet implemented* (Phase 4 roadmap).
- **Takedown attempts** — federation and a peer-to-peer fallback mean there is no single server to kill.

DRIFT does **not** magically defeat (and you should say so loudly in the README):

- **A compromised endpoint.** If there's a keylogger or malware on the actual machine, no messenger on earth can save you. The attacker reads the screen.
- **A truly global passive adversary** who can watch *all* traffic everywhere at once. We raise the cost enormously, but honest cryptographers don't claim to fully solve this — it's an open research frontier. Don't market past this line.
- **User error** — verifying the wrong key, screenshotting a chat, getting phished.

Being precise here is what separates a serious tool from snake oil. "Unstoppable and ultra-secure" is the *goal*; the threat model is the *promise you can actually keep*.

---

## 2. Identity: keys, not accounts

On first run, everything is generated locally and the private parts never leave the device. A user gets three keypairs:

| Key | Curve / algo | Purpose |
|-----|-------------|---------|
| Identity key | Ed25519 | Signs things; anchors your "safety number" for verification |
| Scan key | X25519 | Lets others derive one-time addresses *to* you; lets you **detect** your mail |
| Spend key | X25519 | Additionally required to **decrypt** a detected message |

(The "scan / spend" split is borrowed from stealth-address systems. The two keys carry genuinely different privilege — and as of the M1 audit fix this is real, not just documented: the one-time address and ownership detection depend on the *scan* key alone, but the message key is `HKDF(ECDH(scan) ‖ ECDH(spend))`, so the private *spend* key is required to actually read anything. This means you can hand a **scan-only** key to a low-power device to filter your mail — it can confirm which messages are yours without ever being able to open them. See §3 for the two-step receive.)

> **Before the M1 fix (≤ `v0.14.0`):** the message key derived from the scan secret alone, so the spend key added no confidentiality and a "scan-only" delegate could in fact read everything. Binding the spend key changes the derived message key, so peers must both run `v0.14.1+` to interoperate.

Your shareable identity — your **contact code** — is just a compact encoding of your three public keys, e.g. `drift:aV9k7Hk2...Q2x`, also renderable as a QR code. There is no username registry, no phone number, no email. Your identity *is* your key material.

> **Key-reuse coupling (audit L4, noted).** The Ed25519 identity/signing key is *derived* from the spend key via a domain-separated HKDF (`identity_seed = HKDF(spend_priv)`), while the spend key is also used directly as an X25519 DH key (X3DH identity key, ratchet bootstrap). Using one secret in two algebraic settings is tolerated here because the signing path is hashed — but it does couple the signing identity's compromise to the spend key and vice versa. Storing an independent Ed25519 key would decouple them; that changes the on-disk identity format and needs a migration, so it is **deferred**. Documented so the coupling is explicit rather than silent.

---

## 3. The headline feature: rotating stealth addresses

This is the "address that rotates and never gets pinned to one user" you asked for. The mechanism (the diagram in chat shows the flow):

**Sending to Alice**, Bob's client:
1. Generates a throwaway ephemeral keypair `(r, R)`.
2. Computes two shared secrets: `s_scan = ECDH(r, Alice_scan_pub)` and `s_spend = ECDH(r, Alice_spend_pub)`.
3. Derives a **one-time address** from the scan secret only: `A_once = Alice_spend_pub + Hash(s_scan)·G` (point addition on the curve).
4. Derives the **message key** from *both*: `k = HKDF(s_scan ‖ s_spend)`.
5. Posts `{ R, ciphertext }` to the mailbox keyed by `A_once`.

Every message produces a *different* `A_once`. To the relay these look like uniform random strings with no link to Alice and no link to each other.

**Receiving**, Alice's client periodically scans posted messages in **two steps** (the scan/spend privilege split, audit M1):
1. *Detect — scan key.* For each `{ R, ... }`, compute `s_scan = ECDH(Alice_scan_priv, R)` and candidate `A' = Alice_spend_pub + Hash(s_scan)·G`. If `A'` equals the mailbox address, the message is hers. This step needs only the private **scan** key (and the public spend key), so a scan-only delegate can do it.
2. *Decrypt — spend key.* Compute `s_spend = ECDH(Alice_spend_priv, R)` and the message key `k = HKDF(s_scan ‖ s_spend)`. This step requires the private **spend** key; the scan key alone cannot produce `k`.

Only Alice can run the match, because only she has `scan_priv` — and only Alice (or a device she's given the spend key) can decrypt, because step 2 needs `spend_priv`. The relay is a public bulletin board of opaque, unlinkable blobs.

**The tradeoff (be honest about it):** scanning means Alice does a little work per message in the system. At small scale, just scan recent messages — it's nothing. As it grows, three escalating fixes:
- **Time/shard bucketing** — only scan the windows or shards you could plausibly have mail in.
- **Fuzzy Message Detection (FMD)** — a real cryptographic scheme that lets the relay pre-filter a *subset* of messages for you at a tunable false-positive rate. It's literally an anonymity dial: more noise = more privacy = more relay-side work. **This is now wired end to end (audit M4) — see the FMD subsection below for what's actually implemented and what it costs.**
- **Private Information Retrieval (PIR)** — heavyweight, but lets you fetch your mailbox without the server learning which mailbox. Save this for "phase 99."

---

## 4. Message encryption: the Double Ratchet

Once the first message establishes a shared secret (via the **X3DH** handshake described in "Bootstrap" below), the conversation runs Signal's **Double Ratchet**. You don't need to invent this — it's well documented and there are vetted implementations to learn from.

It buys you two things that static keys can't:
- **Forward secrecy** — steal today's keys and *past* messages remain unreadable.
- **Post-compromise security** — if someone briefly steals a key, the ratchet "heals" and future messages become secure again.

Every individual message is sealed with an AEAD cipher — use **XChaCha20-Poly1305** (the extended-nonce variant is forgiving about nonce handling, which is exactly what you want when you're learning).

### Bootstrap: X3DH asynchronous key agreement

The first message establishes the shared root via **X3DH** (Extended Triple
Diffie-Hellman, the Signal handshake — `crypto/x3dh.py`, `transport/session.py`),
implemented to spec. Every user publishes a **prekey bundle** to the relay ahead
of time: a long-lived **signed prekey** (X25519, signed by the identity's Ed25519
key) plus a batch of **one-time prekeys** (OTPKs). When you open a chat, your
client fetches the contact's bundle, verifies the signature, and runs:

```
DH1 = ECDH(IK_A, SPK_B)     IK = the long-term X25519 spend key
DH2 = ECDH(EK_A, IK_B)      EK = a fresh single-use ephemeral, discarded at once
DH3 = ECDH(EK_A, SPK_B)     SPK = the recipient's signed prekey
DH4 = ECDH(EK_A, OPK_B)     OPK = a one-time prekey, consumed and deleted
root = HKDF(F ‖ DH1 ‖ DH2 ‖ DH3 ‖ DH4)
```

The recipient's signed prekey is its initial Double Ratchet key, so the ratchet
takes over immediately after. The X3DH header (`IK_A`, `EK_A`, prekey ids) rides
*inside* the sealed-sender envelope of every opening-chain message, so a reordered
opening message still bootstraps the responder, and the relay sees nothing.

This is what makes forward secrecy complete (audit H3):

- **Once the DH ratchet has turned even once, forward secrecy is full** — the
  ordinary Double Ratchet guarantee, unchanged.

- **The opening burst is now forward-secret against full key compromise.** The
  one-time prekey's private half is **deleted the moment it is used** (the relay
  hands each OTPK out exactly once; the recipient consumes it on receipt), and the
  sender's `EK_A` private is discarded immediately. So a later compromise of
  **either** party's long-term keys cannot reconstruct the opening master secret:
  the OTPK it depended on no longer exists anywhere. ✅ This closes the residue
  that the earlier deterministic bootstrap left against *recipient* key theft.

- **Post-compromise security** is unchanged: a transient state compromise heals on
  the next DH ratchet from fresh randomness.

**Graceful degradation (legacy bootstrap).** If the relay has no bundle for a
contact — an old client, or a bundle that expired — the sender falls back to the
previous **deterministic** bootstrap (`root = HKDF(ECDH(my_spend, their_spend))`
with a deterministic responder keypair) plus a fresh, discarded forward-secrecy
ephemeral folded into the root. That fallback is forward-secret against the
*sender's* later key theft but **not** the recipient's — the documented earlier
boundary — and the UI shows a one-time amber warning when it engages. It exists
only for interoperability during the transition; with prekeys published (the
default since `drift init`), every conversation uses full X3DH.

So the honest one-liner: *with X3DH prekeys, forward secrecy is complete from the
very first message; the legacy deterministic bootstrap survives only as a
visibly-warned fallback for peers who have published no bundle.*

---

## 5. Metadata privacy: the genuinely hard layer

Hiding *content* is solved. Hiding *who talks to whom* is where most messengers quietly fall short. DRIFT layers several defenses:

- **Sealed sender** — sender-linkable metadata is encrypted *inside* the payload, so the relay sees only the recipient's one-time address and an opaque blob (see the subsection below).
- **Onion transport over Tor by default** — the relay never sees your real IP. The client should bootstrap Tor automatically so the user never thinks about it. (A mixnet like Nym/Loopix is the stronger, heavier upgrade for defeating timing analysis — a later phase.)
- **Cover traffic** *(planned — not yet implemented)* — the client *will* send decoy messages on a randomized schedule so that *volume and timing* leak nothing, so an observer can't tell a real conversation from silence. Targeted for Phase 4; not present in any shipped release.
- **Dead-drop model** — combined with stealth addresses, the relay is a write-only, read-by-scanning bulletin board. There is no "inbox for Alice" to point at.

### Sealed sender (Phase 3b)

DRIFT has no accounts, so the envelope never carried a sender *identity* to begin with. The residual leak was subtler: the Double Ratchet header rode on the wire in the clear, and it contains the sender's current DH ratchet public key — which is **stable across a ratchet epoch**. A relay (or any firehose observer) could therefore group a sender's messages by that key, even with Tor hiding the IP. Sealed sender closes that.

**What the relay sees per message:**

| Field | Contents | Why it's there |
|-------|----------|----------------|
| `addr` | the recipient's one-time stealth address `A_once` | routing/detection — only the recipient recognizes it; rotates every message |
| `ct` | one opaque blob | the actual payload |

The blob is laid out as:

```
ct = R (32 bytes)  ‖  sealed(ratchet_header)  ‖  ratchet_ciphertext
```

- `sealed(ratchet_header)` is XChaCha20-Poly1305 over the ratchet header, keyed by `HKDF(s, "drift-sealed-sender-v1")`, where `s` is the stealth ECDH secret that `derive_one_time_address` / `scan_for_message` already compute on both sides. No extra key material or round-trip is added.
- The recipient's one-time address is bound in as AEAD **associated data**, so the relay cannot move a sealed blob onto a different address without the unseal failing.
- `ratchet_ciphertext` is the content, already sealed by the ratchet message key.

**What the relay no longer sees:** the ratchet header (the stable, linkable field) and, as separate inspectable wire fields, the sender's ephemeral key. It can no longer link a sender's messages.

**The honest limit — `R` is unavoidably public.** The per-message ephemeral key `R` is *not* encrypted, and cannot be: it is the Diffie–Hellman contribution the recipient needs to derive `s` in the first place, so encrypting it under a key derived from itself is circular. It sits inside the opaque blob rather than as a labeled field, but a determined relay can still read those 32 bytes. This is the same shape as **Signal's sealed sender**, where the outer ephemeral is likewise always public; the sealed part is the *identity*, not the ephemeral. In DRIFT `R` is fresh every message, unlinkable to any other message, and tied to no account — so it reveals nothing about who sent it. What sealed sender removes is the relay's ability to *correlate* a sender's traffic, not the existence of one public ephemeral per message.

### Beacon: opt-in, time-boxed discoverability (Phase 6)

Everything else in this section works to make you *unlinkable*. Beacon is the deliberate exception, and it should be understood as one — not pitched as "just as private as the rest."

A beacon lets a user *light* a short human handle (e.g. `Diego552`) for a few minutes. While it's lit, **anyone who knows that exact handle** can resolve it to the user's contact code and add them. The relay indexes the beacon by `SHA256("drift-beacon-lookup-v1" ‖ relay_pubkey ‖ handle)` and stores an opaque blob encrypted under `HKDF(handle, "drift-beacon-v1")` — so the relay never learns the handle or the contact code, only that *some* handle hashing to this value is briefly active. After the TTL (capped at 10 minutes) the entry is **deleted**, not hidden: a lookup afterwards 404s, and there is no retroactive way to discover who was behind it on an *honest* relay.

The index hash is **domain-separated and relay-specific** (audit M3): a fixed `drift-beacon-lookup-v1` prefix *and* the relay's own long-term Ed25519 public key are folded in before the handle. The prefix ties the hash to DRIFT's namespace; the relay pubkey means **a lookup hash from one relay is meaningless against another**. A client fetches the relay pubkey from `GET /beacon/pubkey` (an alias of `/witness/pubkey`, already published since Phase 10) before computing any lookup hash. The practical effect: an attacker who logs lookup hashes and wants to discover *which handles were ever used* must build a separate offline dictionary per relay — there is no universal rainbow table that works everywhere, which dramatically raises the cost of grinding the index across the network.

It still does **not** defend a *guessable* handle on a *known* relay: anyone (including that relay) can build a DRIFT-and-relay-specific dictionary and grind common handles, and — be honest about this — a captured encrypted **payload** is offline-grindable *indefinitely* by anyone who kept the blob, because the payload key is `HKDF(handle)` with no relay binding or time bound. The "deleted after TTL → no retroactive lookup" property is therefore a policy of an honest relay, not a cryptographic guarantee. Both weaknesses are inherent to short, human-memorable handles and are mitigated by handle choice, not by the hash.

**Handles are semi-public.** Treat a handle as a low-entropy shared secret, not a password. For anything sensitive, pick something **unguessable** — a random word pair like `copper-lantern` or a random token, not `Alice123`. A predictable handle is dictionary-grindable (per relay), and a captured payload blob is grindable forever, regardless of the lit window — so the handle is the only thing protecting it.

**What you are trading.** During the window, the handle is a shared secret with a deliberately low bar: anyone you tell it to — and anyone *they* tell, or anyone who guesses a weak handle — can link that handle to your contact code for those minutes. That is a small, bounded amount of **temporal linkability** exchanged for the convenience of being found without exchanging a 90-character contact code out of band. It is opt-in (nothing is discoverable unless you light a beacon), time-boxed (minutes, then gone), and per-handle (lighting `Diego552` says nothing about any other handle or your default traffic).

**What it does *not* give you.** The Ed25519 signature inside a beacon proves the payload wasn't altered in transit, but it does **not** prove the handle's owner is who you expect — a handle is just a string, and anyone can light a beacon claiming any handle and pointing at any contact code. So beacon resolution ends at "here is a contact code," never at "this is definitely Diego." The finder must still confirm the safety number out of band (`drift verify`) before trusting the channel. Beacon is a discovery convenience layered on top of DRIFT's verification model, not a replacement for it.

### Burn requests (Phase 5)

A burn lets either party erase messages after the fact — both clients delete their local copies, and the relay drops any matching blob still sitting in its short replay buffer. A burn is a signed control message: the token is `HMAC(HKDF(static_ECDH), scope ‖ message_id)`, a MAC only the two conversation participants can produce. The relay broadcasts the burn as a **tombstone**; each client *verifies the token end-to-end* before deleting anything. **That verification is the whole security boundary — the relay authenticates nothing.**

**Why the relay can't be trusted to erase a "conversation."** The relay has no shared secret, so it cannot check a burn token. It also cannot tell which buffered blobs belong to one conversation — stealth addresses are unlinkable *by design*, which is the point of the whole system. An earlier version honoured a conversation-scope burn by wiping the entire channel's replay buffer; because the firehose is shared by every user and the relay can't authenticate the request, **any anonymous caller could erase every user's recent traffic with a single POST** (audit finding H2).

**What the relay does now.** Relay-side erasure is addr-scoped only: a burn deletes *only* the single blob whose one-time address is explicitly named (`scope=message`). A `scope=conversation` burn does **not** touch the shared buffer at all. Conversation erasure is delivered entirely end-to-end — each client verifies the token and deletes its own copy on the tombstone — and any blob left in the relay buffer simply expires on its short `RECENT_TTL` (30 s on the full relay).

**Burn tokens are single-use (audit M2).** Each token is `nonce.timestamp.mac`: a fresh 16-byte random nonce and a creation timestamp, both bound into the HMAC and both carried in the clear inside the token. This closes two earlier problems with the old static `HMAC(secret, scope)` token:
- *Replay.* A captured token could previously be re-POSTed forever to force both clients to re-burn. Now the relay tracks seen nonces in a bounded LRU (the same dedup pattern as message envelopes) and rejects a repeat; it also rejects any token whose timestamp is more than `TOKEN_TTL_SECONDS` (300 s) old or in the future. The receiving client independently re-checks the MAC *and* the freshness window. A captured token is therefore either stale (client rejects) or already-burned (relay won't re-broadcast).
- *Linkability.* The conversation token is no longer a stable per-conversation value an observer could cluster across burns — every burn carries a fresh nonce, so two burns of the same conversation are unlinkable on the wire.

**The honest tradeoff.**
- A conversation burn no longer instantly clears the relay's buffer; those opaque, already-encrypted blobs linger for up to `RECENT_TTL` before expiring. The *durable* erasure — your peer's stored copy — still happens immediately via the verified tombstone.
- Because a one-time address is public on the firehose (it's the routing key), anyone who *observed* a message can name its address and evict that one blob from the replay buffer. This is bounded: it only affects the ≤30 s late-join window, never a message already delivered to a connected peer, and it is per-message rather than a one-shot channel wipe. Eliminating even this residue needs authenticated, per-recipient storage (Phase 4).
- Burn remains **best-effort against a non-compliant client**: a peer that chooses to ignore the tombstone keeps its copy. Burn defends against honest clients and an honest-but-curious relay, not against an endpoint that has already decided to retain your message.

### Fuzzy Message Detection (FMD) — the privacy dial, wired (audit M4)

FMD is **off by default** and, when off, changes nothing on the wire — the same
two-segment contact code, the same envelopes, the same full client-side scan.
Turning it on trades a sliver of metadata privacy for scanning efficiency, and
the dial is the false-positive rate `p` (`drift privacy --fmd-rate`).

**What's actually implemented now** (previously `--fmd-rate` set a value that
touched nothing — that was the audit-M4 gap):

- **Detection key in the contact code.** With FMD on, your contact code gains an
  optional 3rd segment `drift:<scan>.<spend>.<fmd>` carrying your FMD detection
  *public* key (the `n = round(-log2 p)` sub-keys). The key is **derived
  deterministically from your spend key** (like the Ed25519 beacon key), so
  there's no extra secret to store or seal — only the rate is persisted. A
  classic 2-segment code is still valid and means "FMD off, scan everything."
- **Senders flag.** When the recipient's stored code carries an FMD key, the
  sender computes an FMD flag bound to that message's one-time stealth address
  and includes it in the envelope. No FMD key on the recipient → no flag, no
  overhead.
- **Relay pre-filters, opt-in.** A client may hand the relay its detection
  sub-keys on subscribe; the relay then runs FMD `Test` against each envelope's
  flag and forwards only matches — plus the scheme's built-in `2^-k` false
  positives. Clients that don't opt in keep receiving the whole firehose and
  scanning locally (unchanged). Unflagged envelopes always pass the filter
  (fail-open): FMD is an efficiency filter on flagged traffic, never a gate that
  could drop a real message.

**Be explicit about the cost.** With FMD on, the relay learns something it did
not before: a *probabilistic, `p`-sized* guess at which envelopes might be
yours. That is the whole point of the dial and the price of the efficiency gain
— lower `p` = the relay's guess is sharper (it learns more); higher `p` = more
noise, a larger anonymity set, but more traffic forwarded to you and more
relay-side work for everyone. Crucially, the signal is **only probabilistic**:
holding your coarse relay key, the relay sees an *identical* "match" for a
genuine message and for a false positive and **cannot tell them apart** — only
you, scanning with your full key (and ultimately the stealth scan + ratchet
decrypt), distinguish your real mail from relay-visible noise. FMD never reveals
message content, never authenticates anything, and sits strictly *alongside* the
stealth addressing it accelerates.

---

## 6. Infrastructure: "unstoppable" = no single chokepoint

A single server is a single subpoena, a single seizure, a single off-switch. DRIFT spreads the bulletin board out:

- **Federated relays** — anyone can run one. Relays gossip new blobs to each other (think email or Matrix, but the servers are dumb and hold only opaque ciphertext with a TTL).
- **P2P fallback** — two users can talk directly over a Tor onion service with no relay at all, which is genuinely serverless.
- Blobs are content-addressed, replicated, and **expire automatically**, so no relay accumulates a forensic goldmine.

"Unstoppable" comes from the *combination*: open protocol + many independent relays + Tor transport + a serverless mode. There's nothing central to compel or kill.

### WITNESS — verifiable blindness (Phase 10)

Everything above makes the relay *structurally* blind. WITNESS makes that
blindness **checkable** rather than something you take on faith. Every 60
seconds the relay generates and signs a **blindness certificate**: a small
structured document stating what it provably cannot know about the traffic it
just routed (zero sender identities — sealed sender; zero recipient identities —
stealth addresses; zero readable contents — E2E; zero linked conversations —
unlinkable envelopes), plus a Merkle root committing to the *set* of envelopes
it routed that period. Each certificate embeds the SHA256 of the previous one,
so the certificates form a hash-chained, tamper-evident transparency log; the
relay signs every certificate with a long-term Ed25519 key generated on first
start (`relay_identity.json`, `chmod 600`) and published at `/witness/pubkey`.

The guarantee is **continuity**. A relay cannot rewrite its past without its
private key (every certificate is signed), and it cannot *silently* start
logging: the structural zeros mean there is no sender/recipient identity in the
envelope to record, so to claim otherwise it would have to sign a false
statement under its own key — or stop publishing certificates, which opens a
detectable gap in the chain. Clients verify a relay's whole 24-hour chain with
`drift witness verify <relay>` and watch it live (a dot per good minute, a loud
alert on any break) with `drift witness subscribe <relay>`. The relay also
serves a plain-English `/cannot-see` page — the current certificate rendered for
a human, including a surveillance state that walks up to it.

What WITNESS proves: the relay has not deviated from blind routing over the
window you can fetch. What it does **not** prove: that the relay won't log in the
*future* — only ongoing chain continuity gives that, moment to moment. The
certificate format is deliberately plain SHA256-over-canonical-JSON + Ed25519, so
it can be verified with `openssl`/`hashlib` and no DRIFT code. Full spec, threat
model, and a "what this means for legal demands" section:
[`docs/witness.md`](docs/witness.md).

---

## 7. What the regular person actually experiences

All of the above is invisible. The entire point is that the user types human things, not crypto things:

```
$ curl -sSL https://get.driftmsg.io | sh        # or grab a single binary
$ drift init
  ✓ keys generated locally (they never leave this machine)
  Your contact code:  drift:aV9k7Hk2···Q2x       (or scan the QR below)

$ drift add bob drift:7Hk2p9L···4fX              # paste a friend's code
$ drift verify bob                               # compare a short word list in person/call
  river-amber-tiger-92  ·  matches? [y/N]

$ drift chat bob
  bob › hey, did it work?
  you › flawlessly
```

Behind that: Tor bootstraps, keys generate, stealth addresses rotate every message, the ratchet turns. The user never reads the word "Curve25519" unless they go looking.

The word list shown by `drift verify` is the **safety number**: `SHA256("drift-safety-v1" ‖ sorted([my_scan‖my_spend, their_scan‖their_spend]))`, rendered as a short hex group. It commits to **both** public keys of **both** parties, sorted so each side computes the same value — a mismatch means a man-in-the-middle. It deliberately covers the spend key, not just the scan key (audit M5): the spend key is the X3DH identity key and the beacon-signing seed, so a contact code that kept the real scan key but swapped the spend key used to pass verification unchanged. It no longer does. **Migration:** this changes the value for every contact, so any verification done on `v0.14.0` or earlier is invalidated — re-verify your contacts out of band once both sides are on `v0.14.1+`.

---

## 8. The unorthodox extras (your "outside the box")

These are the features that make DRIFT distinctive rather than "another Signal clone." Pick the ones that excite you:

- **Stealth rotating addresses** — the headline (Section 3). This alone is the differentiator.
- **Fuzzy Message Detection** — a literal privacy/efficiency dial the user can turn.
- **Panic / duress passphrase** — a *second* passphrase that, when entered, silently wipes keys (or unlocks a believable decoy) instead of opening the real account. Protection against "unlock it or else" coercion. Real and duress passphrases go through the same Argon2id KDF, the same constant-work two-slot unlock, and produce no error or timing difference — and the on-disk vault always has exactly two padded, shuffled slots (the second is indistinguishable random bytes when no duress is set), so a single forced unlock or disk image cannot prove a duress passphrase exists. *Honest limit (audit L2):* the **wipe** variant is single-shot — it shreds the vault and materializes a fresh random identity, so a coercer who forces a *second* unlock afterwards sees no vault and a different identity than the first prompt. The indistinguishability guarantee covers one forced unlock, not repeated ones; the decoy variant (which keeps a plausible vault in place) is the better choice where a second unlock is plausible. Making wipe leave a convincing decoy vault behind is a larger change to the live panic vault and is **deferred** (it must not weaken the constant-work two-slot construction).
- **Decoy contacts and hidden volumes** — a real set of chats behind your true passphrase, an innocuous set behind the duress one. The vault seals **the identity *and* its address book together** (audit H4), so a locked device holds no plaintext contact graph and a decoy unlock materializes only the decoy's contacts — the real contact list is shredded from disk and stays sealed. *Honest limits:* (1) while a session is unlocked, the identity and contacts are materialized in the clear (chmod 0600) — `drift lock`, which re-seals and shreds them, or closing the app is what restores the at-rest protection; the panic key defends the *locked* state. (2) `secure_overwrite` is best-effort on journaling/wear-levelled/snapshotted storage. (3) The vault hides a duress passphrase against a *single* image; an adversary who can diff *multiple* images across voluntary re-locks could spot which slot changed (the untouched duress slot's bytes are stable) — outside the single-image threat model, but stated plainly.
- **Cover traffic** *(planned)* — once shipped, silence and conversation will look identical on the wire.
- **Serverless P2P mode** — for the truly paranoid or for two people on the same network.
- **Ephemeral by default** — messages self-destruct unless a user opts into local-only history. Nothing is retained server-side, ever.
- **Deniable authentication** — a property you get *for free* from the ratchet: a recipient knows a message is authentic, but can never *prove to a third party* who sent it. Everything is deniable after the fact.

---

## 9. Tech stack and a phased roadmap

Two viable paths. Pick based on what you want out of the project:

**Rust** — the right call if you want a hardened, fast, single-binary tool. Libraries: `x25519-dalek`, `ed25519-dalek`, `chacha20poly1305`, `arti` (Tor in Rust), `ratatui` for the terminal UI. Steeper contributor curve, stronger foundation.

**Python** — the right call if you want contributors to show up easily and you want to move fast. Libraries: `PyNaCl` / `cryptography` (libsodium bindings), `stem` or a Tor proxy for transport, `Textual` for a slick TUI, `FastAPI` + Redis for a reference relay. Easiest on-ramp; fine for a learning-grade tool.

**Iron rule for both:** *never roll your own crypto primitives.* Use the vetted libraries for the curve math, the AEAD, the hashing. You are *composing* well-understood building blocks into a protocol — that's the creative part — but you are not reimplementing Curve25519 by hand. That's how subtle, fatal bugs get in.

### Build it in phases — each phase is usable on its own

| Phase | Goal | You'll have learned |
|-------|------|---------------------|
| **0** | Two clients, X25519 + XChaCha20, dumb relay, *no* rotation. Just get one encrypted message across. | Key exchange, AEAD, sockets |
| **1** | Add stealth addresses + scanning. Addresses now rotate. | The headline feature |
| **2** | Add the Double Ratchet. | Forward secrecy, real protocol design |
| **3** | Route over Tor + sealed sender. | Metadata privacy basics |
| **4** | Federation + cover traffic. | Decentralization, traffic analysis |
| **5** | Panic key, decoy volumes, FMD dial. | The distinctive extras |

Ship phase 0 first. A thing that sends one encrypted message end-to-end teaches you more than a hundred pages of design docs, and it gives contributors something real to clone on day one.

---

## 10. The honesty section (keep this in your README)

A few things to state plainly so you build trust instead of overpromising:

- **This is a serious learning-grade tool, not a Signal-killer on day one.** Signal is the product of years of work by world-class cryptographers plus repeated independent audits. DRIFT can be *genuinely strong* against the threat model in Section 1 — and the rotating-address design is a real, interesting contribution — but "rivals all other methods" is *earned* through review and time, not declared at v1.
- **Get the protocol reviewed before anyone trusts their safety to it.** Novel compositions of good primitives can still have flaws. Open-sourcing it is exactly the right move: invite the scrutiny.
- **The endpoint is the weakest link, always.** Say so. The most secure protocol in the world can't help a phone with spyware on it.
- **Metadata is hard.** You're doing more than most by even trying. Be proud of that and precise about its limits.

Build it honest, build it in the open, and let the rotating addresses be the thing people remember.

---

## 11. Group messaging (Phase 8 — pairwise composition, ≤10 members)

Groups in DRIFT are **not** a new cryptographic construction. A group is a
composition of the primitives we already have: the pairwise Double Ratchet
(Section 4) and rotating stealth addresses (Section 3). Every member keeps an
independent pairwise ratchet session with every *other* member. A group message
is encrypted **once per recipient** and each ciphertext is sent to that
recipient's own one-time stealth address. The relay sees N-1 unrelated
envelopes — never a "group message"; the group identifier is encrypted *inside*
the payload, never on the envelope.

The group identifier itself is fresh 32-byte randomness, owned by no member, so
it can't be linked back to whoever created the group.

### Be honest about the costs

- **O(n) bandwidth per message.** Sending one group message costs one ciphertext
  per other member (N-1 envelopes). That is fine for the small groups this phase
  targets (hard cap: **10 members**) and it keeps us honest to the "no new
  primitives" rule — it is pure ratchet + stealth composition. It does **not**
  scale to large groups. The intended fix is **sender keys** (a single per-sender
  message chain whose key is distributed once over the pairwise channels), which
  brings send cost down to O(1) ciphertext + O(n) key distribution. That is
  explicitly deferred to a future **Phase 8b**; do not pretend v1 groups scale.

- **Membership is eventually consistent, not strongly consistent.** There is no
  group state on the relay — the group exists only as the union of members'
  local views, kept in sync by membership-change messages that propagate pairwise
  (each signed with the author's Ed25519 identity key and additionally bound to
  the pairwise channel that delivered it). Practically: **a member who is offline
  during a membership change keeps a stale view until they reconnect and process
  the queued change.** And a just-removed member may still receive one or two
  messages that were already in flight from senders who hadn't yet processed the
  removal. This is inherent to a serverless, no-central-authority design — it is a
  property, not a bug. Joining is out-of-band (the inviter shares the roster, the
  same trust model as exchanging a contact code in the first place).

- **Removal is forward-secret, not retroactive.** Removing a member relies on the
  *existing* forward-secrecy property of the pairwise ratchet — there is no new
  mechanism. After removal the member is dropped from every sender's recipient
  list, so they receive no further envelopes; and because each remaining pair's
  ratchet advances on continued use, a removed member who somehow retained another
  pair's session state still cannot follow future ratchet steps. But removal does
  **not** reach backwards: a removed member who saved earlier message keys can
  still decrypt messages from *before* their removal. This is true of essentially
  every messenger (you cannot un-send a message someone already decrypted) — we
  state it plainly rather than imply otherwise.

### Why this is still worth shipping

Even at O(n), a DRIFT group inherits the whole metadata story: the relay sees
only a fan of unlinkable one-time addresses with independent ciphertexts and no
shared field tying them together, so it cannot even tell that a "group" exists,
let alone who is in it. That unlinkability — not raw throughput — is the point.

---

## 12. Sovereign rooms (Phase 11 — cryptographic chatrooms, no server-side room)

A DRIFT room is **not** a server-side chatroom. There is no row in any database,
no object the relay owns, nothing to subpoena. A room exists purely as **math**:
a shared secret derived from its name. Anyone who knows the name derives the same
key material and participates; anyone who does not cannot find the room, read it,
or even prove it exists. Like groups (Section 11), this is composition of
primitives we already have — HKDF, HMAC, XChaCha20-Poly1305, Ed25519 — not a new
construction.

**Key schedule.** `room_secret = HKDF(SHA256(room_name), info="drift-room-v1",
length=64)`, split into a 32-byte content key (`encrypt_key`) and a 32-byte
address seed (`scan_key`). The name is the password: derivation is byte- and
case-exact, so `cats` and `Cats` are entirely different rooms.

**Rotating addresses.** A room never uses a fixed relay address — that would let
the relay correlate all of a room's traffic. Instead the address rotates every
10 minutes on a deterministic schedule every participant computes independently:
`room_addr_n = HKDF(scan_key, info="drift-room-addr-" + n)`, `n = unix // 600`.
The relay sees a stream of blobs landing at addresses that change every ten
minutes with nothing tying them together. Clients scan the current window plus
the previous three (≈30 minutes) to catch up, and ask the relay — via a capped
`ttl_seconds` on `/send` — to retain room blobs long enough for that catch-up.
The relay change for the entire feature is exactly this one optional retention
knob; it never learns a room exists.

**Sender tags.** Each message carries `HMAC(auth_key, ephemeral_pub)` where
`ephemeral_pub` is a per-session value. This proves the sender knows the room
secret (or, for invite rooms, the posting key) without revealing *which*
participant they are. The first 4 hex chars are shown as a pseudonym (`[a3f9]`).

**Three tiers.** *Open* — anyone with the name reads and posts. *Invite* —
anyone with the name reads; posting needs an invite token that derives a separate
posting key, and honest clients reject a post whose tag doesn't verify under it
(a lurker reads, a token-holder posts). *Dark* — no human-readable name at all;
the room *is* a random 64-byte secret exchanged out of band as a QR code,
undiscoverable by anyone who hasn't scanned it.

**Room shards (the outside-the-box bit).** A room may be split across several
federation relays: each shard has its own address schedule on its own relay, and
clients subscribe to all shards and merge locally. No single relay sees the whole
room, and taking one down doesn't kill it — the Phase 4 federation, used for
something it was never explicitly designed for. The shard list travels in the
room's QR code.

### Be honest about the costs

- **Rooms are encrypted but NOT forward-secret.** Anyone who ever learns the room
  secret can decrypt *all* past and future room messages — there is no ratchet,
  because there is no pairwise channel to ratchet. This is inherent to a
  shared-key construction. The lock shows 🔒, never 🔒⁺, even over Tor, and the
  UI says so out loud. If you need forward secrecy, use a 1:1 chat or a group.

- **The sender tag is within-session consistency, not identity.** You can tell
  that two messages in one session came from the same sender; you cannot link
  that sender to a real identity, to a contact code, or across sessions (a new
  session draws a new ephemeral and thus an unlinkable tag). It is a pseudonym,
  not a name. An optional Ed25519-signed display name lets a sender *choose* to
  attach a name, bound to their session ephemeral — but that's opt-in vanity, not
  an authenticated identity.

- **Open rooms are as guessable as their name.** Treat room names as *passwords,
  not usernames*. A short or common name (`test`, `chat`, `nyc`) is a weak room
  anyone can guess their way into. There is no membership list to gate entry —
  knowing the name *is* membership. The invite token can't be enforced as
  one-use either: the relay is blind, so every holder of a token shares the same
  posting capability; revoking posting means rotating the room.

- **The rotating address hides room traffic from the relay, not from a global
  passive adversary.** Someone who watches all traffic to all relays at once can
  still time-correlate — the same caveat that applies to the rest of DRIFT. The
  rotation defeats a single relay correlating a room's blobs; it does not defeat
  a global observer, and we don't claim it does.

### Why this is still worth shipping

A surveillance state cannot subpoena a room that has no server-side
representation beyond opaque ciphertext indexed by rotating stealth addresses.
The relay's WITNESS certificate (Section 6) counts room messages in
`messages_routed` and attributes exactly zero of them to any sender or recipient
— the same structural blindness as 1:1 traffic. That is the point: not that
rooms are the most secure channel in DRIFT (they are deliberately not), but that
a whole public conversation can exist with no server that owns it, knows it, or
can be compelled to give it up.
