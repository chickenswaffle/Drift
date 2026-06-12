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
- **Traffic analysis** — who-talks-to-whom and when are obscured by sealed sender, onion transport, and cover traffic.
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
| Scan key | X25519 | Lets others derive one-time addresses *to* you; lets you detect your mail |
| Spend key | X25519 | The secret that actually unlocks a detected message |

(The "scan / spend" split is borrowed from stealth-address systems. Keeping them separate means you could one day hand a *scan-only* key to a low-power device to filter your mail without ever giving it the power to read.)

Your shareable identity — your **contact code** — is just a compact encoding of your three public keys, e.g. `drift:aV9k7Hk2...Q2x`, also renderable as a QR code. There is no username registry, no phone number, no email. Your identity *is* your key material.

---

## 3. The headline feature: rotating stealth addresses

This is the "address that rotates and never gets pinned to one user" you asked for. The mechanism (the diagram in chat shows the flow):

**Sending to Alice**, Bob's client:
1. Generates a throwaway ephemeral keypair `(r, R)`.
2. Computes a shared secret `s = ECDH(r, Alice_scan_pub)`.
3. Derives a **one-time address**: `A_once = Alice_spend_pub + Hash(s)·G` (point addition on the curve).
4. Posts `{ R, ciphertext }` to the mailbox keyed by `A_once`.

Every message produces a *different* `A_once`. To the relay these look like uniform random strings with no link to Alice and no link to each other.

**Receiving**, Alice's client periodically scans posted messages:
1. For each `{ R, ... }`, compute `s' = ECDH(Alice_scan_priv, R)`.
2. Derive candidate `A' = Alice_spend_pub + Hash(s')·G`.
3. If `A'` equals the mailbox address, the message is hers — and `s'` also yields the decryption key.

Only Alice can run this match, because only she has `scan_priv`. The relay is a public bulletin board of opaque, unlinkable blobs.

**The tradeoff (be honest about it):** scanning means Alice does a little work per message in the system. At small scale, just scan recent messages — it's nothing. As it grows, three escalating fixes:
- **Time/shard bucketing** — only scan the windows or shards you could plausibly have mail in.
- **Fuzzy Message Detection (FMD)** — a real cryptographic scheme that lets the server pre-filter a *subset* of messages for you with a tunable false-positive rate. It's literally an anonymity dial: more noise = more privacy = more scanning.
- **Private Information Retrieval (PIR)** — heavyweight, but lets you fetch your mailbox without the server learning which mailbox. Save this for "phase 99."

---

## 4. Message encryption: the Double Ratchet

Once the first message establishes a shared secret (via an X3DH-style handshake built on the stealth keys above), the conversation runs Signal's **Double Ratchet**. You don't need to invent this — it's well documented and there are vetted implementations to learn from.

It buys you two things that static keys can't:
- **Forward secrecy** — steal today's keys and *past* messages remain unreadable.
- **Post-compromise security** — if someone briefly steals a key, the ratchet "heals" and future messages become secure again.

Every individual message is sealed with an AEAD cipher — use **XChaCha20-Poly1305** (the extended-nonce variant is forgiving about nonce handling, which is exactly what you want when you're learning).

---

## 5. Metadata privacy: the genuinely hard layer

Hiding *content* is solved. Hiding *who talks to whom* is where most messengers quietly fall short. DRIFT layers several defenses:

- **Sealed sender** — sender-linkable metadata is encrypted *inside* the payload, so the relay sees only the recipient's one-time address and an opaque blob (see the subsection below).
- **Onion transport over Tor by default** — the relay never sees your real IP. The client should bootstrap Tor automatically so the user never thinks about it. (A mixnet like Nym/Loopix is the stronger, heavier upgrade for defeating timing analysis — a later phase.)
- **Cover traffic** — the client sends decoy messages on a randomized schedule so that *volume and timing* leak nothing. An observer can't tell a real conversation from silence.
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

A beacon lets a user *light* a short human handle (e.g. `Diego552`) for a few minutes. While it's lit, **anyone who knows that exact handle** can resolve it to the user's contact code and add them. The relay indexes the beacon by `SHA256("drift-beacon-lookup-v1" ‖ handle)` and stores an opaque blob encrypted under `HKDF(handle, "drift-beacon-v1")` — so the relay never learns the handle or the contact code, only that *some* handle hashing to this value is briefly active. After the TTL (capped at 10 minutes) the entry is **deleted**, not hidden: a lookup afterwards 404s, and there is no retroactive way to discover who was behind it.

The index hash is **domain-separated** (a fixed `drift-beacon-lookup-v1` prefix, not a bare `SHA256(handle)`). This ties the hash to DRIFT's namespace so a relay can't apply a generic, precomputed SHA256 rainbow table to the index. It does **not** defend a *guessable* handle: a relay (or anyone) can still build a DRIFT-specific dictionary and grind common handles. That weakness is inherent to short, human-memorable handles and is mitigated by handle choice, not by the hash.

**Handles are semi-public.** Treat a handle as a low-entropy shared secret, not a password. For anything sensitive, pick something **unguessable** — a random word pair like `copper-lantern` or a random token, not `Alice123`. A predictable handle is dictionary-grindable for as long as the beacon is lit (up to 10 minutes), at which point it links to your contact code.

**What you are trading.** During the window, the handle is a shared secret with a deliberately low bar: anyone you tell it to — and anyone *they* tell, or anyone who guesses a weak handle — can link that handle to your contact code for those minutes. That is a small, bounded amount of **temporal linkability** exchanged for the convenience of being found without exchanging a 90-character contact code out of band. It is opt-in (nothing is discoverable unless you light a beacon), time-boxed (minutes, then gone), and per-handle (lighting `Diego552` says nothing about any other handle or your default traffic).

**What it does *not* give you.** The Ed25519 signature inside a beacon proves the payload wasn't altered in transit, but it does **not** prove the handle's owner is who you expect — a handle is just a string, and anyone can light a beacon claiming any handle and pointing at any contact code. So beacon resolution ends at "here is a contact code," never at "this is definitely Diego." The finder must still confirm the safety number out of band (`drift verify`) before trusting the channel. Beacon is a discovery convenience layered on top of DRIFT's verification model, not a replacement for it.

### Burn requests (Phase 5)

A burn lets either party erase messages after the fact — both clients delete their local copies, and the relay drops any matching blob still sitting in its short replay buffer. A burn is a signed control message: the token is `HMAC(HKDF(static_ECDH), scope ‖ message_id)`, a MAC only the two conversation participants can produce. The relay broadcasts the burn as a **tombstone**; each client *verifies the token end-to-end* before deleting anything. **That verification is the whole security boundary — the relay authenticates nothing.**

**Why the relay can't be trusted to erase a "conversation."** The relay has no shared secret, so it cannot check a burn token. It also cannot tell which buffered blobs belong to one conversation — stealth addresses are unlinkable *by design*, which is the point of the whole system. An earlier version honoured a conversation-scope burn by wiping the entire channel's replay buffer; because the firehose is shared by every user and the relay can't authenticate the request, **any anonymous caller could erase every user's recent traffic with a single POST** (audit finding H2).

**What the relay does now.** Relay-side erasure is addr-scoped only: a burn deletes *only* the single blob whose one-time address is explicitly named (`scope=message`). A `scope=conversation` burn does **not** touch the shared buffer at all. Conversation erasure is delivered entirely end-to-end — each client verifies the token and deletes its own copy on the tombstone — and any blob left in the relay buffer simply expires on its short `RECENT_TTL` (30 s on the full relay).

**The honest tradeoff.**
- A conversation burn no longer instantly clears the relay's buffer; those opaque, already-encrypted blobs linger for up to `RECENT_TTL` before expiring. The *durable* erasure — your peer's stored copy — still happens immediately via the verified tombstone.
- Because a one-time address is public on the firehose (it's the routing key), anyone who *observed* a message can name its address and evict that one blob from the replay buffer. This is bounded: it only affects the ≤30 s late-join window, never a message already delivered to a connected peer, and it is per-message rather than a one-shot channel wipe. Eliminating even this residue needs authenticated, per-recipient storage (Phase 4).
- Burn remains **best-effort against a non-compliant client**: a peer that chooses to ignore the tombstone keeps its copy. Burn defends against honest clients and an honest-but-curious relay, not against an endpoint that has already decided to retain your message.

---

## 6. Infrastructure: "unstoppable" = no single chokepoint

A single server is a single subpoena, a single seizure, a single off-switch. DRIFT spreads the bulletin board out:

- **Federated relays** — anyone can run one. Relays gossip new blobs to each other (think email or Matrix, but the servers are dumb and hold only opaque ciphertext with a TTL).
- **P2P fallback** — two users can talk directly over a Tor onion service with no relay at all, which is genuinely serverless.
- Blobs are content-addressed, replicated, and **expire automatically**, so no relay accumulates a forensic goldmine.

"Unstoppable" comes from the *combination*: open protocol + many independent relays + Tor transport + a serverless mode. There's nothing central to compel or kill.

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

Behind that: Tor bootstraps, keys generate, stealth addresses rotate every message, the ratchet turns, cover traffic hums in the background. The user never reads the word "Curve25519" unless they go looking.

---

## 8. The unorthodox extras (your "outside the box")

These are the features that make DRIFT distinctive rather than "another Signal clone." Pick the ones that excite you:

- **Stealth rotating addresses** — the headline (Section 3). This alone is the differentiator.
- **Fuzzy Message Detection** — a literal privacy/efficiency dial the user can turn.
- **Panic / duress passphrase** — a *second* passphrase that, when entered, silently wipes keys (or unlocks a believable empty decoy inbox). Protection against "unlock it or else" coercion.
- **Decoy contacts and hidden volumes** — a real set of chats behind your true passphrase, an innocuous set behind the duress one. A forced device unlock reveals nothing real.
- **Cover traffic on by default** — silence and conversation look identical on the wire.
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
