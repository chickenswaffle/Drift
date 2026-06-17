# WITNESS — live cryptographic proof of relay blindness

Most messengers ask you to *trust* that the server doesn't log. DRIFT's relays
publish a signed, hash-chained transparency log that lets you **verify** it
instead. This document explains exactly what that proves, what it does not, and
how to check it yourself — including without the DRIFT client.

---

## 1. What WITNESS is

Every 60 seconds a DRIFT relay generates and signs a **blindness certificate**:
a small structured document recording what it provably *cannot* know about the
traffic it just routed. Each certificate embeds the SHA256 hash of the previous
one, so the certificates form a tamper-evident **hash chain** — a transparency
log of the relay's behaviour, minute by minute.

A certificate (`drift-witness-v1`) contains:

| Field | Meaning |
|-------|---------|
| `version` | `"drift-witness-v1"` |
| `relay_id` | the relay's long-term Ed25519 **public** key (hex) |
| `timestamp` | unix seconds the certificate was sealed |
| `period_seconds` | the witnessed window (60) |
| `messages_routed` | how many envelopes the relay routed in the period |
| `sender_identities_known` | **always 0** — sealed sender |
| `recipient_identities_known` | **always 0** — one-time stealth addresses |
| `contents_readable` | **always 0** — end-to-end encrypted |
| `conversations_linked` | **always 0** — unlinkable envelopes |
| `envelope_merkle_root` | Merkle root over the period's routed envelopes |
| `previous_cert_hash` | SHA256 of the previous certificate's canonical bytes |
| `relay_signature` | Ed25519 signature over every other field |
| `statement` | the same claim in plain English |

The four zero counters are not a setting the operator chose — they are
structural consequences of the protocol (sealed sender, stealth addressing, E2E
encryption, unlinkable envelopes; see `DESIGN.md` §5). The certificate is the
relay putting its signature on that fact, every minute.

---

## 2. What it proves — and what it does not

**It proves:** over the window of certificates you can fetch (up to the last
1440 = 24 hours), the relay produced an unbroken, signed chain of blindness
statements. Because each is signed by the relay's long-term key and chained to
its predecessor, the relay **cannot retroactively rewrite that history** without
the private key. The receipts are real.

**It does not prove the future.** A certificate signed at 09:42 says nothing
about what the relay does at 09:43. The guarantee is *continuity*, evaluated
moment to moment: as long as new, correctly-chained certificates keep arriving
on schedule, the relay is still behaving. The instant they stop — or the chain
resets — you know something changed. That is why the watcher
(`drift witness subscribe`) matters: WITNESS is a *liveness* guarantee, not a
one-time stamp.

**It is not a content audit.** WITNESS proves the relay is not accumulating the
metadata it structurally cannot see. It does not, and cannot, vouch for your
endpoint, your peer's device, or the correctness of the wider protocol.

---

## 3. The threat model: a compelled relay

Suppose a relay operator is served a legal order to start logging — to record
who sends what to whom. What can they actually do?

- **Keep routing and keep publishing honest certificates.** Then they are not
  logging, and the order is unsatisfied. The certificates remain true.
- **Start logging but keep publishing certificates that say they aren't.** This
  requires signing a *false* statement with the relay's long-term key — a
  deliberate, attributable lie under a key they published. And it changes
  nothing about what they *can* log: sealed sender and stealth addressing mean
  there is no sender identity or recipient identity in the envelope to record in
  the first place. The certificate's zeros are structural; the relay cannot
  manufacture data it never received.
- **Stop publishing certificates** (the realistic move). The moment it stops,
  the chain develops a **gap** — a missing 60-second window — and every watcher
  detects it within a period. Going dark *is* the tell.
- **Reset the chain / mint a new identity.** A fresh chain starts again from the
  genesis hash under a *different* (or re-genesised) key. A verifier sees the
  `previous_cert_hash` no longer links to the history it had, or the `relay_id`
  changed — a chain **reset**, treated exactly like a break.
- **Forge a different past.** Impossible without the relay's Ed25519 private key.
  Every certificate is signed; altering any field invalidates the signature, and
  re-signing requires the secret key. There is no way to splice a doctored
  history into a chain a watcher has already partly seen.

The honest summary: a compelled relay can stop, but it cannot *silently* comply.
Every path either leaves the certificates true or visibly breaks the chain.

---

## 4. The Merkle tree

During each period the relay collects, for every routed envelope, the leaf
`SHA256(envelope_id)`, where `envelope_id` is derived only from already-public
wire fields (the relay's per-message id, or a hash of the opaque `to`/`ct`/`ts`/
`addr` fields it already broadcasts). It then builds a plain binary Merkle tree:

- pair adjacent leaves and hash each pair as `SHA256(left ‖ right)`;
- if a level has an odd number of nodes, duplicate the last one before pairing;
- repeat until one root remains.

If the relay routed nothing in a period, the root is the fixed constant
`SHA256("empty-period")`.

This lets anyone later prove *"this envelope was routed in this period"* (via a
standard Merkle inclusion proof) without the relay revealing anything about the
envelope's content or its parties — the leaf is a hash of public routing bytes,
nothing more. It is a commitment to the *volume and set* of routed traffic, not
a window into it.

---

## 5. Verify it with the DRIFT client

```
$ drift witness verify ws://localhost:8765
Verifying DRIFT relay: ws://localhost:8765
  ✓ Fetched 1440 certificates (24.0 hours)
  ✓ All 1440 signatures valid
  ✓ Hash chain intact — no gaps or resets
  ✓ Period coverage complete — no missing windows
  ✓ Relay has provably never held sender identities
  ✓ Relay has provably never held recipient identities
  ✓ Current Merkle root: 8f3a2b1c…2b9c
  ✓ Relay identity fingerprint: river-amber-tiger-92

This relay's blindness is cryptographically verified.
```

On a broken chain it tells you precisely what failed, e.g.:

```
  ✗ Gap detected between certificate 441 and 442
    Missing window: 2026-06-15 03:42:00 — 03:43:00 UTC
    This may indicate the relay was compelled to modify its behavior.
    Treat this relay as potentially compromised.
```

Run the live watcher in a terminal next to your chat — it prints a dot per good
minute and shouts the instant the chain breaks:

```
$ drift witness subscribe ws://localhost:8765
Watching ws://localhost:8765 — verifying every new certificate. Ctrl+C to stop.
· · · · · · · · · ·
⚠ CHAIN BREAK DETECTED — relay may be compromised
```

There is also a human-facing page at **`/cannot-see`** — the current certificate
rendered in plain English, suitable for sharing. (`drift witness verify` pins
the relay's published key, so a man-in-the-middle swapping in a different relay's
chain is caught by the `relay_id` mismatch — confirm the fingerprint out of
band the first time, the same as a contact safety number.)

---

## 6. Verify it without the DRIFT client

The format is deliberately boring so you can check it with standard tools.

**Fetch the public key and a certificate:**

```bash
curl -s http://localhost:8765/witness/pubkey
curl -s http://localhost:8765/witness/current | python3 -m json.tool
```

**Check the hash chain** — each certificate's `previous_cert_hash` must equal
the SHA256 of the previous certificate's canonical bytes (the full JSON, keys
sorted, no spaces, byte fields as hex, *including* `relay_signature`):

```python
import hashlib, json, sys

def canonical(cert):
    fields = ["version","relay_id","timestamp","period_seconds","messages_routed",
              "sender_identities_known","recipient_identities_known","contents_readable",
              "conversations_linked","envelope_merkle_root","previous_cert_hash",
              "statement","relay_signature"]
    return json.dumps({k: cert[k] for k in fields}, sort_keys=True,
                      separators=(",", ":")).encode()

def cert_hash(cert):
    return hashlib.sha256(canonical(cert)).hexdigest()

certs = json.load(sys.stdin)["certificates"]      # from /witness/chain
for prev, cur in zip(certs, certs[1:]):
    assert cur["previous_cert_hash"] == cert_hash(prev), "chain break!"
print("chain intact:", len(certs), "certificates")
```

**Check a signature** — the relay signs the canonical bytes of every field
*except* `relay_signature`:

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

def signing_payload(cert):
    fields = ["version","relay_id","timestamp","period_seconds","messages_routed",
              "sender_identities_known","recipient_identities_known","contents_readable",
              "conversations_linked","envelope_merkle_root","previous_cert_hash","statement"]
    return json.dumps({k: cert[k] for k in fields}, sort_keys=True,
                      separators=(",", ":")).encode()

cert = certs[-1]
pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(cert["relay_id"]))
pub.verify(bytes.fromhex(cert["relay_signature"]), signing_payload(cert))  # raises if bad
print("signature valid")
```

`openssl` users can equivalently feed the raw Ed25519 public key and the
`signing_payload` bytes to `openssl pkeyutl -verify`. The point is that nothing
here depends on DRIFT-specific code: it is SHA256 and Ed25519 over canonical
JSON.

---

## 7. What this means for legal demands

This section is deliberately precise, not triumphant.

A subpoena or production order for "all messages sent by Alice," or "the IP
addresses that contacted account X," presupposes that the server holds data of
that shape. A DRIFT relay does not, and the certificates are the standing
receipts for *why*:

- There is **no account** to name. Identity is a keypair; the relay never sees
  it.
- There is **no sender field** to disclose. Sealed sender encrypts sender-linking
  metadata inside the payload; `sender_identities_known = 0` every minute.
- There is **no recipient inbox** to enumerate. Every message lands at a fresh
  one-time stealth address; `recipient_identities_known = 0`.
- There is **no readable content**. It is end-to-end encrypted;
  `contents_readable = 0`.
- There is **no conversation graph**. Envelopes are unlinkable;
  `conversations_linked = 0`.

So a lawful demand for user data reaches a relay that *provably has no such
data* — and can demonstrate, with a signed 24-hour chain, that it had none over
the relevant window. The relay can comply fully and produce nothing, because
there is nothing of that kind to produce.

What WITNESS does **not** claim: it is not legal advice, it does not place the
operator above the law, and it cannot stop a court from compelling the operator
to *change* the relay's behaviour going forward. What it changes is that such a
change cannot be silent: a relay that begins logging must either lie under its
own published key or break a chain that anyone in the world can watch. The
certificates turn "trust us, we don't log" into "here is the math — check it."

---

*See also: `relay/witness.py` (certificate + chain), `relay/server.py`
(`/witness/*` and `/cannot-see` endpoints), `drift/cli.py`
(`drift witness verify` / `subscribe`), and `DESIGN.md` §6.*
