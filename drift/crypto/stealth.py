"""
drift.crypto.stealth — rotating stealth addresses (Phase 1)

This file is a documented placeholder. The function signatures and
docstrings define the exact interface Phase 1 will implement.
The protocol math is described precisely so a contributor can build
it without needing to re-read the design doc.

Background
----------
A stealth address lets a sender post a message for a recipient
without the relay ever learning which recipient it's for, and
without any two messages being linkable to the same recipient.

Every message lands at a unique, randomly-derived one-time address.
Only the recipient — scanning with their private scan key — can
detect it.

The technique is adapted from Monero's stealth address scheme,
using X25519 (Curve25519) instead of Monero's ed25519 variant.

Protocol (sender side)
-----------------------
Given:
  scan_pub   = recipient's public scan key  (32 bytes, X25519)
  spend_pub  = recipient's public spend key (32 bytes, X25519)

1.  Generate a random ephemeral keypair: (r, R)  where R = r·G
2.  Shared secret:  s = ECDH(r, scan_pub)
         → 32-byte raw X25519 output
3.  Derived scalar: h = SHA-256(s)
         → interpreted as a big-endian integer mod l
         (l = 2^252 + 27742317777372353535851937790883648493, the curve order)
4.  One-time address (as a compressed point):
         A_once = spend_pub + h·G
         → 32-byte Ristretto255 or X25519 point
5.  Message payload: { "R": b58(R), "addr": b58(A_once), "ct": b58(ciphertext) }
         where ciphertext = XChaCha20Poly1305_encrypt(
             key = HKDF(s, info=b"drift-v1-msg"),
             plaintext = message_bytes
         )

Protocol (receiver side)
------------------------
For each relay message { R, addr, ct }:
1.  s' = ECDH(scan_priv, R)
2.  h' = SHA-256(s')
3.  Candidate: A' = spend_pub + h'·G
4.  If b58(A') == addr  → message is ours
5.  Decrypt with HKDF(s', info=b"drift-v1-msg")

Implementation note
-------------------
X25519 arithmetic is DH only; it doesn't expose point addition or
scalar multiplication directly. Use the `cryptography` library's
low-level Curve25519 bindings or the `pure25519` library which
exposes the group operations needed for step 4 and step 3 above.

Alternatively, implement on Ristretto255 via the `ristretto255`
PyPI package which wraps libsodium's group operations cleanly.
"""

from __future__ import annotations

from typing import NamedTuple


class StealthEnvelope(NamedTuple):
    """Wire format for a stealth-addressed message (Phase 1)."""
    ephemeral_pub: bytes   # R  — 32 bytes
    one_time_addr: bytes   # A_once — 32 bytes
    ciphertext: bytes      # XChaCha20-Poly1305 payload including nonce


def derive_one_time_address(
    ephemeral_priv: bytes,
    recipient_scan_pub: bytes,
    recipient_spend_pub: bytes,
) -> tuple[bytes, bytes]:
    """
    (Phase 1 — not yet implemented)

    Sender: derive the one-time address and the encryption key.

    Returns:
        (one_time_addr_bytes, message_key_bytes)

    Both 32 bytes. `one_time_addr_bytes` goes in the envelope header;
    `message_key_bytes` is used directly with drift.crypto.encrypt().
    """
    raise NotImplementedError("Phase 1: stealth address derivation not yet implemented")


def scan_for_message(
    envelope_ephemeral_pub: bytes,
    envelope_one_time_addr: bytes,
    my_scan_priv: bytes,
    my_spend_pub: bytes,
) -> bytes | None:
    """
    (Phase 1 — not yet implemented)

    Receiver: check if an envelope is addressed to us.

    Returns:
        message_key_bytes (32 bytes) if the envelope is ours, else None.

    The returned key can be passed directly to drift.crypto.decrypt().
    """
    raise NotImplementedError("Phase 1: stealth address scanning not yet implemented")
