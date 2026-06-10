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

import hashlib
import hmac
from typing import NamedTuple

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from nacl import bindings as _sodium

from drift.crypto import derive_message_key

# Domain-separation tags. Changing any of these breaks address compatibility
# with already-deployed clients, so they are versioned (v1).
_SPEND_POINT_TAG = b"drift-stealth-v1-spend-point"
_MSG_KEY_INFO = b"drift-v1-msg"


# ---------------------------------------------------------------------------
# Wire format
# ---------------------------------------------------------------------------

class StealthEnvelope(NamedTuple):
    """Wire format for a stealth-addressed message (Phase 1)."""
    ephemeral_pub: bytes   # R  — 32 bytes
    one_time_addr: bytes   # A_once — 32 bytes
    ciphertext: bytes      # XChaCha20-Poly1305 payload including nonce


# ---------------------------------------------------------------------------
# Curve helpers
#
# All point/scalar arithmetic is delegated to libsodium via PyNaCl
# (`nacl.bindings`), which wraps the audited ref10 ed25519 implementation.
# We never touch field arithmetic ourselves — the iron rule.
#
# X25519 keys are Montgomery-form and expose ECDH only (no point addition),
# so the Monero-style derivation A_once = B + h·G is done on the ed25519
# group. The recipient's X25519 spend key is mapped to a stable ed25519
# point B via Elligator (`crypto_core_ed25519_from_uniform`); both sender
# and receiver derive B identically from the public spend key, so the
# one-time address is a deterministic routing tag that only ECDH-knowing
# parties can compute.
# ---------------------------------------------------------------------------

def _ecdh(private_bytes: bytes, public_bytes: bytes) -> bytes:
    """Raw X25519 Diffie-Hellman → 32-byte shared secret."""
    priv = X25519PrivateKey.from_private_bytes(private_bytes)
    pub = X25519PublicKey.from_public_bytes(public_bytes)
    return priv.exchange(pub)


def _spend_point(spend_pub: bytes) -> bytes:
    """
    Map a recipient's X25519 spend public key to a fixed ed25519 point B.

    Deterministic: both sender and receiver compute the same B from the
    (public) spend key. Uses libsodium's Elligator map so the result is a
    valid curve point regardless of input.
    """
    seed = hashlib.sha256(_SPEND_POINT_TAG + spend_pub).digest()
    return _sodium.crypto_core_ed25519_from_uniform(seed)


def _address_from_secret(shared_secret: bytes, spend_pub: bytes) -> bytes:
    """
    Compute the one-time address A_once = B + h·G for a given ECDH secret.

      h     = SHA-256(s) reduced mod l   (the ed25519 group order)
      h·G   = scalar mult of the base point
      B     = _spend_point(spend_pub)

    Both parties feed the same shared secret here and get the same address.
    """
    # libsodium scalars are little-endian; scalar_reduce takes 64 bytes.
    digest = hashlib.sha256(shared_secret).digest()
    scalar = _sodium.crypto_core_ed25519_scalar_reduce(digest + b"\x00" * 32)
    h_g = _sodium.crypto_scalarmult_ed25519_base_noclamp(scalar)
    return _sodium.crypto_core_ed25519_add(_spend_point(spend_pub), h_g)


# ---------------------------------------------------------------------------
# Sender / receiver entry points
# ---------------------------------------------------------------------------

def derive_one_time_address(
    ephemeral_priv: bytes,
    recipient_scan_pub: bytes,
    recipient_spend_pub: bytes,
) -> tuple[bytes, bytes]:
    """
    Sender: derive the one-time address and the encryption key.

    Steps 2–5 of the protocol (the caller supplies the ephemeral keypair):
        s        = ECDH(ephemeral_priv, scan_pub)
        A_once   = spend_point(spend_pub) + SHA256(s)·G
        msg_key  = HKDF(s, info="drift-v1-msg")

    Returns:
        (one_time_addr_bytes, message_key_bytes)

    Both 32 bytes. `one_time_addr_bytes` goes in the envelope header;
    `message_key_bytes` is used directly with drift.crypto.encrypt().
    """
    shared_secret = _ecdh(ephemeral_priv, recipient_scan_pub)
    one_time_addr = _address_from_secret(shared_secret, recipient_spend_pub)
    message_key = derive_message_key(shared_secret, info=_MSG_KEY_INFO)
    return one_time_addr, message_key


def scan_for_message(
    envelope_ephemeral_pub: bytes,
    envelope_one_time_addr: bytes,
    my_scan_priv: bytes,
    my_spend_pub: bytes,
) -> bytes | None:
    """
    Receiver: check if an envelope is addressed to us.

        s'       = ECDH(scan_priv, R)
        A'       = spend_point(my_spend_pub) + SHA256(s')·G
        ours iff   A' == envelope_one_time_addr
        msg_key  = HKDF(s', info="drift-v1-msg")

    Returns:
        message_key_bytes (32 bytes) if the envelope is ours, else None.

    The returned key can be passed directly to drift.crypto.decrypt().
    """
    shared_secret = _ecdh(my_scan_priv, envelope_ephemeral_pub)
    candidate = _address_from_secret(shared_secret, my_spend_pub)
    # Constant-time compare so scanning doesn't leak via timing.
    if not hmac.compare_digest(candidate, envelope_one_time_addr):
        return None
    return derive_message_key(shared_secret, info=_MSG_KEY_INFO)
