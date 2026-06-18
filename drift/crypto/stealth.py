"""
drift.crypto.stealth — rotating stealth addresses (Phase 1, live)

A stealth address lets a sender post a message for a recipient without
the relay ever learning which recipient it's for, and without any two
messages being linkable to the same recipient. Every message lands at a
unique, randomly-derived one-time address; only the recipient — scanning
with their private scan key — can detect it.

The construction is adapted from Monero's stealth address scheme, using
X25519 (Curve25519) DH plus libsodium's ed25519 group operations for the
point arithmetic X25519 doesn't expose (the iron rule: no hand-rolled
field math; see the "Curve helpers" note below).

Scan / spend privilege separation (audit M1)
--------------------------------------------
The scan and spend keys carry **different** privilege:

  * **scan key** — detection. The one-time address binds the *public*
    spend key and is derived from ``ECDH(scan, R)`` only, so a device
    holding just the private *scan* key can confirm a message is
    addressed to the user (``scan_for_message`` → :class:`ScanResult`)
    without being able to read it.
  * **spend key** — decryption. The message key is
    ``HKDF(ECDH(scan, R) ‖ ECDH(spend, R))`` — it folds in a second DH
    against the *spend* key, so the private spend key is *required* to
    finish the derivation (:func:`derive_message_key_with_spend`).

A scan-only delegate therefore filters mail but cannot open it; the two
secrets are not interchangeable. See DESIGN.md §2.

Protocol
--------
Given the recipient's public ``scan_pub`` / ``spend_pub`` (32 bytes each):

Sender (``derive_one_time_address``), with a fresh ephemeral ``(r, R=r·G)``:
  s_scan   = ECDH(r, scan_pub)
  s_spend  = ECDH(r, spend_pub)
  A_once   = B + SHA256(s_scan)·G        # B = _spend_point(spend_pub)
  msg_key  = HKDF(s_scan ‖ s_spend, info=b"drift-v2-msg")

Receiver, in two steps:
  1. detect (scan key)  — s_scan = ECDH(scan_priv, R); ours iff
       B + SHA256(s_scan)·G == A_once → :class:`ScanResult`
  2. decrypt (spend key) — s_spend = ECDH(spend_priv, R);
       msg_key = HKDF(s_scan ‖ s_spend, info=b"drift-v2-msg")

The ``drift-v1-msg`` (scan-only) message key from ``v0.14.0`` and earlier
is intentionally incompatible: binding the spend key changes the derived
key, so peers must both run the M1 fix to interoperate.
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
# v2 (audit M1): the message key folds in a second DH against the spend key, so
# it is deliberately incompatible with the scan-only v1 key (drift-v1-msg).
_MSG_KEY_INFO = b"drift-v2-msg"


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

    The caller supplies the ephemeral keypair (r, R):
        s_scan   = ECDH(ephemeral_priv, scan_pub)
        s_spend  = ECDH(ephemeral_priv, spend_pub)
        A_once   = spend_point(spend_pub) + SHA256(s_scan)·G
        msg_key  = HKDF(s_scan ‖ s_spend, info="drift-v2-msg")

    The address is derived from the scan DH alone (so a scan-only receiver
    can detect it), but the message key additionally folds in the spend DH,
    so only the holder of the private *spend* key can decrypt (audit M1).

    Returns:
        (one_time_addr_bytes, message_key_bytes)

    Both 32 bytes. `one_time_addr_bytes` goes in the envelope header;
    `message_key_bytes` is used directly with drift.crypto.encrypt().
    """
    s_scan = _ecdh(ephemeral_priv, recipient_scan_pub)
    s_spend = _ecdh(ephemeral_priv, recipient_spend_pub)
    one_time_addr = _address_from_secret(s_scan, recipient_spend_pub)
    message_key = derive_message_key(s_scan + s_spend, info=_MSG_KEY_INFO)
    return one_time_addr, message_key


class ScanResult(NamedTuple):
    """Partial result of a scan-key-only detection (audit M1).

    Returned by :func:`scan_for_message` when a message is addressed to us.
    It *confirms ownership* but is deliberately insufficient to decrypt:
    deriving the message key additionally requires the private *spend* key,
    via :func:`derive_message_key_with_spend`. A scan-only device can produce
    this result (filter mail) but cannot turn it into a message key.
    """
    ephemeral_pub: bytes   # R — needed for the spend-side ECDH in step 2
    scan_secret: bytes     # s_scan = ECDH(scan_priv, R) — the intermediate


def scan_for_message(
    envelope_ephemeral_pub: bytes,
    envelope_one_time_addr: bytes,
    my_scan_priv: bytes,
    my_spend_pub: bytes,
) -> ScanResult | None:
    """
    Receiver step 1 (scan key only): check if an envelope is addressed to us.

        s_scan   = ECDH(scan_priv, R)
        A'       = spend_point(my_spend_pub) + SHA256(s_scan)·G
        ours iff   A' == envelope_one_time_addr

    Returns:
        A :class:`ScanResult` (confirmed ownership + the intermediate scan
        secret) if the envelope is ours, else None.

    This step needs only the private *scan* key and the public spend key, so
    a scan-only delegate can run it. It does **not** yield a message key — pass
    the result to :func:`derive_message_key_with_spend` with the private spend
    key for that (audit M1).
    """
    s_scan = _ecdh(my_scan_priv, envelope_ephemeral_pub)
    candidate = _address_from_secret(s_scan, my_spend_pub)
    # Constant-time compare so scanning doesn't leak via timing.
    if not hmac.compare_digest(candidate, envelope_one_time_addr):
        return None
    return ScanResult(ephemeral_pub=envelope_ephemeral_pub, scan_secret=s_scan)


def derive_message_key_with_spend(
    scan_result: ScanResult,
    my_spend_priv: bytes,
) -> bytes:
    """
    Receiver step 2 (spend key required): turn a confirmed :class:`ScanResult`
    into the message key.

        s_spend  = ECDH(spend_priv, R)
        msg_key  = HKDF(scan_secret ‖ s_spend, info="drift-v2-msg")

    Only the holder of the private *spend* key can complete this — the scan
    key alone cannot (audit M1). The returned key can be passed directly to
    drift.crypto.decrypt().
    """
    s_spend = _ecdh(my_spend_priv, scan_result.ephemeral_pub)
    return derive_message_key(scan_result.scan_secret + s_spend, info=_MSG_KEY_INFO)
