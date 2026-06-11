"""
drift.crypto.sealed — sealed sender (Phase 3b)

Removes the last sender-correlatable metadata from the clear envelope. Before
this, the relay saw the sender's ephemeral key ``R`` and — more importantly —
the Double Ratchet header, whose DH ratchet public key stays constant across a
sender's messages within a ratchet epoch and so *links* them. Tor hid the
sender's IP, but the relay could still group a sender's traffic by that header.

Sealed sender folds everything except the recipient's one-time detection
address into a single opaque blob. On the wire the relay now sees only:

  - ``addr``  the recipient's one-time stealth address  (routing/detection)
  - ``ct``    one opaque blob

The blob is::

    R (32 bytes)  ||  u16(len)  ||  sealed_header  ||  ratchet_ciphertext

``R`` is the per-message ephemeral public key. It is *not* encrypted, and it
cannot be: it is the Diffie-Hellman contribution the recipient needs to derive
the stealth secret in the first place (encrypting it under a key derived from
itself is circular). This is the one unavoidable clear value in any ECDH
stealth scheme — but it is fresh every message and reveals nothing about the
sender's identity (DRIFT carries no sender identity to begin with). What this
module *does* seal is the ratchet header, the field that actually linked a
sender's messages.

The sealing key is derived from the stealth shared secret that
``derive_one_time_address`` / ``scan_for_message`` already compute (and which,
until now, the session discarded). Both sides reach the same key:

    seal_key = HKDF(stealth_key, info="drift-sealed-sender-v1")

The recipient's one-time address is bound in as AEAD associated data, so the
relay cannot move a sealed blob onto a different address without the unseal
failing.

This module composes existing primitives (``drift.crypto.encrypt`` /
``derive_message_key``); it implements no curve or cipher math itself.
"""

from __future__ import annotations

import struct

from drift.crypto import decrypt, derive_message_key, encrypt

# Domain separation for the header-sealing key. Versioned: changing it breaks
# wire compatibility with already-deployed clients.
SEAL_INFO = b"drift-sealed-sender-v1"

# Ephemeral X25519 public keys are 32 bytes; the sealed-header length prefix is
# a 2-byte big-endian integer (the ratchet header is well under 64 KiB).
_EPK_LEN = 32
_LEN_PREFIX = struct.Struct(">H")


def _seal_key(stealth_key: bytes) -> bytes:
    """Derive the header-sealing key from the per-message stealth secret."""
    return derive_message_key(stealth_key, info=SEAL_INFO)


def seal(
    stealth_key: bytes,
    ephemeral_pub: bytes,
    ratchet_header: bytes,
    ratchet_ciphertext: bytes,
    *,
    address: bytes = b"",
) -> bytes:
    """
    Build the opaque sealed-sender blob.

    ``stealth_key`` is the per-message key returned by
    ``derive_one_time_address``. ``ephemeral_pub`` is R. ``ratchet_header`` is
    the serialized Double Ratchet header to be sealed. ``address`` is the
    recipient one-time address, bound in as associated data.
    """
    if len(ephemeral_pub) != _EPK_LEN:
        raise ValueError(f"ephemeral_pub must be {_EPK_LEN} bytes, got {len(ephemeral_pub)}")
    sealed_header = encrypt(_seal_key(stealth_key), ratchet_header, associated_data=address)
    return b"".join((
        ephemeral_pub,
        _LEN_PREFIX.pack(len(sealed_header)),
        sealed_header,
        ratchet_ciphertext,
    ))


def parse(blob: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Split a blob into ``(ephemeral_pub, sealed_header, ratchet_ciphertext)``.

    Pure framing — no decryption, no key needed (the recipient needs the
    ephemeral key out before it can derive anything). Raises ``ValueError`` if
    the blob is too short or internally inconsistent, which the caller treats as
    "not a well-formed stealth message" and skips.
    """
    if len(blob) < _EPK_LEN + _LEN_PREFIX.size:
        raise ValueError("sealed blob too short for header")
    ephemeral_pub = blob[:_EPK_LEN]
    (slen,) = _LEN_PREFIX.unpack_from(blob, _EPK_LEN)
    start = _EPK_LEN + _LEN_PREFIX.size
    end = start + slen
    if end > len(blob):
        raise ValueError("sealed blob truncated")
    sealed_header = blob[start:end]
    ratchet_ciphertext = blob[end:]
    return ephemeral_pub, sealed_header, ratchet_ciphertext


def open_header(stealth_key: bytes, sealed_header: bytes, *, address: bytes = b"") -> bytes:
    """
    Decrypt a sealed ratchet header.

    Only called after the stealth scan has already confirmed the message is
    ours, so an authentication failure here is genuine tampering — ``InvalidTag``
    is allowed to propagate (the iron rule), never swallowed.
    """
    return decrypt(_seal_key(stealth_key), sealed_header, associated_data=address)
