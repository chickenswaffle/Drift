"""
drift.crypto.cover — cover traffic (Phase 4)

Closes the *traffic-analysis* gap in DRIFT's threat model. Sealed sender and
stealth addressing already hide *who* talks to *whom* and *what* is said, but an
observer watching the wire could still learn *when* a user is active and *how
much* they send — the shape of a conversation leaks through volume and timing
even when the content does not.

Cover traffic fills that gap with two complementary measures, both composed from
primitives already in the codebase (``os.urandom`` and the project's AEAD
framing) — no new crypto:

1. **Dummy envelopes on a Poisson schedule.** While a :class:`~drift.transport.session.Session`
   is active, a Poisson-process scheduler (:func:`next_interval`) fires
   cryptographically indistinguishable dummy envelopes (:func:`make_dummy_envelope`)
   at random intervals. A dummy carries a random 32-byte stealth address and a
   random ``COVER_PAYLOAD_SIZE``-byte ciphertext, so on the wire it is byte-for-
   byte the same shape as a real steady-state message. No recipient's scan key
   matches a dummy's random address, so every client silently drops it — it is
   pure noise that hides the gaps between real messages. The rate is a dial:
   ``LOW`` averages one dummy every 20 s, ``HIGH`` one every 5 s, ``OFF`` none.

2. **Uniform message size.** A real message's ciphertext length otherwise leaks
   its plaintext length. :func:`pad_to_cover_size` pads the *plaintext* (inside
   the AEAD, so the real length is encrypted, never on the wire) to a fixed
   ``COVER_MESSAGE_SIZE`` before it is ratchet-encrypted, so every padded message
   produces the same ``COVER_PAYLOAD_SIZE`` wire ciphertext — matching the
   dummies. :func:`unpad_from_cover` reverses it on receipt and is *tolerant*: a
   message that was never padded is returned unchanged, so the receive path can
   apply it unconditionally without knowing the sender's cover setting.

Honest limits
-------------
- Cover applies to the 1:1 :class:`Session` only; group/room traffic is not
  padded or covered in this phase.
- Only *steady-state* messages match the dummy size exactly. The handful of
  opening (bootstrap) messages carry extra X3DH / forward-secrecy handshake
  material in their sealed header, so they are slightly larger — an observer can
  tell "a session just opened", but not its contents, parties, or later volume.
- Timing is drawn from a CSPRNG (:data:`secrets.SystemRandom`), so dummy
  intervals are unpredictable and a watcher cannot pre-compute when a dummy is
  due in order to distinguish it from a real send.
"""

from __future__ import annotations

import os
import secrets
from enum import Enum
from typing import NamedTuple

from drift.crypto import NONCE_SIZE

# ---------------------------------------------------------------------------
# The dial
# ---------------------------------------------------------------------------

# Poisson rates (events per second): the mean inter-arrival is 1/λ.
_LAMBDA_LOW = 1.0 / 20.0   # one dummy every ~20 s on average
_LAMBDA_HIGH = 1.0 / 5.0   # one dummy every ~5 s on average


class CoverLevel(Enum):
    """How much cover traffic a session emits."""

    OFF = "off"
    LOW = "low"
    HIGH = "high"

    @classmethod
    def parse(cls, value: str) -> CoverLevel:
        """Parse ``off`` / ``low`` / ``high`` (case-insensitive); raise on junk."""
        try:
            return cls(value.strip().lower())
        except ValueError as exc:
            raise ValueError(
                f"unknown cover level {value!r} — use off, low, or high"
            ) from exc


_RATES: dict[CoverLevel, float] = {
    CoverLevel.LOW: _LAMBDA_LOW,
    CoverLevel.HIGH: _LAMBDA_HIGH,
}

# A cryptographically secure RNG for the inter-arrival draw, so dummy timing is
# unpredictable (a predictable schedule would let a watcher tell dummies apart).
_rng = secrets.SystemRandom()


def next_interval(level: CoverLevel) -> float:
    """Seconds to wait before the next dummy — an exponential (Poisson) draw.

    The inter-arrival time of a Poisson process with rate ``λ`` is
    ``Exponential(λ)``; we sample it from a CSPRNG. Raises :class:`ValueError`
    for :attr:`CoverLevel.OFF`, which has no schedule.
    """
    rate = _RATES.get(level)
    if rate is None:
        raise ValueError("cover is off — there is no scheduling interval")
    return _rng.expovariate(rate)


# ---------------------------------------------------------------------------
# Sizes — a dummy must be the same wire shape as a real steady-state message
# ---------------------------------------------------------------------------

_ADDR_LEN = 32          # one-time stealth address
_AEAD_TAG = 16          # Poly1305 tag
_SEAL_LEN_PREFIX = 2    # sealed-sender u16 header-length prefix
# Double Ratchet header on the wire: dh(32) ‖ pn(4) ‖ n(4) — see crypto.ratchet.
_RATCHET_HEADER = 32 + 4 + 4
# Sealed-sender inner payload, steady state: flag(1) ‖ ratchet header.
_INNER = 1 + _RATCHET_HEADER
# sealed_header = AEAD(inner): nonce ‖ ciphertext ‖ tag.
_SEALED_HEADER = NONCE_SIZE + _INNER + _AEAD_TAG

# Fixed plaintext size every padded message is stretched to (its true length is
# carried inside the AEAD, so it never reaches the wire). Generous enough for a
# chat line; longer messages raise in cover mode.
COVER_MESSAGE_SIZE = 1024
_PAD_MARKER = 0xFF      # invalid as a UTF-8 leading byte → never collides with a
                        # real (UTF-8 text) message that was not padded.
_PAD_HEADER = 1 + 2     # marker(1) ‖ u16 real length

# The resulting uniform wire-ciphertext size: a sealed blob is
# R(32) ‖ u16 ‖ sealed_header ‖ ratchet_ciphertext, where the ratchet ciphertext
# is AEAD(padded plaintext) = nonce ‖ COVER_MESSAGE_SIZE ‖ tag.
COVER_PAYLOAD_SIZE = (
    _ADDR_LEN + _SEAL_LEN_PREFIX + _SEALED_HEADER
    + NONCE_SIZE + COVER_MESSAGE_SIZE + _AEAD_TAG
)


class CoverEnvelope(NamedTuple):
    """The wire fields of a dummy envelope (kept network-free, no transport import).

    The :class:`~drift.transport.session.Session` wraps these into a transport
    ``Envelope`` and ships them; this module only mints the indistinguishable
    bytes.
    """

    one_time_addr: bytes   # random 32-byte address (looks exactly like a real A_once)
    ciphertext: bytes      # random COVER_PAYLOAD_SIZE bytes (size of a padded real blob)


def make_dummy_envelope() -> CoverEnvelope:
    """A fresh dummy: a random stealth address + a random, real-sized ciphertext.

    Both halves are uniform random bytes, so the dummy is indistinguishable on
    the wire from a real sealed message and no scan key will ever match it (so
    every client drops it).
    """
    return CoverEnvelope(os.urandom(_ADDR_LEN), os.urandom(COVER_PAYLOAD_SIZE))


# ---------------------------------------------------------------------------
# Uniform message size (plaintext padding, hidden inside the AEAD)
# ---------------------------------------------------------------------------

def pad_to_cover_size(message: bytes) -> bytes:
    """Pad a plaintext message to the fixed :data:`COVER_MESSAGE_SIZE`.

    Layout: ``marker(1) ‖ u16(len) ‖ message ‖ zero-fill``. Because this is done
    *before* ratchet encryption, the real length is sealed inside the AEAD and
    never appears on the wire — every padded message yields the same
    ``COVER_PAYLOAD_SIZE`` ciphertext. Raises :class:`ValueError` if the message
    is too long to fit.
    """
    if len(message) > COVER_MESSAGE_SIZE - _PAD_HEADER:
        raise ValueError(
            f"message too long for cover mode "
            f"(max {COVER_MESSAGE_SIZE - _PAD_HEADER} bytes, got {len(message)})"
        )
    body = bytes([_PAD_MARKER]) + len(message).to_bytes(2, "big") + message
    return body + b"\x00" * (COVER_MESSAGE_SIZE - len(body))


def unpad_from_cover(plaintext: bytes) -> bytes:
    """Reverse :func:`pad_to_cover_size`; return non-padded input unchanged.

    Tolerant by design: it only strips a payload that is exactly
    ``COVER_MESSAGE_SIZE`` bytes *and* carries the pad marker, so the receive
    path can apply it to every decrypted message without knowing whether the
    sender used cover mode. A message that was never padded (an off-mode peer, or
    any non-1:1 path) falls through unchanged.
    """
    if len(plaintext) != COVER_MESSAGE_SIZE or plaintext[0] != _PAD_MARKER:
        return plaintext
    n = int.from_bytes(plaintext[1:3], "big")
    if _PAD_HEADER + n > len(plaintext):
        return plaintext  # marker present but frame inconsistent — leave as-is
    return plaintext[_PAD_HEADER:_PAD_HEADER + n]
