"""
drift.crypto.burn — burn-request token generation and verification

A burn token authorises erasing a message (or signalling a conversation burn).
It is an HMAC-SHA256 MAC keyed with a conversation-specific secret (HKDF from the
static ECDH output, domain-separated from the ratchet key material), but — unlike
the original static design (audit M2) — it is **single-use**: every token carries
a fresh 16-byte random nonce and a creation timestamp, both bound into the MAC and
both carried on the wire as part of the token string.

Wire format (audit M2)::

    <nonce_hex(32)>.<timestamp>.<mac_hex(64)>

The relay (which has no shared secret and cannot verify the MAC) reads the nonce
and timestamp out of the token to (a) reject tokens older than ``TOKEN_TTL_SECONDS``
and (b) reject a nonce it has already seen — a bounded LRU, the same dedup pattern
used for message envelopes. The *receiving client* still verifies the MAC
end-to-end before honouring the tombstone, and additionally rejects a token whose
timestamp is outside the freshness window. Together this closes the replay hole:
a captured token is either stale (client rejects) or its nonce is already burned
(relay won't re-broadcast it).
"""

from __future__ import annotations

import hmac as _hmac
import os
import time

from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# HMAC-SHA256 produces 32 bytes = 64 hex characters.
MAC_HEX_LEN = 64
# Backwards-compatible alias (the MAC portion of the token).
TOKEN_HEX_LEN = MAC_HEX_LEN
NONCE_BYTES = 16
NONCE_HEX_LEN = 2 * NONCE_BYTES  # 32

# A token is valid for five minutes from its embedded timestamp. Outside this
# window both the relay and the client reject it (replay / clock-skew bound).
TOKEN_TTL_SECONDS = 300

VALID_SCOPES = frozenset(("message", "conversation"))


class BurnTokenError(ValueError):
    """Raised when a burn token string is malformed."""


def _derive_burn_key(shared_secret: bytes) -> bytes:
    """Derive a 32-byte burn key via HKDF-SHA256, domain-separated from ratchet."""
    return HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=b"drift-burn-v1",
    ).derive(shared_secret)


def _mac_input(scope: str, message_id: str | None, nonce_hex: str, timestamp: int) -> bytes:
    """The bytes the HMAC covers — scope, target, nonce, and timestamp are all
    bound, so none can be altered without invalidating the token."""
    return f"{scope}:{message_id or ''}:{nonce_hex}:{timestamp}".encode()


def generate_burn_token(
    shared_secret: bytes,
    scope: str,
    message_id: str | None = None,
    nonce: bytes | None = None,
    *,
    timestamp: int | None = None,
) -> str:
    """Return a single-use ``nonce.timestamp.mac`` burn token (audit M2).

    Args:
        shared_secret: Raw ECDH output of the conversation (both sides derive
                       the same value from their static spend keys).
        scope:         ``"message"`` or ``"conversation"``.
        message_id:    For message-scope burns, the base64-encoded one-time
                       stealth address of the target message.  ``None`` for
                       conversation-scope burns.
        nonce:         16 random bytes bound into the MAC; generated with
                       ``os.urandom(16)`` when not supplied. Supplying it is for
                       tests / re-deriving a known token only — production callers
                       leave it ``None`` so every token is fresh.
        timestamp:     Unix seconds bound into the MAC; defaults to now. Exposed
                       for tests that need a controlled (e.g. expired) token.
    """
    if nonce is None:
        nonce = os.urandom(NONCE_BYTES)
    if len(nonce) != NONCE_BYTES:
        raise ValueError(f"nonce must be {NONCE_BYTES} bytes, got {len(nonce)}")
    nonce_hex = nonce.hex()
    ts = int(time.time()) if timestamp is None else int(timestamp)

    key = _derive_burn_key(shared_secret)
    h = HMAC(key, SHA256())
    h.update(_mac_input(scope, message_id, nonce_hex, ts))
    mac = h.finalize().hex()
    return f"{nonce_hex}.{ts}.{mac}"


def parse_burn_token(token: str) -> tuple[str, int, str]:
    """Split a token into ``(nonce_hex, timestamp, mac_hex)`` without verifying
    the MAC. Used by the relay, which has no shared secret but still needs the
    nonce and timestamp for freshness + replay checks. Raises
    :class:`BurnTokenError` on any shape problem."""
    if not isinstance(token, str):
        raise BurnTokenError("token must be a string")
    parts = token.split(".")
    if len(parts) != 3:
        raise BurnTokenError("token must be 'nonce.timestamp.mac'")
    nonce_hex, ts_str, mac = parts
    if len(nonce_hex) != NONCE_HEX_LEN or len(mac) != MAC_HEX_LEN:
        raise BurnTokenError("token field has wrong length")
    try:
        bytes.fromhex(nonce_hex)
        bytes.fromhex(mac)
        ts = int(ts_str)
    except ValueError as exc:
        raise BurnTokenError("token field is not valid") from exc
    return nonce_hex, ts, mac


def verify_burn_token(
    shared_secret: bytes,
    token: str,
    scope: str,
    message_id: str | None = None,
    *,
    now: int | None = None,
    ttl: int = TOKEN_TTL_SECONDS,
) -> bool:
    """Return True iff *token* is a fresh, correctly-MAC'd token for this
    scope + message_id.

    Checks, in order: the token parses, its timestamp is within ``ttl`` seconds of
    ``now`` (rejecting both stale replays and implausibly future tokens), and the
    MAC matches (constant-time). The relay enforces single-use via nonce dedup;
    this client-side freshness check is what makes a captured-and-replayed token
    useless once it ages out.
    """
    try:
        nonce_hex, ts, _mac = parse_burn_token(token)
    except BurnTokenError:
        return False
    now = int(time.time()) if now is None else now
    if abs(now - ts) > ttl:
        return False
    expected = generate_burn_token(
        shared_secret, scope, message_id, nonce=bytes.fromhex(nonce_hex), timestamp=ts
    )
    return _hmac.compare_digest(expected, token)
