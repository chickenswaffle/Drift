"""
drift.crypto.burn — burn-request token generation and verification

A burn token is an HMAC-SHA256 MAC over ``scope + ':' + (message_id or '')``,
keyed with a conversation-specific secret derived via HKDF from the static
ECDH output (domain-separated from the ratchet key material).

The relay has no shared secret and cannot verify tokens — it processes burn
requests unconditionally and posts tombstones to the channel.  Security is
end-to-end: the *receiving client* verifies the token before honouring the
burn; a tombstone with an invalid token is silently ignored.  This is the
"best-effort" model described in the help text.
"""

from __future__ import annotations

import hmac as _hmac

from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# HMAC-SHA256 produces 32 bytes = 64 hex characters.
TOKEN_HEX_LEN = 64

VALID_SCOPES = frozenset(("message", "conversation"))


def _derive_burn_key(shared_secret: bytes) -> bytes:
    """Derive a 32-byte burn key via HKDF-SHA256, domain-separated from ratchet."""
    return HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=b"drift-burn-v1",
    ).derive(shared_secret)


def generate_burn_token(
    shared_secret: bytes,
    scope: str,
    message_id: str | None = None,
) -> str:
    """Return a 64-hex-char HMAC-SHA256 token for a burn request.

    Args:
        shared_secret: Raw ECDH output of the conversation (both sides derive
                       the same value from their static spend keys).
        scope:         ``"message"`` or ``"conversation"``.
        message_id:    For message-scope burns, the base64-encoded one-time
                       stealth address of the target message.  ``None`` for
                       conversation-scope burns.
    """
    key = _derive_burn_key(shared_secret)
    msg = f"{scope}:{message_id or ''}".encode()
    h = HMAC(key, SHA256())
    h.update(msg)
    return h.finalize().hex()


def verify_burn_token(
    shared_secret: bytes,
    token: str,
    scope: str,
    message_id: str | None = None,
) -> bool:
    """Return True iff *token* is the correct MAC for this scope + message_id.

    Uses ``hmac.compare_digest`` for constant-time comparison.
    """
    if len(token) != TOKEN_HEX_LEN:
        return False
    expected = generate_burn_token(shared_secret, scope, message_id)
    return _hmac.compare_digest(expected, token)
