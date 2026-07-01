"""
drift.crypto.invite — disappearing contact codes (one-time invites)

An *invite* is a beacon (:mod:`drift.crypto.beacon`) whose handle is a random
128-bit string instead of a memorable one. Same signature, same encryption,
same relay endpoints — a relay cannot even distinguish an invite from a handle
beacon, so lighting one adds no new metadata class.

The differences are policy, not cryptography:

  - **Handle entropy.** A human beacon handle (``Diego552``) is guessable, so
    its TTL is capped at 10 minutes and the docs warn that a captured blob is
    offline-grindable. An invite handle is ``secrets.token_bytes(16)`` —
    grinding 2^128 handles is infeasible regardless of how long the sealed blob
    lives — which is why invites may run up to 24 hours.

  - **One-time.** The *redeemer* deletes the beacon from the relay immediately
    after a successful resolve, via the existing idempotent
    ``DELETE /beacon/{lookup_hash}``. On a blind relay only someone who already
    knows the handle can compute the lookup hash, so deletion authority is the
    same as resolution authority — the delete is honest, but best-effort: a
    relay that ignores deletes, or a federation peer holding a replica, keeps
    the sealed blob until expiry. **Expiry is the hard guarantee; one-time is
    best-effort.** The UI says so.

No new cryptography: this module only generates a random handle, formats the
``driftinvite:`` string, and delegates to ``beacon.create_beacon`` with a
larger TTL ceiling.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from drift.crypto import Identity, b58decode, b58encode
from drift.crypto.beacon import BeaconPayload, create_beacon

# Wire prefix for invite codes, mirroring the "drift:" contact-code prefix.
INVITE_PREFIX = "driftinvite:"

# 128 bits of handle entropy — the reason invites may outlive the 10-minute
# human-handle cap (see module docstring).
INVITE_HANDLE_BYTES = 16

# Ceiling for an invite's lifetime. The relay's own cap (BEACON_MAX_TTL) still
# applies server-side; callers should trust the relay's returned TTL.
INVITE_MAX_TTL_SECONDS = 24 * 3600


@dataclass(frozen=True)
class InvitePayload:
    """A minted invite: the shareable code plus the beacon to POST."""

    code: str              # "driftinvite:<b58 handle>"
    beacon: BeaconPayload  # ready for POST /beacon


def new_invite_handle() -> str:
    """A fresh random handle: base58 of 16 random bytes (~22 chars)."""
    return b58encode(secrets.token_bytes(INVITE_HANDLE_BYTES))


def encode_invite(handle: str) -> str:
    return INVITE_PREFIX + handle


def is_invite_code(code: str) -> bool:
    return code.strip().startswith(INVITE_PREFIX)


def parse_invite(code: str) -> str:
    """Strip and validate an invite code, returning the beacon handle.

    Raises :class:`ValueError` on anything that isn't a well-formed invite —
    wrong prefix, non-base58 body, or a handle with less than the full 128 bits
    of entropy (a short handle would silently forfeit the grinding resistance
    that justifies the long TTL).
    """
    code = code.strip()
    if not code.startswith(INVITE_PREFIX):
        raise ValueError("not an invite code (expected driftinvite:…)")
    handle = code[len(INVITE_PREFIX):]
    try:
        raw = b58decode(handle)
    except ValueError:
        raise ValueError("invite code is not valid base58") from None
    if len(raw) != INVITE_HANDLE_BYTES:
        raise ValueError("invite code has the wrong length")
    return handle


def create_invite(
    identity: Identity, ttl_seconds: int, relay_pubkey: bytes
) -> InvitePayload:
    """Mint a disappearing contact code for ``identity``.

    ``ttl_seconds`` is clamped to ``[1, INVITE_MAX_TTL_SECONDS]``; the relay
    clamps again server-side, so use the relay's response as the truth for
    countdowns.
    """
    handle = new_invite_handle()
    payload = create_beacon(
        identity, handle, ttl_seconds, relay_pubkey,
        max_ttl_seconds=INVITE_MAX_TTL_SECONDS,
    )
    return InvitePayload(code=encode_invite(handle), beacon=payload)
