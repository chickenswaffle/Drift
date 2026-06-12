"""
drift.crypto.beacon — ephemeral discoverable handles (Phase 6)

A *beacon* is an opt-in, time-boxed exception to DRIFT's default unlinkability.
A user "lights" a short human handle (e.g. ``Diego552``) for a few minutes;
anyone who knows that exact handle during the window can resolve it to the
user's contact code and add them. After expiry the handle is gone — no trace,
no retroactive lookup.

This module is the *crypto*: it binds a contact code to a handle for a TTL, in a
form the relay can store and serve but **not read**. It builds entirely on
primitives already in the codebase (HKDF + XChaCha20-Poly1305 from
``drift.crypto``, Ed25519 from PyNaCl) — no new primitives.

Construction
------------
Let ``H`` be the handle string and ``id`` the lighting identity.

  - **Confidentiality from the relay.** The payload is encrypted with
    ``K = HKDF(H, info="drift-beacon-v1")`` — a key *anyone who knows the exact
    handle* can derive, and the relay (which only ever sees ``SHA256(H)`` and
    the ciphertext) cannot. Get the handle wrong by one character and the HKDF
    output is unrelated, so decryption fails.

  - **Authenticity / binding to the identity.** Inside the ciphertext sits
    ``{contact_code, handle, expires_at, sign_pub}`` plus an Ed25519 signature
    over it, made with the identity's signing key (``Identity.signing_key()``,
    derived from the spend key). ``sign_pub`` is the verify key; the resolver
    checks the signature against it, so the payload can't be altered without
    detection. A finder must still verify the safety number out of band before
    trusting the binding (the signature proves integrity, not that the handle's
    owner is who you think — that's what ``drift verify`` is for).

  - **Relay index.** The relay stores the beacon under
    ``SHA256("drift-beacon-lookup-v1" ‖ H)`` (computed by the client). The
    plaintext handle never crosses the wire, and the domain-separation prefix
    keeps a generic SHA256 rainbow table from applying to the index.

What the relay learns is exactly: a hash of the handle, an opaque blob, and a
TTL. What a *handle-knower* learns during the window is the contact code — that
is the deliberate, time-boxed linkability the user opted into.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from drift.crypto import Identity, decrypt, derive_message_key, encrypt

# Domain separation for the handle-derived encryption key. Versioned.
BEACON_INFO = b"drift-beacon-v1"

# Domain separation for the relay index hash. Prefixed (not bare SHA256(handle))
# so a relay can't reuse a generic SHA256 rainbow table against the index — the
# lookup hash is tied to DRIFT's namespace. This does *not* defend a guessable
# handle against a targeted dictionary attack (see DESIGN.md: handles are
# semi-public — pick something unguessable for anything sensitive).
BEACON_LOOKUP_PREFIX = b"drift-beacon-lookup-v1"

# Hard cap on a beacon's lifetime, mirrored by the relay server-side.
MAX_TTL_SECONDS = 600  # 10 minutes

# Fields covered by the Ed25519 signature, in a fixed order (canonical JSON).
_SIGNED_FIELDS = ("contact_code", "handle", "expires_at", "sign_pub")


@dataclass(frozen=True)
class BeaconPayload:
    """A lit beacon ready to POST to a relay."""

    handle: str
    lookup_hash: str   # hex SHA256(handle) — the relay's index key
    encrypted: bytes   # opaque to the relay (nonce ‖ ciphertext+tag)
    expires_at: int    # unix seconds
    ttl_seconds: int   # effective lifetime (already clamped to MAX_TTL_SECONDS)


@dataclass(frozen=True)
class ContactInfo:
    """The result of resolving a beacon."""

    contact_code: str
    handle: str
    expires_at: int


def lookup_hash(handle: str) -> str:
    """The relay index key for a handle: ``SHA256(prefix ‖ handle)`` as hex.

    The fixed ``BEACON_LOOKUP_PREFIX`` domain-separates the index from a bare
    ``SHA256(handle)`` so a generic rainbow table doesn't apply.
    """
    return hashlib.sha256(BEACON_LOOKUP_PREFIX + handle.encode("utf-8")).hexdigest()


def _encryption_key(handle: str) -> bytes:
    return derive_message_key(handle.encode("utf-8"), info=BEACON_INFO)


def _canonical(fields: dict[str, object]) -> bytes:
    """Deterministic JSON over the signed fields, so signer and verifier agree."""
    return json.dumps(
        {k: fields[k] for k in _SIGNED_FIELDS},
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")


def create_beacon(identity: Identity, handle: str, ttl_seconds: int) -> BeaconPayload:
    """
    Light a beacon for ``handle`` pointing at ``identity``'s contact code.

    ``ttl_seconds`` is clamped to ``[1, MAX_TTL_SECONDS]`` so the signed expiry
    never outlives the relay's own cap. The returned payload's ``encrypted``
    bytes are opaque to the relay; only someone with the exact handle can open
    them.
    """
    import base64

    ttl = max(1, min(int(ttl_seconds), MAX_TTL_SECONDS))
    expires_at = int(time.time()) + ttl

    inner: dict[str, object] = {
        "contact_code": identity.contact_code(),
        "handle": handle,
        "expires_at": expires_at,
        "sign_pub": base64.b64encode(identity.verify_key_bytes()).decode(),
    }
    signature = identity.signing_key().sign(_canonical(inner)).signature
    envelope = {**inner, "sig": base64.b64encode(signature).decode()}
    plaintext = json.dumps(envelope, separators=(",", ":")).encode("utf-8")

    encrypted = encrypt(_encryption_key(handle), plaintext)
    return BeaconPayload(
        handle=handle,
        lookup_hash=lookup_hash(handle),
        encrypted=encrypted,
        expires_at=expires_at,
        ttl_seconds=ttl,
    )


def resolve_beacon(handle: str, encrypted_payload: bytes) -> ContactInfo | None:
    """
    Resolve a beacon fetched from a relay back to a contact code.

    Returns ``None`` on *any* failure — wrong handle (decryption fails), a
    tampered payload (signature fails), or an expired beacon — so the caller
    treats every failure mode identically.
    """
    import base64

    try:
        plaintext = decrypt(_encryption_key(handle), encrypted_payload)
    except (InvalidTag, ValueError):
        # Wrong handle, corrupted ciphertext, or a payload too short to even hold
        # the AEAD tag — all "not for us".
        return None

    try:
        envelope = json.loads(plaintext)
        if not isinstance(envelope, dict):
            return None
        inner = {k: envelope[k] for k in _SIGNED_FIELDS}
        signature = base64.b64decode(envelope["sig"])
        verify_key = VerifyKey(base64.b64decode(inner["sign_pub"]))
    except (KeyError, ValueError, TypeError):
        return None

    try:
        verify_key.verify(_canonical(inner), signature)
    except BadSignatureError:
        return None

    # The handle inside must match the one we looked up (defends against a relay
    # serving someone else's beacon under this hash).
    if inner["handle"] != handle:
        return None

    try:
        expires_at = int(inner["expires_at"])
    except (TypeError, ValueError):
        return None
    if expires_at <= int(time.time()):
        return None

    # Sanity: the advertised contact code must parse.
    try:
        Identity.parse_contact_code(str(inner["contact_code"]))
    except ValueError:
        return None

    return ContactInfo(
        contact_code=str(inner["contact_code"]),
        handle=handle,
        expires_at=expires_at,
    )
