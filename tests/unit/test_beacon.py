"""
tests/unit/test_beacon.py — ephemeral discoverable handles (Phase 6)

Crypto-level tests for drift.crypto.beacon: round-trip resolution, wrong-handle
rejection, expiry, tamper rejection, and the server-mirrored TTL clamp. Pure
crypto — no network.

Run: pytest tests/unit/test_beacon.py -v
"""

from __future__ import annotations

import base64
import json
import time

from drift.crypto import Identity
from drift.crypto import beacon as beacon_mod
from drift.crypto.beacon import (
    MAX_TTL_SECONDS,
    create_beacon,
    lookup_hash,
    resolve_beacon,
)

# A stand-in for a relay's long-term Ed25519 public key (raw 32 bytes). The lookup
# hash is bound to it (audit M3), so tests fix one value.
_RELAY_PK = bytes(range(32))

# --------------------------------------------------------------------------- #
# Identity signing key
# --------------------------------------------------------------------------- #


class TestSigningKey:
    def test_deterministic_per_identity(self) -> None:
        idy = Identity.generate()
        assert idy.verify_key_bytes() == idy.verify_key_bytes()

    def test_differs_across_identities(self) -> None:
        assert Identity.generate().verify_key_bytes() != Identity.generate().verify_key_bytes()

    def test_survives_save_load(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        idy = Identity.generate()
        path = tmp_path / "id.json"
        idy.save(path)
        # Derived from the spend key, so a reloaded identity signs identically.
        assert Identity.load(path).verify_key_bytes() == idy.verify_key_bytes()


# --------------------------------------------------------------------------- #
# Round trip
# --------------------------------------------------------------------------- #


class TestRoundTrip:
    def test_resolve_with_correct_handle(self) -> None:
        idy = Identity.generate()
        b = create_beacon(idy, "Diego552", 300, _RELAY_PK)
        info = resolve_beacon("Diego552", b.encrypted)
        assert info is not None
        assert info.contact_code == idy.contact_code()
        assert info.handle == "Diego552"

    def test_lookup_hash_binds_prefix_and_relay_pubkey(self) -> None:
        import hashlib

        from drift.crypto.beacon import BEACON_LOOKUP_PREFIX

        assert lookup_hash("Diego552", _RELAY_PK) == hashlib.sha256(
            BEACON_LOOKUP_PREFIX + _RELAY_PK + b"Diego552"
        ).hexdigest()

    def test_lookup_hash_is_not_bare_sha256(self) -> None:
        import hashlib

        # The domain-separation prefix + relay pubkey must actually change the
        # digest, so a generic SHA256(handle) rainbow table doesn't apply.
        assert lookup_hash("Diego552", _RELAY_PK) != hashlib.sha256(b"Diego552").hexdigest()

    def test_lookup_hash_is_relay_specific(self) -> None:
        # Audit M3: the same handle hashes differently per relay, so an offline
        # table built against one relay is useless against another.
        other_relay = bytes(range(1, 33))
        assert lookup_hash("Diego552", _RELAY_PK) != lookup_hash("Diego552", other_relay)

    def test_handle_never_appears_in_ciphertext(self) -> None:
        b = create_beacon(Identity.generate(), "SecretHandle9", 300, _RELAY_PK)
        assert b"SecretHandle9" not in b.encrypted


# --------------------------------------------------------------------------- #
# Failure modes — all return None
# --------------------------------------------------------------------------- #


class TestFailureModes:
    def test_wrong_handle_fails(self) -> None:
        b = create_beacon(Identity.generate(), "Diego552", 300, _RELAY_PK)
        # One character off → a completely different HKDF key → decryption fails.
        assert resolve_beacon("Diego553", b.encrypted) is None
        assert resolve_beacon("diego552", b.encrypted) is None

    def test_tampered_payload_fails(self) -> None:
        b = create_beacon(Identity.generate(), "Diego552", 300, _RELAY_PK)
        corrupt = bytearray(b.encrypted)
        corrupt[-1] ^= 0xFF
        assert resolve_beacon("Diego552", bytes(corrupt)) is None

    def test_expired_beacon_fails(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        idy = Identity.generate()
        b = create_beacon(idy, "Diego552", 5, _RELAY_PK)
        # Correct handle, but the clock has moved past expiry.
        monkeypatch.setattr(beacon_mod.time, "time", lambda: b.expires_at + 1)
        assert resolve_beacon("Diego552", b.encrypted) is None

    def test_not_yet_expired_resolves(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        idy = Identity.generate()
        b = create_beacon(idy, "Diego552", 300, _RELAY_PK)
        monkeypatch.setattr(beacon_mod.time, "time", lambda: b.expires_at - 1)
        assert resolve_beacon("Diego552", b.encrypted) is not None

    def test_garbage_payload_fails(self) -> None:
        assert resolve_beacon("Diego552", b"not a valid beacon at all") is None


# --------------------------------------------------------------------------- #
# TTL clamp (client side, mirrors the server cap)
# --------------------------------------------------------------------------- #


class TestTTL:
    def test_clamped_to_max(self) -> None:
        b = create_beacon(Identity.generate(), "Diego552", 3600, _RELAY_PK)  # 1 hour requested
        assert b.ttl_seconds == MAX_TTL_SECONDS
        assert b.expires_at <= int(time.time()) + MAX_TTL_SECONDS

    def test_minimum_one_second(self) -> None:
        b = create_beacon(Identity.generate(), "Diego552", 0, _RELAY_PK)
        assert b.ttl_seconds == 1

    def test_normal_ttl_preserved(self) -> None:
        b = create_beacon(Identity.generate(), "Diego552", 300, _RELAY_PK)
        assert b.ttl_seconds == 300

    def test_custom_max_ttl_respected(self) -> None:
        # Invites raise the ceiling via max_ttl_seconds; the default stays 600 s.
        b = create_beacon(
            Identity.generate(), "Diego552", 3600, _RELAY_PK, max_ttl_seconds=7200
        )
        assert b.ttl_seconds == 3600
        clamped = create_beacon(
            Identity.generate(), "Diego552", 9999, _RELAY_PK, max_ttl_seconds=7200
        )
        assert clamped.ttl_seconds == 7200


# --------------------------------------------------------------------------- #
# Signature integrity
# --------------------------------------------------------------------------- #


def test_signature_rejects_field_swap() -> None:
    """
    Re-encrypting a payload with a changed contact code but the *original*
    signature must fail verification (a handle-knower can't silently rebind the
    beacon to a different code without re-signing).
    """
    idy = Identity.generate()
    handle = "Diego552"
    b = create_beacon(idy, handle, 300, _RELAY_PK)

    # Decrypt (we know the handle), swap the contact code, re-encrypt — but keep
    # the original signature, which no longer covers the new code.
    key = beacon_mod._encryption_key(handle)  # type: ignore[attr-defined]
    from drift.crypto import decrypt, encrypt
    env = json.loads(decrypt(key, b.encrypted))
    env["contact_code"] = Identity.generate().contact_code()
    forged = encrypt(key, json.dumps(env).encode())
    assert resolve_beacon(handle, forged) is None


def test_resolve_returns_none_for_non_drift_code() -> None:
    idy = Identity.generate()
    handle = "Diego552"
    b = create_beacon(idy, handle, 300, _RELAY_PK)
    key = beacon_mod._encryption_key(handle)  # type: ignore[attr-defined]
    from drift.crypto import decrypt, encrypt
    env = json.loads(decrypt(key, b.encrypted))
    # Re-sign a bogus contact code with this identity so the signature is valid…
    env["contact_code"] = "not-a-drift-code"
    inner = {k: env[k] for k in ("contact_code", "handle", "expires_at", "sign_pub")}
    sig = idy.signing_key().sign(beacon_mod._canonical(inner)).signature  # type: ignore[attr-defined]
    env["sig"] = base64.b64encode(sig).decode()
    forged = encrypt(key, json.dumps(env).encode())
    # …but resolution still rejects it because the code doesn't parse.
    assert resolve_beacon(handle, forged) is None
