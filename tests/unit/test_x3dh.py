"""
tests/unit/test_x3dh.py — X3DH asynchronous key agreement (audit H3)

Covers the Signal X3DH handshake DRIFT uses to bootstrap the Double Ratchet:
sender/receiver agreement, one-time-prekey consumption, signed-prekey signature
verification, the no-OTPK fallback, the forward-secrecy regression that closes
H3, and the rotation/replenishment policy helpers.
"""

from __future__ import annotations

import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from drift.crypto import Identity
from drift.crypto.ratchet import (
    init_receiver,
    init_sender,
    ratchet_decrypt,
    ratchet_encrypt,
)
from drift.crypto.x3dh import (
    SIGNED_PREKEY_LIFETIME,
    PreKeyBundle,
    PreKeyPrivates,
    X3DHError,
    X3DHHeader,
    derive_master_secret_recv,
    drop_expired_prev_signed_prekey,
    generate_prekey_bundle,
    low_on_one_time,
    needs_signed_prekey_rotation,
    replenish_one_time,
    rotate_signed_prekey,
    verify_prekey_bundle,
    x3dh_receive,
    x3dh_send,
)


def _pair() -> tuple[Identity, Identity]:
    return Identity.generate(), Identity.generate()


# ---------------------------------------------------------------------------
# Identity-key consistency (iron rule: cryptography Ed25519, same key as PyNaCl)
# ---------------------------------------------------------------------------

class TestIdentityKey:
    def test_bundle_identity_key_matches_existing_signing_key(self) -> None:
        bob = Identity.generate()
        bundle, _ = generate_prekey_bundle(bob)
        # The bundle's Ed25519 identity key is byte-for-byte the identity's
        # existing verify key (loaded from the same seed via cryptography).
        assert bundle.identity_key == bob.verify_key_bytes()
        # And it actually verifies the signature it carries.
        Ed25519PublicKey.from_public_bytes(bundle.identity_key).verify(
            bundle.signed_prekey_sig, bundle.signed_prekey
        )


# ---------------------------------------------------------------------------
# Handshake round trip
# ---------------------------------------------------------------------------

class TestRoundTrip:
    def test_sender_and_receiver_derive_identical_master(self) -> None:
        alice, bob = _pair()
        bundle, privates = generate_prekey_bundle(bob)
        result_s, header = x3dh_send(alice, bundle)
        result_r = x3dh_receive(bob, privates, header)
        assert result_s.master_secret == result_r.master_secret
        assert len(result_s.master_secret) == 32

    def test_master_secret_bootstraps_a_working_ratchet(self) -> None:
        alice, bob = _pair()
        bundle, privates = generate_prekey_bundle(bob)
        result_s, header = x3dh_send(alice, bundle)
        result_r = x3dh_receive(bob, privates, header)
        # Bob's signed prekey is his initial ratchet key (the X3DH→DR handoff).
        a_rt = init_sender(result_s.master_secret, bundle.signed_prekey)
        spk = privates.signed_prekey_private(header.signed_prekey_id)
        b_rt = init_receiver(result_r.master_secret, spk)
        hdr, ct = ratchet_encrypt(a_rt, b"opening burst")
        assert ratchet_decrypt(b_rt, hdr, ct) == b"opening burst"

    def test_two_senders_get_distinct_otpks_and_masters(self) -> None:
        alice, bob = _pair()
        carol = Identity.generate()
        bundle1, privates = generate_prekey_bundle(bob, num_one_time=2)
        # Simulate the relay handing each sender a different OTPK.
        ids = list(privates.one_time)
        b1 = PreKeyBundle(
            bundle1.identity_key, bundle1.identity_dh_key, bundle1.signed_prekey,
            bundle1.signed_prekey_sig, bundle1.signed_prekey_id,
            privates.one_time[ids[0]].public_bytes(), ids[0],
        )
        b2 = PreKeyBundle(
            bundle1.identity_key, bundle1.identity_dh_key, bundle1.signed_prekey,
            bundle1.signed_prekey_sig, bundle1.signed_prekey_id,
            privates.one_time[ids[1]].public_bytes(), ids[1],
        )
        r1, h1 = x3dh_send(alice, b1)
        r2, h2 = x3dh_send(carol, b2)
        assert r1.master_secret != r2.master_secret
        assert x3dh_receive(bob, privates, h1).master_secret == r1.master_secret
        assert x3dh_receive(bob, privates, h2).master_secret == r2.master_secret


# ---------------------------------------------------------------------------
# One-time prekey consumption
# ---------------------------------------------------------------------------

class TestOneTimePrekeyConsumed:
    def test_otpk_cannot_be_used_twice(self) -> None:
        alice, bob = _pair()
        bundle, privates = generate_prekey_bundle(bob, num_one_time=1)
        before = privates.one_time_count()
        _, header = x3dh_send(alice, bundle)
        x3dh_receive(bob, privates, header)
        assert privates.one_time_count() == before - 1
        # The same OTPK id is now gone — a second receive cannot reuse it.
        with pytest.raises(X3DHError):
            x3dh_receive(bob, privates, header)

    def test_derive_does_not_consume(self) -> None:
        alice, bob = _pair()
        bundle, privates = generate_prekey_bundle(bob, num_one_time=1)
        _, header = x3dh_send(alice, bundle)
        # The non-consuming variant the session uses for its trial decrypt.
        derive_master_secret_recv(bob, privates, header)
        assert privates.one_time_count() == 1  # untouched


# ---------------------------------------------------------------------------
# Signature verification — a MITM swapping prekeys is detectable
# ---------------------------------------------------------------------------

class TestSignatureVerification:
    def test_valid_bundle_verifies(self) -> None:
        bundle, _ = generate_prekey_bundle(Identity.generate())
        assert verify_prekey_bundle(bundle) is True

    def test_tampered_signed_prekey_rejected(self) -> None:
        bundle, _ = generate_prekey_bundle(Identity.generate())
        forged = PreKeyBundle(
            bundle.identity_key, bundle.identity_dh_key,
            bytes(32),  # attacker-substituted signed prekey
            bundle.signed_prekey_sig, bundle.signed_prekey_id,
            bundle.one_time_prekey, bundle.one_time_prekey_id,
        )
        assert verify_prekey_bundle(forged) is False

    def test_swapped_identity_key_rejected(self) -> None:
        bundle, _ = generate_prekey_bundle(Identity.generate())
        attacker = Identity.generate()
        forged = PreKeyBundle(
            attacker.verify_key_bytes(), bundle.identity_dh_key, bundle.signed_prekey,
            bundle.signed_prekey_sig, bundle.signed_prekey_id,
            bundle.one_time_prekey, bundle.one_time_prekey_id,
        )
        assert verify_prekey_bundle(forged) is False

    def test_x3dh_send_refuses_an_invalid_bundle(self) -> None:
        bundle, _ = generate_prekey_bundle(Identity.generate())
        forged = PreKeyBundle(
            bundle.identity_key, bundle.identity_dh_key, bytes(32),
            bundle.signed_prekey_sig, bundle.signed_prekey_id, None, None,
        )
        with pytest.raises(X3DHError):
            x3dh_send(Identity.generate(), forged)


# ---------------------------------------------------------------------------
# X3DH without a one-time prekey (relay exhausted) — weaker but valid
# ---------------------------------------------------------------------------

class TestWithoutOneTimePrekey:
    def test_handshake_succeeds_without_otpk(self) -> None:
        alice, bob = _pair()
        bundle, privates = generate_prekey_bundle(bob, num_one_time=0)
        assert bundle.one_time_prekey is None
        result_s, header = x3dh_send(alice, bundle)
        assert header.one_time_prekey_id is None
        result_r = x3dh_receive(bob, privates, header)
        assert result_s.master_secret == result_r.master_secret


# ---------------------------------------------------------------------------
# Forward-secrecy regression — closes H3
# ---------------------------------------------------------------------------

class TestForwardSecrecyClosesH3:
    def test_opening_burst_unrecoverable_after_otpk_deleted(self) -> None:
        """The headline H3 closure: after the session is established and the OTPK
        consumed/deleted, an adversary who later compromises ALL of Bob's retained
        long-term + signed-prekey secrets still cannot reconstruct the opening
        master secret — the one-time prekey it depended on is gone, and the
        sender's ephemeral was discarded immediately."""
        alice, bob = _pair()
        bundle, privates = generate_prekey_bundle(bob, num_one_time=1)
        result_s, header = x3dh_send(alice, bundle)
        result_r = x3dh_receive(bob, privates, header)
        assert result_s.master_secret == result_r.master_secret

        # The OTPK is now deleted; the sender's EK_A private never existed past
        # x3dh_send. The header on the wire still names the (now-gone) OTPK id.
        assert privates.one_time_count() == 0

        # 1) A later compromise that replays the exact header cannot recompute the
        #    master — the OTPK private is irretrievably gone.
        with pytest.raises(X3DHError):
            derive_master_secret_recv(bob, privates, header)

        # 2) Even using everything Bob still holds (spend key + signed prekey) and
        #    dropping the missing DH4 yields a DIFFERENT secret — i.e. the real
        #    opening secret genuinely depended on the deleted prekey.
        header_no_otpk = X3DHHeader(
            ik_a=header.ik_a, ek_a=header.ek_a,
            signed_prekey_id=header.signed_prekey_id, one_time_prekey_id=None,
        )
        adversary_secret = derive_master_secret_recv(bob, privates, header_no_otpk)
        assert adversary_secret != result_s.master_secret


# ---------------------------------------------------------------------------
# Rotation / replenishment policy helpers
# ---------------------------------------------------------------------------

class TestRotationAndReplenish:
    def test_fresh_bundle_is_not_due_for_rotation(self) -> None:
        _, privates = generate_prekey_bundle(Identity.generate())
        assert needs_signed_prekey_rotation(privates) is False

    def test_old_signed_prekey_is_due(self) -> None:
        _, privates = generate_prekey_bundle(Identity.generate())
        privates.signed_prekey_created = time.time() - SIGNED_PREKEY_LIFETIME - 1
        assert needs_signed_prekey_rotation(privates) is True

    def test_rotation_retains_previous_for_decrypt(self) -> None:
        bob = Identity.generate()
        alice = Identity.generate()
        bundle, privates = generate_prekey_bundle(bob, num_one_time=1)
        # A session opened against the OLD signed prekey, still in flight.
        _, header = x3dh_send(alice, bundle)
        old_id = privates.signed_prekey_id
        rotate_signed_prekey(bob, privates)
        assert privates.signed_prekey_id != old_id
        # The in-flight handshake against the previous signed prekey still works.
        derive_master_secret_recv(bob, privates, header)

    def test_expired_previous_signed_prekey_is_dropped(self) -> None:
        bob = Identity.generate()
        _, privates = generate_prekey_bundle(bob)
        rotate_signed_prekey(bob, privates)
        assert privates.prev_signed_prekey is not None
        # Age the retirement past the 24h grace.
        privates.prev_signed_prekey_retired = time.time() - 25 * 3600
        drop_expired_prev_signed_prekey(privates)
        assert privates.prev_signed_prekey is None

    def test_low_watermark_and_replenish(self) -> None:
        _, privates = generate_prekey_bundle(Identity.generate(), num_one_time=2)
        assert low_on_one_time(privates) is True
        new_ids = replenish_one_time(privates, count=10)
        assert len(new_ids) == 10
        assert privates.one_time_count() == 12
        assert low_on_one_time(privates) is False


# ---------------------------------------------------------------------------
# Serialization round trips
# ---------------------------------------------------------------------------

class TestSerialization:
    def test_header_roundtrips(self) -> None:
        bundle, _ = generate_prekey_bundle(Identity.generate())
        _, header = x3dh_send(Identity.generate(), bundle)
        assert X3DHHeader.from_bytes(header.to_bytes()) == header

    def test_header_without_otpk_roundtrips(self) -> None:
        bundle, _ = generate_prekey_bundle(Identity.generate(), num_one_time=0)
        _, header = x3dh_send(Identity.generate(), bundle)
        assert header.one_time_prekey_id is None
        assert X3DHHeader.from_bytes(header.to_bytes()) == header

    def test_bundle_dict_roundtrips(self) -> None:
        bundle, _ = generate_prekey_bundle(Identity.generate())
        assert PreKeyBundle.from_dict(bundle.to_dict()).to_dict() == bundle.to_dict()

    def test_privates_dict_roundtrips(self) -> None:
        bob = Identity.generate()
        _, privates = generate_prekey_bundle(bob)
        rotate_signed_prekey(bob, privates)  # exercise the prev-key fields too
        restored = PreKeyPrivates.from_dict(privates.to_dict())
        assert restored.signed_prekey.private_bytes() == privates.signed_prekey.private_bytes()
        assert restored.one_time.keys() == privates.one_time.keys()
        assert restored.prev_signed_prekey_id == privates.prev_signed_prekey_id

    def test_malformed_header_rejected(self) -> None:
        with pytest.raises(X3DHError):
            X3DHHeader.from_bytes(b"too short")
