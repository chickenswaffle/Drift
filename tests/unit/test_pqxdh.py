"""
tests/unit/test_pqxdh.py — the hybrid post-quantum handshake (PQXDH-style)

Covers the ML-KEM-768 wrapper (drift.crypto.pqkem), the hybrid X3DH derivation,
downgrade visibility/rules, header wire framing, vault serialization, rotation
grace, and the relay's opaque passthrough of the PQ bundle fields.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import relay.server as server
from drift.crypto import Identity
from drift.crypto.pqkem import (
    PQ_CIPHERTEXT_LEN,
    PQ_PUBLIC_LEN,
    PQ_SECRET_LEN,
    PQ_SEED_LEN,
    PQKEMError,
    PQKeypair,
    encapsulate,
)
from drift.crypto.x3dh import (
    PreKeyBundle,
    PreKeyPrivates,
    X3DHError,
    X3DHHeader,
    derive_master_secret_recv,
    generate_prekey_bundle,
    rotate_signed_prekey,
    verify_prekey_bundle,
    x3dh_receive,
    x3dh_send,
)

_CLASSIC_HEADER_LEN = 73
_HYBRID_HEADER_LEN = _CLASSIC_HEADER_LEN + 4 + PQ_CIPHERTEXT_LEN


def _strip_pq(bundle: PreKeyBundle) -> PreKeyBundle:
    """A legitimately pre-PQ bundle (no PQ fields at all)."""
    d = bundle.to_dict()
    d["pq_prekey"] = None
    d["pq_prekey_sig"] = None
    d["pq_prekey_id"] = None
    return PreKeyBundle.from_dict(d)


class TestPQKEM:
    def test_encapsulate_decapsulate_round_trip(self) -> None:
        kp = PQKeypair.generate()
        ss, ct = encapsulate(kp.public_bytes())
        assert len(ss) == PQ_SECRET_LEN
        assert len(ct) == PQ_CIPHERTEXT_LEN
        assert kp.decapsulate(ct) == ss

    def test_seed_round_trip_preserves_decapsulation(self) -> None:
        kp = PQKeypair.generate()
        seed = kp.seed_bytes()
        assert len(seed) == PQ_SEED_LEN
        ss, ct = encapsulate(kp.public_bytes())
        restored = PQKeypair.from_seed(seed)
        assert restored.decapsulate(ct) == ss
        assert restored.public_bytes() == kp.public_bytes()

    def test_wrong_ciphertext_yields_wrong_secret_not_error(self) -> None:
        # FIPS 203 implicit rejection: well-formed-but-wrong ct decapsulates to
        # a garbage secret (the mismatch surfaces later as an AEAD InvalidTag).
        a, b = PQKeypair.generate(), PQKeypair.generate()
        ss, ct = encapsulate(a.public_bytes())
        assert b.decapsulate(ct) != ss

    def test_bad_lengths_rejected(self) -> None:
        kp = PQKeypair.generate()
        with pytest.raises(PQKEMError):
            encapsulate(b"\x00" * (PQ_PUBLIC_LEN - 1))
        with pytest.raises(PQKEMError):
            kp.decapsulate(b"\x00" * (PQ_CIPHERTEXT_LEN + 1))
        with pytest.raises(PQKEMError):
            PQKeypair.from_seed(b"\x00" * 32)


class TestHybridHandshake:
    def test_hybrid_by_default_and_secrets_match(self) -> None:
        bob, alice = Identity.generate(), Identity.generate()
        bundle, privates = generate_prekey_bundle(bob)
        assert bundle.has_pq
        result_s, header = x3dh_send(alice, bundle)
        assert result_s.pq and header.is_hybrid
        result_r = x3dh_receive(bob, privates, header)
        assert result_r.pq
        assert result_s.master_secret == result_r.master_secret

    def test_classic_peer_downgrades_visibly(self) -> None:
        bob, alice = Identity.generate(), Identity.generate()
        bundle, privates = generate_prekey_bundle(bob)
        classic = _strip_pq(bundle)
        result_s, header = x3dh_send(alice, classic)
        assert not result_s.pq and not header.is_hybrid
        result_r = x3dh_receive(bob, privates, header)
        assert not result_r.pq
        assert result_s.master_secret == result_r.master_secret

    def test_hybrid_and_classic_secrets_are_domain_separated(self) -> None:
        # Same parties, same bundle modulo PQ — the derived secrets must differ
        # (distinct HKDF info), so a downgrade can never silently collide.
        bob, alice = Identity.generate(), Identity.generate()
        bundle, _ = generate_prekey_bundle(bob, num_one_time=0)
        r_hybrid, _ = x3dh_send(alice, bundle)
        r_classic, _ = x3dh_send(alice, _strip_pq(bundle))
        assert r_hybrid.master_secret != r_classic.master_secret

    def test_tampered_pq_signature_rejected_not_downgraded(self) -> None:
        bob, alice = Identity.generate(), Identity.generate()
        bundle, _ = generate_prekey_bundle(bob)
        d = bundle.to_dict()
        d["pq_prekey_sig"] = d["signed_prekey_sig"]  # a wrong-but-valid-shape sig
        tampered = PreKeyBundle.from_dict(d)
        assert not verify_prekey_bundle(tampered)
        with pytest.raises(X3DHError):
            x3dh_send(alice, tampered)

    def test_missing_pq_signature_rejected_not_downgraded(self) -> None:
        # A MITM must not be able to strip PQ by deleting just the signature.
        bob, alice = Identity.generate(), Identity.generate()
        bundle, _ = generate_prekey_bundle(bob)
        d = bundle.to_dict()
        d["pq_prekey_sig"] = None
        with pytest.raises(X3DHError):
            x3dh_send(alice, PreKeyBundle.from_dict(d))

    def test_unknown_pq_prekey_id_raises(self) -> None:
        bob, alice = Identity.generate(), Identity.generate()
        bundle, privates = generate_prekey_bundle(bob)
        _, header = x3dh_send(alice, bundle)
        privates.pq_prekey_id = (privates.pq_prekey_id or 0) + 1  # desync
        with pytest.raises(X3DHError):
            derive_master_secret_recv(bob, privates, header)


class TestHeaderFraming:
    def test_hybrid_header_round_trips(self) -> None:
        bob, alice = Identity.generate(), Identity.generate()
        bundle, _ = generate_prekey_bundle(bob)
        _, header = x3dh_send(alice, bundle)
        raw = header.to_bytes()
        assert len(raw) == _HYBRID_HEADER_LEN
        assert X3DHHeader.from_bytes(raw) == header

    def test_classic_header_layout_is_unchanged(self) -> None:
        # Byte-identical to pre-PQ DRIFT: old clients' headers parse unchanged.
        h = X3DHHeader(
            ik_a=b"\x01" * 32, ek_a=b"\x02" * 32,
            signed_prekey_id=42, one_time_prekey_id=7,
        )
        raw = h.to_bytes()
        assert len(raw) == _CLASSIC_HEADER_LEN
        assert X3DHHeader.from_bytes(raw) == h

    def test_wrong_length_header_rejected(self) -> None:
        with pytest.raises(X3DHError):
            X3DHHeader.from_bytes(b"\x00" * (_CLASSIC_HEADER_LEN + 1))


class TestPersistenceAndRotation:
    def test_vault_round_trip_preserves_pq(self) -> None:
        bob, alice = Identity.generate(), Identity.generate()
        bundle, privates = generate_prekey_bundle(bob)
        result_s, header = x3dh_send(alice, bundle)
        restored = PreKeyPrivates.from_dict(privates.to_dict())
        assert derive_master_secret_recv(bob, restored, header) == result_s.master_secret

    def test_rotation_rotates_pq_and_keeps_prev_for_in_flight(self) -> None:
        bob, alice = Identity.generate(), Identity.generate()
        bundle, privates = generate_prekey_bundle(bob, num_one_time=0)
        result_s, header = x3dh_send(alice, bundle)
        old_id = privates.pq_prekey_id
        rotate_signed_prekey(bob, privates)
        assert privates.pq_prekey_id != old_id
        assert privates.prev_pq_prekey_id == old_id
        # A handshake sent against the pre-rotation bundle still derives.
        assert derive_master_secret_recv(bob, privates, header) == result_s.master_secret

    def test_prev_pq_dropped_with_grace_expiry(self) -> None:
        from drift.crypto.x3dh import PREV_SIGNED_PREKEY_GRACE, drop_expired_prev_signed_prekey

        bob = Identity.generate()
        _, privates = generate_prekey_bundle(bob, num_one_time=0)
        rotate_signed_prekey(bob, privates, now=1_000.0)
        assert privates.prev_pq_prekey is not None
        drop_expired_prev_signed_prekey(privates, now=1_000.0 + PREV_SIGNED_PREKEY_GRACE + 1)
        assert privates.prev_pq_prekey is None
        assert privates.prev_pq_prekey_id is None


class TestRelayPassthrough:
    @pytest.fixture(autouse=True)
    def _clean(self) -> None:
        server._prekeys.clear()
        server._prekey_fetch_ip_bucket.clear()
        server._prekey_fetch_addr_bucket.clear()
        server._prekey_write_bucket.clear()

    def test_pq_fields_stored_and_served_verbatim(self) -> None:
        client = TestClient(server.app)
        bob = Identity.generate()
        bundle, privates = generate_prekey_bundle(bob)
        addr = bob.scan_keypair.public_b58()
        assert client.post(
            f"/prekeys/{addr}", json=privates.publish_payload(bob)
        ).status_code == 200
        fetched = client.get(f"/prekeys/{addr}").json()
        served = PreKeyBundle.from_dict(fetched)
        assert served.has_pq
        assert served.pq_prekey == bundle.pq_prekey
        # And the served bundle drives a real hybrid handshake end to end.
        alice = Identity.generate()
        result_s, header = x3dh_send(alice, served)
        assert result_s.pq
        assert x3dh_receive(bob, privates, header).master_secret == result_s.master_secret

    def test_pre_pq_publish_still_accepted(self) -> None:
        # An old client's payload (no pq fields) publishes and serves cleanly.
        client = TestClient(server.app)
        bob = Identity.generate()
        _, privates = generate_prekey_bundle(bob)
        payload = privates.publish_payload(bob)
        for f in ("pq_prekey", "pq_prekey_sig", "pq_prekey_id"):
            payload.pop(f, None)
        addr = bob.scan_keypair.public_b58()
        assert client.post(f"/prekeys/{addr}", json=payload).status_code == 200
        fetched = client.get(f"/prekeys/{addr}").json()
        assert not PreKeyBundle.from_dict(fetched).has_pq
