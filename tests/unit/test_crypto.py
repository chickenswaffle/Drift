"""
tests/unit/test_crypto.py — unit tests for drift.crypto

Run: pytest tests/unit/test_crypto.py -v
"""

from __future__ import annotations

import pytest
from cryptography.exceptions import InvalidTag

from drift.crypto import (
    Keypair,
    Identity,
    derive_message_key,
    encrypt,
    decrypt,
    b58encode,
    b58decode,
)


# ---------------------------------------------------------------------------
# Base58
# ---------------------------------------------------------------------------

class TestBase58:
    def test_roundtrip_random(self):
        import os
        for _ in range(20):
            data = os.urandom(32)
            assert b58decode(b58encode(data)) == data

    def test_known_value(self):
        # b58encode(b'\x00' * 1) should be '1'
        assert b58encode(b"\x00") == "1"

    def test_empty(self):
        assert b58decode(b58encode(b"")) == b""


# ---------------------------------------------------------------------------
# Keypair
# ---------------------------------------------------------------------------

class TestKeypair:
    def test_generate_produces_32_byte_keys(self):
        kp = Keypair.generate()
        assert len(kp.public_bytes()) == 32
        assert len(kp.private_bytes()) == 32

    def test_ecdh_is_symmetric(self):
        alice = Keypair.generate()
        bob = Keypair.generate()
        shared_alice = alice.ecdh(bob.public_bytes())
        shared_bob = bob.ecdh(alice.public_bytes())
        assert shared_alice == shared_bob

    def test_different_keypairs_differ(self):
        a = Keypair.generate()
        b = Keypair.generate()
        assert a.public_bytes() != b.public_bytes()

    def test_public_b58_is_str(self):
        kp = Keypair.generate()
        b58 = kp.public_b58()
        assert isinstance(b58, str)
        assert len(b58) > 0


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

class TestKeyDerivation:
    def test_derive_is_deterministic(self):
        secret = b"\x42" * 32
        k1 = derive_message_key(secret)
        k2 = derive_message_key(secret)
        assert k1 == k2

    def test_derive_produces_32_bytes(self):
        key = derive_message_key(b"\x01" * 32)
        assert len(key) == 32

    def test_different_infos_produce_different_keys(self):
        secret = b"\x55" * 32
        k1 = derive_message_key(secret, info=b"info-a")
        k2 = derive_message_key(secret, info=b"info-b")
        assert k1 != k2

    def test_different_salts_produce_different_keys(self):
        secret = b"\x55" * 32
        k1 = derive_message_key(secret, salt=b"salt-a")
        k2 = derive_message_key(secret, salt=b"salt-b")
        assert k1 != k2


# ---------------------------------------------------------------------------
# AEAD encrypt / decrypt
# ---------------------------------------------------------------------------

class TestAEAD:
    def test_roundtrip(self):
        import os
        key = os.urandom(32)
        plaintext = b"hello drift"
        ct = encrypt(key, plaintext)
        assert decrypt(key, ct) == plaintext

    def test_nonce_is_random(self):
        import os
        key = os.urandom(32)
        ct1 = encrypt(key, b"same message")
        ct2 = encrypt(key, b"same message")
        # Different nonces → different ciphertexts even for same plaintext
        assert ct1 != ct2

    def test_wrong_key_raises(self):
        import os
        key = os.urandom(32)
        wrong_key = os.urandom(32)
        ct = encrypt(key, b"secret")
        with pytest.raises(InvalidTag):
            decrypt(wrong_key, ct)

    def test_tampered_ciphertext_raises(self):
        import os
        key = os.urandom(32)
        ct = bytearray(encrypt(key, b"secret"))
        ct[-1] ^= 0xFF  # flip a bit in the auth tag
        with pytest.raises(InvalidTag):
            decrypt(key, bytes(ct))

    def test_associated_data_mismatch_raises(self):
        import os
        key = os.urandom(32)
        ct = encrypt(key, b"secret", associated_data=b"context-a")
        with pytest.raises(InvalidTag):
            decrypt(key, ct, associated_data=b"context-b")

    def test_wrong_key_length_raises(self):
        with pytest.raises(ValueError):
            encrypt(b"tooshort", b"data")

    def test_large_message(self):
        import os
        key = os.urandom(32)
        plaintext = os.urandom(1024 * 64)  # 64 KB
        assert decrypt(key, encrypt(key, plaintext)) == plaintext


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------

class TestIdentity:
    def test_generate(self):
        identity = Identity.generate()
        code = identity.contact_code()
        assert code.startswith("drift:")
        assert "." in code

    def test_contact_code_roundtrip(self):
        identity = Identity.generate()
        code = identity.contact_code()
        scan_pub, spend_pub = Identity.parse_contact_code(code)
        assert scan_pub == identity.scan_keypair.public_bytes()
        assert spend_pub == identity.spend_keypair.public_bytes()

    def test_save_and_load(self, tmp_path):
        identity = Identity.generate()
        path = tmp_path / "identity.json"
        identity.save(path)
        loaded = Identity.load(path)
        assert loaded.scan_keypair.public_bytes() == identity.scan_keypair.public_bytes()
        assert loaded.spend_keypair.public_bytes() == identity.spend_keypair.public_bytes()

    def test_identity_file_permissions(self, tmp_path):
        import stat
        identity = Identity.generate()
        path = tmp_path / "identity.json"
        identity.save(path)
        mode = stat.S_IMODE(path.stat().st_mode)
        assert mode == 0o600, f"Expected 0o600, got {oct(mode)}"

    def test_malformed_contact_code_raises(self):
        with pytest.raises(ValueError):
            Identity.parse_contact_code("notdrift:something")

    def test_two_identities_are_different(self):
        a = Identity.generate()
        b = Identity.generate()
        assert a.contact_code() != b.contact_code()
