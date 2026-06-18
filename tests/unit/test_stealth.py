"""
tests/unit/test_stealth.py — unit tests for drift.crypto.stealth

Covers the Phase 1 rotating stealth-address scheme:
  - sender derives a one-time address + message key
  - receiver scans (scan key) then derives the key (spend key)
  - non-recipients cannot detect the message
  - every message lands at a unique, unlinkable address
  - scan/spend privilege separation (audit M1): scan key detects, spend
    key is required to decrypt

Run: pytest tests/unit/test_stealth.py -v
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from drift.crypto import Identity, decrypt, encrypt
from drift.crypto.stealth import (
    ScanResult,
    StealthEnvelope,
    derive_message_key_with_spend,
    derive_one_time_address,
    scan_for_message,
)


def _recover_key(eph_pub: bytes, addr: bytes, recipient: Identity) -> bytes | None:
    """Full two-step receive (scan then spend) → message key, or None."""
    scanned = scan_for_message(
        eph_pub,
        addr,
        recipient.scan_keypair.private_bytes(),
        recipient.spend_keypair.public_bytes(),
    )
    if scanned is None:
        return None
    return derive_message_key_with_spend(
        scanned, recipient.spend_keypair.private_bytes()
    )


def _ephemeral() -> tuple[bytes, bytes]:
    """Return (private_bytes, public_bytes) for a fresh X25519 keypair."""
    priv = X25519PrivateKey.generate()
    return priv.private_bytes_raw(), priv.public_key().public_bytes_raw()


# ---------------------------------------------------------------------------
# Core sender/receiver agreement
# ---------------------------------------------------------------------------

class TestStealthRoundtrip:
    def test_sender_and_receiver_agree_on_address_and_key(self) -> None:
        recipient = Identity.generate()
        scan_pub = recipient.scan_keypair.public_bytes()
        spend_pub = recipient.spend_keypair.public_bytes()
        eph_priv, eph_pub = _ephemeral()

        addr, send_key = derive_one_time_address(eph_priv, scan_pub, spend_pub)
        recovered_key = _recover_key(eph_pub, addr, recipient)

        assert recovered_key is not None
        assert recovered_key == send_key

    def test_addr_and_key_are_32_bytes(self) -> None:
        recipient = Identity.generate()
        eph_priv, _ = _ephemeral()
        addr, key = derive_one_time_address(
            eph_priv,
            recipient.scan_keypair.public_bytes(),
            recipient.spend_keypair.public_bytes(),
        )
        assert len(addr) == 32
        assert len(key) == 32

    def test_end_to_end_encrypt_decrypt_through_stealth(self) -> None:
        recipient = Identity.generate()
        scan_pub = recipient.scan_keypair.public_bytes()
        spend_pub = recipient.spend_keypair.public_bytes()

        eph_priv, eph_pub = _ephemeral()
        addr, send_key = derive_one_time_address(eph_priv, scan_pub, spend_pub)
        ciphertext = encrypt(send_key, b"the eagle lands at midnight")

        recovered_key = _recover_key(eph_pub, addr, recipient)
        assert recovered_key is not None
        assert decrypt(recovered_key, ciphertext) == b"the eagle lands at midnight"


# ---------------------------------------------------------------------------
# Negative cases — scanning must not produce false positives
# ---------------------------------------------------------------------------

class TestStealthScanning:
    def test_non_recipient_cannot_detect(self) -> None:
        alice = Identity.generate()
        eve = Identity.generate()

        eph_priv, eph_pub = _ephemeral()
        addr, _ = derive_one_time_address(
            eph_priv,
            alice.scan_keypair.public_bytes(),
            alice.spend_keypair.public_bytes(),
        )

        # Eve scans with her own scan key → must not match.
        result = scan_for_message(
            eph_pub,
            addr,
            eve.scan_keypair.private_bytes(),
            eve.spend_keypair.public_bytes(),
        )
        assert result is None

    def test_wrong_ephemeral_pub_does_not_match(self) -> None:
        recipient = Identity.generate()
        scan_pub = recipient.scan_keypair.public_bytes()
        spend_pub = recipient.spend_keypair.public_bytes()
        scan_priv = recipient.scan_keypair.private_bytes()

        eph_priv, _ = _ephemeral()
        addr, _ = derive_one_time_address(eph_priv, scan_pub, spend_pub)

        # A different ephemeral pub → recomputed address won't match.
        _, other_eph_pub = _ephemeral()
        assert scan_for_message(other_eph_pub, addr, scan_priv, spend_pub) is None

    def test_tampered_address_does_not_match(self) -> None:
        recipient = Identity.generate()
        scan_pub = recipient.scan_keypair.public_bytes()
        spend_pub = recipient.spend_keypair.public_bytes()
        scan_priv = recipient.scan_keypair.private_bytes()

        eph_priv, eph_pub = _ephemeral()
        addr, _ = derive_one_time_address(eph_priv, scan_pub, spend_pub)

        tampered = bytearray(addr)
        tampered[0] ^= 0x01
        assert scan_for_message(eph_pub, bytes(tampered), scan_priv, spend_pub) is None


# ---------------------------------------------------------------------------
# Unlinkability — the whole point of stealth addresses
# ---------------------------------------------------------------------------

class TestStealthUnlinkability:
    def test_each_message_gets_a_unique_address(self) -> None:
        recipient = Identity.generate()
        scan_pub = recipient.scan_keypair.public_bytes()
        spend_pub = recipient.spend_keypair.public_bytes()

        addresses = set()
        for _ in range(50):
            eph_priv, _ = _ephemeral()
            addr, _key = derive_one_time_address(eph_priv, scan_pub, spend_pub)
            addresses.add(addr)

        # 50 fresh ephemerals → 50 distinct addresses, none linkable.
        assert len(addresses) == 50

    def test_addresses_for_different_recipients_differ(self) -> None:
        a = Identity.generate()
        b = Identity.generate()

        # Same ephemeral key, two recipients → two unrelated addresses.
        eph_priv, _ = _ephemeral()
        addr_a, _ = derive_one_time_address(
            eph_priv, a.scan_keypair.public_bytes(), a.spend_keypair.public_bytes()
        )
        addr_b, _ = derive_one_time_address(
            eph_priv, b.scan_keypair.public_bytes(), b.spend_keypair.public_bytes()
        )
        assert addr_a != addr_b


# ---------------------------------------------------------------------------
# Scan/spend privilege separation (audit M1)
# ---------------------------------------------------------------------------

class TestScanSpendPrivilegeSeparation:
    """The scan key detects; the spend *private* key is required to decrypt."""

    def test_scan_only_confirms_ownership_without_spend_priv(self) -> None:
        # A scan-only delegate holds the private scan key + public spend key.
        recipient = Identity.generate()
        eph_priv, eph_pub = _ephemeral()
        addr, _ = derive_one_time_address(
            eph_priv,
            recipient.scan_keypair.public_bytes(),
            recipient.spend_keypair.public_bytes(),
        )

        scanned = scan_for_message(
            eph_pub,
            addr,
            recipient.scan_keypair.private_bytes(),
            recipient.spend_keypair.public_bytes(),
        )
        # Ownership confirmed — but the result is only an intermediate, not a key.
        assert isinstance(scanned, ScanResult)
        assert scanned.ephemeral_pub == eph_pub
        assert scanned.scan_secret != addr  # not the message key, not the address

    def test_spend_priv_required_to_derive_message_key(self) -> None:
        # Sender's key is bound to BOTH scan and spend; the scan secret alone
        # (all a scan-only device has) cannot reconstruct it.
        recipient = Identity.generate()
        eph_priv, eph_pub = _ephemeral()
        addr, send_key = derive_one_time_address(
            eph_priv,
            recipient.scan_keypair.public_bytes(),
            recipient.spend_keypair.public_bytes(),
        )

        scanned = scan_for_message(
            eph_pub,
            addr,
            recipient.scan_keypair.private_bytes(),
            recipient.spend_keypair.public_bytes(),
        )
        assert scanned is not None

        # The intermediate scan secret is NOT the message key.
        assert scanned.scan_secret != send_key
        # Only folding in the spend private key reproduces the sender's key.
        full_key = derive_message_key_with_spend(
            scanned, recipient.spend_keypair.private_bytes()
        )
        assert full_key == send_key

    def test_wrong_spend_priv_yields_wrong_key(self) -> None:
        # A device with the right scan key but a *different* spend key cannot
        # derive the real message key — confidentiality rests on the spend key.
        recipient = Identity.generate()
        attacker = Identity.generate()
        eph_priv, eph_pub = _ephemeral()
        addr, send_key = derive_one_time_address(
            eph_priv,
            recipient.scan_keypair.public_bytes(),
            recipient.spend_keypair.public_bytes(),
        )

        scanned = scan_for_message(
            eph_pub,
            addr,
            recipient.scan_keypair.private_bytes(),
            recipient.spend_keypair.public_bytes(),
        )
        assert scanned is not None
        wrong_key = derive_message_key_with_spend(
            scanned, attacker.spend_keypair.private_bytes()
        )
        assert wrong_key != send_key


# ---------------------------------------------------------------------------
# Envelope shape
# ---------------------------------------------------------------------------

class TestStealthEnvelope:
    def test_envelope_fields(self) -> None:
        env = StealthEnvelope(
            ephemeral_pub=b"R" * 32,
            one_time_addr=b"A" * 32,
            ciphertext=os.urandom(40),
        )
        assert env.ephemeral_pub == b"R" * 32
        assert env.one_time_addr == b"A" * 32
        assert len(env.ciphertext) == 40
