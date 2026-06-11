"""
tests/unit/test_ratchet.py — unit tests for drift.crypto.ratchet

Exercises the Double Ratchet directly (no network):
  - 10 messages each way, interleaved (a DH ratchet on every turn)
  - out-of-order delivery within a chain and across a DH ratchet
  - header integrity (tampered header → InvalidTag)
  - forward secrecy: a later state cannot reconstruct an earlier message key

Run: pytest tests/unit/test_ratchet.py -v
"""

from __future__ import annotations

import os

import pytest
from cryptography.exceptions import InvalidTag

from drift.crypto import Keypair
from drift.crypto.ratchet import (
    Header,
    RatchetError,
    init_receiver,
    init_sender,
    ratchet_decrypt,
    ratchet_encrypt,
)


def _bootstrap() -> tuple[object, object]:
    """A fresh Alice (sender) / Bob (receiver) ratchet pair sharing a secret."""
    shared = os.urandom(32)
    bob_kp = Keypair.generate()
    alice = init_sender(shared, bob_kp.public_bytes())
    bob = init_receiver(shared, bob_kp)
    return alice, bob


# ---------------------------------------------------------------------------
# Header serialization
# ---------------------------------------------------------------------------

class TestHeader:
    def test_roundtrip(self) -> None:
        h = Header(dh=os.urandom(32), pn=7, n=42)
        assert Header.from_bytes(h.to_bytes()) == h

    def test_wire_length_is_40(self) -> None:
        h = Header(dh=os.urandom(32), pn=0, n=0)
        assert len(h.to_bytes()) == 40

    def test_rejects_wrong_length(self) -> None:
        with pytest.raises(ValueError):
            Header.from_bytes(b"\x00" * 39)


# ---------------------------------------------------------------------------
# Basic flow
# ---------------------------------------------------------------------------

class TestBasicFlow:
    def test_single_message(self) -> None:
        alice, bob = _bootstrap()
        header, ct = ratchet_encrypt(alice, b"hello bob")
        assert ratchet_decrypt(bob, header, ct) == b"hello bob"

    def test_receiver_cannot_send_before_receiving(self) -> None:
        _, bob = _bootstrap()
        with pytest.raises(RatchetError):
            ratchet_encrypt(bob, b"too early")

    def test_responder_can_reply_after_first_receive(self) -> None:
        alice, bob = _bootstrap()
        h, ct = ratchet_encrypt(alice, b"hi")
        assert ratchet_decrypt(bob, h, ct) == b"hi"
        # Now Bob has a sending chain.
        h2, ct2 = ratchet_encrypt(bob, b"hi back")
        assert ratchet_decrypt(alice, h2, ct2) == b"hi back"


# ---------------------------------------------------------------------------
# The headline test: 10 each way, interleaved
# ---------------------------------------------------------------------------

class TestInterleaved:
    def test_ten_each_way_interleaved(self) -> None:
        alice, bob = _bootstrap()

        for i in range(10):
            # Alice → Bob
            msg = f"A->B #{i}".encode()
            header, ct = ratchet_encrypt(alice, msg)
            assert ratchet_decrypt(bob, header, ct) == msg

            # Bob → Alice (turns the DH ratchet back the other way)
            reply = f"B->A #{i}".encode()
            header, ct = ratchet_encrypt(bob, reply)
            assert ratchet_decrypt(alice, header, ct) == reply

    def test_burst_then_reply(self) -> None:
        # 10 from Alice with no reply (single sending chain), then 10 from Bob.
        alice, bob = _bootstrap()

        for i in range(10):
            header, ct = ratchet_encrypt(alice, f"a{i}".encode())
            assert ratchet_decrypt(bob, header, ct) == f"a{i}".encode()

        for i in range(10):
            header, ct = ratchet_encrypt(bob, f"b{i}".encode())
            assert ratchet_decrypt(alice, header, ct) == f"b{i}".encode()


# ---------------------------------------------------------------------------
# Out-of-order delivery
# ---------------------------------------------------------------------------

class TestOutOfOrder:
    def test_within_one_chain(self) -> None:
        alice, bob = _bootstrap()

        # Alice encrypts three; the network reorders them.
        msgs = [ratchet_encrypt(alice, f"m{i}".encode()) for i in range(3)]
        h0, c0 = msgs[0]
        h1, c1 = msgs[1]
        h2, c2 = msgs[2]

        # Bob receives 2, then 0, then 1.
        assert ratchet_decrypt(bob, h2, c2) == b"m2"  # skips 0,1 into cache
        assert ratchet_decrypt(bob, h0, c0) == b"m0"  # from cache
        assert ratchet_decrypt(bob, h1, c1) == b"m1"  # from cache

    def test_across_a_dh_ratchet(self) -> None:
        alice, bob = _bootstrap()

        # Alice's first chain: a0, a1. a1 will be delayed in the network.
        a0 = ratchet_encrypt(alice, b"a0")
        a1 = ratchet_encrypt(alice, b"a1")

        # Bob receives a0, so he can now reply.
        assert ratchet_decrypt(bob, a0[0], a0[1]) == b"a0"

        # Bob replies; Alice receives it and turns her DH ratchet onto a new
        # sending chain.
        bh, bc = ratchet_encrypt(bob, b"bobs reply")
        assert ratchet_decrypt(alice, bh, bc) == b"bobs reply"

        # Alice sends on her *new* chain. Its header PN tells Bob the old chain
        # had 2 messages, so receiving it skips a1 into the cache.
        a_new = ratchet_encrypt(alice, b"new chain msg")
        assert ratchet_decrypt(bob, a_new[0], a_new[1]) == b"new chain msg"

        # The straggler from the previous chain still decrypts (from the cache).
        assert ratchet_decrypt(bob, a1[0], a1[1]) == b"a1"


# ---------------------------------------------------------------------------
# Integrity
# ---------------------------------------------------------------------------

class TestIntegrity:
    def test_tampered_ciphertext_raises(self) -> None:
        alice, bob = _bootstrap()
        header, ct = ratchet_encrypt(alice, b"secret")
        bad = bytearray(ct)
        bad[-1] ^= 0xFF
        with pytest.raises(InvalidTag):
            ratchet_decrypt(bob, header, bytes(bad))

    def test_tampered_header_raises(self) -> None:
        alice, bob = _bootstrap()
        header, ct = ratchet_encrypt(alice, b"secret")
        # Same ratchet key (no DH ratchet) but a forged message number → the
        # header is bound as AD, so authentication fails.
        forged = Header(dh=header.dh, pn=header.pn, n=header.n + 5)
        with pytest.raises(InvalidTag):
            ratchet_decrypt(bob, forged, ct)

    def test_too_many_skipped_raises(self) -> None:
        alice, bob = _bootstrap()
        header, ct = ratchet_encrypt(alice, b"way ahead")
        # Forge a message number far beyond MAX_SKIP.
        forged = Header(dh=header.dh, pn=header.pn, n=10_000)
        with pytest.raises(RatchetError):
            ratchet_decrypt(bob, forged, ct)


# ---------------------------------------------------------------------------
# Forward secrecy
# ---------------------------------------------------------------------------

class TestForwardSecrecy:
    def test_later_state_cannot_decrypt_earlier_message(self) -> None:
        alice, bob = _bootstrap()

        # Capture the first message, then consume it normally.
        h1, c1 = ratchet_encrypt(alice, b"the launch code is 0000")
        assert ratchet_decrypt(bob, h1, c1) == b"the launch code is 0000"

        # Conversation continues; Bob's receiving chain advances past msg #1.
        for i in range(5):
            h, c = ratchet_encrypt(alice, f"later {i}".encode())
            assert ratchet_decrypt(bob, h, c) == f"later {i}".encode()

        # An attacker who later compromises Bob's *current* state replays the
        # captured first ciphertext. The message key was consumed and the chain
        # key is one-way, so it cannot be reconstructed → no plaintext recovery.
        with pytest.raises(InvalidTag):
            ratchet_decrypt(bob, h1, c1)

        # The consumed key is not lingering in the skipped-key cache either.
        assert (h1.dh, h1.n) not in bob.message_keys

    def test_erased_chain_key_destroys_recoverability(self) -> None:
        alice, bob = _bootstrap()

        h1, c1 = ratchet_encrypt(alice, b"past secret")
        assert ratchet_decrypt(bob, h1, c1) == b"past secret"

        # Simulate secure erasure of mid-conversation key material.
        bob.receiving_chain_key = None
        bob.sending_chain_key = None
        bob.message_keys.clear()

        # With the chain key gone there is provably no way back to the message.
        with pytest.raises((InvalidTag, RatchetError)):
            ratchet_decrypt(bob, h1, c1)

    def test_each_message_uses_a_distinct_key(self) -> None:
        # Indirect forward-secrecy property: identical plaintext encrypts to
        # different ciphertext each step (chain advances every message).
        alice, _ = _bootstrap()
        seen = set()
        for _ in range(20):
            _, ct = ratchet_encrypt(alice, b"same plaintext")
            seen.add(ct)
        assert len(seen) == 20
