"""Cross-implementation vector conformance (Phase 13a).

Asserts the Python reference implementation reproduces every committed vector
in ``tests/vectors/`` bit-for-bit. The Rust ``drift-core`` runs the same files;
together they are the parity gate from ``docs/app-plan.md`` §6. A failure here
means the protocol changed — either revert, or regenerate the vectors with
``scripts/export_vectors.py`` as a deliberate, reviewed compatibility break.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from drift.crypto import Identity, Keypair, b58encode, decrypt, derive_message_key, encrypt
from drift.crypto.burn import generate_burn_token, verify_burn_token
from drift.crypto.fmd import FMDKeypair, derive_fmd_key, fmd_test
from drift.crypto.panic import KDFParams, derive_unlock_key, try_unlock
from drift.crypto.pqkem import PQKeypair
from drift.crypto.ratchet import (
    Header,
    _kdf_ck,
    _kdf_rk,
    init_receiver,
    init_sender,
    ratchet_decrypt,
    ratchet_encrypt,
)
from drift.crypto.sealed import open_header, parse
from drift.crypto.stealth import (
    derive_message_key_with_spend,
    derive_one_time_address,
    scan_for_message,
)
from drift.crypto.x3dh import (
    PreKeyBundle,
    PreKeyPrivates,
    X3DHHeader,
    derive_master_secret_recv,
    verify_prekey_bundle,
)

VECTORS = Path(__file__).resolve().parent.parent / "vectors"


def load(name: str) -> dict[str, Any]:
    return json.loads((VECTORS / f"{name}.json").read_text())


def keypair(priv_hex: str) -> Keypair:
    priv = X25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex))
    return Keypair(private_key=priv, public_key=priv.public_key())


def identity(scan_priv_hex: str, spend_priv_hex: str) -> Identity:
    return Identity(scan_keypair=keypair(scan_priv_hex), spend_keypair=keypair(spend_priv_hex))


# ---------------------------------------------------------------------------


class TestBase58:
    def test_vectors(self) -> None:
        for v in load("base58")["vectors"]:
            assert b58encode(bytes.fromhex(v["raw"])) == v["b58"]


class TestKDF:
    def test_hkdf_vectors(self) -> None:
        for v in load("kdf")["vectors"]:
            if "kind" in v:
                continue
            salt = bytes.fromhex(v["salt"]) if v["salt"] else None
            out = derive_message_key(
                bytes.fromhex(v["ikm"]), salt=salt, info=v["info"].encode()
            )
            assert out.hex() == v["okm"]

    def test_ratchet_kdfs(self) -> None:
        for v in load("kdf")["vectors"]:
            if v.get("kind") == "ratchet-rk":
                rk, ck = _kdf_rk(bytes.fromhex(v["root_key"]), bytes.fromhex(v["dh_out"]))
                assert rk.hex() == v["new_root_key"] and ck.hex() == v["chain_key"]
            elif v.get("kind") == "ratchet-ck":
                nck, mk = _kdf_ck(bytes.fromhex(v["chain_key"]))
                assert nck.hex() == v["next_chain_key"] and mk.hex() == v["message_key"]


class TestAEAD:
    def test_decrypt_direction(self) -> None:
        for v in load("aead")["vectors"]:
            pt = decrypt(
                bytes.fromhex(v["key"]),
                bytes.fromhex(v["ciphertext"]),
                associated_data=bytes.fromhex(v["associated_data"]),
            )
            assert pt.hex() == v["plaintext"]

    def test_roundtrip_fresh_nonce(self) -> None:
        for v in load("aead")["vectors"]:
            key = bytes.fromhex(v["key"])
            ad = bytes.fromhex(v["associated_data"])
            pt = bytes.fromhex(v["plaintext"])
            assert decrypt(key, encrypt(key, pt, associated_data=ad), associated_data=ad) == pt


class TestIdentity:
    def test_vector(self) -> None:
        v = load("identity")
        idn = identity(v["scan_priv"], v["spend_priv"])
        assert idn.scan_keypair.public_bytes().hex() == v["scan_pub"]
        assert idn.spend_keypair.public_bytes().hex() == v["spend_pub"]
        assert idn.contact_code() == v["contact_code"]
        assert idn.signing_seed().hex() == v["signing_seed"]
        assert idn.verify_key_bytes().hex() == v["verify_key"]
        sig = idn.signing_key().sign(bytes.fromhex(v["signed_message"])).signature
        assert sig.hex() == v["signature"]
        assert (
            idn.scan_keypair.ecdh(bytes.fromhex(v["ecdh"]["their_pub"])).hex()
            == v["ecdh"]["shared_secret"]
        )


class TestStealth:
    def test_vector(self) -> None:
        v = load("stealth")
        addr, msg_key = derive_one_time_address(
            bytes.fromhex(v["ephemeral_priv"]),
            bytes.fromhex(v["recipient_scan_pub"]),
            bytes.fromhex(v["recipient_spend_pub"]),
        )
        assert addr.hex() == v["one_time_address"]
        assert msg_key.hex() == v["message_key"]

        result = scan_for_message(
            bytes.fromhex(v["ephemeral_pub"]),
            bytes.fromhex(v["one_time_address"]),
            bytes.fromhex(v["recipient_scan_priv"]),
            bytes.fromhex(v["recipient_spend_pub"]),
        )
        assert result is not None
        assert result.scan_secret.hex() == v["scan_secret"]
        recv_key = derive_message_key_with_spend(
            result, bytes.fromhex(v["recipient_spend_priv"])
        )
        assert recv_key.hex() == v["message_key"]

        assert (
            scan_for_message(
                bytes.fromhex(v["ephemeral_pub"]),
                bytes.fromhex(v["one_time_address"]),
                bytes.fromhex(v["non_recipient_scan_priv"]),
                bytes.fromhex(v["non_recipient_spend_pub"]),
            )
            is None
        )


class TestSealed:
    def test_vector(self) -> None:
        v = load("sealed")
        eph, sealed_header, ct = parse(bytes.fromhex(v["blob"]))
        assert eph.hex() == v["ephemeral_pub"]
        assert ct.hex() == v["ratchet_ciphertext"]
        header = open_header(
            bytes.fromhex(v["stealth_key"]),
            sealed_header,
            address=bytes.fromhex(v["address"]),
        )
        assert header.hex() == v["ratchet_header"]


class TestRatchet:
    def test_transcript_replays_bit_for_bit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Replay the whole recorded conversation with the key/nonce tapes
        injected — every header and ciphertext must reproduce exactly, and
        every delivery (including the out-of-order skipped-key case) must
        decrypt. This is the same replay the Rust core runs."""
        import drift.crypto as crypto_mod

        v = load("ratchet")
        key_tape = [bytes.fromhex(k) for k in v["generated_ratchet_privs"]]
        nonce_tape = [bytes.fromhex(n) for n in v["aead_nonces"]]
        real_urandom = crypto_mod.os.urandom

        monkeypatch.setattr(
            Keypair, "generate", classmethod(lambda cls: keypair(key_tape.pop(0).hex()))
        )
        monkeypatch.setattr(
            crypto_mod.os,
            "urandom",
            lambda n: nonce_tape.pop(0) if n == crypto_mod.NONCE_SIZE else real_urandom(n),
        )

        alice = init_sender(
            bytes.fromhex(v["shared_secret"]),
            keypair(v["bob_initial_ratchet_priv"]).public_bytes(),
        )
        bob = init_receiver(
            bytes.fromhex(v["shared_secret"]),
            keypair(v["bob_initial_ratchet_priv"]),
        )
        states = {"alice": alice, "bob": bob}
        by_id = {m["id"]: m for m in v["messages"]}
        produced: dict[str, tuple[Header, bytes]] = {}

        for event in v["events"]:
            m = by_id[event["id"]]
            if event["type"] == "send":
                header, ct = ratchet_encrypt(
                    states[m["sender"]], bytes.fromhex(m["plaintext"])
                )
                assert header.to_bytes().hex() == m["header"], event["id"]
                assert ct.hex() == m["ciphertext"], event["id"]
                produced[event["id"]] = (header, ct)
            else:
                receiver = "bob" if m["sender"] == "alice" else "alice"
                header, ct = produced[event["id"]]
                pt = ratchet_decrypt(states[receiver], header, ct)
                assert pt.hex() == m["plaintext"], event["id"]

        assert not key_tape and not nonce_tape, "tapes must be fully consumed"

    def test_transcript_covers_dh_turns_and_skip(self) -> None:
        v = load("ratchet")
        senders = [m["sender"] for m in v["messages"]]
        assert "alice" in senders and "bob" in senders
        assert v["delivery_order"].index("A3") < v["delivery_order"].index("A2")


class TestX3DH:
    def _privates(self, case: dict[str, Any]) -> PreKeyPrivates:
        one_time = {}
        if "one_time_prekey_priv" in case:
            one_time[case["one_time_prekey_id"]] = keypair(case["one_time_prekey_priv"])
        return PreKeyPrivates(
            signed_prekey=keypair(case["bob_signed_prekey_priv"]),
            signed_prekey_id=case["signed_prekey_id"],
            signed_prekey_created=0.0,
            signed_prekey_sig=bytes.fromhex(case["signed_prekey_sig"]),
            one_time=one_time,
        )

    def test_receive_derives_master(self) -> None:
        v = load("x3dh")
        bob = identity(v["bob_scan_priv"], v["bob_spend_priv"])
        for case in v["cases"]:
            header = X3DHHeader.from_bytes(bytes.fromhex(case["header"]))
            master = derive_master_secret_recv(bob, self._privates(case), header)
            assert master.hex() == case["master_secret"]

    def test_bundle_signature_verifies(self) -> None:
        v = load("x3dh")
        bob = identity(v["bob_scan_priv"], v["bob_spend_priv"])
        for case in v["cases"]:
            privates = self._privates(case)
            bundle = PreKeyBundle(
                identity_key=bob.verify_key_bytes(),
                identity_dh_key=bob.spend_keypair.public_bytes(),
                signed_prekey=privates.signed_prekey.public_bytes(),
                signed_prekey_sig=privates.signed_prekey_sig,
                signed_prekey_id=privates.signed_prekey_id,
            )
            assert verify_prekey_bundle(bundle)

    def test_handoff_first_message_decrypts(self) -> None:
        v = load("x3dh")
        h = v["handoff"]
        bob = identity(v["bob_scan_priv"], v["bob_spend_priv"])
        privates = self._privates(h)
        header = X3DHHeader.from_bytes(bytes.fromhex(h["x3dh_header"]))
        master = derive_master_secret_recv(bob, privates, header)
        assert master.hex() == h["master_secret"]
        state = init_receiver(master, privates.signed_prekey)
        pt = ratchet_decrypt(
            state,
            Header.from_bytes(bytes.fromhex(h["ratchet_header"])),
            bytes.fromhex(h["ciphertext"]),
        )
        assert pt.hex() == h["plaintext"]


class TestPQXDH:
    """The hybrid post-quantum handshake. ML-KEM encapsulation is randomized,
    so the vector pins the deterministic receiver side: seed → keypair →
    decapsulate the recorded ciphertext → the recorded master secret."""

    def test_kem_decapsulation_pins(self) -> None:
        k = load("pqxdh")["kem"]
        kem = PQKeypair.from_seed(bytes.fromhex(k["seed"]))
        assert kem.public_bytes().hex() == k["public_key"]
        ss = kem.decapsulate(bytes.fromhex(k["ciphertext"]))
        assert ss.hex() == k["shared_secret"]

    def test_hybrid_receive_derives_master(self) -> None:
        h = load("pqxdh")["handshake"]
        bob = identity(h["bob_scan_priv"], h["bob_spend_priv"])
        privates = PreKeyPrivates(
            signed_prekey=keypair(h["bob_signed_prekey_priv"]),
            signed_prekey_id=h["signed_prekey_id"],
            signed_prekey_created=0.0,
            signed_prekey_sig=bytes.fromhex(h["signed_prekey_sig"]),
            one_time={h["one_time_prekey_id"]: keypair(h["one_time_prekey_priv"])},
            pq_prekey=PQKeypair.from_seed(bytes.fromhex(h["pq_prekey_seed"])),
            pq_prekey_id=h["pq_prekey_id"],
            pq_prekey_sig=bytes.fromhex(h["pq_prekey_sig"]),
        )
        header = X3DHHeader.from_bytes(bytes.fromhex(h["header"]))
        assert header.is_hybrid
        master = derive_master_secret_recv(bob, privates, header)
        assert master.hex() == h["master_secret"]

    def test_pq_bundle_signature_verifies(self) -> None:
        h = load("pqxdh")["handshake"]
        bob = identity(h["bob_scan_priv"], h["bob_spend_priv"])
        pq = PQKeypair.from_seed(bytes.fromhex(h["pq_prekey_seed"]))
        bundle = PreKeyBundle(
            identity_key=bob.verify_key_bytes(),
            identity_dh_key=bob.spend_keypair.public_bytes(),
            signed_prekey=keypair(h["bob_signed_prekey_priv"]).public_bytes(),
            signed_prekey_sig=bytes.fromhex(h["signed_prekey_sig"]),
            signed_prekey_id=h["signed_prekey_id"],
            pq_prekey=pq.public_bytes(),
            pq_prekey_sig=bytes.fromhex(h["pq_prekey_sig"]),
            pq_prekey_id=h["pq_prekey_id"],
        )
        assert verify_prekey_bundle(bundle)


class TestBurn:
    def test_vectors(self) -> None:
        for v in load("burn")["vectors"]:
            token = generate_burn_token(
                bytes.fromhex(v["shared_secret"]),
                v["scope"],
                v["message_id"],
                nonce=bytes.fromhex(v["nonce"]),
                timestamp=v["timestamp"],
            )
            assert token == v["token"]
            assert verify_burn_token(
                bytes.fromhex(v["shared_secret"]),
                token,
                v["scope"],
                v["message_id"],
                now=v["timestamp"],
            )


class TestVault:
    def test_kdf_pin(self) -> None:
        k = load("vault")["kdf"]
        params = KDFParams(
            time_cost=k["time_cost"],
            memory_cost=k["memory_cost"],
            parallelism=k["parallelism"],
        )
        key = derive_unlock_key(k["passphrase"], bytes.fromhex(k["salt"]), params)
        assert key.hex() == k["unlock_key"]

    def test_unlocks(self) -> None:
        for vault in load("vault")["vaults"]:
            blob = bytes.fromhex(vault["blob"])
            for case in vault["unlocks"]:
                got = try_unlock(blob, case["passphrase"])
                if case["payload"] is None:
                    assert got is None
                else:
                    assert got is not None and got.hex() == case["payload"]


class TestFMD:
    def test_key_derivation(self) -> None:
        v = load("fmd")
        key = derive_fmd_key(bytes.fromhex(v["seed"]), v["num_subkeys"])
        assert [k.hex() for k in key.secret_keys] == v["secret_keys"]
        assert [k.hex() for k in key.public_keys] == v["public_keys"]

    def test_flag_tests(self) -> None:
        v = load("fmd")
        flag = bytes.fromhex(v["flag"])
        full = FMDKeypair(
            secret_keys=[bytes.fromhex(k) for k in v["secret_keys"]],
            public_keys=[bytes.fromhex(k) for k in v["public_keys"]],
        )
        for t in v["tests"]:
            key = FMDKeypair(
                secret_keys=full.secret_keys[: t["subkeys"]],
                public_keys=full.public_keys,
            )
            assert fmd_test(flag, key, bytes.fromhex(t["message"])) == t["match"]


@pytest.mark.parametrize(
    "name",
    [
        "base58",
        "kdf",
        "aead",
        "identity",
        "stealth",
        "sealed",
        "ratchet",
        "x3dh",
        "pqxdh",
        "burn",
        "vault",
        "fmd",
    ],
)
def test_vector_file_exists_and_has_meta(name: str) -> None:
    data = load(name)
    assert data["_meta"]["generator"] == "scripts/export_vectors.py"
