#!/usr/bin/env python3
"""
scripts/export_vectors.py — cross-implementation test vectors (Phase 13a)

Exports deterministic JSON vectors from the Python reference implementation to
``tests/vectors/``. The Rust core (``drift-core``) must reproduce every vector
bit-for-bit; ``tests/unit/test_vectors.py`` asserts the Python core itself
still does. Together they are the parity gate `docs/app-plan.md` §6 requires
before any second implementation ships.

Determinism
-----------
Private keys, seeds and passphrases are derived from labeled SHA-256 streams —
never ``os.urandom`` — so the *inputs* are stable across regenerations. Two
kinds of vector exist:

  - **derivation vectors** (base58, HKDF, identity, stealth, X3DH, burn, FMD
    key derivation): pure functions of the recorded inputs. Regenerating the
    file reproduces them byte-for-byte.
  - **transcript vectors** (ratchet, sealed, AEAD, vault, FMD flags): the live
    code draws AEAD nonces / ratchet keypairs at random, so generation patches
    ``Keypair.generate`` and the AEAD nonce source with recorded deterministic
    streams (ratchet/x3dh transcripts) or simply records the random output for
    decrypt-direction verification (AEAD, vault, FMD flags).

Regenerate with ``python scripts/export_vectors.py`` only when the protocol
deliberately changes; the committed vectors are the compatibility contract.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey  # noqa: E402

import drift.crypto as crypto  # noqa: E402
from drift.crypto import (  # noqa: E402
    Identity,
    Keypair,
    b58encode,
    decrypt,
    derive_message_key,
    encrypt,
)
from drift.crypto.burn import generate_burn_token, verify_burn_token  # noqa: E402
from drift.crypto.fmd import derive_fmd_key, fmd_flag, fmd_test  # noqa: E402
from drift.crypto.panic import KDFParams, create_vault, derive_unlock_key, try_unlock  # noqa: E402
from drift.crypto.ratchet import (  # noqa: E402
    Header,
    _kdf_ck,
    _kdf_rk,
    init_receiver,
    init_sender,
    ratchet_decrypt,
    ratchet_encrypt,
)
from drift.crypto.sealed import open_header, parse, seal  # noqa: E402
from drift.crypto.stealth import (  # noqa: E402
    derive_message_key_with_spend,
    derive_one_time_address,
    scan_for_message,
)
from drift.crypto.x3dh import (  # noqa: E402
    PreKeyBundle,
    PreKeyPrivates,
    _sign_signed_prekey,
    derive_master_secret_recv,
    verify_prekey_bundle,
    x3dh_send,
)

OUT_DIR = REPO / "tests" / "vectors"


# ---------------------------------------------------------------------------
# Deterministic material
# ---------------------------------------------------------------------------


def dbytes(label: str, n: int = 32) -> bytes:
    """`n` deterministic bytes from a labeled SHA-256 counter stream."""
    out = b""
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(f"drift-vectors-v1:{label}:{counter}".encode()).digest()
        counter += 1
    return out[:n]


def dkeypair(label: str) -> Keypair:
    """A deterministic X25519 keypair (private bytes = dbytes(label))."""
    priv = X25519PrivateKey.from_private_bytes(dbytes(label))
    return Keypair(private_key=priv, public_key=priv.public_key())


def didentity(label: str) -> Identity:
    return Identity(
        scan_keypair=dkeypair(f"{label}:scan"),
        spend_keypair=dkeypair(f"{label}:spend"),
    )


class KeypairTape:
    """Replaces ``Keypair.generate`` during transcript generation.

    Serves deterministic keypairs from a labeled stream and records each
    private key so a replaying implementation can inject the same sequence.
    """

    def __init__(self, label: str) -> None:
        self.label = label
        self.recorded: list[str] = []

    def generate(self) -> Keypair:
        kp = dkeypair(f"{self.label}:gen:{len(self.recorded)}")
        self.recorded.append(kp.private_bytes().hex())
        return kp


class NonceTape:
    """Replaces the AEAD nonce source (``os.urandom`` 24-byte calls) during
    transcript generation. Non-24-byte requests fall through to the real
    ``os.urandom`` so nothing else is silently made deterministic."""

    def __init__(self, label: str) -> None:
        self.label = label
        self.count = 0
        self.recorded: list[str] = []
        self._real = os.urandom

    def urandom(self, n: int) -> bytes:
        if n != crypto.NONCE_SIZE:
            return self._real(n)
        nonce = dbytes(f"{self.label}:nonce:{self.count}", n)
        self.count += 1
        self.recorded.append(nonce.hex())
        return nonce


@contextmanager
def transcript_mode(label: str) -> Iterator[tuple[KeypairTape, NonceTape]]:
    """Patch ``Keypair.generate`` + the AEAD nonce source, recording both."""
    keys = KeypairTape(label)
    nonces = NonceTape(label)
    orig_generate = Keypair.generate
    orig_urandom = crypto.os.urandom
    Keypair.generate = classmethod(lambda cls: keys.generate())  # type: ignore[method-assign, assignment]
    crypto.os.urandom = nonces.urandom  # type: ignore[assignment]
    try:
        yield keys, nonces
    finally:
        Keypair.generate = orig_generate  # type: ignore[method-assign]
        crypto.os.urandom = orig_urandom


# ---------------------------------------------------------------------------
# Vector builders — one function per file
# ---------------------------------------------------------------------------


def build_base58() -> dict[str, Any]:
    cases = [
        b"",
        b"\x00",
        b"\x00\x00\x01",
        b"hello world",
        bytes(range(32)),
        dbytes("base58:random"),
        b"\x00" * 4 + dbytes("base58:zeros", 8),
    ]
    return {
        "vectors": [{"raw": c.hex(), "b58": b58encode(c)} for c in cases],
    }


def build_kdf() -> dict[str, Any]:
    """HKDF-SHA256 vectors for every domain-separated info string the core uses."""
    ikm = dbytes("kdf:ikm")
    salt = dbytes("kdf:salt")
    vectors: list[dict[str, Any]] = []
    for info, use_salt in [
        (b"drift-v0-msg", False),
        (b"drift-v2-msg", False),
        (b"drift-sealed-sender-v1", False),
        (b"drift-identity-sign-v1", False),
        (b"drift-fmd-seed-v1", False),
        (b"drift-burn-v1", False),
        (b"drift-ratchet-v1-fs-bootstrap", True),
    ]:
        out = derive_message_key(ikm, salt=salt if use_salt else None, info=info)
        vectors.append(
            {
                "ikm": ikm.hex(),
                "salt": salt.hex() if use_salt else None,
                "info": info.decode(),
                "length": 32,
                "okm": out.hex(),
            }
        )
    # The two ratchet KDFs (64-byte HKDF split into two 32-byte keys).
    rk, ck = _kdf_rk(dbytes("kdf:rk:root"), dbytes("kdf:rk:dh"))
    vectors.append(
        {
            "kind": "ratchet-rk",
            "root_key": dbytes("kdf:rk:root").hex(),
            "dh_out": dbytes("kdf:rk:dh").hex(),
            "new_root_key": rk.hex(),
            "chain_key": ck.hex(),
        }
    )
    nck, mk = _kdf_ck(dbytes("kdf:ck:chain"))
    vectors.append(
        {
            "kind": "ratchet-ck",
            "chain_key": dbytes("kdf:ck:chain").hex(),
            "next_chain_key": nck.hex(),
            "message_key": mk.hex(),
        }
    )
    return {"vectors": vectors}


def build_aead() -> dict[str, Any]:
    """XChaCha20-Poly1305 envelope vectors (nonce ‖ ct+tag). Deterministic:
    the nonce is drawn from a recorded tape, so encryption is replayable."""
    vectors: list[dict[str, Any]] = []
    cases = [
        (b"", b""),
        (b"attack at dawn", b""),
        (b"bound to metadata", b"drift-ad-example"),
        (dbytes("aead:big", 1000), b"\x00\x01\x02"),
    ]
    with transcript_mode("aead") as (_keys, _nonces):
        for i, (pt, ad) in enumerate(cases):
            key = dbytes(f"aead:key:{i}")
            ct = encrypt(key, pt, associated_data=ad)
            assert decrypt(key, ct, associated_data=ad) == pt
            vectors.append(
                {
                    "key": key.hex(),
                    "plaintext": pt.hex(),
                    "associated_data": ad.hex(),
                    "ciphertext": ct.hex(),
                }
            )
    return {"vectors": vectors}


def build_identity() -> dict[str, Any]:
    idn = didentity("identity:alice")
    msg = b"drift identity vector message"
    sig = idn.signing_key().sign(msg).signature
    return {
        "scan_priv": idn.scan_keypair.private_bytes().hex(),
        "scan_pub": idn.scan_keypair.public_bytes().hex(),
        "spend_priv": idn.spend_keypair.private_bytes().hex(),
        "spend_pub": idn.spend_keypair.public_bytes().hex(),
        "contact_code": idn.contact_code(),
        "signing_seed": idn.signing_seed().hex(),
        "verify_key": idn.verify_key_bytes().hex(),
        "signed_message": msg.hex(),
        "signature": sig.hex(),
        "ecdh": {
            "their_pub": dkeypair("identity:peer").public_bytes().hex(),
            "shared_secret": idn.scan_keypair.ecdh(
                dkeypair("identity:peer").public_bytes()
            ).hex(),
        },
    }


def build_stealth() -> dict[str, Any]:
    recipient = didentity("stealth:recipient")
    eph = dkeypair("stealth:ephemeral")
    scan_pub = recipient.scan_keypair.public_bytes()
    spend_pub = recipient.spend_keypair.public_bytes()

    addr, msg_key = derive_one_time_address(eph.private_bytes(), scan_pub, spend_pub)

    result = scan_for_message(
        eph.public_bytes(), addr, recipient.scan_keypair.private_bytes(), spend_pub
    )
    assert result is not None
    recv_key = derive_message_key_with_spend(result, recipient.spend_keypair.private_bytes())
    assert recv_key == msg_key

    # A different recipient must NOT detect it.
    other = didentity("stealth:other")
    miss = scan_for_message(
        eph.public_bytes(),
        addr,
        other.scan_keypair.private_bytes(),
        other.spend_keypair.public_bytes(),
    )
    assert miss is None

    return {
        "recipient_scan_priv": recipient.scan_keypair.private_bytes().hex(),
        "recipient_scan_pub": scan_pub.hex(),
        "recipient_spend_priv": recipient.spend_keypair.private_bytes().hex(),
        "recipient_spend_pub": spend_pub.hex(),
        "ephemeral_priv": eph.private_bytes().hex(),
        "ephemeral_pub": eph.public_bytes().hex(),
        "one_time_address": addr.hex(),
        "scan_secret": result.scan_secret.hex(),
        "message_key": msg_key.hex(),
        "non_recipient_scan_priv": other.scan_keypair.private_bytes().hex(),
        "non_recipient_spend_pub": other.spend_keypair.public_bytes().hex(),
    }


def build_sealed() -> dict[str, Any]:
    stealth_key = dbytes("sealed:stealth-key")
    eph_pub = dkeypair("sealed:ephemeral").public_bytes()
    ratchet_header = Header(dh=dbytes("sealed:header-dh"), pn=3, n=7).to_bytes()
    ratchet_ct = dbytes("sealed:ratchet-ct", 80)
    address = dbytes("sealed:address")

    with transcript_mode("sealed"):
        blob = seal(stealth_key, eph_pub, ratchet_header, ratchet_ct, address=address)

    got_eph, sealed_header, got_ct = parse(blob)
    assert got_eph == eph_pub and got_ct == ratchet_ct
    assert open_header(stealth_key, sealed_header, address=address) == ratchet_header

    return {
        "stealth_key": stealth_key.hex(),
        "ephemeral_pub": eph_pub.hex(),
        "ratchet_header": ratchet_header.hex(),
        "ratchet_ciphertext": ratchet_ct.hex(),
        "address": address.hex(),
        "blob": blob.hex(),
    }


def build_ratchet() -> dict[str, Any]:
    """A full two-party Double Ratchet transcript with recorded key/nonce tapes.

    Exercises: bootstrap, both directions, two DH ratchet turns, and an
    out-of-order delivery served from the skipped-key cache.
    """
    shared = dbytes("ratchet:shared-secret")
    bob_init = dkeypair("ratchet:bob-initial")

    plan: list[tuple[str, str]] = [
        ("alice", "A0: hello bob"),
        ("alice", "A1: still alice"),
        ("bob", "B0: hi alice"),
        ("bob", "B1: bob again"),
        ("alice", "A2: round two"),
        ("alice", "A3: out of order test"),
        ("bob", "B2: final"),
    ]
    # Delivery order: A3 arrives before A2 (skipped-key path).
    delivery: list[str] = ["A0", "A1", "B0", "B1", "A3", "A2", "B2"]

    messages: dict[str, dict[str, Any]] = {}
    events: list[dict[str, str]] = []
    with transcript_mode("ratchet") as (keys, nonces):
        alice = init_sender(shared, bob_init.public_bytes())
        bob = init_receiver(shared, bob_init)
        states = {"alice": alice, "bob": bob}
        counters = {"alice": 0, "bob": 0}
        sent: list[str] = []
        plan_iter = iter(plan)
        pending: dict[str, tuple[Header, bytes]] = {}

        def send_next() -> None:
            sender, text = next(plan_iter)
            header, ct = ratchet_encrypt(states[sender], text.encode())
            mid = f"{sender[0].upper()}{counters[sender]}"
            counters[sender] += 1
            pending[mid] = (header, ct)
            messages[mid] = {
                "sender": sender,
                "plaintext": text.encode().hex(),
                "header": header.to_bytes().hex(),
                "ciphertext": ct.hex(),
            }
            sent.append(mid)
            events.append({"type": "send", "id": mid})

        # Send/receive interleaved exactly as the delivery list demands: a
        # party must have received the peer's newest chain before replying.
        for mid in delivery:
            while mid not in pending:
                send_next()
            header, ct = pending.pop(mid)
            receiver = "bob" if messages[mid]["sender"] == "alice" else "alice"
            pt = ratchet_decrypt(states[receiver], header, ct)
            assert pt.hex() == messages[mid]["plaintext"]
            events.append({"type": "recv", "id": mid})

    return {
        "shared_secret": shared.hex(),
        "bob_initial_ratchet_priv": bob_init.private_bytes().hex(),
        "generated_ratchet_privs": keys.recorded,
        "aead_nonces": nonces.recorded,
        "messages": [messages[mid] | {"id": mid} for mid in sent],
        "events": events,
        "delivery_order": delivery,
    }


def _build_prekey_material(
    label: str, identity: Identity, *, otpk: bool
) -> tuple[PreKeyBundle, PreKeyPrivates]:
    spk = dkeypair(f"{label}:spk")
    spk_id = 1001
    spk_sig = _sign_signed_prekey(identity, spk.public_bytes())
    one_time: dict[int, Keypair] = {}
    otpk_id = None
    if otpk:
        otpk_id = 2002
        one_time[otpk_id] = dkeypair(f"{label}:otpk")
    privates = PreKeyPrivates(
        signed_prekey=spk,
        signed_prekey_id=spk_id,
        signed_prekey_created=0.0,
        signed_prekey_sig=spk_sig,
        one_time=one_time,
    )
    bundle = PreKeyBundle(
        identity_key=identity.verify_key_bytes(),
        identity_dh_key=identity.spend_keypair.public_bytes(),
        signed_prekey=spk.public_bytes(),
        signed_prekey_sig=spk_sig,
        signed_prekey_id=spk_id,
        one_time_prekey=one_time[otpk_id].public_bytes() if otpk else None,
        one_time_prekey_id=otpk_id,
    )
    assert verify_prekey_bundle(bundle)
    return bundle, privates


def build_x3dh() -> dict[str, Any]:
    alice = didentity("x3dh:alice")
    bob = didentity("x3dh:bob")

    out: dict[str, Any] = {
        "alice_scan_priv": alice.scan_keypair.private_bytes().hex(),
        "alice_spend_priv": alice.spend_keypair.private_bytes().hex(),
        "bob_scan_priv": bob.scan_keypair.private_bytes().hex(),
        "bob_spend_priv": bob.spend_keypair.private_bytes().hex(),
        "cases": [],
    }

    for name, with_otpk in [("with-otpk", True), ("without-otpk", False)]:
        bundle, privates = _build_prekey_material(f"x3dh:{name}", bob, otpk=with_otpk)
        with transcript_mode(f"x3dh:{name}") as (keys, _nonces):
            result, header = x3dh_send(alice, bundle)
        recv_master = derive_master_secret_recv(bob, privates, header)
        assert recv_master == result.master_secret

        case: dict[str, Any] = {
            "name": name,
            "bob_signed_prekey_priv": privates.signed_prekey.private_bytes().hex(),
            "signed_prekey_id": privates.signed_prekey_id,
            "signed_prekey_sig": privates.signed_prekey_sig.hex(),
            "alice_ephemeral_priv": keys.recorded[0],
            "header": header.to_bytes().hex(),
            "master_secret": result.master_secret.hex(),
        }
        if with_otpk:
            case["one_time_prekey_priv"] = privates.one_time[2002].private_bytes().hex()
            case["one_time_prekey_id"] = 2002
        out["cases"].append(case)

    # The X3DH → Double Ratchet handoff, pinned end-to-end: alice bootstraps a
    # sender ratchet on the master secret against bob's signed prekey.
    bundle, privates = _build_prekey_material("x3dh:handoff", bob, otpk=True)
    with transcript_mode("x3dh:handoff") as (keys, nonces):
        result, header = x3dh_send(alice, bundle)
        alice_state = init_sender(result.master_secret, bundle.signed_prekey)
        h, ct = ratchet_encrypt(alice_state, b"first message after x3dh")
        bob_master = derive_master_secret_recv(bob, privates, header)
        bob_state = init_receiver(bob_master, privates.signed_prekey)
        assert ratchet_decrypt(bob_state, h, ct) == b"first message after x3dh"

    out["handoff"] = {
        "bob_signed_prekey_priv": privates.signed_prekey.private_bytes().hex(),
        "signed_prekey_id": privates.signed_prekey_id,
        "one_time_prekey_priv": privates.one_time[2002].private_bytes().hex(),
        "one_time_prekey_id": 2002,
        "signed_prekey_sig": privates.signed_prekey_sig.hex(),
        "generated_privs": keys.recorded,
        "aead_nonces": nonces.recorded,
        "x3dh_header": header.to_bytes().hex(),
        "master_secret": result.master_secret.hex(),
        "ratchet_header": h.to_bytes().hex(),
        "ciphertext": ct.hex(),
        "plaintext": b"first message after x3dh".hex(),
    }
    return out


def build_burn() -> dict[str, Any]:
    shared = dbytes("burn:shared-secret")
    nonce = dbytes("burn:nonce", 16)
    ts = 1750000000
    vectors = []
    for scope, message_id in [
        ("conversation", None),
        ("message", "dGVzdC1hZGRyZXNzLWJhc2U2NA=="),
    ]:
        token = generate_burn_token(shared, scope, message_id, nonce=nonce, timestamp=ts)
        assert verify_burn_token(shared, token, scope, message_id, now=ts)
        vectors.append(
            {
                "shared_secret": shared.hex(),
                "scope": scope,
                "message_id": message_id,
                "nonce": nonce.hex(),
                "timestamp": ts,
                "token": token,
            }
        )
    return {"vectors": vectors}


def build_vault() -> dict[str, Any]:
    """Two-slot panic vault: decrypt-direction vectors (the blob embeds its
    salts, nonces and KDF params; slot order is random by design)."""
    params = KDFParams(time_cost=1, memory_cost=8 * 1024, parallelism=1)
    real_payload = b'{"who":"real identity payload"}'
    duress_payload = b'{"who":"decoy"}'

    vault_duress = create_vault(
        "correct horse battery staple",
        real_payload,
        duress_passphrase="duress pass",  # noqa: S106
        duress_payload=duress_payload,
        params=params,
    )
    assert try_unlock(vault_duress, "correct horse battery staple") == real_payload
    assert try_unlock(vault_duress, "duress pass") == duress_payload
    assert try_unlock(vault_duress, "wrong") is None

    vault_plain = create_vault("only real", real_payload, params=params)
    assert try_unlock(vault_plain, "only real") == real_payload

    # A raw Argon2id KDF vector so the KDF itself is pinned independently.
    salt = dbytes("vault:salt", 16)
    key = derive_unlock_key("kdf pin passphrase", salt, params)

    return {
        "kdf": {
            "passphrase": "kdf pin passphrase",
            "salt": salt.hex(),
            "time_cost": params.time_cost,
            "memory_cost": params.memory_cost,
            "parallelism": params.parallelism,
            "unlock_key": key.hex(),
        },
        "vaults": [
            {
                "name": "with-duress",
                "blob": vault_duress.hex(),
                "unlocks": [
                    {"passphrase": "correct horse battery staple", "payload": real_payload.hex()},
                    {"passphrase": "duress pass", "payload": duress_payload.hex()},
                    {"passphrase": "wrong", "payload": None},
                ],
            },
            {
                "name": "no-duress",
                "blob": vault_plain.hex(),
                "unlocks": [
                    {"passphrase": "only real", "payload": real_payload.hex()},
                    {"passphrase": "anything else", "payload": None},
                ],
            },
        ],
    }


def build_fmd() -> dict[str, Any]:
    seed = dbytes("fmd:seed")
    key = derive_fmd_key(seed, 3)
    message = b"fmd vector message"
    other = b"a different message"
    flag = fmd_flag(message, key.public_keys)

    assert fmd_test(flag, key, message)
    coarse = key.downgrade(0.5)  # 1 sub-key

    return {
        "seed": seed.hex(),
        "num_subkeys": 3,
        "secret_keys": [k.hex() for k in key.secret_keys],
        "public_keys": [k.hex() for k in key.public_keys],
        "flag_message": message.hex(),
        "flag": flag.hex(),
        "tests": [
            {"message": message.hex(), "subkeys": 3, "match": fmd_test(flag, key, message)},
            {"message": other.hex(), "subkeys": 3, "match": fmd_test(flag, key, other)},
            {"message": message.hex(), "subkeys": 1, "match": fmd_test(flag, coarse, message)},
        ],
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

BUILDERS = {
    "base58": build_base58,
    "kdf": build_kdf,
    "aead": build_aead,
    "identity": build_identity,
    "stealth": build_stealth,
    "sealed": build_sealed,
    "ratchet": build_ratchet,
    "x3dh": build_x3dh,
    "burn": build_burn,
    "vault": build_vault,
    "fmd": build_fmd,
}


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for name, builder in BUILDERS.items():
        data = {
            "_meta": {
                "file": f"{name}.json",
                "generator": "scripts/export_vectors.py",
                "contract": (
                    "Every implementation of DRIFT-P/1 must reproduce these values "
                    "bit-for-bit. Regenerate only on a deliberate protocol change."
                ),
            },
            **builder(),
        }
        path = OUT_DIR / f"{name}.json"
        path.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n")
        print(f"wrote {path.relative_to(REPO)}")


if __name__ == "__main__":
    main()
