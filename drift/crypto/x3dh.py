"""
drift.crypto.x3dh — X3DH asynchronous key agreement (Extended Triple Diffie-Hellman)

Reference: https://signal.org/docs/specifications/x3dh/

X3DH replaces DRIFT's deterministic ratchet bootstrap (which derived the initial
root key purely from long-term spend keys — audit H3). The recipient publishes
*prekeys* ahead of time: a long-lived **signed prekey** and a batch of **one-time
prekeys** (OTPKs). A sender fetches a bundle, runs the handshake against it, and
the OTPK is consumed (deleted) after a single use. Because that OTPK private half
no longer exists, a later compromise of the recipient's long-term spend key can
no longer decrypt the opening burst of a past session that used it — closing the
recipient-side residual H3 left open.

How DRIFT's keys map onto the Signal spec
-----------------------------------------
Signal fuses signing and DH into one identity key via XEdDSA. DRIFT keeps them
separate, so each Signal role maps onto an existing DRIFT key:

  - **IK (the DH identity key)** = the X25519 **spend key**. It is already
    DRIFT's long-term DH identity (the deterministic bootstrap and H3 are about
    exactly this key). So ``DH1 = ECDH(IK_A=spend_A, SPK_B)`` and
    ``DH2 = ECDH(EK_A, IK_B=spend_B)``.
  - **The signing identity key** = the existing Ed25519 key
    (:meth:`Identity.signing_key`, derived from the spend key). It signs the
    signed prekey and is the bundle's ``identity_key``.

So a :class:`PreKeyBundle` carries *both* the Ed25519 ``identity_key`` (to verify
the signed-prekey signature) and the X25519 ``identity_dh_key`` (the spend pub,
needed for DH2), since DRIFT splits the two identities Signal merges.

The Double Ratchet handoff
--------------------------
Bob's **signed prekey is his initial Double Ratchet key**: the initiator runs
``init_sender(master_secret, their_signed_prekey_pub)`` and the responder runs
``init_receiver(master_secret, signed_prekey_keypair)``. After that the ratchet
(``drift.crypto.ratchet``) proceeds unchanged.

Iron rule
---------
Ed25519, X25519 and HKDF all come from ``cryptography``. The Ed25519 key is
loaded from :meth:`Identity.signing_seed` — the *same* seed the existing PyNaCl
``signing_key`` uses — so the rule is honoured and there is still exactly one
identity signing key (RFC 8032 is byte-identical across the two libraries).
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from drift.crypto import Identity, Keypair, b58decode, b58encode

# --- KDF construction, exactly per the X3DH spec -------------------------------
# SK = HKDF-SHA256(IKM = F || DH1||DH2||DH3[||DH4]), where F is 32 0xFF bytes for
# X25519, salt is a zero-filled byte sequence of the hash output length, and info
# is the application identifier. 32 bytes of output become the initial root key.
_F = b"\xff" * 32
_HKDF_SALT = b"\x00" * 32
X3DH_INFO = b"drift-x3dh-v1"
_MASTER_LEN = 32

# Signed prekeys rotate weekly; the previous one is kept this long to decrypt
# sessions that were in flight across the rotation.
SIGNED_PREKEY_LIFETIME = 7 * 24 * 3600   # 7 days
PREV_SIGNED_PREKEY_GRACE = 24 * 3600     # keep the old one 24h after rotation

# Replenish one-time prekeys when fewer than this remain locally.
ONE_TIME_LOW_WATERMARK = 3
ONE_TIME_BATCH = 10

_KEY_LEN = 32
_ID_LEN = 4


class X3DHError(Exception):
    """Raised on a malformed bundle, an unknown/consumed prekey id, or bad input."""


def _new_id() -> int:
    """A positive 4-byte rotation/prekey identifier."""
    return secrets.randbelow(2 ** 31) + 1


def _kdf(dh_concat: bytes) -> bytes:
    """The X3DH master-secret KDF: HKDF over ``F || <DH outputs>``."""
    return HKDF(
        algorithm=SHA256(), length=_MASTER_LEN, salt=_HKDF_SALT, info=X3DH_INFO
    ).derive(_F + dh_concat)


def _ed25519_private(identity: Identity) -> Ed25519PrivateKey:
    """The identity's Ed25519 signing key, via ``cryptography`` (same seed/key as
    the PyNaCl :meth:`Identity.signing_key`)."""
    return Ed25519PrivateKey.from_private_bytes(identity.signing_seed())


def _ed25519_public_bytes(priv: Ed25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


# ---------------------------------------------------------------------------
# Public bundle (publishable) and the X3DH header carried on the wire
# ---------------------------------------------------------------------------

@dataclass
class PreKeyBundle:
    """
    One peer's public prekey material — what a sender fetches and runs X3DH
    against. Carries a single one-time prekey (the relay hands out one per fetch
    and deletes it); ``one_time_prekey`` is ``None`` when the relay's store is
    exhausted (a weaker but valid X3DH, per spec).

      identity_key      Ed25519 verify key (signs the signed prekey)
      identity_dh_key   X25519 spend pub (the DH identity IK_B)
      signed_prekey     X25519 pub, signed by ``identity_key``
      signed_prekey_sig Ed25519 signature over ``signed_prekey``
      signed_prekey_id  rotation identifier
      one_time_prekey   X25519 pub, consumed once (or None)
      one_time_prekey_id
    """
    identity_key: bytes
    identity_dh_key: bytes
    signed_prekey: bytes
    signed_prekey_sig: bytes
    signed_prekey_id: int
    one_time_prekey: bytes | None = None
    one_time_prekey_id: int | None = None

    def to_dict(self) -> dict[str, object]:
        d: dict[str, object] = {
            "identity_key": b58encode(self.identity_key),
            "identity_dh_key": b58encode(self.identity_dh_key),
            "signed_prekey": b58encode(self.signed_prekey),
            "signed_prekey_sig": b58encode(self.signed_prekey_sig),
            "signed_prekey_id": self.signed_prekey_id,
            "one_time_prekey": (
                b58encode(self.one_time_prekey) if self.one_time_prekey else None
            ),
            "one_time_prekey_id": self.one_time_prekey_id,
        }
        return d

    @classmethod
    def from_dict(cls, d: dict[str, object]) -> PreKeyBundle:
        try:
            otpk_raw = d.get("one_time_prekey")
            otpk = b58decode(otpk_raw) if isinstance(otpk_raw, str) else None
            otpk_id = d.get("one_time_prekey_id")
            bundle = cls(
                identity_key=b58decode(str(d["identity_key"])),
                identity_dh_key=b58decode(str(d["identity_dh_key"])),
                signed_prekey=b58decode(str(d["signed_prekey"])),
                signed_prekey_sig=b58decode(str(d["signed_prekey_sig"])),
                signed_prekey_id=int(str(d["signed_prekey_id"])),
                one_time_prekey=otpk,
                one_time_prekey_id=int(otpk_id) if isinstance(otpk_id, int) else None,
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise X3DHError(f"malformed prekey bundle: {exc}") from exc
        if len(bundle.identity_key) != _KEY_LEN or len(bundle.identity_dh_key) != _KEY_LEN:
            raise X3DHError("bad identity key length in bundle")
        if len(bundle.signed_prekey) != _KEY_LEN:
            raise X3DHError("bad signed prekey length in bundle")
        if bundle.one_time_prekey is not None and len(bundle.one_time_prekey) != _KEY_LEN:
            raise X3DHError("bad one-time prekey length in bundle")
        return bundle


@dataclass(frozen=True)
class X3DHHeader:
    """
    The handshake header the initiator carries (sealed) on every bootstrap-chain
    message, so the responder can derive the same master secret:

      ik_a              initiator's X25519 spend pub (IK_A)
      ek_a              initiator's single-use ephemeral pub (EK_A)
      signed_prekey_id  which of the responder's signed prekeys was used
      one_time_prekey_id which OTPK was consumed (or None)
    """
    ik_a: bytes
    ek_a: bytes
    signed_prekey_id: int
    one_time_prekey_id: int | None

    def to_bytes(self) -> bytes:
        otpk_flag = 1 if self.one_time_prekey_id is not None else 0
        otpk_id = self.one_time_prekey_id or 0
        return (
            self.ik_a
            + self.ek_a
            + self.signed_prekey_id.to_bytes(_ID_LEN, "big")
            + bytes([otpk_flag])
            + otpk_id.to_bytes(_ID_LEN, "big")
        )

    @classmethod
    def from_bytes(cls, raw: bytes) -> X3DHHeader:
        expected = 2 * _KEY_LEN + _ID_LEN + 1 + _ID_LEN
        if len(raw) != expected:
            raise X3DHError(f"x3dh header must be {expected} bytes, got {len(raw)}")
        ik_a = raw[:_KEY_LEN]
        ek_a = raw[_KEY_LEN:2 * _KEY_LEN]
        off = 2 * _KEY_LEN
        spk_id = int.from_bytes(raw[off:off + _ID_LEN], "big")
        otpk_flag = raw[off + _ID_LEN]
        otpk_id = int.from_bytes(raw[off + _ID_LEN + 1:off + 2 * _ID_LEN + 1], "big")
        return cls(
            ik_a=ik_a,
            ek_a=ek_a,
            signed_prekey_id=spk_id,
            one_time_prekey_id=otpk_id if otpk_flag else None,
        )


@dataclass(frozen=True)
class X3DHResult:
    """The output of a handshake: the 32-byte master secret = initial root key."""
    master_secret: bytes


# ---------------------------------------------------------------------------
# Private prekey store (vault-sealed at rest — see drift.storage)
# ---------------------------------------------------------------------------

@dataclass
class PreKeyPrivates:
    """
    The local private halves of our published prekeys. Sealed in the vault
    alongside the identity and contacts (audit H4 pattern), shredded on
    lock/decoy/wipe.

      signed_prekey          current signed-prekey keypair
      signed_prekey_id / _created
      signed_prekey_sig      the Ed25519 signature we published over it
      prev_signed_prekey…    the previous signed prekey, kept ``PREV_…_GRACE``
                             seconds to decrypt in-flight sessions
      one_time               {id: keypair} of unconsumed one-time prekeys
    """
    signed_prekey: Keypair
    signed_prekey_id: int
    signed_prekey_created: float
    signed_prekey_sig: bytes
    one_time: dict[int, Keypair] = field(default_factory=dict)
    prev_signed_prekey: Keypair | None = None
    prev_signed_prekey_id: int | None = None
    prev_signed_prekey_sig: bytes | None = None
    prev_signed_prekey_retired: float | None = None
    last_replenished: float = field(default_factory=time.time)

    # -- lookups used by the receiver side --------------------------------
    def signed_prekey_private(self, prekey_id: int) -> Keypair:
        """The signed-prekey keypair matching ``prekey_id`` (current or the
        still-retained previous one). Raises if neither matches."""
        if prekey_id == self.signed_prekey_id:
            return self.signed_prekey
        if self.prev_signed_prekey is not None and prekey_id == self.prev_signed_prekey_id:
            return self.prev_signed_prekey
        raise X3DHError(f"unknown signed prekey id {prekey_id}")

    def one_time_private(self, prekey_id: int) -> Keypair:
        kp = self.one_time.get(prekey_id)
        if kp is None:
            raise X3DHError(f"unknown or already-consumed one-time prekey id {prekey_id}")
        return kp

    def consume(self, prekey_id: int) -> None:
        """Delete a one-time prekey after use — it must never be reused."""
        self.one_time.pop(prekey_id, None)

    def one_time_count(self) -> int:
        return len(self.one_time)

    # -- the publishable bundle for the relay -----------------------------
    def publish_payload(self, identity: Identity) -> dict[str, object]:
        """The relay POST body: identity keys + signed prekey + the *batch* of
        one-time prekey publics (the relay stores them and hands out one per
        fetch)."""
        return {
            "identity_key": b58encode(identity.verify_key_bytes()),
            "identity_dh_key": b58encode(identity.spend_keypair.public_bytes()),
            "signed_prekey": b58encode(self.signed_prekey.public_bytes()),
            "signed_prekey_sig": b58encode(self.signed_prekey_sig),
            "signed_prekey_id": self.signed_prekey_id,
            "one_time_prekeys": [
                {"id": pid, "pub": b58encode(kp.public_bytes())}
                for pid, kp in self.one_time.items()
            ],
        }

    def one_time_publish_list(self) -> list[dict[str, object]]:
        """Just the one-time prekey publics, for ``/replenish``."""
        return [
            {"id": pid, "pub": b58encode(kp.public_bytes())}
            for pid, kp in self.one_time.items()
        ]

    # -- serialization for the vault / prekeys.json -----------------------
    def to_dict(self) -> dict[str, object]:
        d: dict[str, object] = {
            "signed_prekey": b58encode(self.signed_prekey.private_bytes()),
            "signed_prekey_id": self.signed_prekey_id,
            "signed_prekey_created": self.signed_prekey_created,
            "signed_prekey_sig": b58encode(self.signed_prekey_sig),
            "one_time": {
                str(pid): b58encode(kp.private_bytes()) for pid, kp in self.one_time.items()
            },
            "last_replenished": self.last_replenished,
        }
        if self.prev_signed_prekey is not None:
            d["prev_signed_prekey"] = b58encode(self.prev_signed_prekey.private_bytes())
            d["prev_signed_prekey_id"] = self.prev_signed_prekey_id
            d["prev_signed_prekey_sig"] = (
                b58encode(self.prev_signed_prekey_sig) if self.prev_signed_prekey_sig else None
            )
            d["prev_signed_prekey_retired"] = self.prev_signed_prekey_retired
        return d

    @classmethod
    def from_dict(cls, d: dict[str, object]) -> PreKeyPrivates:
        try:
            raw_one_time = d.get("one_time", {})
            if not isinstance(raw_one_time, dict):
                raise X3DHError("one_time must be a mapping")
            one_time = {
                int(pid): _keypair_from_priv(b58decode(str(priv)))
                for pid, priv in raw_one_time.items()
            }
            privates = cls(
                signed_prekey=_keypair_from_priv(b58decode(str(d["signed_prekey"]))),
                signed_prekey_id=int(str(d["signed_prekey_id"])),
                signed_prekey_created=float(str(d["signed_prekey_created"])),
                signed_prekey_sig=b58decode(str(d["signed_prekey_sig"])),
                one_time=one_time,
                last_replenished=float(str(d.get("last_replenished", time.time()))),
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise X3DHError(f"malformed prekey privates: {exc}") from exc
        prev = d.get("prev_signed_prekey")
        if isinstance(prev, str):
            privates.prev_signed_prekey = _keypair_from_priv(b58decode(prev))
            prev_id = d.get("prev_signed_prekey_id")
            privates.prev_signed_prekey_id = int(prev_id) if isinstance(prev_id, int) else None
            prev_sig = d.get("prev_signed_prekey_sig")
            privates.prev_signed_prekey_sig = (
                b58decode(prev_sig) if isinstance(prev_sig, str) else None
            )
            retired = d.get("prev_signed_prekey_retired")
            privates.prev_signed_prekey_retired = (
                float(retired) if isinstance(retired, (int, float)) else None
            )
        return privates


def _keypair_from_priv(priv: bytes) -> Keypair:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    sk = X25519PrivateKey.from_private_bytes(priv)
    return Keypair(private_key=sk, public_key=sk.public_key())


# ---------------------------------------------------------------------------
# Generation, rotation, replenishment
# ---------------------------------------------------------------------------

def _sign_signed_prekey(identity: Identity, signed_prekey_pub: bytes) -> bytes:
    return _ed25519_private(identity).sign(signed_prekey_pub)


def generate_prekey_bundle(
    identity: Identity, num_one_time: int = ONE_TIME_BATCH
) -> tuple[PreKeyBundle, PreKeyPrivates]:
    """
    Generate a fresh signed prekey (signed by the identity Ed25519) and
    ``num_one_time`` one-time prekeys.

    Returns the public :class:`PreKeyBundle` (its ``one_time_prekey`` is the
    first OTPK, a representative; the relay is given the whole batch via
    :meth:`PreKeyPrivates.publish_payload`) and the :class:`PreKeyPrivates` to
    store vault-sealed.
    """
    now = time.time()
    spk = Keypair.generate()
    spk_id = _new_id()
    spk_sig = _sign_signed_prekey(identity, spk.public_bytes())

    one_time: dict[int, Keypair] = {}
    while len(one_time) < max(0, num_one_time):
        one_time[_new_id()] = Keypair.generate()

    privates = PreKeyPrivates(
        signed_prekey=spk,
        signed_prekey_id=spk_id,
        signed_prekey_created=now,
        signed_prekey_sig=spk_sig,
        one_time=one_time,
        last_replenished=now,
    )

    first_id = next(iter(one_time), None)
    bundle = PreKeyBundle(
        identity_key=identity.verify_key_bytes(),
        identity_dh_key=identity.spend_keypair.public_bytes(),
        signed_prekey=spk.public_bytes(),
        signed_prekey_sig=spk_sig,
        signed_prekey_id=spk_id,
        one_time_prekey=one_time[first_id].public_bytes() if first_id is not None else None,
        one_time_prekey_id=first_id,
    )
    return bundle, privates


def needs_signed_prekey_rotation(privates: PreKeyPrivates, now: float | None = None) -> bool:
    """True when the signed prekey is older than its weekly lifetime."""
    now = time.time() if now is None else now
    return (now - privates.signed_prekey_created) >= SIGNED_PREKEY_LIFETIME


def low_on_one_time(privates: PreKeyPrivates) -> bool:
    """True when we should replenish one-time prekeys (fewer than the watermark)."""
    return privates.one_time_count() < ONE_TIME_LOW_WATERMARK


def rotate_signed_prekey(
    identity: Identity, privates: PreKeyPrivates, now: float | None = None
) -> None:
    """Rotate the signed prekey: retain the current one as ``prev`` (24h grace)
    and generate + sign a fresh one. Mutates ``privates`` in place."""
    now = time.time() if now is None else now
    privates.prev_signed_prekey = privates.signed_prekey
    privates.prev_signed_prekey_id = privates.signed_prekey_id
    privates.prev_signed_prekey_sig = privates.signed_prekey_sig
    privates.prev_signed_prekey_retired = now
    spk = Keypair.generate()
    privates.signed_prekey = spk
    privates.signed_prekey_id = _new_id()
    privates.signed_prekey_created = now
    privates.signed_prekey_sig = _sign_signed_prekey(identity, spk.public_bytes())


def drop_expired_prev_signed_prekey(privates: PreKeyPrivates, now: float | None = None) -> None:
    """Forget the previous signed prekey once its 24h grace has elapsed."""
    now = time.time() if now is None else now
    if (
        privates.prev_signed_prekey_retired is not None
        and (now - privates.prev_signed_prekey_retired) >= PREV_SIGNED_PREKEY_GRACE
    ):
        privates.prev_signed_prekey = None
        privates.prev_signed_prekey_id = None
        privates.prev_signed_prekey_sig = None
        privates.prev_signed_prekey_retired = None


def replenish_one_time(
    privates: PreKeyPrivates, count: int = ONE_TIME_BATCH, now: float | None = None
) -> list[int]:
    """Top up the one-time prekey store by ``count``. Returns the new ids (for
    uploading just those to the relay's ``/replenish``)."""
    new_ids: list[int] = []
    while len(new_ids) < max(0, count):
        pid = _new_id()
        if pid in privates.one_time:
            continue
        privates.one_time[pid] = Keypair.generate()
        new_ids.append(pid)
    privates.last_replenished = time.time() if now is None else now
    return new_ids


# ---------------------------------------------------------------------------
# The handshake — sender and receiver, exactly per spec
# ---------------------------------------------------------------------------

def verify_prekey_bundle(bundle: PreKeyBundle) -> bool:
    """Verify the Ed25519 signature on the signed prekey. A MITM that swapped the
    signed prekey can't forge this signature under the published identity key, so
    a tampered bundle is rejected (returns ``False``)."""
    try:
        Ed25519PublicKey.from_public_bytes(bundle.identity_key).verify(
            bundle.signed_prekey_sig, bundle.signed_prekey
        )
        return True
    except (InvalidSignature, ValueError):
        return False


def x3dh_send(
    my_identity: Identity, their_bundle: PreKeyBundle
) -> tuple[X3DHResult, X3DHHeader]:
    """
    Sender side. Verifies the bundle, generates a single-use ephemeral ``EK_A``,
    computes DH1–DH4 per spec, derives the master secret, and **discards the
    ephemeral private half immediately** (it goes out of scope here and is never
    stored or derived from a long-term key — this is what makes the opening burst
    forward-secret against later key theft).

      DH1 = ECDH(IK_A, SPK_B)
      DH2 = ECDH(EK_A, IK_B)
      DH3 = ECDH(EK_A, SPK_B)
      DH4 = ECDH(EK_A, OPK_B)   # only if the bundle carried a one-time prekey
    """
    if not verify_prekey_bundle(their_bundle):
        raise X3DHError("prekey bundle signature invalid — refusing handshake")

    ek = Keypair.generate()
    ik_a = my_identity.spend_keypair

    dh1 = ik_a.ecdh(their_bundle.signed_prekey)
    dh2 = ek.ecdh(their_bundle.identity_dh_key)
    dh3 = ek.ecdh(their_bundle.signed_prekey)
    dh_concat = dh1 + dh2 + dh3

    otpk_id: int | None = None
    if their_bundle.one_time_prekey is not None:
        dh_concat += ek.ecdh(their_bundle.one_time_prekey)
        otpk_id = their_bundle.one_time_prekey_id

    master = _kdf(dh_concat)
    header = X3DHHeader(
        ik_a=ik_a.public_bytes(),
        ek_a=ek.public_bytes(),
        signed_prekey_id=their_bundle.signed_prekey_id,
        one_time_prekey_id=otpk_id,
    )
    # ek (private) and the dhN values fall out of scope here — never retained.
    return X3DHResult(master), header


def derive_master_secret_recv(
    my_identity: Identity, my_prekey_privates: PreKeyPrivates, header: X3DHHeader
) -> bytes:
    """Receiver side, **without** consuming the one-time prekey — recompute the
    same DH1–DH4 and derive the master secret. The session uses this for a trial
    decrypt and only consumes the OTPK once the message authenticates (so a forged
    bootstrap can't burn an OTPK or disturb a live ratchet — the H1 guarantee)."""
    spk = my_prekey_privates.signed_prekey_private(header.signed_prekey_id)
    ik_b = my_identity.spend_keypair

    dh1 = spk.ecdh(header.ik_a)
    dh2 = ik_b.ecdh(header.ek_a)
    dh3 = spk.ecdh(header.ek_a)
    dh_concat = dh1 + dh2 + dh3

    if header.one_time_prekey_id is not None:
        otpk = my_prekey_privates.one_time_private(header.one_time_prekey_id)
        dh_concat += otpk.ecdh(header.ek_a)

    return _kdf(dh_concat)


def x3dh_receive(
    my_identity: Identity, my_prekey_privates: PreKeyPrivates, header: X3DHHeader
) -> X3DHResult:
    """
    Receiver side per spec: derive the same master secret and **mark the consumed
    one-time prekey as used** (never reused). For the security-sensitive session
    bootstrap, prefer :func:`derive_master_secret_recv` + an explicit
    :meth:`PreKeyPrivates.consume` after the message authenticates.
    """
    master = derive_master_secret_recv(my_identity, my_prekey_privates, header)
    if header.one_time_prekey_id is not None:
        my_prekey_privates.consume(header.one_time_prekey_id)
    return X3DHResult(master)
