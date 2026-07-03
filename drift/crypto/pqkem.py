"""
drift.crypto.pqkem — ML-KEM-768 (FIPS 203) for the hybrid handshake.

A thin, typed wrapper over ``cryptography``'s ML-KEM so the rest of DRIFT never
touches ``hazmat`` directly. Used by the PQXDH-style hybrid bootstrap
(``drift.crypto.x3dh``): the recipient publishes a signed ML-KEM encapsulation
key alongside their X25519 prekeys, the sender encapsulates against it, and the
KEM shared secret is folded into the X3DH master-secret KDF *alongside* the
classical DH outputs — hybrid, so the handshake is never weaker than X25519
alone, and an adversary recording traffic today can't decrypt it with a future
quantum computer ("harvest now, decrypt later").

Iron rule: this module implements **no cryptography**. ML-KEM-768 comes from
``cryptography`` (OpenSSL's FIPS 203 implementation) — the same vetted library
that already provides DRIFT's X25519, Ed25519, and HKDF. No new dependency.

Honesty note (mirrors Signal's PQXDH): only the *handshake* is hybrid. The
Double Ratchet's ongoing DH steps remain X25519, so post-compromise security
against a quantum adversary is future work — see DESIGN.md.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.mlkem import (
    MLKEM768PrivateKey,
    MLKEM768PublicKey,
)

# FIPS 203 ML-KEM-768 sizes (bytes).
PQ_PUBLIC_LEN = 1184   # encapsulation key
PQ_CIPHERTEXT_LEN = 1088
PQ_SEED_LEN = 64       # the (d || z) generation seed — the stored private form
PQ_SECRET_LEN = 32     # the shared secret


class PQKEMError(Exception):
    """Raised on malformed ML-KEM key/ciphertext bytes or a failed operation."""


@dataclass
class PQKeypair:
    """An ML-KEM-768 keypair. The private half is stored as its 64-byte
    generation seed (compact, and deterministic to re-expand per FIPS 203)."""

    _private: MLKEM768PrivateKey

    @classmethod
    def generate(cls) -> PQKeypair:
        return cls(_private=MLKEM768PrivateKey.generate())

    @classmethod
    def from_seed(cls, seed: bytes) -> PQKeypair:
        if len(seed) != PQ_SEED_LEN:
            raise PQKEMError(f"ML-KEM seed must be {PQ_SEED_LEN} bytes, got {len(seed)}")
        return cls(_private=MLKEM768PrivateKey.from_seed_bytes(seed))

    def seed_bytes(self) -> bytes:
        """The 64-byte private seed — vault-sealed at rest, never published."""
        return self._private.private_bytes_raw()

    def public_bytes(self) -> bytes:
        """The 1184-byte encapsulation key — the publishable half."""
        return self._private.public_key().public_bytes_raw()

    def decapsulate(self, ciphertext: bytes) -> bytes:
        """Recover the 32-byte shared secret from a sender's encapsulation.

        Note: per FIPS 203, decapsulation of a *well-formed but wrong*
        ciphertext does not error — it returns an implicit-rejection secret
        that simply won't match the sender's. The mismatch then surfaces as an
        ``InvalidTag`` on the first AEAD open, which is the failure path DRIFT
        already treats as authoritative.
        """
        if len(ciphertext) != PQ_CIPHERTEXT_LEN:
            raise PQKEMError(
                f"ML-KEM ciphertext must be {PQ_CIPHERTEXT_LEN} bytes, got {len(ciphertext)}"
            )
        return self._private.decapsulate(ciphertext)


def encapsulate(public_bytes: bytes) -> tuple[bytes, bytes]:
    """Sender side: ``(shared_secret, ciphertext)`` against a peer's
    encapsulation key. The shared secret is folded into the handshake KDF and
    discarded; the ciphertext travels (sealed) in the X3DH header."""
    if len(public_bytes) != PQ_PUBLIC_LEN:
        raise PQKEMError(
            f"ML-KEM public key must be {PQ_PUBLIC_LEN} bytes, got {len(public_bytes)}"
        )
    try:
        ek = MLKEM768PublicKey.from_public_bytes(public_bytes)
    except ValueError as exc:
        raise PQKEMError(f"malformed ML-KEM public key: {exc}") from exc
    return ek.encapsulate()
