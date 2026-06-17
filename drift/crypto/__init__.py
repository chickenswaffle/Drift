"""
drift.crypto — all cryptographic operations for DRIFT.

Design principles:
  - Never implement primitives from scratch. Compose PyNaCl / cryptography.
  - All secrets are bytes; encode to/from base58 only at the boundary.
  - Functions are pure where possible — no hidden state, easy to test.

Phase 0 scope:
  - X25519 keypair generation
  - X25519 ECDH shared-secret derivation
  - HKDF key derivation
  - XChaCha20-Poly1305 AEAD encrypt / decrypt

Phase 1 will add:
  - Stealth address derivation (sender-side)
  - Stealth address scanning  (receiver-side)

Phase 2 will add:
  - Double Ratchet state machine
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
)
from nacl.exceptions import CryptoError
from nacl.signing import SigningKey

if TYPE_CHECKING:
    from drift.crypto.fmd import FMDKeypair

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

BASE58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(data: bytes) -> str:
    """Minimal base58 encoder (no checksum — DRIFT adds its own)."""
    count = 0
    for byte in data:
        if byte == 0:
            count += 1
        else:
            break
    num = int.from_bytes(data, "big")
    result = []
    while num > 0:
        num, rem = divmod(num, 58)
        result.append(BASE58_ALPHABET[rem:rem+1])
    return (b"1" * count + b"".join(reversed(result))).decode("ascii")


def b58decode(text: str) -> bytes:
    """Minimal base58 decoder."""
    count = 0
    for char in text:
        if char == "1":
            count += 1
        else:
            break
    num = 0
    for char in text:
        num = num * 58 + BASE58_ALPHABET.index(ord(char))
    result = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    return b"\x00" * count + result


# ---------------------------------------------------------------------------
# Keypair
# ---------------------------------------------------------------------------

@dataclass
class Keypair:
    """An X25519 keypair: private key + derived public key."""
    private_key: X25519PrivateKey
    public_key: X25519PublicKey

    @classmethod
    def generate(cls) -> Keypair:
        priv = X25519PrivateKey.generate()
        return cls(private_key=priv, public_key=priv.public_key())

    def public_bytes(self) -> bytes:
        return self.public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    def private_bytes(self) -> bytes:
        return self.private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

    def public_b58(self) -> str:
        return b58encode(self.public_bytes())

    def ecdh(self, their_public_bytes: bytes) -> bytes:
        """Perform ECDH and return the raw shared secret bytes."""
        their_pub = X25519PublicKey.from_public_bytes(their_public_bytes)
        return self.private_key.exchange(their_pub)


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

def derive_message_key(
    shared_secret: bytes, salt: bytes | None = None, info: bytes = b"drift-v0-msg"
) -> bytes:
    """
    HKDF-SHA256: stretch an ECDH shared secret into a 32-byte message key.
    `info` is domain-separated — change it for different derived keys.
    """
    hkdf = HKDF(algorithm=SHA256(), length=32, salt=salt, info=info)
    return hkdf.derive(shared_secret)


# ---------------------------------------------------------------------------
# AEAD: XChaCha20-Poly1305
# ---------------------------------------------------------------------------

# XChaCha20 uses a 24-byte nonce — much more forgiving than AES-GCM's 12 bytes.
# At 24 bytes you can safely generate nonces randomly without collision risk.
NONCE_SIZE = 24  # bytes (192 bits)


def encrypt(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> bytes:
    """
    Encrypt plaintext with XChaCha20-Poly1305.

    Returns: nonce (24 bytes) || ciphertext+tag

    The associated_data is authenticated but not encrypted. Use it for
    metadata you want to bind to the ciphertext (e.g. message sequence number,
    recipient address) without encrypting it.
    """
    if len(key) != 32:
        raise ValueError(f"Key must be 32 bytes, got {len(key)}")
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext, associated_data, nonce, key
    )
    return nonce + ciphertext


def decrypt(key: bytes, ciphertext_with_nonce: bytes, associated_data: bytes = b"") -> bytes:
    """
    Decrypt a payload produced by `encrypt`.

    Raises cryptography.exceptions.InvalidTag if authentication fails —
    always let this propagate; a tampered message must be rejected.
    """
    if len(key) != 32:
        raise ValueError(f"Key must be 32 bytes, got {len(key)}")
    nonce = ciphertext_with_nonce[:NONCE_SIZE]
    ciphertext = ciphertext_with_nonce[NONCE_SIZE:]
    try:
        return crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, associated_data, nonce, key)
    except CryptoError as exc:
        raise InvalidTag() from exc


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------

@dataclass
class Identity:
    """
    A DRIFT identity: three keypairs + a human-readable contact code.

    identity_key  — Ed25519 signing anchor, derived from the spend key on demand
                    (see signing_key()); used to sign Phase 6 beacons
    scan_key      — X25519: others use your public scan key to derive one-time addresses
    spend_key     — X25519: your private spend key lets you detect + decrypt incoming mail

    The contact code is: drift:<b58(scan_pub)><b58(spend_pub)>
    Separated by "." internally but displayed as a single compact string.
    """
    scan_keypair: Keypair
    spend_keypair: Keypair

    @classmethod
    def generate(cls) -> Identity:
        return cls(
            scan_keypair=Keypair.generate(),
            spend_keypair=Keypair.generate(),
        )

    def contact_code(self, fmd_pubs: list[bytes] | None = None) -> str:
        """Your contact code: ``drift:<scan>.<spend>`` (FMD off, the default).

        When ``fmd_pubs`` is given (the recipient has an FMD detection key
        published), it is appended as an optional 3rd segment
        ``.<b58(concat sub-keys)>`` so senders can flag messages for you. Omitting
        it yields the exact 2-segment code as before — zero overhead, fully
        backward-compatible.
        """
        scan_pub = self.scan_keypair.public_b58()
        spend_pub = self.spend_keypair.public_b58()
        code = f"drift:{scan_pub}.{spend_pub}"
        if fmd_pubs:
            code += "." + b58encode(b"".join(fmd_pubs))
        return code

    def fmd_keypair(self, n: int) -> FMDKeypair:
        """Deterministic FMD detection keypair with ``n`` sub-keys.

        Derived from the spend key (like :meth:`signing_key`), so the FMD key is
        a stable function of the identity with no extra secret to store or seal.
        ``n = 0`` (FMD off) → an empty keypair.
        """
        from drift.crypto.fmd import FMDKeypair, derive_fmd_key

        if n <= 0:
            return FMDKeypair(secret_keys=[], public_keys=[])
        seed = derive_message_key(
            self.spend_keypair.private_bytes(), info=b"drift-fmd-seed-v1"
        )
        return derive_fmd_key(seed, n)

    def signing_seed(self) -> bytes:
        """
        The 32-byte Ed25519 seed for this identity, derived deterministically
        from the spend key via a domain-separated HKDF. Both :meth:`signing_key`
        (PyNaCl, for beacons) and X3DH's signed-prekey signature (``cryptography``
        Ed25519, loaded from this same seed) reconstruct the *same* RFC 8032
        keypair from it — so there is exactly one identity signing key regardless
        of which library consumes the seed.
        """
        return derive_message_key(
            self.spend_keypair.private_bytes(), info=b"drift-identity-sign-v1"
        )

    def signing_key(self) -> SigningKey:
        """
        The identity's Ed25519 signing key (the design doc's "identity_key"
        anchor). It is *derived* deterministically from the spend key via a
        domain-separated HKDF rather than stored as a fourth keypair — so the
        on-disk format and the contact code are unchanged, yet every identity
        has a stable signing key for Phase 6 beacons. Same identity → same key.
        """
        return SigningKey(self.signing_seed())

    def verify_key_bytes(self) -> bytes:
        """Public half of :meth:`signing_key`, for signature verification."""
        return bytes(self.signing_key().verify_key)

    def to_dict(self) -> dict[str, str]:
        return {
            "scan_priv": b58encode(self.scan_keypair.private_bytes()),
            "scan_pub": self.scan_keypair.public_b58(),
            "spend_priv": b58encode(self.spend_keypair.private_bytes()),
            "spend_pub": self.spend_keypair.public_b58(),
        }

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2))
        path.chmod(0o600)  # owner-read-only

    @classmethod
    def load(cls, path: Path) -> Identity:
        data = json.loads(path.read_text())
        scan_priv = X25519PrivateKey.from_private_bytes(b58decode(data["scan_priv"]))
        spend_priv = X25519PrivateKey.from_private_bytes(b58decode(data["spend_priv"]))
        return cls(
            scan_keypair=Keypair(private_key=scan_priv, public_key=scan_priv.public_key()),
            spend_keypair=Keypair(private_key=spend_priv, public_key=spend_priv.public_key()),
        )

    @staticmethod
    def parse_contact_code(code: str) -> tuple[bytes, bytes]:
        """
        Parse a contact code → (scan_pub_bytes, spend_pub_bytes).
        Raises ValueError on malformed input.
        """
        if not code.startswith("drift:"):
            raise ValueError("Not a DRIFT contact code (must start with 'drift:')")
        parts = code[len("drift:"):].split(".")
        # 2 segments = classic code; an optional 3rd carries the FMD detection
        # public key (see parse_fmd_pubs). Extra segments beyond that are rejected.
        if len(parts) not in (2, 3):
            raise ValueError("Malformed contact code — expected drift:<scan>.<spend>[.<fmd>]")
        scan_pub = b58decode(parts[0])
        spend_pub = b58decode(parts[1])
        if len(scan_pub) != 32 or len(spend_pub) != 32:
            raise ValueError("Invalid key length in contact code")
        return scan_pub, spend_pub

    @staticmethod
    def parse_fmd_pubs(code: str) -> list[bytes] | None:
        """The recipient's FMD detection public sub-keys, or ``None`` if absent.

        Encoded as the optional 3rd contact-code segment — ``b58`` of the ``n``
        public sub-keys concatenated (32 bytes each). A 2-segment code (FMD off)
        returns ``None``; a sender uses these to flag messages for the recipient.
        """
        if not code.startswith("drift:"):
            raise ValueError("Not a DRIFT contact code (must start with 'drift:')")
        parts = code[len("drift:"):].split(".")
        if len(parts) < 3 or not parts[2]:
            return None
        blob = b58decode(parts[2])
        if not blob or len(blob) % 32 != 0:
            raise ValueError("Invalid FMD key segment in contact code")
        return [blob[i:i + 32] for i in range(0, len(blob), 32)]
