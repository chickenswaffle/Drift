"""
drift.crypto.panic — duress passphrase vault (Phase 5)

The most safety-sensitive module in DRIFT. It exists for one threat: **coercion
at unlock time** — someone makes you type your passphrase. The defence is a
*second* passphrase that, entered exactly like the first, silently triggers a
pre-chosen response instead of opening your real account.

Design goals (in priority order)
--------------------------------
1. **Indistinguishable.** Real and duress passphrases go through the *same* KDF,
   the same unlock path, and the same constant work. There is no error, no
   different timing, no on-disk flag that says "duress is configured." The two
   are distinguishable only by which one *you* know.
2. **Deniable on disk.** The vault *always* has exactly two slots, whether or
   not a duress passphrase was set. When it wasn't, the second slot is
   indistinguishable random bytes. A forensic image cannot prove a second
   passphrase exists, so an adversary cannot know to demand one.
3. **At-rest protection.** The real identity is encrypted in the vault under the
   real passphrase. The duress passphrase cannot derive that key, so under decoy
   mode the real identity stays sealed and unreachable.

What this module does / doesn't do
-----------------------------------
This module is the *crypto*: a passphrase KDF, a two-slot vault that seals/opens
opaque payloads, and a best-effort file shredder. It is deliberately ignorant of
what a payload *means* — the role/mode (real, decoy, wipe) is encoded by the
storage layer inside the opaque payload bytes, so this module has no "is this the
duress slot?" branch to leak. Slot order is randomized and every payload is
padded to a fixed size, so neither position nor length distinguishes slots.

Primitives (iron rule: composed, never rolled)
----------------------------------------------
- **Argon2id** via ``argon2-cffi`` (memory-hard passphrase KDF).
- **XChaCha20-Poly1305** via :func:`drift.crypto.encrypt` / ``decrypt`` for each
  slot; a wrong passphrase fails the Poly1305 tag, which is exactly the
  "this slot isn't yours" signal.

Honest limits
-------------
``secure_overwrite`` overwrites then unlinks a file, but on journaling
filesystems, SSDs with wear-levelling, or snapshotted/backed-up volumes the
original bytes may survive in copies this process cannot reach. Wipe mode raises
the bar a great deal; it is not a guarantee against a forensic lab with the raw
flash. And while a real session is open, the working identity is materialized in
the clear (chmod 0600) — the vault protects the *locked* state, between sessions.
These limits are stated plainly so nobody over-trusts the feature.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag

from drift.crypto import decrypt, encrypt

# Vault binary layout constants.
_MAGIC = b"DRIFTVLT"
_VERSION = 1
_SALT_LEN = 16
# Every payload is padded to this size before sealing, so a wipe-marker slot and
# a full-decoy-identity slot produce identical-length ciphertext. Big enough for
# an identity plus a handful of decoy contacts.
PAYLOAD_SIZE = 4096
_LEN_PREFIX = 4  # u32 big-endian length header inside the padded block


@dataclass(frozen=True)
class KDFParams:
    """
    Argon2id cost parameters, stored (non-secret) in the vault header so a vault
    can always be opened with the parameters it was created under.

    Defaults target a memory-hard ~strong setting for an interactive unlock.
    Tests pass a deliberately cheap set so the suite stays fast.
    """

    time_cost: int = 3
    memory_cost: int = 64 * 1024  # KiB → 64 MiB
    parallelism: int = 4

    def to_header(self) -> bytes:
        return b"".join(
            v.to_bytes(4, "big")
            for v in (self.time_cost, self.memory_cost, self.parallelism)
        )

    @classmethod
    def from_header(cls, data: bytes) -> KDFParams:
        t = int.from_bytes(data[0:4], "big")
        m = int.from_bytes(data[4:8], "big")
        p = int.from_bytes(data[8:12], "big")
        return cls(time_cost=t, memory_cost=m, parallelism=p)


DEFAULT_PARAMS = KDFParams()

# Size of one sealed slot on disk: salt ‖ (nonce ‖ ciphertext+tag). encrypt()
# prepends a 24-byte nonce and Poly1305 adds a 16-byte tag.
_SLOT_SIZE = _SALT_LEN + 24 + PAYLOAD_SIZE + 16


# ---------------------------------------------------------------------------
# KDF
# ---------------------------------------------------------------------------


def derive_unlock_key(passphrase: str, salt: bytes, params: KDFParams = DEFAULT_PARAMS) -> bytes:
    """
    Derive a 32-byte unlock key from a passphrase with Argon2id.

    The *same* function and parameters are used for the real and the duress
    passphrase — they are indistinguishable by construction. A per-slot ``salt``
    is required (a saltless passphrase KDF would be trivially precomputable); it
    is stored in the slot, non-secret. This is the one deviation from the
    nominal ``derive_unlock_key(passphrase)`` signature, and a necessary one.
    """
    return hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_cost,
        parallelism=params.parallelism,
        hash_len=32,
        type=Type.ID,
    )


# ---------------------------------------------------------------------------
# Payload padding (constant-length, so slot ciphertexts don't leak content size)
# ---------------------------------------------------------------------------


def _pad(payload: bytes) -> bytes:
    if len(payload) > PAYLOAD_SIZE - _LEN_PREFIX:
        raise ValueError(f"payload too large to seal (max {PAYLOAD_SIZE - _LEN_PREFIX} bytes)")
    body = len(payload).to_bytes(_LEN_PREFIX, "big") + payload
    return body + b"\x00" * (PAYLOAD_SIZE - len(body))


def _unpad(block: bytes) -> bytes:
    n = int.from_bytes(block[:_LEN_PREFIX], "big")
    if n > PAYLOAD_SIZE - _LEN_PREFIX:
        raise ValueError("corrupt padded block")
    return block[_LEN_PREFIX:_LEN_PREFIX + n]


# ---------------------------------------------------------------------------
# Slots
# ---------------------------------------------------------------------------


def _seal_slot(passphrase: str, payload: bytes, params: KDFParams) -> bytes:
    salt = os.urandom(_SALT_LEN)
    key = derive_unlock_key(passphrase, salt, params)
    sealed = encrypt(key, _pad(payload))  # nonce ‖ ciphertext+tag
    return salt + sealed


def _random_slot() -> bytes:
    """An indistinguishable, never-openable slot (used when no duress is set)."""
    return os.urandom(_SLOT_SIZE)


def _open_slot(passphrase: str, slot: bytes, params: KDFParams) -> bytes | None:
    """Return the slot's payload if the passphrase opens it, else None."""
    salt, sealed = slot[:_SALT_LEN], slot[_SALT_LEN:]
    key = derive_unlock_key(passphrase, salt, params)
    try:
        return _unpad(decrypt(key, sealed))
    except (InvalidTag, ValueError):
        return None


# ---------------------------------------------------------------------------
# Vault
# ---------------------------------------------------------------------------


def create_vault(
    real_passphrase: str,
    real_payload: bytes,
    *,
    duress_passphrase: str | None = None,
    duress_payload: bytes = b"",
    params: KDFParams = DEFAULT_PARAMS,
) -> bytes:
    """
    Build a two-slot vault.

    Slot 1 seals ``real_payload`` under ``real_passphrase``. Slot 2 seals
    ``duress_payload`` under ``duress_passphrase`` when one is given, otherwise
    it is indistinguishable random bytes. The two slots are shuffled so position
    reveals nothing. Returns the serialized vault bytes.
    """
    real_slot = _seal_slot(real_passphrase, real_payload, params)
    if duress_passphrase is not None:
        other_slot = _seal_slot(duress_passphrase, duress_payload, params)
    else:
        other_slot = _random_slot()

    slots = [real_slot, other_slot]
    # Randomize order: a deterministic "real is first" would itself be a tell.
    if secrets.randbits(1):
        slots.reverse()

    header = _MAGIC + bytes([_VERSION]) + params.to_header()
    return header + slots[0] + slots[1]


def _parse_vault(vault: bytes) -> tuple[KDFParams, bytes, bytes]:
    if vault[: len(_MAGIC)] != _MAGIC:
        raise ValueError("not a DRIFT vault")
    off = len(_MAGIC)
    version = vault[off]
    off += 1
    if version != _VERSION:
        raise ValueError(f"unsupported vault version {version}")
    params = KDFParams.from_header(vault[off:off + 12])
    off += 12
    slot1 = vault[off:off + _SLOT_SIZE]
    slot2 = vault[off + _SLOT_SIZE:off + 2 * _SLOT_SIZE]
    if len(slot1) != _SLOT_SIZE or len(slot2) != _SLOT_SIZE:
        raise ValueError("truncated vault")
    return params, slot1, slot2


def try_unlock(vault: bytes, passphrase: str) -> bytes | None:
    """
    Attempt to open a vault with a passphrase.

    Returns the decrypted payload of whichever slot the passphrase opens, or
    ``None`` if it opens neither. **Both** slots are always derived and tried, in
    fixed order, with no early return — so the time taken and the work done are
    identical whether the real passphrase, the duress passphrase, or a wrong
    passphrase was entered. The caller inspects the returned payload to learn the
    role; this module never branches on it.
    """
    params, slot1, slot2 = _parse_vault(vault)
    # Derive + try both slots unconditionally (constant work, no short-circuit).
    result1 = _open_slot(passphrase, slot1, params)
    result2 = _open_slot(passphrase, slot2, params)
    if result1 is not None:
        return result1
    return result2


# ---------------------------------------------------------------------------
# Secure file shredding
# ---------------------------------------------------------------------------


def secure_overwrite(path: str | os.PathLike[str], passes: int = 3) -> None:
    """
    Best-effort secure delete: overwrite a file's bytes with random data over
    several passes (each flushed + fsync'd), then unlink it.

    See the module docstring's "Honest limits": on copy-on-write / journaling /
    wear-levelled storage, or where snapshots/backups exist, the original bytes
    may persist in copies this cannot reach. This raises the bar; it is not a
    guarantee against a forensic lab with the raw device. Missing files are a
    no-op (the end state — gone — is what we want).
    """
    p = os.fspath(path)
    try:
        size = os.path.getsize(p)
    except OSError:
        return
    try:
        with open(p, "r+b", buffering=0) as fh:
            for _ in range(max(1, passes)):
                fh.seek(0)
                fh.write(os.urandom(size) if size else b"")
                fh.flush()
                os.fsync(fh.fileno())
        os.remove(p)
    except OSError:
        # If we couldn't overwrite, still try to remove so the file is gone.
        try:
            os.remove(p)
        except OSError:
            pass
