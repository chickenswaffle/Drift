"""
tests/unit/test_panic.py — duress passphrase / panic key (Phase 5)

The most safety-sensitive tests in the project. They verify:
  - wipe mode destroys the real identity irrecoverably (file-content checks),
  - decoy mode switches cleanly and the real identity stays sealed — unreachable
    without the real passphrase,
  - the on-disk vault is indistinguishable whether or not a duress passphrase
    is configured (deniability).

All use cheap Argon2 parameters so the suite stays fast; production uses the
strong defaults.

Run: pytest tests/unit/test_panic.py -v
"""

from __future__ import annotations

from pathlib import Path

import pytest

from drift import storage
from drift.crypto import Identity, panic
from drift.crypto.panic import (
    KDFParams,
    create_vault,
    derive_unlock_key,
    secure_overwrite,
    try_unlock,
)

_FAST = KDFParams(time_cost=1, memory_cost=8, parallelism=1)


def _disk_contains(root: Path, needle: str) -> bool:
    """True if any file under root contains the needle bytes (forensic check)."""
    raw = needle.encode()
    for p in root.rglob("*"):
        if p.is_file() and raw in p.read_bytes():
            return True
    return False


# --------------------------------------------------------------------------- #
# KDF
# --------------------------------------------------------------------------- #


class TestKDF:
    def test_deterministic_for_same_inputs(self) -> None:
        salt = b"\x01" * 16
        a = derive_unlock_key("hunter2", salt, _FAST)
        b = derive_unlock_key("hunter2", salt, _FAST)
        assert a == b and len(a) == 32

    def test_salt_changes_output(self) -> None:
        k1 = derive_unlock_key("hunter2", b"\x01" * 16, _FAST)
        k2 = derive_unlock_key("hunter2", b"\x02" * 16, _FAST)
        assert k1 != k2

    def test_passphrase_changes_output(self) -> None:
        salt = b"\x07" * 16
        assert derive_unlock_key("real", salt, _FAST) != derive_unlock_key("duress", salt, _FAST)


# --------------------------------------------------------------------------- #
# Vault crypto
# --------------------------------------------------------------------------- #


class TestVault:
    def test_real_and_duress_both_open(self) -> None:
        v = create_vault("realpass", b"REAL", duress_passphrase="duress",
                         duress_payload=b"DURESS", params=_FAST)
        assert try_unlock(v, "realpass") == b"REAL"
        assert try_unlock(v, "duress") == b"DURESS"

    def test_wrong_passphrase_opens_nothing(self) -> None:
        v = create_vault("realpass", b"REAL", duress_passphrase="duress",
                         duress_payload=b"DURESS", params=_FAST)
        assert try_unlock(v, "nope") is None

    def test_no_duress_second_slot_never_opens(self) -> None:
        v = create_vault("realpass", b"REAL", params=_FAST)  # no duress
        assert try_unlock(v, "realpass") == b"REAL"
        assert try_unlock(v, "anything-else") is None

    def test_vault_indistinguishable_with_or_without_duress(self) -> None:
        # Deniability: a vault with a duress passphrase is byte-length identical
        # to one without — the second slot is either a real sealed slot or
        # indistinguishable random bytes.
        with_duress = create_vault("rp", b"REAL", duress_passphrase="dp",
                                   duress_payload=b"D", params=_FAST)
        without = create_vault("rp", b"REAL", params=_FAST)
        assert len(with_duress) == len(without)

    def test_slot_order_is_randomized(self) -> None:
        # Real isn't always slot 0 — over several vaults the real slot lands in
        # both positions (so position isn't a tell). Probabilistic but robust.
        from drift.crypto.panic import _MAGIC, _SALT_LEN, _SLOT_SIZE
        header = len(_MAGIC) + 1 + 12
        first_is_real = []
        for _ in range(12):
            v = create_vault("rp", b"REALMARKER", duress_passphrase="dp",
                             duress_payload=b"DURMARKER", params=_FAST)
            slot0 = v[header:header + _SLOT_SIZE]
            # Try opening slot0 specifically by reconstructing the open.
            opened = panic._open_slot("rp", slot0, _FAST)  # type: ignore[attr-defined]
            first_is_real.append(opened == b"REALMARKER")
            assert _SALT_LEN  # touch import
        assert any(first_is_real) and not all(first_is_real)


# --------------------------------------------------------------------------- #
# Secure overwrite
# --------------------------------------------------------------------------- #


class TestSecureOverwrite:
    def test_removes_file(self, tmp_path: Path) -> None:
        f = tmp_path / "secret"
        f.write_bytes(b"PRIVATE KEY MATERIAL" * 50)
        secure_overwrite(f)
        assert not f.exists()

    def test_missing_file_is_noop(self, tmp_path: Path) -> None:
        secure_overwrite(tmp_path / "does-not-exist")  # must not raise


# --------------------------------------------------------------------------- #
# Storage integration — the real duress behaviours
# --------------------------------------------------------------------------- #


@pytest.fixture
def store(tmp_path, monkeypatch):  # type: ignore[no-untyped-def]
    """Isolated config dir + cheap Argon2 params for the storage-level tests."""
    monkeypatch.setattr(panic, "DEFAULT_PARAMS", _FAST)
    monkeypatch.setattr(storage, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(storage, "IDENTITY_FILE", tmp_path / "identity.json")
    monkeypatch.setattr(storage, "CONTACTS_DIR", tmp_path / "contacts")
    monkeypatch.setattr(storage, "VAULT_FILE", tmp_path / "vault.bin")
    monkeypatch.setattr(storage, "SETTINGS_FILE", tmp_path / "settings.json")
    return tmp_path


def _real_scan_priv(identity: Identity) -> str:
    return identity.to_dict()["scan_priv"]


class TestDecoyMode:
    def test_decoy_unlock_switches_and_real_stays_sealed(self, store: Path) -> None:
        real = Identity.generate()
        # Locked state: no plaintext real identity materialized.
        storage.create_vault(real, "realpass", duress_passphrase="duress",
                             duress_mode="decoy", materialize=False)

        # The real private key must NOT be on disk in the clear — only in the vault.
        assert not (store / "identity.json").exists()

        # Duress passphrase → a *different* identity is materialized.
        assert storage.unlock("duress") == storage.UNLOCK_PROCEED
        materialized = Identity.load(store / "identity.json")
        assert materialized.scan_keypair.public_b58() != real.scan_keypair.public_b58()

        # The real private key is still nowhere in plaintext — sealed in the vault.
        assert not _disk_contains(store / "identity.json", _real_scan_priv(real))

    def test_real_passphrase_recovers_real_after_decoy(self, store: Path) -> None:
        real = Identity.generate()
        storage.create_vault(real, "realpass", duress_passphrase="duress",
                             duress_mode="decoy", materialize=False)
        storage.unlock("duress")  # decoy now materialized
        # Only the real passphrase brings back the real identity.
        assert storage.unlock("realpass") == storage.UNLOCK_PROCEED
        assert (Identity.load(store / "identity.json").scan_keypair.public_b58()
                == real.scan_keypair.public_b58())

    def test_duress_passphrase_cannot_reach_real_identity(self, store: Path) -> None:
        real = Identity.generate()
        storage.create_vault(real, "realpass", duress_passphrase="duress",
                             duress_mode="decoy", materialize=False)
        vault = (store / "vault.bin").read_bytes()
        # The duress passphrase opens only the decoy slot; the real payload is
        # cryptographically unreachable with it.
        duress_payload = try_unlock(vault, "duress")
        assert duress_payload is not None
        assert _real_scan_priv(real) not in duress_payload.decode()


class TestWipeMode:
    def test_wipe_destroys_real_irrecoverably(self, store: Path) -> None:
        real = Identity.generate()
        real_priv = _real_scan_priv(real)
        storage.create_vault(real, "realpass", duress_passphrase="duress",
                             duress_mode="wipe", materialize=True)
        # Sanity: the real key is reachable before the wipe (via the vault).
        assert _disk_contains(store, real_priv) or try_unlock(
            (store / "vault.bin").read_bytes(), "realpass") is not None

        # Duress passphrase → silent wipe, then a fresh empty identity.
        assert storage.unlock("duress") == storage.UNLOCK_PROCEED

        # The vault is gone and the real private key is nowhere on disk anymore.
        assert not (store / "vault.bin").exists()
        assert not _disk_contains(store, real_priv)
        # An app still opens: a materialized (different, empty) identity remains.
        materialized = Identity.load(store / "identity.json")
        assert materialized.scan_keypair.public_b58() != real.scan_keypair.public_b58()

    def test_wipe_leaves_no_recovery_path(self, store: Path) -> None:
        real = Identity.generate()
        storage.create_vault(real, "realpass", duress_passphrase="duress",
                             duress_mode="wipe", materialize=False)
        storage.unlock("duress")
        # The real passphrase can no longer recover anything — the vault is gone.
        assert storage.unlock("realpass") == storage.UNLOCK_FAILED


class TestUnlockDispatch:
    def test_wrong_passphrase_fails(self, store: Path) -> None:
        storage.create_vault(Identity.generate(), "realpass", materialize=False)
        assert storage.unlock("totally-wrong") == storage.UNLOCK_FAILED

    def test_real_passphrase_proceeds(self, store: Path) -> None:
        real = Identity.generate()
        storage.create_vault(real, "realpass", materialize=False)
        assert storage.unlock("realpass") == storage.UNLOCK_PROCEED
        assert (Identity.load(store / "identity.json").scan_keypair.public_b58()
                == real.scan_keypair.public_b58())

    def test_unlock_without_vault_fails(self, store: Path) -> None:
        assert storage.unlock("anything") == storage.UNLOCK_FAILED


class TestLock:
    def test_lock_shreds_identity_but_keeps_vault(self, store: Path) -> None:
        real = Identity.generate()
        storage.create_vault(real, "realpass", materialize=True)
        assert (store / "identity.json").exists()

        assert storage.lock() is True
        # The unlocked working copy is gone; the sealed vault remains.
        assert not (store / "identity.json").exists()
        assert (store / "vault.bin").exists()
        # Re-unlocking restores the real identity from the vault.
        assert storage.unlock("realpass") == storage.UNLOCK_PROCEED
        assert (Identity.load(store / "identity.json").scan_keypair.public_b58()
                == real.scan_keypair.public_b58())

    def test_lock_refuses_without_vault(self, store: Path) -> None:
        # A legacy unencrypted identity has no vault — locking would be
        # irrecoverable data loss, so lock() refuses and leaves the file intact.
        save_identity_legacy = Identity.generate()
        storage.save_identity(save_identity_legacy)
        assert (store / "identity.json").exists()
        assert storage.lock() is False
        assert (store / "identity.json").exists()


class TestFMDSettings:
    def test_default_off(self, store: Path) -> None:
        assert storage.get_fmd_rate() == 0.0

    def test_set_and_persist(self, store: Path) -> None:
        storage.set_fmd_rate(0.1)
        assert storage.get_fmd_rate() == pytest.approx(0.1)

    def test_clamped(self, store: Path) -> None:
        assert storage.set_fmd_rate(-5) == 0.0
        assert storage.set_fmd_rate(2.0) == pytest.approx(0.999)
