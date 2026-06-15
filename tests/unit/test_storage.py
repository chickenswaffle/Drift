"""
tests/unit/test_storage.py — the local persistence model

Focus: contacts are scoped *per identity* (keyed by the public scan key), so
two identities sharing one machine never see each other's address book. This
is the regression guard for the "duplicate contacts" bug.
"""

from __future__ import annotations

import pytest

from drift import storage
from drift.crypto import Identity


@pytest.fixture
def store(tmp_path, monkeypatch):  # type: ignore[no-untyped-def]
    """Redirect storage at an isolated temp config dir (never touch ~)."""
    monkeypatch.setattr(storage, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(storage, "CONTACTS_DIR", tmp_path / "contacts")
    monkeypatch.setattr(storage, "IDENTITY_FILE", tmp_path / "identity.json")
    return tmp_path


def test_contacts_scoped_per_identity(store) -> None:  # type: ignore[no-untyped-def]
    """The core bug-1 fix: each identity sees only the contacts it added."""
    alice = Identity.generate()
    bob = Identity.generate()

    storage.add_contact(alice, "carol", Identity.generate().contact_code())
    storage.add_contact(bob, "dave", Identity.generate().contact_code())

    assert set(storage.load_contacts(alice)) == {"carol"}
    assert set(storage.load_contacts(bob)) == {"dave"}


def test_contacts_file_named_by_scan_key(store) -> None:  # type: ignore[no-untyped-def]
    alice = Identity.generate()
    path = storage.contacts_file(alice)
    assert path.name == f"{alice.scan_keypair.public_b58()}.json"
    assert path.parent == storage.CONTACTS_DIR


def test_load_contacts_empty_when_none(store) -> None:  # type: ignore[no-untyped-def]
    assert storage.load_contacts(Identity.generate()) == {}


def test_add_contact_rejects_bad_code(store) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(storage.StorageError):
        storage.add_contact(Identity.generate(), "x", "not-a-drift-code")


def test_add_contact_rejects_blank_name(store) -> None:  # type: ignore[no-untyped-def]
    code = Identity.generate().contact_code()
    with pytest.raises(storage.StorageError):
        storage.add_contact(Identity.generate(), "   ", code)


def test_contacts_file_is_chmod_600(store) -> None:  # type: ignore[no-untyped-def]
    alice = Identity.generate()
    storage.add_contact(alice, "carol", Identity.generate().contact_code())
    mode = storage.contacts_file(alice).stat().st_mode & 0o777
    assert mode == 0o600


# ---------------------------------------------------------------------------
# Phase 8 — group persistence + at-rest vault sealing (audit H4)
# ---------------------------------------------------------------------------

from drift.crypto import panic  # noqa: E402
from drift.crypto.groups import ContactInfo, create_group  # noqa: E402

_FAST = panic.KDFParams(time_cost=1, memory_cost=8, parallelism=1)


@pytest.fixture
def gstore(tmp_path, monkeypatch):  # type: ignore[no-untyped-def]
    """Isolated config dir (incl. groups + vault) with cheap Argon2 params."""
    monkeypatch.setattr(panic, "DEFAULT_PARAMS", _FAST)
    monkeypatch.setattr(storage, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(storage, "IDENTITY_FILE", tmp_path / "identity.json")
    monkeypatch.setattr(storage, "CONTACTS_DIR", tmp_path / "contacts")
    monkeypatch.setattr(storage, "GROUPS_DIR", tmp_path / "groups")
    monkeypatch.setattr(storage, "VAULT_FILE", tmp_path / "vault.bin")
    monkeypatch.setattr(storage, "SETTINGS_FILE", tmp_path / "settings.json")
    return tmp_path


def _group(name: str) -> object:
    return create_group(name, [ContactInfo("alice", Identity.generate().contact_code())])


def test_groups_save_load_roundtrip(gstore) -> None:  # type: ignore[no-untyped-def]
    idt = Identity.generate()
    g = _group("ops")
    storage.add_group(idt, g)
    loaded = storage.load_groups(idt)
    assert "ops" in loaded
    assert loaded["ops"].group_id.raw == g.group_id.raw
    assert storage.is_group(idt, "ops")
    assert storage.get_group(idt, "ops") is not None


def test_groups_scoped_per_identity(gstore) -> None:  # type: ignore[no-untyped-def]
    a, b = Identity.generate(), Identity.generate()
    storage.add_group(a, _group("ops"))
    assert storage.load_groups(b) == {}  # b sees none of a's groups


def test_groups_file_is_chmod_600(gstore) -> None:  # type: ignore[no-untyped-def]
    idt = Identity.generate()
    storage.add_group(idt, _group("ops"))
    mode = storage.groups_file(idt).stat().st_mode & 0o777
    assert mode == 0o600


def test_remove_group(gstore) -> None:  # type: ignore[no-untyped-def]
    idt = Identity.generate()
    storage.add_group(idt, _group("ops"))
    storage.remove_group(idt, "ops")
    assert not storage.is_group(idt, "ops")


def test_vault_seals_and_restores_groups(gstore) -> None:  # type: ignore[no-untyped-def]
    idt = Identity.generate()
    storage.create_vault(idt, "pw", materialize=True)
    g = _group("ops")
    storage.add_group(idt, g)

    # Lock: re-seal (incl. groups) and shred the plaintext group graph.
    assert storage.lock("pw") is True
    assert storage.load_groups(idt) == {}  # no plaintext group membership at rest

    # Unlock: groups come back from the vault.
    assert storage.unlock("pw") == storage.UNLOCK_PROCEED
    restored = storage.load_groups(idt)
    assert "ops" in restored
    assert restored["ops"].group_id.raw == g.group_id.raw
