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
