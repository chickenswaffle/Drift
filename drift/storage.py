"""
drift.storage — local persistence (the "model" layer)

Single source of truth for on-disk state: the user's identity and their
contact list, both under ``~/.config/drift/``. The CLI and the TUI are two
"views" over this model; neither re-implements file IO or key handling.

Architecture note
-----------------
Per CLAUDE.md, ``ui/`` knows nothing about crypto. This module is the seam:
it may import ``drift.crypto`` (it loads key material and derives the public
safety number), and the UI talks to *this* module instead of to crypto. A
future web backend can reuse this same model unchanged.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import TypedDict

from drift.crypto import Identity

# Default config directory: ~/.config/drift/
CONFIG_DIR = Path.home() / ".config" / "drift"
IDENTITY_FILE = CONFIG_DIR / "identity.json"
CONTACTS_FILE = CONFIG_DIR / "contacts.json"


class Contact(TypedDict):
    """A saved contact record."""
    code: str


Contacts = dict[str, Contact]


class StorageError(Exception):
    """Raised when identity/contact state is missing or invalid."""


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------

def identity_exists() -> bool:
    return IDENTITY_FILE.exists()


def load_identity() -> Identity:
    """Load the local identity, or raise ``StorageError`` if none exists."""
    if not IDENTITY_FILE.exists():
        raise StorageError("no identity found — run `drift init` first")
    return Identity.load(IDENTITY_FILE)


def save_identity(identity: Identity, *, overwrite: bool = False) -> None:
    """
    Persist an identity. Refuses to clobber an existing one unless
    ``overwrite`` is set. ``Identity.save`` writes the file ``chmod 0o600``.
    """
    if IDENTITY_FILE.exists() and not overwrite:
        raise StorageError("identity already exists")
    identity.save(IDENTITY_FILE)


# ---------------------------------------------------------------------------
# Contacts
# ---------------------------------------------------------------------------

def load_contacts() -> Contacts:
    if not CONTACTS_FILE.exists():
        return {}
    data: Contacts = json.loads(CONTACTS_FILE.read_text())
    return data


def save_contacts(contacts: Contacts) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONTACTS_FILE.write_text(json.dumps(contacts, indent=2))
    CONTACTS_FILE.chmod(0o600)


def is_valid_contact_code(code: str) -> bool:
    """True if ``code`` parses as a DRIFT contact code."""
    try:
        Identity.parse_contact_code(code)
    except ValueError:
        return False
    return True


def add_contact(name: str, code: str) -> Contacts:
    """
    Validate and save a contact, returning the updated contact map.

    Raises ``StorageError`` if the name is blank or the code is malformed.
    """
    if not name.strip():
        raise StorageError("contact name cannot be empty")
    if not is_valid_contact_code(code):
        raise StorageError("invalid contact code")
    contacts = load_contacts()
    contacts[name] = {"code": code}
    save_contacts(contacts)
    return contacts


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def safety_number(identity: Identity, contact_code: str) -> str:
    """
    Derive the short out-of-band safety number shared by both parties.

    Symmetric (sorted scan keys), so each side computes the same value; a
    mismatch means a man-in-the-middle. This is a *public* verification value,
    not secret key material — which is why it lives in the model, not the UI.
    """
    their_scan, _ = Identity.parse_contact_code(contact_code)
    my_scan = identity.scan_keypair.public_bytes()
    combined = b"drift-safety-v0" + b"".join(sorted([my_scan, their_scan]))
    digest = hashlib.sha256(combined).digest()
    return "-".join(f"{digest[i * 4]:02x}{digest[i * 4 + 1]:02x}" for i in range(4))
