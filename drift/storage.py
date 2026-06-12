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
import os
from pathlib import Path
from typing import TypedDict

from drift.crypto import Identity

# Config directory: ~/.config/drift/ by default, overridable via $DRIFT_CONFIG.
# The override lets two terminals run separate identities on one machine (each
# `DRIFT_CONFIG=/tmp/alice drift …`), which is essential for local testing.
CONFIG_DIR = Path(os.environ.get("DRIFT_CONFIG", Path.home() / ".config" / "drift"))
IDENTITY_FILE = CONFIG_DIR / "identity.json"

# Contacts are scoped *per identity*, not global: each identity keeps its own
# address book under ~/.config/drift/contacts/<scan_pub_b58>.json. Keying by the
# public scan key (the routable half of the identity) means two identities on
# the same machine never see each other's contacts.
CONTACTS_DIR = CONFIG_DIR / "contacts"

# Phase 5: the encrypted duress vault (the at-rest sealed identity store) and the
# small settings file (currently just the FMD privacy-dial rate). The vault is
# always two slots — its mere presence reveals nothing about whether a duress
# passphrase is configured (see drift.crypto.panic).
VAULT_FILE = CONFIG_DIR / "vault.bin"
SETTINGS_FILE = CONFIG_DIR / "settings.json"


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

def contacts_file(identity: Identity) -> Path:
    """Path to ``identity``'s address book, named by its public scan key."""
    return CONTACTS_DIR / f"{identity.scan_keypair.public_b58()}.json"


def load_contacts(identity: Identity) -> Contacts:
    """Load the contacts belonging to ``identity`` (empty if none saved)."""
    path = contacts_file(identity)
    if not path.exists():
        return {}
    data: Contacts = json.loads(path.read_text())
    return data


def save_contacts(identity: Identity, contacts: Contacts) -> None:
    """Persist ``contacts`` for ``identity`` only."""
    CONTACTS_DIR.mkdir(parents=True, exist_ok=True)
    path = contacts_file(identity)
    path.write_text(json.dumps(contacts, indent=2))
    path.chmod(0o600)


def is_valid_contact_code(code: str) -> bool:
    """True if ``code`` parses as a DRIFT contact code."""
    try:
        Identity.parse_contact_code(code)
    except ValueError:
        return False
    return True


def add_contact(identity: Identity, name: str, code: str) -> Contacts:
    """
    Validate and save a contact for ``identity``, returning the updated map.

    Raises ``StorageError`` if the name is blank or the code is malformed.
    """
    if not name.strip():
        raise StorageError("contact name cannot be empty")
    if not is_valid_contact_code(code):
        raise StorageError("invalid contact code")
    contacts = load_contacts(identity)
    contacts[name] = {"code": code}
    save_contacts(identity, contacts)
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


# ---------------------------------------------------------------------------
# Phase 5 — duress vault (panic key)
#
# The vault seals the identity at rest under a passphrase. ``drift unlock``
# materializes a working identity.json from it; the duress passphrase instead
# triggers a silent wipe or swaps in a decoy. All the indistinguishability and
# constant-time guarantees live in drift.crypto.panic — this layer only encodes
# what a sealed payload *means* and moves files around.
# ---------------------------------------------------------------------------

# How `unlock` resolved — the CLI must treat PROCEED identically for real, decoy,
# and wipe so an onlooker sees no difference. Only a wrong passphrase differs.
UNLOCK_PROCEED = "proceed"
UNLOCK_FAILED = "failed"

# Number of innocuous auto-generated contacts in a decoy identity, so the decoy
# messenger looks lived-in rather than suspiciously empty.
_DECOY_CONTACT_NAMES = ("mum", "work", "pizza-place", "gym", "landlord")


def vault_exists() -> bool:
    return VAULT_FILE.exists()


def _identity_payload(identity: Identity) -> dict[str, object]:
    return {"identity": identity.to_dict()}


def _materialize(identity_dict: dict[str, str], contacts: Contacts) -> None:
    """Write identity.json + that identity's contacts file (the working copy)."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    IDENTITY_FILE.write_text(json.dumps(identity_dict, indent=2))
    IDENTITY_FILE.chmod(0o600)
    if contacts:
        CONTACTS_DIR.mkdir(parents=True, exist_ok=True)
        path = CONTACTS_DIR / f"{identity_dict['scan_pub']}.json"
        path.write_text(json.dumps(contacts, indent=2))
        path.chmod(0o600)


def _generate_decoy() -> tuple[dict[str, str], Contacts]:
    """A believable but innocuous decoy: a fresh identity + a few boring contacts."""
    decoy = Identity.generate()
    contacts: Contacts = {
        name: {"code": Identity.generate().contact_code()}
        for name in _DECOY_CONTACT_NAMES[:3]
    }
    return decoy.to_dict(), contacts


def create_vault(
    real_identity: Identity,
    real_passphrase: str,
    *,
    duress_passphrase: str | None = None,
    duress_mode: str | None = None,
    materialize: bool = True,
    params: object | None = None,
) -> None:
    """
    Seal ``real_identity`` into the vault under ``real_passphrase``.

    ``duress_mode`` is ``"wipe"`` or ``"decoy"`` (ignored unless
    ``duress_passphrase`` is given). For decoy a throwaway identity + a few
    innocuous contacts are generated and sealed under the duress passphrase; for
    wipe a tiny marker is sealed. With no duress passphrase the second slot is
    indistinguishable random bytes. When ``materialize`` is set (the default for
    ``drift init``) the real identity.json is also written so the user is ready
    to go immediately.
    """
    from drift.crypto import panic

    kdf = params if params is not None else panic.DEFAULT_PARAMS

    real_payload = json.dumps({"role": "real", **_identity_payload(real_identity)}).encode()

    duress_payload = b""
    if duress_passphrase is not None:
        if duress_mode == "decoy":
            decoy_id, decoy_contacts = _generate_decoy()
            duress_payload = json.dumps({
                "role": "duress", "mode": "decoy",
                "identity": decoy_id, "contacts": decoy_contacts,
            }).encode()
        else:  # wipe (default duress behaviour)
            duress_payload = json.dumps({"role": "duress", "mode": "wipe"}).encode()

    vault_bytes = panic.create_vault(
        real_passphrase,
        real_payload,
        duress_passphrase=duress_passphrase,
        duress_payload=duress_payload,
        params=kdf,  # type: ignore[arg-type]
    )
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    VAULT_FILE.write_bytes(vault_bytes)
    VAULT_FILE.chmod(0o600)

    if materialize:
        _materialize(real_identity.to_dict(), {})


def shred_working_copy() -> None:
    """Securely delete the materialized identity.json + every contacts file."""
    from drift.crypto import panic

    panic.secure_overwrite(IDENTITY_FILE)
    if CONTACTS_DIR.exists():
        for path in CONTACTS_DIR.glob("*.json"):
            panic.secure_overwrite(path)


def _wipe_everything() -> None:
    """Duress wipe: shred working copies AND the vault — irrecoverable."""
    from drift.crypto import panic

    shred_working_copy()
    panic.secure_overwrite(VAULT_FILE)


def unlock(passphrase: str) -> str:
    """
    Open the vault with ``passphrase`` and act on what it finds — silently.

    Returns :data:`UNLOCK_PROCEED` for the real passphrase, a decoy duress
    passphrase, *and* a wipe duress passphrase: all three leave a usable,
    materialized identity.json and look identical to the caller. Only a
    passphrase that opens neither slot returns :data:`UNLOCK_FAILED`.

    The vault stores its own KDF parameters, so unlocking needs only the
    passphrase.

      real  → materialize the real identity
      decoy → materialize the decoy identity (real stays sealed, unreachable)
      wipe  → shred the real identity + contacts + vault, then materialize a
              fresh empty identity so the app still opens to an innocuous,
              empty messenger (no error, no tell)
    """
    from drift.crypto import panic

    if not VAULT_FILE.exists():
        return UNLOCK_FAILED
    payload = panic.try_unlock(VAULT_FILE.read_bytes(), passphrase)
    if payload is None:
        return UNLOCK_FAILED

    data = json.loads(payload)
    if data.get("role") == "real":
        _materialize(data["identity"], {})
        return UNLOCK_PROCEED

    # Duress.
    if data.get("mode") == "decoy":
        _materialize(data["identity"], data.get("contacts", {}))
        return UNLOCK_PROCEED

    # Wipe: destroy the real identity, then present an empty messenger.
    _wipe_everything()
    _materialize(Identity.generate().to_dict(), {})
    return UNLOCK_PROCEED


# ---------------------------------------------------------------------------
# Phase 5 — FMD privacy dial (settings)
# ---------------------------------------------------------------------------

def _load_settings() -> dict[str, object]:
    if not SETTINGS_FILE.exists():
        return {}
    try:
        data: dict[str, object] = json.loads(SETTINGS_FILE.read_text())
        return data
    except (OSError, json.JSONDecodeError):
        return {}


def get_fmd_rate() -> float:
    """Current FMD false-positive rate (0.0 = off, pure client-side scanning)."""
    raw = _load_settings().get("fmd_rate", 0.0)
    try:
        return float(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0.0


def set_fmd_rate(rate: float) -> float:
    """
    Persist the FMD false-positive rate, clamped to [0, 1). Returns the value
    stored. 0 disables FMD; larger values let the relay pre-filter more (more
    noise, less client scanning).
    """
    rate = max(0.0, min(0.999, float(rate)))
    settings = _load_settings()
    settings["fmd_rate"] = rate
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    SETTINGS_FILE.write_text(json.dumps(settings, indent=2))
    SETTINGS_FILE.chmod(0o600)
    return rate
