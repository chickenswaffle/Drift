"""
drift.storage — local persistence (the "model" layer)

Single source of truth for on-disk state: the user's identity and their
contact list, both under ``~/.config/drift/``. The CLI and the TUI are two
"views" over this model; neither re-implements file IO or key handling.

Architecture note
-----------------
Per AGENTS.md, ``ui/`` knows nothing about crypto. This module is the seam:
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

from drift.crypto import Identity, x3dh
from drift.crypto.groups import GroupState
from drift.crypto.rooms import Room
from drift.crypto.x3dh import PreKeyPrivates

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

# Phase 8: groups are scoped per identity exactly like contacts — a group is
# part of the contact graph, so it gets the same per-identity isolation and the
# same at-rest vault sealing (audit H4): a locked/seized device holds no
# plaintext group membership.
GROUPS_DIR = CONFIG_DIR / "groups"

# Phase 11: sovereign rooms are scoped per identity exactly like contacts and
# groups. A room record can hold real secret material — a dark room's only key,
# or an invite room's posting secret — so it gets the same per-identity
# isolation, the same chmod 0o600, and (audit H4) is sealed into the duress
# vault and shredded on lock/decoy: a seized device must not leak a dark room's
# secret in plaintext.
ROOMS_DIR = CONFIG_DIR / "rooms"

# X3DH (audit H3): the private halves of our published prekeys — the signed
# prekey and the batch of one-time prekeys. Scoped per identity exactly like
# contacts/groups/rooms, sealed into the duress vault and shredded on
# lock/decoy/wipe (the same at-rest protection): a one-time prekey private is the
# secret whose deletion-after-use closes H3, so a seized locked device must not
# leak it in plaintext.
PREKEYS_DIR = CONFIG_DIR / "prekeys"

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
# Groups (Phase 8) — per-identity, keyed by local group name
# ---------------------------------------------------------------------------

Groups = dict[str, GroupState]


def groups_file(identity: Identity) -> Path:
    """Path to ``identity``'s groups file, named by its public scan key."""
    return GROUPS_DIR / f"{identity.scan_keypair.public_b58()}.json"


def load_groups(identity: Identity) -> Groups:
    """Load ``identity``'s groups (empty if none saved)."""
    path = groups_file(identity)
    if not path.exists():
        return {}
    raw: dict[str, dict[str, object]] = json.loads(path.read_text())
    return {name: GroupState.from_dict(d) for name, d in raw.items()}


def save_groups(identity: Identity, groups: Groups) -> None:
    """Persist ``groups`` for ``identity`` only (``chmod 0o600``)."""
    GROUPS_DIR.mkdir(parents=True, exist_ok=True)
    path = groups_file(identity)
    path.write_text(
        json.dumps({name: gs.to_dict() for name, gs in groups.items()}, indent=2)
    )
    path.chmod(0o600)


def add_group(identity: Identity, group: GroupState) -> Groups:
    """Save ``group`` under its local name, returning the updated map."""
    groups = load_groups(identity)
    groups[group.name] = group
    save_groups(identity, groups)
    return groups


def get_group(identity: Identity, name: str) -> GroupState | None:
    """The group labelled ``name``, or ``None`` if there is no such group."""
    return load_groups(identity).get(name)


def remove_group(identity: Identity, name: str) -> Groups:
    """Forget the group labelled ``name`` (local only), returning the rest."""
    groups = load_groups(identity)
    groups.pop(name, None)
    save_groups(identity, groups)
    return groups


def is_group(identity: Identity, name: str) -> bool:
    """True if ``name`` refers to a group (used by ``drift chat`` to route)."""
    return name in load_groups(identity)


# ---------------------------------------------------------------------------
# Rooms (Phase 11) — per-identity, keyed by local room label
# ---------------------------------------------------------------------------

Rooms = dict[str, Room]


def rooms_file(identity: Identity) -> Path:
    """Path to ``identity``'s rooms file, named by its public scan key."""
    return ROOMS_DIR / f"{identity.scan_keypair.public_b58()}.json"


def load_rooms(identity: Identity) -> Rooms:
    """Load ``identity``'s joined rooms (empty if none saved)."""
    path = rooms_file(identity)
    if not path.exists():
        return {}
    raw: dict[str, dict[str, object]] = json.loads(path.read_text())
    return {label: Room.from_dict(d) for label, d in raw.items()}


def save_rooms(identity: Identity, rooms: Rooms) -> None:
    """Persist ``rooms`` for ``identity`` only (``chmod 0o600``)."""
    ROOMS_DIR.mkdir(parents=True, exist_ok=True)
    path = rooms_file(identity)
    path.write_text(
        json.dumps({label: r.to_dict() for label, r in rooms.items()}, indent=2)
    )
    path.chmod(0o600)


def add_room(identity: Identity, room: Room) -> Rooms:
    """Save ``room`` under its local label, returning the updated map."""
    rooms = load_rooms(identity)
    rooms[room.label] = room
    save_rooms(identity, rooms)
    return rooms


def get_room(identity: Identity, label: str) -> Room | None:
    """The room labelled ``label``, or ``None`` if there is no such room."""
    return load_rooms(identity).get(label)


def remove_room(identity: Identity, label: str) -> Rooms:
    """Forget the room labelled ``label`` (local only), returning the rest.

    Rooms have no server-side state, so leaving is purely local: the keys can be
    re-derived at any time from the name (or the saved dark-room secret/QR)."""
    rooms = load_rooms(identity)
    rooms.pop(label, None)
    save_rooms(identity, rooms)
    return rooms


def is_room(identity: Identity, label: str) -> bool:
    """True if ``label`` refers to a room (used by ``drift chat`` to route)."""
    return label in load_rooms(identity)


# ---------------------------------------------------------------------------
# X3DH prekeys (audit H3) — per-identity private prekey store
# ---------------------------------------------------------------------------

def prekeys_file(identity: Identity) -> Path:
    """Path to ``identity``'s prekey privates, named by its public scan key."""
    return PREKEYS_DIR / f"{identity.scan_keypair.public_b58()}.json"


def load_prekey_privates(identity: Identity) -> PreKeyPrivates | None:
    """Load ``identity``'s prekey privates, or ``None`` if none have been generated."""
    path = prekeys_file(identity)
    if not path.exists():
        return None
    return PreKeyPrivates.from_dict(json.loads(path.read_text()))


def save_prekey_privates(identity: Identity, privates: PreKeyPrivates) -> None:
    """Persist ``identity``'s prekey privates (``chmod 0o600``)."""
    PREKEYS_DIR.mkdir(parents=True, exist_ok=True)
    path = prekeys_file(identity)
    path.write_text(json.dumps(privates.to_dict(), indent=2))
    path.chmod(0o600)


def ensure_prekeys(identity: Identity) -> PreKeyPrivates:
    """
    Return ``identity``'s prekey privates, generating them on first use and
    keeping them maintained: rotate the signed prekey weekly (retaining the
    previous one for 24h), drop the previous one once its grace elapses, and
    replenish one-time prekeys when fewer than the watermark remain. Persists any
    change.
    """
    privates = load_prekey_privates(identity)
    changed = False
    if privates is None:
        _, privates = x3dh.generate_prekey_bundle(identity)
        changed = True
    else:
        if x3dh.needs_signed_prekey_rotation(privates):
            x3dh.rotate_signed_prekey(identity, privates)
            changed = True
        had_prev = privates.prev_signed_prekey is not None
        x3dh.drop_expired_prev_signed_prekey(privates)
        if had_prev and privates.prev_signed_prekey is None:
            changed = True
        if x3dh.low_on_one_time(privates):
            x3dh.replenish_one_time(privates)
            changed = True
    if changed:
        save_prekey_privates(identity, privates)
    return privates


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


def _shred_contacts_dir() -> None:
    """Securely delete every plaintext contacts, groups **and rooms** file (any
    identity's).

    Used before materializing a different identity and on lock, so a previous
    identity's address book — contacts, group membership *and* joined rooms
    (including any dark-room secret) — never lingers in plaintext (audit H4 — a
    decoy unlock must leave no trace of the real contact graph, of which groups
    and rooms are a part).
    """
    from drift.crypto import panic

    for directory in (CONTACTS_DIR, GROUPS_DIR, ROOMS_DIR, PREKEYS_DIR):
        if directory.exists():
            for path in directory.glob("*.json"):
                panic.secure_overwrite(path)


def _materialize(
    identity_dict: dict[str, str],
    contacts: Contacts,
    groups_data: dict[str, dict[str, object]] | None = None,
    rooms_data: dict[str, dict[str, object]] | None = None,
    prekeys_data: dict[str, object] | None = None,
) -> None:
    """Write identity.json + that identity's contacts, groups, rooms and prekeys
    (working copy).

    Any other identity's plaintext contacts/groups/rooms/prekeys are shredded
    first, so switching identities (real ↔ decoy) never leaves a stale address
    book, group membership, joined-room secret, or prekey private on disk.
    ``groups_data``/``rooms_data`` are the on-disk JSON forms
    (``{name: GroupState.to_dict()}`` / ``{label: Room.to_dict()}``);
    ``prekeys_data`` is ``PreKeyPrivates.to_dict()``.
    """
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    IDENTITY_FILE.write_text(json.dumps(identity_dict, indent=2))
    IDENTITY_FILE.chmod(0o600)
    _shred_contacts_dir()
    if contacts:
        CONTACTS_DIR.mkdir(parents=True, exist_ok=True)
        path = CONTACTS_DIR / f"{identity_dict['scan_pub']}.json"
        path.write_text(json.dumps(contacts, indent=2))
        path.chmod(0o600)
    if groups_data:
        GROUPS_DIR.mkdir(parents=True, exist_ok=True)
        gpath = GROUPS_DIR / f"{identity_dict['scan_pub']}.json"
        gpath.write_text(json.dumps(groups_data, indent=2))
        gpath.chmod(0o600)
    if rooms_data:
        ROOMS_DIR.mkdir(parents=True, exist_ok=True)
        rpath = ROOMS_DIR / f"{identity_dict['scan_pub']}.json"
        rpath.write_text(json.dumps(rooms_data, indent=2))
        rpath.chmod(0o600)
    if prekeys_data:
        PREKEYS_DIR.mkdir(parents=True, exist_ok=True)
        ppath = PREKEYS_DIR / f"{identity_dict['scan_pub']}.json"
        ppath.write_text(json.dumps(prekeys_data, indent=2))
        ppath.chmod(0o600)


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
    real_contacts: Contacts | None = None,
    real_groups: dict[str, dict[str, object]] | None = None,
    real_rooms: dict[str, dict[str, object]] | None = None,
    real_prekeys: dict[str, object] | None = None,
    materialize: bool = True,
    params: object | None = None,
) -> None:
    """
    Seal ``real_identity`` (and its ``real_contacts``) into the vault under
    ``real_passphrase``.

    ``duress_mode`` is ``"wipe"`` or ``"decoy"`` (ignored unless
    ``duress_passphrase`` is given). For decoy a throwaway identity + a few
    innocuous contacts are generated and sealed under the duress passphrase; for
    wipe a tiny marker is sealed. With no duress passphrase the second slot is
    indistinguishable random bytes. When ``materialize`` is set (the default for
    ``drift init``) the real identity.json + contacts are also written so the
    user is ready to go immediately.

    Contacts are sealed alongside the identity (audit H4): a locked device holds
    no plaintext address book, and a decoy unlock exposes only the decoy's
    contacts. At ``drift init`` the real address book is normally empty; ``lock``
    re-seals it with whatever the user has since added.
    """
    from drift.crypto import panic

    kdf = params if params is not None else panic.DEFAULT_PARAMS
    real_contacts = real_contacts or {}
    real_groups = real_groups or {}
    real_rooms = real_rooms or {}
    real_prekeys = real_prekeys or {}

    real_payload = json.dumps({
        "role": "real", **_identity_payload(real_identity),
        "contacts": real_contacts,
        "groups": real_groups,
        "rooms": real_rooms,
        "prekeys": real_prekeys,
    }).encode()

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
        _materialize(
            real_identity.to_dict(), real_contacts, real_groups, real_rooms, real_prekeys
        )


def shred_working_copy() -> None:
    """Securely delete the materialized identity.json + every contacts and
    groups file (the whole plaintext contact graph)."""
    from drift.crypto import panic

    panic.secure_overwrite(IDENTITY_FILE)
    _shred_contacts_dir()


def lock(passphrase: str) -> bool:
    """
    Re-seal the vault from the current working state, then securely shred the
    plaintext identity.json **and** every contacts file, so a locked device
    holds no private keys and no plaintext address book (audit H4).

    ``passphrase`` must open one of the vault's slots — it re-seals *that* slot
    (preserving its role, so a real session re-seals the real slot and the duress
    slot is carried over untouched) with the identity + contacts currently
    materialized on disk. The keys and contacts come back with
    ``unlock(passphrase)``.

    Returns ``False`` without shredding anything when there is no vault (the
    plaintext identity.json would be the only copy of the keys) or when the
    passphrase opens neither slot (so a typo can't destroy data).
    """
    if not VAULT_FILE.exists():
        return False
    from drift.crypto import panic

    vault = VAULT_FILE.read_bytes()
    current = panic.try_unlock(vault, passphrase)
    if current is None:
        return False  # passphrase opens neither slot — refuse, shred nothing

    # Refresh the opened slot's identity + contacts from the working copies,
    # keeping its role/mode so duress semantics survive a lock.
    identity = load_identity()
    contacts = load_contacts(identity)
    groups = load_groups(identity)
    rooms = load_rooms(identity)
    prekeys = load_prekey_privates(identity)
    payload_obj = dict(json.loads(current))
    payload_obj["identity"] = identity.to_dict()
    payload_obj["contacts"] = contacts
    payload_obj["groups"] = {name: gs.to_dict() for name, gs in groups.items()}
    payload_obj["rooms"] = {label: r.to_dict() for label, r in rooms.items()}
    payload_obj["prekeys"] = prekeys.to_dict() if prekeys is not None else {}
    new_vault = panic.reseal_slot(vault, passphrase, json.dumps(payload_obj).encode())
    if new_vault is None:  # pragma: no cover - try_unlock already proved it opens
        return False

    VAULT_FILE.write_bytes(new_vault)
    VAULT_FILE.chmod(0o600)
    panic.secure_overwrite(IDENTITY_FILE)
    _shred_contacts_dir()
    return True


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
        _materialize(data["identity"], data.get("contacts", {}),
                     data.get("groups", {}), data.get("rooms", {}),
                     data.get("prekeys", {}))
        return UNLOCK_PROCEED

    # Duress.
    if data.get("mode") == "decoy":
        _materialize(data["identity"], data.get("contacts", {}),
                     data.get("groups", {}), data.get("rooms", {}),
                     data.get("prekeys", {}))
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
