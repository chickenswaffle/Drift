"""
drift.crypto.groups — Phase 8 group state (pairwise composition, ≤10 members)

DRIFT groups are *not* a new cryptographic construction. A group is purely a
composition of the existing pairwise Double Ratchet (``drift.crypto.ratchet``)
and stealth addressing (``drift.crypto.stealth``):

  - Every member keeps an independent pairwise ratchet session with every other
    member, exactly as in a 1:1 chat.
  - A group message is encrypted **once per recipient** (N-1 ciphertexts for an
    N-member group) using each pairwise session, and each ciphertext is sent to
    that recipient's own stealth one-time address. The relay therefore sees N-1
    unrelated envelopes, never a "group message".

Tradeoff (documented in DESIGN.md §11): this costs **O(n) bandwidth per message**
— fine for the small groups this phase targets (``GROUP_MAX_MEMBERS`` = 10) and
it introduces no new primitives. Sender-keys (a single per-sender chain fanned
out via pairwise channels) would cut send cost to O(1) ciphertext + O(n) key
distribution; that is explicitly deferred to a future **Phase 8b** for larger
groups.

This module owns only *state and framing* (no network, no I/O):

  GroupId        — a random 32-byte identifier, owned by no single member
  ContactInfo    — (local name, contact code) for one member
  GroupState     — the local view: group id, local label, the OTHER members,
                   and a creation timestamp
  MembershipChange — a signed add/remove record (Ed25519 via the identity's
                   existing signing key — no new primitive, mirrors beacons)
  pack/unpack_group_payload — frame the plaintext that rides the ratchet so the
                   receiver can tell which group a decrypted message belongs to

Group identifier ownership
--------------------------
``GroupId`` is fresh randomness, **not** derived from any member's keys, so no
single member "owns" the group or can be linked to it by the identifier alone.

Membership-change authenticity
------------------------------
A :class:`MembershipChange` carries the author's Ed25519 verify key and a
signature over its canonical bytes (the same self-attested pattern beacons use,
see ``drift.crypto.beacon``). The signature is *tamper-evidence*. The binding of
the change to a real member is provided by the **pairwise authenticated
channel** it arrives on: the transport layer (``GroupSession``) only accepts a
change whose declared author matches the pairwise ratchet that decrypted it.
For transitively-relayed changes, trust is transitive through the relaying
member — an inherent property of the eventual-consistency model (DESIGN.md §11).
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field, replace
from typing import cast

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from drift.crypto import Identity, b58decode, b58encode

# A pairwise-ratchet group stays cheap only while it is small: every message
# costs one ciphertext per other member. Beyond this, use Phase 8b sender-keys.
GROUP_MAX_MEMBERS = 10

GROUP_ID_LEN = 32

# Frame marker prefixing every group payload that rides a pairwise ratchet. It
# distinguishes a group message from an ordinary 1:1 plaintext on the *same*
# pairwise session (a 1:1 message simply lacks this marker), so a receiver can
# route a decrypted blob to the right conversation.
_MAGIC = b"DRIFTGRP\x01"

KIND_TEXT = 0          # body is the UTF-8 group message
KIND_MEMBERSHIP = 1    # body is a serialized MembershipChange

ACTION_ADD = "add"
ACTION_REMOVE = "remove"


class GroupError(Exception):
    """Raised on an invalid group operation (bad size, bad member, bad frame)."""


# ---------------------------------------------------------------------------
# Group identity + membership
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class GroupId:
    """A random 32-byte group identifier (owned by no member)."""

    raw: bytes

    def __post_init__(self) -> None:
        if len(self.raw) != GROUP_ID_LEN:
            raise GroupError(f"group id must be {GROUP_ID_LEN} bytes, got {len(self.raw)}")

    @classmethod
    def generate(cls) -> GroupId:
        return cls(os.urandom(GROUP_ID_LEN))

    @property
    def b58(self) -> str:
        return b58encode(self.raw)

    @classmethod
    def from_b58(cls, text: str) -> GroupId:
        return cls(b58decode(text))


@dataclass(frozen=True)
class ContactInfo:
    """One member: a local display ``name`` and their routable ``code``."""

    name: str
    code: str

    def validate(self) -> None:
        # Raises ValueError on a malformed contact code.
        Identity.parse_contact_code(self.code)


@dataclass
class GroupState:
    """
    The local view of a group.

    ``members`` are the **other** members only (you are implicit); each one is
    a peer you hold an independent pairwise ratchet with. ``name`` is local —
    never synced — so each member may label the same group differently.
    """

    group_id: GroupId
    name: str
    members: list[ContactInfo] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    @property
    def size(self) -> int:
        """Total participants including yourself."""
        return len(self.members) + 1

    def member_codes(self) -> list[str]:
        return [m.code for m in self.members]

    def has_member(self, code: str) -> bool:
        return any(m.code == code for m in self.members)

    # -- serialization (for storage; the group id/name are local-only) --------

    def to_dict(self) -> dict[str, object]:
        return {
            "group_id": self.group_id.b58,
            "name": self.name,
            "members": [{"name": m.name, "code": m.code} for m in self.members],
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> GroupState:
        members_raw = cast("list[dict[str, str]]", data.get("members", []))
        members = [
            ContactInfo(name=str(m["name"]), code=str(m["code"])) for m in members_raw
        ]
        return cls(
            group_id=GroupId.from_b58(str(data["group_id"])),
            name=str(data["name"]),
            members=members,
            created_at=float(cast("float", data.get("created_at", 0.0))),
        )


def _check_capacity(member_count: int) -> None:
    # member_count counts the OTHER members; +1 for self.
    if member_count + 1 > GROUP_MAX_MEMBERS:
        raise GroupError(
            f"group would exceed the {GROUP_MAX_MEMBERS}-member limit "
            f"(pairwise ratchets only — see Phase 8b sender-keys)"
        )


def create_group(name: str, initial_members: list[ContactInfo]) -> GroupState:
    """
    Build a new group with a fresh random :class:`GroupId`.

    ``initial_members`` are the *other* members (not yourself). Their pairwise
    ratchet sessions bootstrap deterministically from the static keys (see
    ``drift.transport.session``); nothing extra is established here — this layer
    is pure state. Raises :class:`GroupError` if the group would exceed
    :data:`GROUP_MAX_MEMBERS` or a member's contact code is malformed.
    """
    if not name.strip():
        raise GroupError("group name cannot be empty")
    _check_capacity(len(initial_members))
    for m in initial_members:
        try:
            m.validate()
        except ValueError as exc:
            raise GroupError(f"invalid contact code for {m.name!r}: {exc}") from exc
    # De-duplicate by code while preserving order.
    seen: set[str] = set()
    members: list[ContactInfo] = []
    for m in initial_members:
        if m.code not in seen:
            seen.add(m.code)
            members.append(m)
    return GroupState(group_id=GroupId.generate(), name=name, members=members)


def add_member(group: GroupState, new_member: ContactInfo) -> GroupState:
    """Add ``new_member`` to ``group`` (mutates and returns it)."""
    new_member.validate()
    if group.has_member(new_member.code):
        raise GroupError(f"{new_member.name!r} is already in the group")
    _check_capacity(len(group.members) + 1)
    group.members.append(new_member)
    return group


def remove_member(group: GroupState, code: str) -> GroupState:
    """
    Remove the member with contact ``code`` from ``group`` (mutates, returns it).

    Security note (DESIGN.md §11): removal forward-secrecy relies on the existing
    pairwise-ratchet property, **not** a new mechanism. After removal the member
    is dropped from every sender's recipient list, so they receive no further
    envelopes; and because each remaining pair's ratchet advances on continued
    use, a removed member who somehow retained another pair's session state
    still cannot follow future ratchet steps. Removal is **not** retroactive: a
    removed member who saved earlier message keys can still read messages from
    *before* the removal — true of essentially every messenger.
    """
    if not group.has_member(code):
        raise GroupError("no such member in the group")
    group.members = [m for m in group.members if m.code != code]
    return group


# ---------------------------------------------------------------------------
# Membership change records (signed; authenticity bound by the pairwise channel)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class MembershipChange:
    """
    A signed add/remove announcement, sent pairwise to the affected members.

    ``author_code`` is the contact code of the member making the change;
    ``author_verify_key`` is their Ed25519 public key (so the signature is
    self-verifiable, like a beacon). The transport layer additionally checks
    that ``author_code`` matches the pairwise channel that delivered it.
    """

    action: str                 # ACTION_ADD | ACTION_REMOVE
    group_id: GroupId
    target: ContactInfo         # the member added or removed
    author_code: str
    author_verify_key: bytes
    timestamp: float
    signature: bytes = b""

    def _signing_payload(self) -> bytes:
        """Canonical bytes covered by the signature (everything but the sig)."""
        return json.dumps(
            {
                "action": self.action,
                "group_id": self.group_id.b58,
                "target_name": self.target.name,
                "target_code": self.target.code,
                "author_code": self.author_code,
                "author_verify_key": b58encode(self.author_verify_key),
                "timestamp": self.timestamp,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()

    def to_bytes(self) -> bytes:
        obj = json.loads(self._signing_payload())
        obj["signature"] = b58encode(self.signature)
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()

    @classmethod
    def from_bytes(cls, raw: bytes) -> MembershipChange:
        try:
            obj = json.loads(raw)
            return cls(
                action=str(obj["action"]),
                group_id=GroupId.from_b58(str(obj["group_id"])),
                target=ContactInfo(name=str(obj["target_name"]), code=str(obj["target_code"])),
                author_code=str(obj["author_code"]),
                author_verify_key=b58decode(str(obj["author_verify_key"])),
                timestamp=float(obj["timestamp"]),
                signature=b58decode(str(obj["signature"])),
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise GroupError(f"malformed membership change: {exc}") from exc


def make_membership_change(
    identity: Identity, group: GroupState, action: str, target: ContactInfo
) -> MembershipChange:
    """Build and sign a membership change authored by ``identity``."""
    if action not in (ACTION_ADD, ACTION_REMOVE):
        raise GroupError(f"unknown membership action {action!r}")
    change = MembershipChange(
        action=action,
        group_id=group.group_id,
        target=target,
        author_code=identity.contact_code(),
        author_verify_key=identity.verify_key_bytes(),
        timestamp=time.time(),
    )
    signature = identity.signing_key().sign(change._signing_payload()).signature
    return replace(change, signature=signature)


def verify_membership_change(change: MembershipChange) -> bool:
    """
    Verify a membership change's signature against its embedded verify key.

    Proves the record was not altered and was signed by whoever holds
    ``author_verify_key``. Binding that key to a real member is the caller's job
    (the transport layer checks it against the delivering pairwise channel).
    """
    try:
        VerifyKey(change.author_verify_key).verify(
            change._signing_payload(), change.signature
        )
    except (BadSignatureError, ValueError):
        return False
    return True


def apply_membership_change(group: GroupState, change: MembershipChange) -> GroupState:
    """
    Fold an (already-authenticated) change into the local ``group`` view.

    Idempotent: re-applying a change that's already reflected is a no-op, so
    duplicate delivery during eventual-consistency convergence is harmless.
    """
    if change.action == ACTION_ADD:
        if not group.has_member(change.target.code):
            # Don't add yourself back if you are the target of someone's view.
            _check_capacity(len(group.members) + 1)
            group.members.append(change.target)
    elif change.action == ACTION_REMOVE:
        group.members = [m for m in group.members if m.code != change.target.code]
    else:  # pragma: no cover - guarded at construction
        raise GroupError(f"unknown membership action {change.action!r}")
    return group


# ---------------------------------------------------------------------------
# Group payload framing (rides inside the pairwise ratchet ciphertext)
# ---------------------------------------------------------------------------

def pack_group_payload(group_id: GroupId, kind: int, body: bytes) -> bytes:
    """
    Frame a group payload: ``_MAGIC || group_id(32) || kind(1) || body``.

    The whole frame is what gets ratchet-encrypted, so the group id and kind are
    encrypted end-to-end and never visible to the relay (the envelope carries
    only a stealth one-time address).
    """
    if kind not in (KIND_TEXT, KIND_MEMBERSHIP):
        raise GroupError(f"unknown group payload kind {kind}")
    return _MAGIC + group_id.raw + bytes([kind]) + body


def unpack_group_payload(blob: bytes) -> tuple[GroupId, int, bytes] | None:
    """
    Parse a framed group payload, or return ``None`` if ``blob`` is not one.

    Returning ``None`` (rather than raising) lets a receiver cleanly distinguish
    an ordinary 1:1 message decrypted on the same pairwise ratchet from a group
    message — the 1:1 message simply lacks the frame marker.
    """
    if not blob.startswith(_MAGIC):
        return None
    rest = blob[len(_MAGIC):]
    if len(rest) < GROUP_ID_LEN + 1:
        return None
    group_id = GroupId(rest[:GROUP_ID_LEN])
    kind = rest[GROUP_ID_LEN]
    body = rest[GROUP_ID_LEN + 1:]
    if kind not in (KIND_TEXT, KIND_MEMBERSHIP):
        return None
    return group_id, kind, body
