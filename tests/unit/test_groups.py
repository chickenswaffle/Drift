"""
tests/unit/test_groups.py — Phase 8 group state + framing (pure crypto layer)

Covers drift.crypto.groups: GroupId, membership mutation + capacity, signed
membership changes (sign/verify/tamper), idempotent application, and the
group-payload frame (including that a 1:1 plaintext is *not* mistaken for one).
"""

from __future__ import annotations

import pytest

from drift.crypto import Identity
from drift.crypto.groups import (
    ACTION_ADD,
    ACTION_REMOVE,
    GROUP_MAX_MEMBERS,
    KIND_MEMBERSHIP,
    KIND_TEXT,
    ContactInfo,
    GroupError,
    GroupId,
    GroupState,
    add_member,
    apply_membership_change,
    create_group,
    make_membership_change,
    pack_group_payload,
    remove_member,
    unpack_group_payload,
    verify_membership_change,
)


def _member(name: str) -> ContactInfo:
    return ContactInfo(name=name, code=Identity.generate().contact_code())


class TestGroupId:
    def test_generate_is_32_bytes_and_unique(self) -> None:
        a, b = GroupId.generate(), GroupId.generate()
        assert len(a.raw) == 32
        assert a.raw != b.raw

    def test_b58_roundtrip(self) -> None:
        gid = GroupId.generate()
        assert GroupId.from_b58(gid.b58).raw == gid.raw

    def test_bad_length_rejected(self) -> None:
        with pytest.raises(GroupError):
            GroupId(b"too-short")


class TestCreateGroup:
    def test_creates_with_members_and_random_id(self) -> None:
        g = create_group("ops", [_member("alice"), _member("bob")])
        assert g.name == "ops"
        assert g.size == 3  # two others + me
        assert len(g.group_id.raw) == 32

    def test_dedupes_members(self) -> None:
        m = _member("alice")
        g = create_group("g", [m, m])
        assert len(g.members) == 1

    def test_rejects_empty_name(self) -> None:
        with pytest.raises(GroupError):
            create_group("  ", [_member("a")])

    def test_rejects_bad_code(self) -> None:
        with pytest.raises(GroupError):
            create_group("g", [ContactInfo(name="x", code="not-a-code")])

    def test_enforces_max_members(self) -> None:
        # GROUP_MAX_MEMBERS includes me, so MAX-1 others is the ceiling.
        others = [_member(f"m{i}") for i in range(GROUP_MAX_MEMBERS)]
        with pytest.raises(GroupError):
            create_group("big", others)


class TestMembershipMutation:
    def test_add_and_remove(self) -> None:
        g = create_group("g", [_member("alice")])
        bob = _member("bob")
        add_member(g, bob)
        assert g.has_member(bob.code)
        remove_member(g, bob.code)
        assert not g.has_member(bob.code)

    def test_add_duplicate_rejected(self) -> None:
        m = _member("alice")
        g = create_group("g", [m])
        with pytest.raises(GroupError):
            add_member(g, m)

    def test_remove_absent_rejected(self) -> None:
        g = create_group("g", [_member("alice")])
        with pytest.raises(GroupError):
            remove_member(g, _member("ghost").code)

    def test_add_over_capacity_rejected(self) -> None:
        g = create_group("g", [_member(f"m{i}") for i in range(GROUP_MAX_MEMBERS - 1)])
        with pytest.raises(GroupError):
            add_member(g, _member("one-too-many"))

    def test_to_from_dict_roundtrip(self) -> None:
        g = create_group("ops", [_member("alice"), _member("bob")])
        restored = GroupState.from_dict(g.to_dict())
        assert restored.group_id.raw == g.group_id.raw
        assert restored.name == g.name
        assert restored.member_codes() == g.member_codes()


class TestMembershipChange:
    def test_sign_and_verify(self) -> None:
        author = Identity.generate()
        g = create_group("g", [_member("alice")])
        target = _member("bob")
        change = make_membership_change(author, g, ACTION_ADD, target)
        assert change.action == ACTION_ADD
        assert change.author_code == author.contact_code()
        assert verify_membership_change(change)

    def test_tampered_change_fails_verification(self) -> None:
        author = Identity.generate()
        g = create_group("g", [_member("alice")])
        change = make_membership_change(author, g, ACTION_REMOVE, _member("bob"))
        # Flip the action — signature no longer covers the payload.
        forged = type(change)(
            action=ACTION_ADD,
            group_id=change.group_id,
            target=change.target,
            author_code=change.author_code,
            author_verify_key=change.author_verify_key,
            timestamp=change.timestamp,
            signature=change.signature,
        )
        assert not verify_membership_change(forged)

    def test_bytes_roundtrip_preserves_signature(self) -> None:
        author = Identity.generate()
        g = create_group("g", [_member("alice")])
        change = make_membership_change(author, g, ACTION_ADD, _member("bob"))
        restored = type(change).from_bytes(change.to_bytes())
        assert restored.signature == change.signature
        assert verify_membership_change(restored)

    def test_apply_is_idempotent(self) -> None:
        author = Identity.generate()
        g = create_group("g", [_member("alice")])
        bob = _member("bob")
        change = make_membership_change(author, g, ACTION_ADD, bob)
        apply_membership_change(g, change)
        apply_membership_change(g, change)  # twice — must not double-add
        assert sum(1 for m in g.members if m.code == bob.code) == 1
        rm = make_membership_change(author, g, ACTION_REMOVE, bob)
        apply_membership_change(g, rm)
        apply_membership_change(g, rm)
        assert not g.has_member(bob.code)


class TestGroupPayloadFraming:
    def test_pack_unpack_text(self) -> None:
        gid = GroupId.generate()
        blob = pack_group_payload(gid, KIND_TEXT, b"hello group")
        out = unpack_group_payload(blob)
        assert out is not None
        out_id, kind, body = out
        assert out_id.raw == gid.raw
        assert kind == KIND_TEXT
        assert body == b"hello group"

    def test_pack_unpack_membership(self) -> None:
        gid = GroupId.generate()
        blob = pack_group_payload(gid, KIND_MEMBERSHIP, b"\x00\x01")
        out = unpack_group_payload(blob)
        assert out is not None
        assert out[1] == KIND_MEMBERSHIP

    def test_plain_1to1_message_is_not_a_group_payload(self) -> None:
        # An ordinary 1:1 plaintext (no frame marker) must not parse as a group
        # payload — this is how a receiver tells the two apart on one ratchet.
        assert unpack_group_payload(b"just a normal message") is None

    def test_truncated_frame_returns_none(self) -> None:
        gid = GroupId.generate()
        blob = pack_group_payload(gid, KIND_TEXT, b"x")
        assert unpack_group_payload(blob[:10]) is None
