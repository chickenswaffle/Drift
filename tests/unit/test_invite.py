"""
tests/unit/test_invite.py — disappearing contact codes (one-time invites)

Crypto-level tests for drift.crypto.invite: the driftinvite: format, handle
entropy, TTL ceiling, and round-trip resolution through the underlying beacon
construction. Pure crypto — no network (the one-time delete is transport
behavior, covered in the sidecar/e2e tests).

Run: pytest tests/unit/test_invite.py -v
"""

from __future__ import annotations

import time

import pytest

from drift.crypto import Identity, b58decode, b58encode
from drift.crypto.beacon import MAX_TTL_SECONDS, resolve_beacon
from drift.crypto.invite import (
    INVITE_HANDLE_BYTES,
    INVITE_MAX_TTL_SECONDS,
    INVITE_PREFIX,
    create_invite,
    encode_invite,
    is_invite_code,
    new_invite_handle,
    parse_invite,
)

_RELAY_PK = bytes(range(32))


class TestFormat:
    def test_roundtrip(self) -> None:
        handle = new_invite_handle()
        assert parse_invite(encode_invite(handle)) == handle

    def test_handle_is_128_bits(self) -> None:
        assert INVITE_HANDLE_BYTES == 16
        assert len(b58decode(new_invite_handle())) == 16

    def test_handles_are_unique(self) -> None:
        assert len({new_invite_handle() for _ in range(64)}) == 64

    def test_is_invite_code(self) -> None:
        assert is_invite_code(encode_invite(new_invite_handle()))
        assert is_invite_code("  driftinvite:abc  ")  # tolerant of whitespace
        assert not is_invite_code("drift:something")
        assert not is_invite_code("")

    def test_parse_rejects_wrong_prefix(self) -> None:
        with pytest.raises(ValueError):
            parse_invite("drift:notaninvite")

    def test_parse_rejects_bad_base58(self) -> None:
        with pytest.raises(ValueError):
            parse_invite(INVITE_PREFIX + "0OIl+/")  # not base58 alphabet

    def test_parse_rejects_short_handle(self) -> None:
        # A short handle would forfeit the grinding resistance that justifies
        # the long TTL — reject it outright.
        with pytest.raises(ValueError):
            parse_invite(INVITE_PREFIX + b58encode(b"short"))


class TestCreateInvite:
    def test_roundtrip_resolves(self) -> None:
        idy = Identity.generate()
        invite = create_invite(idy, 3600, _RELAY_PK)
        handle = parse_invite(invite.code)
        info = resolve_beacon(handle, invite.beacon.encrypted)
        assert info is not None
        assert info.contact_code == idy.contact_code()

    def test_wrong_handle_returns_none(self) -> None:
        idy = Identity.generate()
        invite = create_invite(idy, 3600, _RELAY_PK)
        assert resolve_beacon(new_invite_handle(), invite.beacon.encrypted) is None

    def test_expired_invite_returns_none(self) -> None:
        idy = Identity.generate()
        invite = create_invite(idy, 1, _RELAY_PK)
        handle = parse_invite(invite.code)
        # An expires_at in the past must resolve to None (same path as beacon).
        assert invite.beacon.expires_at <= int(time.time()) + 1
        time.sleep(1.1)
        assert resolve_beacon(handle, invite.beacon.encrypted) is None

    def test_ttl_clamped_to_invite_max(self) -> None:
        idy = Identity.generate()
        invite = create_invite(idy, INVITE_MAX_TTL_SECONDS + 999, _RELAY_PK)
        assert invite.beacon.ttl_seconds == INVITE_MAX_TTL_SECONDS

    def test_invite_ttl_may_exceed_human_handle_cap(self) -> None:
        # The whole point: a 128-bit handle may outlive beacon.MAX_TTL_SECONDS.
        idy = Identity.generate()
        invite = create_invite(idy, 4 * 3600, _RELAY_PK)
        assert invite.beacon.ttl_seconds == 4 * 3600 > MAX_TTL_SECONDS
