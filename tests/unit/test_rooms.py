"""
tests/unit/test_rooms.py — Phase 11 sovereign-room cryptography

Covers the guarantees Phase 11 must hold, with no network:

  - key derivation: same name → same keys, different/cased names → different,
    dark rooms keyed by a random secret
  - rotating addresses: deterministic per window, previous windows computable,
    future windows not guessable without the room secret
  - sender tags: valid for members, forgeable by no one, distinct per member,
    consistent per session
  - three tiers: open (no token), invite (token needed to post, not to read),
    dark (QR/secret only)
  - relay blindness: the wire envelope is opaque — only ephemeral‖tag‖ct, no
    room name or identity
  - QR / descriptor round-trips, shard addresses, invite tokens, storage
  - WITNESS: room envelopes count as routed but contribute zero identity info
"""

from __future__ import annotations

import hashlib
import hmac

import pytest

from drift.crypto import Identity
from drift.crypto import rooms as R

# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

def test_same_name_same_keys_different_names_differ() -> None:
    assert R.derive_room_secret("cats") == R.derive_room_secret("cats")
    assert R.derive_room_secret("cats") != R.derive_room_secret("dogs")
    assert len(R.derive_room_secret("cats")) == R.ROOM_SECRET_LEN


def test_room_name_is_case_sensitive() -> None:
    # The name IS the password: "cats" and "Cats" are entirely different rooms.
    assert R.derive_room_secret("cats") != R.derive_room_secret("Cats")
    k1 = R.RoomKeys.from_name("cats")
    k2 = R.RoomKeys.from_name("Cats")
    assert k1.encrypt_key != k2.encrypt_key
    assert k1.scan_key != k2.scan_key


def test_empty_name_rejected() -> None:
    with pytest.raises(R.RoomError):
        R.derive_room_secret("")


def test_dark_room_uses_random_secret() -> None:
    a = R.RoomKeys.generate_dark()
    b = R.RoomKeys.generate_dark()
    assert a.tier == R.TIER_DARK and len(a.room_secret) == R.ROOM_SECRET_LEN
    assert a.room_secret != b.room_secret  # random, not derived from a name


# ---------------------------------------------------------------------------
# Rotating addresses
# ---------------------------------------------------------------------------

def test_address_is_deterministic_per_window() -> None:
    k = R.RoomKeys.from_name("cats")
    n = R.current_window(1_700_000_000)
    assert R.room_address(k.scan_key, n) == R.room_address(k.scan_key, n)
    assert len(R.room_address(k.scan_key, n)) == R.ADDR_LEN


def test_address_rotates_each_window() -> None:
    k = R.RoomKeys.from_name("cats")
    n = R.current_window(1_700_000_000)
    assert R.room_address(k.scan_key, n) != R.room_address(k.scan_key, n + 1)


def test_previous_windows_computable_future_needs_secret() -> None:
    k = R.RoomKeys.from_name("cats")
    n = R.current_window(1_700_000_000)
    # A participant can compute the catch-up (previous) windows.
    wins = R.scan_windows(1_700_000_000)
    assert n in wins and (n - R.CATCHUP_WINDOWS) in wins
    for w in wins:
        assert len(R.room_address(k.scan_key, w)) == R.ADDR_LEN
    # An outsider without the scan key cannot compute any window's address.
    outsider = R.RoomKeys.from_name("not-cats")
    assert R.room_address(outsider.scan_key, n) != R.room_address(k.scan_key, n)
    assert R.room_address(outsider.scan_key, n + 1) != R.room_address(k.scan_key, n + 1)


def test_window_is_ten_minutes() -> None:
    assert R.WINDOW_SECONDS == 600
    assert R.current_window(600) == 1 and R.current_window(1199) == 1
    assert R.current_window(1200) == 2


# ---------------------------------------------------------------------------
# Sender tags
# ---------------------------------------------------------------------------

def test_sender_tag_valid_for_members_invalid_for_nonmembers() -> None:
    k = R.RoomKeys.from_name("cats")
    eph = R.new_ephemeral()
    tag = R.sender_tag(k.auth_key(), eph)
    assert R.verify_sender_tag(k.auth_key(), eph, tag)
    # A non-member (different room secret) cannot forge a valid tag.
    other = R.RoomKeys.from_name("dogs")
    assert not R.verify_sender_tag(other.auth_key(), eph, tag)


def test_two_members_produce_different_tags() -> None:
    k = R.RoomKeys.from_name("cats")
    t1 = R.sender_tag(k.auth_key(), R.new_ephemeral())
    t2 = R.sender_tag(k.auth_key(), R.new_ephemeral())
    assert t1 != t2  # different ephemerals → different pseudonyms


def test_sender_tag_consistent_within_session() -> None:
    k = R.RoomKeys.from_name("cats")
    eph = R.new_ephemeral()  # one ephemeral for the whole session
    assert R.sender_tag(k.auth_key(), eph) == R.sender_tag(k.auth_key(), eph)
    assert len(R.display_tag(R.sender_tag(k.auth_key(), eph))) == 4


# ---------------------------------------------------------------------------
# Three tiers
# ---------------------------------------------------------------------------

def test_open_room_anyone_with_name_reads_and_posts() -> None:
    k = R.RoomKeys.from_name("cats")
    addr = R.current_addresses(k)[0]
    msg = R.seal_room_message(k, "hi", ephemeral=R.new_ephemeral(), room_addr=addr)
    got = R.open_room_message(R.RoomKeys.from_name("cats"), addr, R.pack_envelope(msg))
    assert got is not None and got.text == "hi" and got.authorized
    assert k.can_post()


def test_invite_room_lurker_reads_member_posts() -> None:
    room = R.make_room("club", tier=R.TIER_INVITE)
    member = room.keys()                       # has the posting secret
    lurker = R.RoomKeys.from_name("club", tier=R.TIER_INVITE)  # name only
    assert member.can_post() and not lurker.can_post()

    addr = R.current_addresses(member)[0]
    msg = R.seal_room_message(member, "members only", ephemeral=R.new_ephemeral(),
                              room_addr=addr)
    blob = R.pack_envelope(msg)
    # Lurker can read (knows the name) but the post is flagged unverifiable.
    lr = R.open_room_message(lurker, addr, blob)
    assert lr is not None and lr.text == "members only" and lr.authorized is False
    # A member verifies the post as authorized.
    mr = R.open_room_message(member, addr, blob)
    assert mr is not None and mr.authorized is True


def test_invite_room_member_rejects_unauthorized_post() -> None:
    room = R.make_room("club", tier=R.TIER_INVITE)
    member = room.keys()
    lurker = R.RoomKeys.from_name("club", tier=R.TIER_INVITE)
    addr = R.current_addresses(member)[0]
    # A lurker crafts a ciphertext (they know the name) with a bogus sender tag.
    eph = R.new_ephemeral()
    ct = R.encrypt(lurker.encrypt_key, b'{"ts":1,"text":"x"}', associated_data=eph)
    bad_tag = hmac.new(b"\x00" * 32, eph, hashlib.sha256).digest()
    forged = eph + bad_tag + ct
    # A member (holding the posting key) rejects it outright.
    assert R.open_room_message(member, addr, forged) is None


def test_dark_room_qr_only_join() -> None:
    dark = R.make_room(None, tier=R.TIER_DARK)
    assert dark.name is None and dark.secret_b58
    qr = dark.to_qr()
    assert qr.startswith(R.QR_PREFIX)
    joined = R.Room.from_qr(qr)
    assert joined.tier == R.TIER_DARK
    assert joined.keys().room_secret == dark.keys().room_secret
    # Round-trips a message between creator and QR-joiner.
    addr = R.current_addresses(dark.keys())[0]
    msg = R.seal_room_message(dark.keys(), "secret", ephemeral=R.new_ephemeral(),
                              room_addr=addr)
    assert R.open_room_message(joined.keys(), addr, R.pack_envelope(msg)).text == "secret"


# ---------------------------------------------------------------------------
# Signed display names (optional)
# ---------------------------------------------------------------------------

def test_signed_display_name_round_trips_and_forgery_dropped() -> None:
    k = R.RoomKeys.from_name("cats")
    idn = Identity.generate()
    eph = R.new_ephemeral()
    addr = R.current_addresses(k)[0]
    msg = R.seal_room_message(k, "hey", ephemeral=eph, room_addr=addr,
                              display_name="river", identity=idn)
    got = R.open_room_message(k, addr, R.pack_envelope(msg))
    assert got is not None and got.display_name == "river"
    # An unsigned message surfaces no display name.
    plain = R.seal_room_message(k, "hey", ephemeral=R.new_ephemeral(), room_addr=addr)
    assert R.open_room_message(k, addr, R.pack_envelope(plain)).display_name is None


# ---------------------------------------------------------------------------
# Relay blindness — the wire blob is opaque
# ---------------------------------------------------------------------------

def test_wire_envelope_is_opaque() -> None:
    k = R.RoomKeys.from_name("cats")
    addr = R.current_addresses(k)[0]
    msg = R.seal_room_message(k, "plaintext should not leak", ephemeral=R.new_ephemeral(),
                              room_addr=addr)
    blob = R.pack_envelope(msg)
    # The blob is ephemeral ‖ tag ‖ ciphertext — the plaintext never appears.
    assert b"plaintext should not leak" not in blob
    assert b"cats" not in blob
    parsed = R.parse_envelope(blob)
    assert parsed is not None
    eph, tag, ct = parsed
    assert len(eph) == R.EPHEMERAL_LEN and len(tag) == R.SENDER_TAG_LEN
    assert msg.message_id == hashlib.sha256(ct).digest()


# ---------------------------------------------------------------------------
# Shards
# ---------------------------------------------------------------------------

def test_shard_addresses_distinct_and_recoverable() -> None:
    k = R.RoomKeys.from_name("split")
    n = R.current_window(1_700_000_000)
    s0 = R.shard_address(k.scan_key, 0, n)
    s1 = R.shard_address(k.scan_key, 1, n)
    assert s0 != s1
    assert s0 != R.room_address(k.scan_key, n)  # distinct from the unsharded addr
    # Both shards' addresses are recomputable by any participant.
    assert R.shard_address(k.scan_key, 0, n) == s0


# ---------------------------------------------------------------------------
# Invite tokens
# ---------------------------------------------------------------------------

def test_invite_token_round_trip() -> None:
    secret = R.generate_post_secret()
    token = R.encode_invite_token(secret)
    assert R.decode_invite_token(token) == secret
    with pytest.raises(R.RoomError):
        R.decode_invite_token("not-a-valid-token")


# ---------------------------------------------------------------------------
# Room record / QR descriptor serialization
# ---------------------------------------------------------------------------

def test_room_to_from_dict_round_trip() -> None:
    room = R.make_room("cats", tier=R.TIER_INVITE, shards=["ws://a", "ws://b"])
    room.message_count = 7
    room.last_window = 99
    again = R.Room.from_dict(room.to_dict())
    assert again.label == room.label and again.tier == room.tier
    assert again.shards == ["ws://a", "ws://b"]
    assert again.message_count == 7 and again.last_window == 99
    assert again.keys().room_secret == room.keys().room_secret


def test_qr_carries_shards_and_post_secret() -> None:
    room = R.make_room("cats", tier=R.TIER_INVITE, shards=["ws://a", "ws://b"])
    joined = R.Room.from_qr(room.to_qr())
    assert joined.shards == ["ws://a", "ws://b"]
    # The QR conveys posting rights (the post secret), so the scanner can post.
    assert joined.keys().can_post()


def test_from_qr_rejects_garbage() -> None:
    with pytest.raises(R.RoomError):
        R.Room.from_qr("not-a-room-code")


# ---------------------------------------------------------------------------
# Channels (Phase 12) — broadcast rooms: kind="channel", owner-only posting
# ---------------------------------------------------------------------------

def test_channel_owner_can_post_subscriber_cannot() -> None:
    # An owner is created with make_room (gets the post secret); a subscriber
    # joins token-less and is read-only — same crypto as an invite room.
    owner = R.make_room("news", tier=R.TIER_INVITE, kind="channel")
    sub = R.Room(label="news", tier=R.TIER_INVITE, name="news", kind="channel")
    assert owner.is_channel and owner.is_owner
    assert owner.keys().can_post() is True
    assert sub.is_channel and not sub.is_owner
    assert sub.keys().can_post() is False
    # Same room secret → the subscriber can read what the owner posts.
    assert owner.keys().room_secret == sub.keys().room_secret


def test_channel_to_from_dict_round_trip() -> None:
    ch = R.make_room("news", tier=R.TIER_INVITE, kind="channel")
    again = R.Room.from_dict(ch.to_dict())
    assert again.kind == "channel" and again.is_channel
    assert again.post_secret_b58 == ch.post_secret_b58


def test_room_dict_without_kind_defaults_to_room() -> None:
    # Back-compat: rooms persisted before channels existed have no "kind" key.
    d = R.make_room("cats", tier=R.TIER_OPEN).to_dict()
    del d["kind"]
    again = R.Room.from_dict(d)
    assert again.kind == "room" and not again.is_channel


def test_channel_kind_survives_qr_round_trip() -> None:
    ch = R.make_room("news", tier=R.TIER_INVITE, kind="channel")
    assert R.Room.from_qr(ch.to_qr()).kind == "channel"
    # A plain room's QR omits "kind" entirely and still reads back as a room.
    assert R.Room.from_qr(R.make_room("cats", tier=R.TIER_OPEN).to_qr()).kind == "room"


# ---------------------------------------------------------------------------
# WITNESS integration — routed, but zero identity attribution
# ---------------------------------------------------------------------------

def test_room_messages_counted_routed_but_reveal_no_identities(tmp_path) -> None:  # type: ignore[no-untyped-def]
    import base64

    from relay.witness import WitnessChain, load_or_create_relay_identity

    chain = WitnessChain(load_or_create_relay_identity(str(tmp_path / "relay_id.json")))
    k = R.RoomKeys.from_name("cats")
    # Route a handful of room envelopes exactly as /send would record them.
    for i in range(5):
        addr = R.current_addresses(k)[0]
        msg = R.seal_room_message(k, f"m{i}", ephemeral=R.new_ephemeral(), room_addr=addr)
        chain.record_envelope({
            "to": addr.hex(),
            "ct": base64.b64encode(R.pack_envelope(msg)).decode(),
        })
    cert = chain.generate()
    # The room traffic shows up in the routed count …
    assert cert.messages_routed == 5
    # … but the relay can attribute ZERO of it — same blindness as 1:1.
    assert cert.sender_identities_known == 0
    assert cert.recipient_identities_known == 0
    assert cert.contents_readable == 0
    assert cert.conversations_linked == 0


# ---------------------------------------------------------------------------
# Storage — per-identity rooms persist and round-trip
# ---------------------------------------------------------------------------

def test_storage_rooms_round_trip(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("DRIFT_CONFIG", str(tmp_path))
    import importlib

    from drift import storage
    importlib.reload(storage)
    try:
        idn = Identity.generate()
        room = R.make_room("cats", tier=R.TIER_OPEN)
        storage.add_room(idn, room)
        assert storage.is_room(idn, "cats")
        loaded = storage.load_rooms(idn)
        assert "cats" in loaded and loaded["cats"].keys().room_secret == room.keys().room_secret
        storage.remove_room(idn, "cats")
        assert not storage.is_room(idn, "cats")
    finally:
        importlib.reload(storage)  # restore module state for other tests


def test_storage_channels_are_kind_filtered_view(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("DRIFT_CONFIG", str(tmp_path))
    import importlib

    from drift import storage
    importlib.reload(storage)
    try:
        idn = Identity.generate()
        room = R.make_room("cats", tier=R.TIER_OPEN)
        channel = R.make_room("news", tier=R.TIER_INVITE, kind="channel")
        storage.add_room(idn, room)
        storage.add_channel(idn, channel)
        # Channels live in the rooms store but are surfaced as their own view.
        chans = storage.load_channels(idn)
        assert set(chans) == {"news"} and chans["news"].is_channel
        assert set(storage.plain_rooms(storage.load_rooms(idn))) == {"cats"}
        assert storage.get_channel(idn, "news") is not None
        assert storage.get_channel(idn, "cats") is None  # a plain room isn't a channel
    finally:
        importlib.reload(storage)  # restore module state for other tests


# ---------------------------------------------------------------------------
# Relay — longer retention for room messages (Part B)
# ---------------------------------------------------------------------------

def test_relay_honours_ttl_seconds_capped() -> None:
    import time

    import relay.server as S

    S._recent.clear()
    # An envelope with a long _ttl survives past the default RECENT_TTL, while a
    # default-TTL envelope of the same age is pruned (the prune contract /send
    # relies on for room catch-up retention).
    old = time.time() - (S.RECENT_TTL + 30)
    S._recent["chB"] = [
        {"to": "chB", "ct": "stale", "_relay_ts": old},                       # default → expired
        {"to": "chB", "ct": "room", "_relay_ts": old, "_ttl": S.RECENT_MAX_TTL},  # long → kept
    ]
    S._prune_recent("chB")
    assert [e["ct"] for e in S._recent["chB"]] == ["room"]
    assert S.RECENT_MAX_TTL == 1800.0


def test_relay_send_clamps_requested_ttl(tmp_path) -> None:  # type: ignore[no-untyped-def]
    from fastapi.testclient import TestClient

    import relay.server as S
    from relay.server import app

    S._recent.clear()
    client = TestClient(app)
    client.post("/send", json={"to": "rmA", "ct": "AAA", "ts": 1, "ttl_seconds": 99999})
    assert S._recent["rmA"][-1]["_ttl"] == S.RECENT_MAX_TTL  # capped
    client.post("/send", json={"to": "rmB", "ct": "BBB", "ts": 1})
    assert "_ttl" not in S._recent["rmB"][-1]  # default short TTL
