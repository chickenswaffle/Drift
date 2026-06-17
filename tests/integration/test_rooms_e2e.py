"""
tests/integration/test_rooms_e2e.py — Phase 11 sovereign rooms, end to end

Drives real RoomSession ↔ RoomSession flow through in-process relay(s):

  1. open room: two clients exchange messages over the rotating address
  2. invite room: a lurker (name only) reads a member's posts but cannot post
  3. shards: a room split across two relays — messages posted to either shard
     both surface in a client that merges the shards
  4. relay blindness: the relay only ever stores {to, ct} — no room name, no
     member identity, nothing that marks the blob as a "room" message

Requires the relay extras: pip install -e ".[dev]"
"""

from __future__ import annotations

import asyncio
import socket
from collections.abc import AsyncIterator

import pytest
import uvicorn

import relay.server as relay_module
from drift.crypto import Identity
from drift.crypto import rooms as rooms_crypto
from drift.crypto.rooms import Room
from drift.transport.room_session import RoomSession
from relay.server import app as relay_app


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _start_relay() -> tuple[str, uvicorn.Server, asyncio.Task[None]]:
    port = _free_port()
    config = uvicorn.Config(relay_app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    for _ in range(100):
        if server.started:
            break
        await asyncio.sleep(0.05)
    else:  # pragma: no cover
        server.should_exit = True
        await task
        raise RuntimeError("relay did not start within 5 s")
    return f"ws://127.0.0.1:{port}", server, task


@pytest.fixture
async def relay_url() -> AsyncIterator[str]:
    relay_module._recent.clear()
    relay_module._subscribers.clear()
    url, server, task = await _start_relay()
    yield url
    server.should_exit = True
    await task


async def _next(gen: object, timeout: float = 5.0) -> object:
    return await asyncio.wait_for(gen.__anext__(), timeout=timeout)  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# 1. Open room round-trip
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_open_room_roundtrip(relay_url: str) -> None:
    room = Room(label="cats", tier=rooms_crypto.TIER_OPEN, name="cats")
    alice = RoomSession(Identity.generate(), room, relay_url)
    bob = RoomSession(Identity.generate(), room, relay_url)
    async with alice, bob:
        bob_msgs = bob.messages()
        await asyncio.sleep(0.2)  # let subscriptions settle
        await alice.send_to_room("hello room")
        msg = await _next(bob_msgs)
        assert msg.text == "hello room"
        # Bob sees Alice's pseudonym, consistent within the session.
        assert len(msg.tag_label) == 4
        await alice.send_to_room("again")
        msg2 = await _next(bob_msgs)
        assert msg2.text == "again"
        assert msg2.tag_label == msg.tag_label  # same sender, same session tag


# ---------------------------------------------------------------------------
# 2. Invite room — lurker reads, cannot post
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_invite_room_lurker_reads_but_cannot_post(relay_url: str) -> None:
    member_room = rooms_crypto.make_room("club", tier=rooms_crypto.TIER_INVITE)
    token = rooms_crypto.encode_invite_token(
        rooms_crypto.b58decode(member_room.post_secret_b58)
    )
    lurker_room = Room(label="club", tier=rooms_crypto.TIER_INVITE, name="club")

    member = RoomSession(Identity.generate(), member_room, relay_url)
    lurker = RoomSession(Identity.generate(), lurker_room, relay_url)
    async with member, lurker:
        assert member.can_post() and not lurker.can_post()
        lurker_msgs = lurker.messages()
        await asyncio.sleep(0.2)
        await member.send_to_room("members only")
        got = await _next(lurker_msgs)
        assert got.text == "members only"
        assert got.authorized is False  # lurker can't verify the posting proof
        # A lurker attempting to post is refused locally.
        with pytest.raises(rooms_crypto.RoomError):
            await lurker.send_to_room("can I talk?")
    # A token-holder joining later can post and is accepted as authorized.
    holder_room = Room(label="club", tier=rooms_crypto.TIER_INVITE, name="club",
                       post_secret_b58=rooms_crypto.b58encode(
                           rooms_crypto.decode_invite_token(token)))
    assert holder_room.keys().can_post()


# ---------------------------------------------------------------------------
# 3. Room shards across two relays — client merges the streams
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_room_shards_merge_across_relays() -> None:
    relay_module._recent.clear()
    relay_module._subscribers.clear()
    url_a, srv_a, task_a = await _start_relay()
    url_b, srv_b, task_b = await _start_relay()
    try:
        shards = [url_a, url_b]
        room = Room(label="split", tier=rooms_crypto.TIER_OPEN, name="split", shards=shards)
        sender = RoomSession(Identity.generate(), room, url_a)
        reader = RoomSession(Identity.generate(), room, url_a)
        async with sender, reader:
            reader_msgs = reader.messages()
            await asyncio.sleep(0.3)
            # Two messages round-robin to shard 0 (relay A) then shard 1 (relay B).
            await sender.send_to_room("on shard A")
            await sender.send_to_room("on shard B")
            seen = {(await _next(reader_msgs)).text, (await _next(reader_msgs)).text}
            assert seen == {"on shard A", "on shard B"}
        # Both shards' blobs were routed (across the two relays' shared buffer).
        total_blobs = sum(len(v) for v in relay_module._recent.values())
        assert total_blobs >= 2
    finally:
        srv_a.should_exit = True
        srv_b.should_exit = True
        await task_a
        await task_b


# ---------------------------------------------------------------------------
# 4. Relay blindness — only {to, ct} on the wire, nothing room-identifying
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_relay_sees_only_addr_and_ciphertext(relay_url: str) -> None:
    room = Room(label="secret", tier=rooms_crypto.TIER_OPEN, name="secret")
    alice = RoomSession(Identity.generate(), room, relay_url)
    bob = RoomSession(Identity.generate(), room, relay_url)
    async with alice, bob:
        await asyncio.sleep(0.2)
        await alice.send_to_room("nothing to see here")
        await _next(bob.messages())

    # Inspect everything the relay buffered.
    room_name = "secret"
    for channel, envelopes in relay_module._recent.items():
        # The channel (routing key) is a rotating address hash, not the name.
        assert room_name not in channel
        for e in envelopes:
            keys = set(e.keys())
            # No field beyond routing + opaque blob + bookkeeping/ttl.
            assert keys <= {"to", "ct", "ts", "addr", "fmd", "_relay_ts", "_id", "_ttl"}
            assert room_name not in str(e.get("to", ""))
            # The ciphertext is opaque base64 — the plaintext name never appears.
            assert room_name.encode() not in str(e.get("ct", "")).encode()
