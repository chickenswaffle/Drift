"""
tests/integration/test_e2e.py — end-to-end encrypted message exchange

Spins up the DRIFT relay in-process and drives full Session ↔ Session flow
through all three layers:

  Phase 1 — rotating stealth addresses (unlinkable one-time addressing)
  Phase 2 — Double Ratchet content encryption (forward secrecy)

Requires the relay extras: pip install -e ".[dev]"
Run: pytest tests/integration/ -v
"""

from __future__ import annotations

import asyncio
import json
import socket

import pytest
import uvicorn
import websockets

import relay.server as relay_module
from drift.crypto import Identity
from drift.transport.client import Envelope, RelayClient
from drift.transport.session import STEALTH_CHANNEL, Session
from relay.server import app as relay_app

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _free_port() -> int:
    """Bind to port 0 to let the OS pick a free port, then release it."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _alice_and_bob() -> tuple[Identity, Identity]:
    """
    Return (alice, bob) where alice is the ratchet *initiator* (lower static
    spend key). Only the initiator may send the first message, so tests that
    open with "alice sends" must guarantee alice holds that role.
    """
    a = Identity.generate()
    b = Identity.generate()
    if a.spend_keypair.public_bytes() > b.spend_keypair.public_bytes():
        a, b = b, a
    return a, b


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def relay_url() -> str:  # type: ignore[misc]
    """
    Spin up a fresh relay instance on a free port for the duration of a test.

    Clears module-level relay state before starting so tests are isolated
    even though _recent and _subscribers are global defaultdicts.
    """
    relay_module._recent.clear()
    relay_module._subscribers.clear()

    port = _free_port()
    config = uvicorn.Config(relay_app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)

    task = asyncio.create_task(server.serve())

    # Wait for the server to finish binding before yielding to the test.
    for _ in range(100):
        if server.started:
            break
        await asyncio.sleep(0.05)
    else:
        server.should_exit = True
        await task
        raise RuntimeError("relay did not start within 5 s")

    yield f"ws://127.0.0.1:{port}"

    server.should_exit = True
    await task


# ---------------------------------------------------------------------------
# Delivery
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_alice_sends_bob_receives(relay_url: str) -> None:
    """Alice sends; Bob scans, turns his ratchet, and decrypts."""
    alice, bob = _alice_and_bob()

    async with (
        Session(alice, bob.contact_code(), relay_url) as alice_session,
        Session(bob, alice.contact_code(), relay_url) as bob_session,
    ):
        await alice_session.send("hello from alice")

        bob_msgs = bob_session.messages()
        received = await asyncio.wait_for(bob_msgs.__anext__(), timeout=5.0)

    assert received == "hello from alice"


@pytest.mark.asyncio
async def test_bidirectional_exchange(relay_url: str) -> None:
    """
    Alice (initiator) opens; Bob can only reply after receiving her first
    message and turning his DH ratchet. Each side also sees its own outbound
    message on the shared channel and must skip it.
    """
    alice, bob = _alice_and_bob()

    async with (
        Session(alice, bob.contact_code(), relay_url) as alice_session,
        Session(bob, alice.contact_code(), relay_url) as bob_session,
    ):
        alice_msgs = alice_session.messages()
        bob_msgs = bob_session.messages()

        await alice_session.send("ping")
        assert await asyncio.wait_for(bob_msgs.__anext__(), timeout=5.0) == "ping"

        # Bob now has a sending chain and can reply.
        await bob_session.send("pong")
        assert await asyncio.wait_for(alice_msgs.__anext__(), timeout=5.0) == "pong"


@pytest.mark.asyncio
async def test_first_sender_may_be_key_order_responder(relay_url: str) -> None:
    """
    Regression for the handshake bug: whoever sends first becomes the ratchet
    initiator. The initiator used to be fixed by static-key comparison, so if
    the key-order *responder* opened the conversation, send() raised
    "no sending chain yet". Here the higher-key party deliberately speaks first
    — the case _alice_and_bob() (which always sorts the initiator first) hides.
    """
    a = Identity.generate()
    b = Identity.generate()
    # `first` is the party the OLD code treated as the responder (higher key).
    if a.spend_keypair.public_bytes() < b.spend_keypair.public_bytes():
        first, second = b, a
    else:
        first, second = a, b

    async with (
        Session(first, second.contact_code(), relay_url) as first_session,
        Session(second, first.contact_code(), relay_url) as second_session,
    ):
        second_msgs = second_session.messages()
        await first_session.send("responder speaks first")
        got = await asyncio.wait_for(second_msgs.__anext__(), timeout=5.0)
        assert got == "responder speaks first"

        # The other side can still reply once it has received and turned its ratchet.
        first_msgs = first_session.messages()
        await second_session.send("reply")
        assert await asyncio.wait_for(first_msgs.__anext__(), timeout=5.0) == "reply"


@pytest.mark.asyncio
async def test_many_messages_each_way(relay_url: str) -> None:
    """Ten messages each way, interleaved, all the way through the ratchet."""
    alice, bob = _alice_and_bob()

    async with (
        Session(alice, bob.contact_code(), relay_url) as alice_session,
        Session(bob, alice.contact_code(), relay_url) as bob_session,
    ):
        alice_msgs = alice_session.messages()
        bob_msgs = bob_session.messages()

        for i in range(10):
            await alice_session.send(f"a{i}")
            assert await asyncio.wait_for(bob_msgs.__anext__(), timeout=5.0) == f"a{i}"
            await bob_session.send(f"b{i}")
            assert await asyncio.wait_for(alice_msgs.__anext__(), timeout=5.0) == f"b{i}"


@pytest.mark.asyncio
async def test_late_joiner_receives_message_sent_before_connecting(relay_url: str) -> None:
    """
    Regression for the firehose offline-delivery bug: Alice sends *before* Bob
    has subscribed. Because the sender is itself a live subscriber, the relay's
    old delivered==0 mailbox never queued the message and Bob lost it forever.
    The replay buffer must hand the recent envelope to Bob when he connects.
    """
    alice, bob = _alice_and_bob()

    async with Session(alice, bob.contact_code(), relay_url) as alice_session:
        # Bob is NOT connected yet.
        await alice_session.send("are you there?")

        # Bob opens his session only now — and must still get the message.
        async with Session(bob, alice.contact_code(), relay_url) as bob_session:
            bob_msgs = bob_session.messages()
            got = await asyncio.wait_for(bob_msgs.__anext__(), timeout=5.0)
            assert got == "are you there?"


@pytest.mark.asyncio
async def test_replayed_envelope_is_deduped_not_double_delivered(relay_url: str) -> None:
    """
    The relay replays recent traffic to every new subscriber, so a reconnecting
    client can be handed an envelope it already processed. The session must drop
    the duplicate (by one-time address) rather than feed it to the ratchet a
    second time — which would advance past the key and raise a spurious
    InvalidTag. Here we deliver the *same* envelope twice and expect exactly one
    decrypted message, no error.
    """
    alice, bob = _alice_and_bob()
    observer = RelayClient(relay_url, STEALTH_CHANNEL)

    async with observer, Session(alice, bob.contact_code(), relay_url) as alice_session:
        await alice_session.send("once")
        captured = await asyncio.wait_for(observer.receive(), timeout=5.0)

    injector = RelayClient(relay_url, "injector")
    async with Session(bob, alice.contact_code(), relay_url) as bob_session, injector:
        env = Envelope(
            to=STEALTH_CHANNEL,
            ciphertext=captured.ciphertext,
            one_time_addr=captured.one_time_addr,
        )
        # Bob's own subscribe already replayed the genuine "once" from the
        # buffer; now inject a byte-identical duplicate.
        await injector.send(env)

        bob_msgs = bob_session.messages()
        assert await asyncio.wait_for(bob_msgs.__anext__(), timeout=5.0) == "once"
        # The duplicate must NOT yield a second message or raise.
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(bob_msgs.__anext__(), timeout=1.5)


# ---------------------------------------------------------------------------
# Rotating addresses — the Phase 1 property still holds under the ratchet
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_messages_use_rotating_addresses(relay_url: str) -> None:
    """
    Two messages must land at two distinct one-time addresses with distinct
    ephemeral keys — unlinkable on the wire — yet both decrypt in order.
    """
    alice, bob = _alice_and_bob()

    # A passive observer on the broadcast channel — stands in for the relay
    # operator, who must not be able to link the two messages.
    observer = RelayClient(relay_url, STEALTH_CHANNEL)

    async with (
        observer,
        Session(alice, bob.contact_code(), relay_url) as alice_session,
        Session(bob, alice.contact_code(), relay_url) as bob_session,
    ):
        await alice_session.send("first")
        await alice_session.send("second")

        # Capture both envelopes as the relay broadcasts them.
        env1 = await asyncio.wait_for(observer.receive(), timeout=5.0)
        env2 = await asyncio.wait_for(observer.receive(), timeout=5.0)

        # Wire-level unlinkability: different one-time address + ephemeral key.
        # Sealed sender — the ephemeral key now lives *inside* the opaque blob.
        from drift.crypto.sealed import parse as parse_sealed
        r1, sealed_hdr1, _ = parse_sealed(env1.ciphertext)
        r2, sealed_hdr2, _ = parse_sealed(env2.ciphertext)
        assert env1.one_time_addr != env2.one_time_addr
        assert r1 != r2                          # distinct per-message ephemeral keys
        assert env1.ciphertext != env2.ciphertext
        # Both still route to the shared channel — the relay learns nothing else.
        assert env1.to == STEALTH_CHANNEL == env2.to
        # The ratchet header is no longer a clear wire field — it is sealed
        # inside the blob, so the relay can't link a sender by their ratchet key.
        assert not hasattr(env1, "ratchet_header")
        assert sealed_hdr1 and sealed_hdr2

        # Despite rotation, Bob decrypts both in order.
        bob_msgs = bob_session.messages()
        got = [
            await asyncio.wait_for(bob_msgs.__anext__(), timeout=5.0),
            await asyncio.wait_for(bob_msgs.__anext__(), timeout=5.0),
        ]

    assert got == ["first", "second"]


@pytest.mark.asyncio
async def test_non_recipient_cannot_decrypt(relay_url: str) -> None:
    """
    A third party (Eve) on the same broadcast channel scans every envelope
    but never matches a message addressed to Bob — she sees only opaque
    traffic, never plaintext.
    """
    alice, bob = _alice_and_bob()
    eve = Identity.generate()

    async with (
        Session(alice, bob.contact_code(), relay_url) as alice_session,
        Session(bob, alice.contact_code(), relay_url) as bob_session,
        # Eve points her session at Bob's code, but scans with her own keys.
        Session(eve, bob.contact_code(), relay_url) as eve_session,
    ):
        await alice_session.send("for bob only")

        # Bob gets it.
        bob_msgs = bob_session.messages()
        assert await asyncio.wait_for(bob_msgs.__anext__(), timeout=5.0) == "for bob only"

        # Eve's scan never matches → her generator yields nothing in time.
        eve_msgs = eve_session.messages()
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(eve_msgs.__anext__(), timeout=1.0)


# ---------------------------------------------------------------------------
# Integrity — tampered ciphertext for a genuinely-ours message
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tampered_ciphertext_raises_invalid_tag(relay_url: str) -> None:
    """
    Capture a real Alice→Bob envelope, corrupt its ciphertext, and deliver it
    to Bob. His scan matches and his ratchet derives the right key, so the
    corruption is caught — InvalidTag, never a silent drop.
    """
    from cryptography.exceptions import InvalidTag

    alice, bob = _alice_and_bob()

    # Alice + a passive observer are connected; Bob is not yet. We capture the
    # real envelope, then clear the relay's replay buffer so a late-joining Bob
    # won't be handed the genuine copy — leaving the corrupted copy as the only
    # thing he scans.
    observer = RelayClient(relay_url, STEALTH_CHANNEL)
    async with observer, Session(alice, bob.contact_code(), relay_url) as alice_session:
        await alice_session.send("surprise")
        captured = await asyncio.wait_for(observer.receive(), timeout=5.0)

    # Drop the genuine envelope from the replay buffer; only the corrupt
    # injection below should reach Bob.
    relay_module._recent.clear()

    # Flip a bit in the trailing ratchet-content auth tag (the blob ends with
    # the ratchet ciphertext; R and the sealed header sit ahead of it, so the
    # scan still matches and the header still unseals — the corruption only
    # surfaces when the ratchet body is authenticated).
    corrupt = bytearray(captured.ciphertext)
    corrupt[-1] ^= 0xFF

    injector = RelayClient(relay_url, "injector")
    async with Session(bob, alice.contact_code(), relay_url) as bob_session, injector:
        await injector.send(
            Envelope(
                to=STEALTH_CHANNEL,
                ciphertext=bytes(corrupt),
                one_time_addr=captured.one_time_addr,
            )
        )

        bob_msgs = bob_session.messages()
        with pytest.raises(InvalidTag):
            await asyncio.wait_for(bob_msgs.__anext__(), timeout=5.0)


# ---------------------------------------------------------------------------
# Sealed sender (Phase 3b) — the relay sees no sender metadata
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_relay_sees_only_address_and_opaque_blob(relay_url: str) -> None:
    """
    A raw observer on the firehose (standing in for the relay operator) sees the
    exact JSON the relay broadcasts. Sealed sender guarantees it carries only the
    recipient's one-time address and an opaque ciphertext — never the sender's
    ephemeral key ("R") or the Double Ratchet header ("hdr"), which used to be in
    the clear and let the relay link a sender's messages.
    """
    alice, bob = _alice_and_bob()

    # Subscribe a raw websocket to the firehose *before* Alice sends.
    async with websockets.connect(f"{relay_url}/ws/{STEALTH_CHANNEL}") as raw:
        async with Session(alice, bob.contact_code(), relay_url) as alice_session:
            await alice_session.send("metadata?")

            # Read frames until the message envelope arrives (skip control frames).
            for _ in range(10):
                frame = json.loads(await asyncio.wait_for(raw.recv(), timeout=5.0))
                if "ct" in frame and not frame.get("type"):
                    break
            else:
                raise AssertionError("relay never broadcast the message envelope")

    # The relay forwards the one-time address (to route/detect) + opaque blob …
    assert "addr" in frame
    assert "ct" in frame
    # … and crucially NOT the sender's ephemeral key or ratchet header.
    assert "R" not in frame
    assert "hdr" not in frame

    # The plaintext is nowhere in the broadcast, and neither is any structured
    # sender metadata — just an opaque base64 blob.
    assert "metadata?" not in json.dumps(frame)
