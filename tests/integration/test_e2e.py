"""
tests/integration/test_e2e.py — end-to-end encrypted message exchange

Spins up the DRIFT relay in-process, connects two Session instances as
Alice and Bob, and exercises Phase 1 rotating stealth addresses:
messages flow over a shared broadcast channel, each lands at a fresh
unlinkable one-time address, and the receiver detects its own messages
by scanning.

Requires the relay extras: pip install -e ".[dev]"
Run: pytest tests/integration/ -v
"""

from __future__ import annotations

import asyncio
import socket

import pytest
import uvicorn

import relay.server as relay_module
from drift.crypto import Identity, Keypair, encrypt
from drift.crypto.stealth import derive_one_time_address
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


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def relay_url() -> str:  # type: ignore[misc]
    """
    Spin up a fresh relay instance on a free port for the duration of a test.

    Clears module-level relay state before starting so tests are isolated
    even though _mailbox and _subscribers are global defaultdicts.
    """
    relay_module._mailbox.clear()
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
    """Alice sends a stealth-addressed message; Bob scans and decrypts it."""
    alice = Identity.generate()
    bob = Identity.generate()

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
    Both clients sit on the same broadcast channel, so each also sees its
    own outbound message — scanning must skip those and surface only the
    message actually addressed to it.
    """
    alice = Identity.generate()
    bob = Identity.generate()

    async with (
        Session(alice, bob.contact_code(), relay_url) as alice_session,
        Session(bob, alice.contact_code(), relay_url) as bob_session,
    ):
        await alice_session.send("ping")
        await bob_session.send("pong")

        alice_msgs = alice_session.messages()
        bob_msgs = bob_session.messages()

        bob_received = await asyncio.wait_for(bob_msgs.__anext__(), timeout=5.0)
        alice_received = await asyncio.wait_for(alice_msgs.__anext__(), timeout=5.0)

    assert bob_received == "ping"
    assert alice_received == "pong"


# ---------------------------------------------------------------------------
# Rotating addresses — the Phase 1 property
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_messages_use_rotating_addresses(relay_url: str) -> None:
    """
    Two messages to the same contact must land at two distinct one-time
    addresses with distinct ephemeral keys — unlinkable on the wire — yet
    both decrypt correctly for the recipient.
    """
    alice = Identity.generate()
    bob = Identity.generate()

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
        assert env1.one_time_addr != env2.one_time_addr
        assert env1.ephemeral_pub != env2.ephemeral_pub
        # Both still route to the shared channel — the relay learns nothing else.
        assert env1.to == STEALTH_CHANNEL == env2.to

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
    alice = Identity.generate()
    bob = Identity.generate()
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
# Integrity — tampered ciphertext for a genuinely-ours address
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tampered_ciphertext_raises_invalid_tag(relay_url: str) -> None:
    """
    An envelope correctly addressed to Bob (his scan matches) but carrying
    corrupt ciphertext must raise InvalidTag on receive — a tampered
    message is rejected, never silently dropped.
    """
    from cryptography.exceptions import InvalidTag

    bob = Identity.generate()
    alice = Identity.generate()

    # Derive a valid one-time address for Bob so his scan succeeds...
    ephemeral = Keypair.generate()
    one_time_addr, key = derive_one_time_address(
        ephemeral.private_bytes(),
        bob.scan_keypair.public_bytes(),
        bob.spend_keypair.public_bytes(),
    )
    # ...but corrupt the ciphertext after encryption.
    corrupt = bytearray(encrypt(key, b"surprise"))
    corrupt[-1] ^= 0xFF  # flip a bit in the auth tag

    async with Session(bob, alice.contact_code(), relay_url) as bob_session:
        injector = RelayClient(relay_url, "injector")
        async with injector:
            await injector.send(
                Envelope(
                    to=STEALTH_CHANNEL,
                    ciphertext=bytes(corrupt),
                    ephemeral_pub=ephemeral.public_bytes(),
                    one_time_addr=one_time_addr,
                )
            )

            bob_msgs = bob_session.messages()
            with pytest.raises(InvalidTag):
                await asyncio.wait_for(bob_msgs.__anext__(), timeout=5.0)
