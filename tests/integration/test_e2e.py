"""
tests/integration/test_e2e.py — end-to-end encrypted message exchange

Spins up the DRIFT relay in-process, connects two Session instances as
Alice and Bob, sends a message from Alice, and asserts Bob receives the
correct plaintext.

Requires the relay extras: pip install -e ".[dev]"
Run: pytest tests/integration/ -v
"""

from __future__ import annotations

import asyncio
import socket

import pytest
import uvicorn

import relay.server as relay_module
from relay.server import app as relay_app
from drift.crypto import Identity
from drift.transport.session import Session


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
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_alice_sends_bob_receives(relay_url: str) -> None:
    """Alice encrypts a message; Bob decrypts the correct plaintext."""
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
    """Alice and Bob can each send and receive a message."""
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


@pytest.mark.asyncio
async def test_tampered_ciphertext_raises_invalid_tag(relay_url: str) -> None:
    """Injecting garbage ciphertext to a session raises InvalidTag on receive."""
    import base64

    import httpx
    from cryptography.exceptions import InvalidTag

    bob = Identity.generate()
    alice = Identity.generate()

    async with Session(bob, alice.contact_code(), relay_url) as bob_session:
        # Post garbage ciphertext directly to the relay targeting Bob's listen address.
        # 24 bytes (nonce-sized header) + 40 bytes of zeros → auth tag mismatch.
        bob_addr = bob.spend_keypair.public_b58()
        http_url = relay_url.replace("ws://", "http://")
        async with httpx.AsyncClient() as http:
            await http.post(
                f"{http_url}/send",
                json={"to": bob_addr, "ct": base64.b64encode(b"\x00" * 64).decode(), "ts": 0},
            )

        bob_msgs = bob_session.messages()
        with pytest.raises(InvalidTag):
            await asyncio.wait_for(bob_msgs.__anext__(), timeout=5.0)
