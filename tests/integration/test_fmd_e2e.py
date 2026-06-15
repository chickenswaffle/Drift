"""
tests/integration/test_fmd_e2e.py — FMD relay pre-filtering, end to end (audit M4)

Spins up the real relay and confirms an FMD-subscribed client receives:
  - true positives (envelopes flagged for it),
  - unflagged traffic (fail-open — FMD never drops a possible message),
but NOT envelopes flagged for someone else (filtered, here at a 2^-10 rate so
the assertion is deterministic in practice).

A classic subscriber (no FMD key) still receives the whole firehose — proving
FMD is opt-in and the default path is unchanged.
"""

from __future__ import annotations

import asyncio
import os
import socket

import pytest
import uvicorn

import relay.server as relay_module
from drift.crypto import Identity
from drift.crypto.fmd import fmd_flag
from drift.transport.client import Envelope, RelayClient
from drift.transport.session import STEALTH_CHANNEL
from relay.server import app as relay_app


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
async def relay_url() -> str:  # type: ignore[misc]
    relay_module._recent.clear()
    relay_module._subscribers.clear()
    relay_module._fmd_filters.clear()
    port = _free_port()
    config = uvicorn.Config(relay_app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
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


async def _collect(client: RelayClient, timeout: float = 1.0) -> set[bytes]:
    """Drain one-time addresses the client receives until it goes quiet."""
    addrs: set[bytes] = set()
    it = client.__aiter__()
    try:
        while True:
            item = await asyncio.wait_for(it.__anext__(), timeout=timeout)
            if isinstance(item, Envelope) and item.one_time_addr is not None:
                addrs.add(item.one_time_addr)
    except (TimeoutError, StopAsyncIteration):
        pass
    return addrs


@pytest.mark.asyncio
async def test_relay_prefilters_for_fmd_subscriber(relay_url: str) -> None:
    me = Identity.generate()
    key = me.fmd_keypair(10)  # 2^-10 → flagged-for-others reliably filtered out

    # An FMD subscriber hands the relay its detection sub-keys.
    sub = RelayClient(relay_url, STEALTH_CHANNEL, fmd_secret_keys=key.secret_keys)
    sender = RelayClient(relay_url, STEALTH_CHANNEL)
    await sub.connect()
    await sender.connect()
    # Let the relay process the FMD subscribe frame before any traffic flows.
    await asyncio.sleep(0.4)

    try:
        addr_true = os.urandom(32)   # flagged for me → must arrive
        addr_other = os.urandom(32)  # flagged for a stranger → must be filtered
        addr_plain = os.urandom(32)  # unflagged → fail-open, must arrive
        stranger = Identity.generate().fmd_keypair(10)

        await sender.send(Envelope(
            to=STEALTH_CHANNEL, ciphertext=b"t",
            one_time_addr=addr_true, fmd_flag=fmd_flag(addr_true, key.public_keys),
        ))
        await sender.send(Envelope(
            to=STEALTH_CHANNEL, ciphertext=b"o",
            one_time_addr=addr_other, fmd_flag=fmd_flag(addr_other, stranger.public_keys),
        ))
        await sender.send(Envelope(
            to=STEALTH_CHANNEL, ciphertext=b"p", one_time_addr=addr_plain,
        ))

        got = await _collect(sub)
        assert addr_true in got    # true positive forwarded
        assert addr_plain in got   # unflagged → fail-open
        assert addr_other not in got  # flagged for someone else → pre-filtered out
    finally:
        await sub.close()
        await sender.close()


@pytest.mark.asyncio
async def test_classic_subscriber_still_gets_everything(relay_url: str) -> None:
    # No FMD key → the relay forwards the whole firehose, exactly as before.
    classic = RelayClient(relay_url, STEALTH_CHANNEL)
    sender = RelayClient(relay_url, STEALTH_CHANNEL)
    await classic.connect()
    await sender.connect()
    await asyncio.sleep(0.2)
    try:
        stranger = Identity.generate().fmd_keypair(10)
        addr_flagged = os.urandom(32)
        addr_plain = os.urandom(32)
        await sender.send(Envelope(
            to=STEALTH_CHANNEL, ciphertext=b"f",
            one_time_addr=addr_flagged, fmd_flag=fmd_flag(addr_flagged, stranger.public_keys),
        ))
        await sender.send(Envelope(
            to=STEALTH_CHANNEL, ciphertext=b"p", one_time_addr=addr_plain,
        ))
        got = await _collect(classic)
        assert addr_flagged in got and addr_plain in got  # nothing filtered
    finally:
        await classic.close()
        await sender.close()
