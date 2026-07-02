"""
tests/integration/test_tor_socks_e2e.py — the Tor transport path, end to end

Proves the code DRIFT owns for Tor actually tunnels traffic: a real message
exchange and the beacon/invite HTTP both routed through a **real SOCKS5 proxy**
against the in-process relay. To our transport, a TorClient pointed at this
proxy is identical to one pointed at a live tor SocksPort — so this validates
open_socks_websocket (the Session's Tor path) and beacon_http's socks client
without depending on the Tor network being reachable from CI.

The proxy counts the bytes it forwards; the tests assert it was non-zero, so a
regression that silently bypassed the proxy (connecting direct) would fail
rather than pass.

Requires the relay + tor extras: pip install -e ".[dev,tor]"
Run: pytest tests/integration/test_tor_socks_e2e.py -v
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
from typing import Any

import pytest
import uvicorn

import relay.server as relay_module
from drift.crypto import Identity
from drift.crypto.beacon import create_beacon, lookup_hash, resolve_beacon
from drift.transport import beacon_http
from drift.transport.beacon_http import relay_http
from drift.transport.session import Session
from drift.transport.tor import TorClient


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class _Socks5Proxy:
    """A minimal real SOCKS5 CONNECT proxy (no auth). Counts forwarded bytes."""

    def __init__(self) -> None:
        self.forwarded = 0
        self.port = 0
        self._server: asyncio.AbstractServer | None = None

    async def start(self) -> None:
        self.port = _free_port()
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", self.port)

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await self._server.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            _ver, nmethods = await reader.readexactly(2)
            await reader.readexactly(nmethods)
            writer.write(b"\x05\x00")  # choose no-auth
            await writer.drain()

            _ver, _cmd, _rsv, atyp = await reader.readexactly(4)
            if atyp == 1:
                host = socket.inet_ntoa(await reader.readexactly(4))
            elif atyp == 3:
                ln = (await reader.readexactly(1))[0]
                host = (await reader.readexactly(ln)).decode()
            else:  # IPv6
                host = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
            port = int.from_bytes(await reader.readexactly(2), "big")

            up_r, up_w = await asyncio.open_connection(host, port)
            writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")  # success
            await writer.drain()
            await asyncio.gather(
                self._pump(reader, up_w), self._pump(up_r, writer),
            )
        except Exception:
            with contextlib.suppress(Exception):
                writer.close()

    async def _pump(self, r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        with contextlib.suppress(Exception):
            while (data := await r.read(65536)):
                self.forwarded += len(data)
                w.write(data)
                await w.drain()
        with contextlib.suppress(Exception):
            w.close()


@pytest.fixture
async def relay_url() -> Any:
    relay_module._recent.clear()
    relay_module._subscribers.clear()
    relay_module._prekeys.clear()
    relay_module._beacons.clear()
    port = _free_port()
    cfg = uvicorn.Config(relay_module.app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(cfg)
    task = asyncio.create_task(server.serve())
    for _ in range(100):
        if server.started:
            break
        await asyncio.sleep(0.05)
    else:
        server.should_exit = True
        await task
        raise RuntimeError("relay did not start")
    yield f"ws://127.0.0.1:{port}"
    server.should_exit = True
    await task


@pytest.fixture
async def proxy() -> Any:
    p = _Socks5Proxy()
    await p.start()
    yield p
    await p.stop()


def _tor_client(proxy: _Socks5Proxy) -> TorClient:
    # Indistinguishable, to our transport, from a live tor SocksPort.
    return TorClient(socks_host="127.0.0.1", socks_port=proxy.port, backend="mock", num_hops=3)


@pytest.mark.asyncio
async def test_session_message_routes_through_socks(relay_url: str, proxy: Any) -> None:
    """A full Session↔Session exchange (X3DH + ratchet + stealth) delivered
    through open_socks_websocket over a real SOCKS5 proxy."""
    a, b = Identity.generate(), Identity.generate()
    if a.spend_keypair.public_bytes() > b.spend_keypair.public_bytes():
        a, b = b, a
    tor = _tor_client(proxy)
    async with (
        Session(a, b.contact_code(), relay_url, tor_client=tor) as sa,
        Session(b, a.contact_code(), relay_url, tor_client=tor) as sb,
    ):
        await sa.send("routed over a real SOCKS5 proxy")
        msg = await asyncio.wait_for(sb.messages().__anext__(), timeout=10)
    assert msg == "routed over a real SOCKS5 proxy"
    assert proxy.forwarded > 0, "traffic bypassed the proxy — Tor path not wired"


@pytest.mark.asyncio
async def test_beacon_roundtrip_routes_through_socks(relay_url: str, proxy: Any) -> None:
    """The invite path (beacon_http fetch/post/get) rides the SOCKS proxy too —
    the leak we closed so enabling Tor doesn't expose the IP on invites."""
    idy = Identity.generate()
    http_base = relay_http(relay_url)
    socks = _tor_client(proxy).socks_proxy

    pk = await beacon_http.fetch_relay_pubkey(http_base, socks)
    assert pk is not None
    payload = create_beacon(idy, "ProofHandle", 300, pk)
    await beacon_http.post_beacon(http_base, payload, socks)
    got = await beacon_http.get_beacon(http_base, lookup_hash("ProofHandle", pk), socks)
    assert got is not None
    info = resolve_beacon("ProofHandle", got)
    assert info is not None and info.contact_code == idy.contact_code()
    assert proxy.forwarded > 0, "beacon traffic bypassed the proxy"
