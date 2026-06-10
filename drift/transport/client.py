"""
drift.transport.client — async WebSocket client for the DRIFT relay.

Responsibilities
----------------
- Subscribe to the relay for incoming message envelopes (WebSocket).
- POST outgoing envelopes to the relay's HTTP /send endpoint.
- Queue arriving envelopes for the caller to consume via receive().
- Keep the relay connection alive with periodic pings.

This layer knows nothing about crypto. It moves bytes. Encoding
(base64) lives here because JSON can't carry raw bytes — it is NOT
a crypto concern, just a serialisation detail.

Wire format (Phase 0)
---------------------
{ "to": "<addr>", "ct": "<base64>", "ts": <unix_int> }

Phase 3 upgrade point: route self._http and the WS connection through
Tor (via a SOCKS proxy) without touching any other module.
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
from dataclasses import dataclass, field
from typing import Any

import httpx
import websockets
from websockets.exceptions import ConnectionClosed


class RelayError(Exception):
    """Raised when the relay rejects a request or the connection is lost."""


@dataclass
class Envelope:
    """
    A message blob as seen by the transport layer.

    ``ciphertext`` is opaque bytes — the transport layer base64-encodes
    them for JSON transit and decodes them on receipt.  Nothing here
    knows what the bytes contain.

    Phase 1 stealth-address fields (both optional, opaque to transport):
      ``ephemeral_pub``  — the sender's one-time public key R
      ``one_time_addr``  — the derived one-time address A_once

    Both are carried verbatim so the receiver can scan for messages
    addressed to it. The transport layer never interprets them.
    """

    to: str            # destination/routing key — opaque to transport
    ciphertext: bytes  # encrypted payload — opaque to transport
    timestamp: int = field(default_factory=lambda: int(time.time()))
    ephemeral_pub: bytes | None = None  # R — stealth ephemeral public key
    one_time_addr: bytes | None = None  # A_once — stealth one-time address


class RelayClient:
    """
    Async client for the DRIFT reference relay.

    Typical usage::

        async with RelayClient("ws://localhost:8765", my_addr) as client:
            # Send a blob to a peer
            await client.send(Envelope(to=their_addr, ciphertext=ct))

            # Block until a message arrives (or connection drops)
            envelope = await client.receive()

    ``relay_url`` is the WebSocket base URL (``ws://…`` or ``wss://…``).
    The HTTP base URL is derived automatically.
    """

    def __init__(
        self,
        relay_url: str,
        listen_addr: str,
        *,
        ping_interval: float = 30.0,
    ) -> None:
        self._ws_url = f"{relay_url}/ws/{listen_addr}"
        self._http_base = relay_url.replace("ws://", "http://").replace("wss://", "https://")
        self._ping_interval = ping_interval

        self._ws: Any = None
        self._http: httpx.AsyncClient | None = None
        # None sentinel signals a clean disconnect to receive()
        self._queue: asyncio.Queue[Envelope | None] = asyncio.Queue()
        self._listener: asyncio.Task[None] | None = None
        self._pinger: asyncio.Task[None] | None = None
        self._connected = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Open the WebSocket subscription and start background tasks."""
        self._http = httpx.AsyncClient()
        try:
            self._ws = await websockets.connect(self._ws_url)
        except Exception as exc:
            await self._http.aclose()
            self._http = None
            raise RelayError(f"could not connect to relay at {self._ws_url}: {exc}") from exc

        self._connected = True
        self._listener = asyncio.create_task(self._listen(), name="relay-listener")
        self._pinger = asyncio.create_task(self._keepalive(), name="relay-pinger")

    async def close(self) -> None:
        """Cancel background tasks and close connections."""
        self._connected = False
        for task in (self._pinger, self._listener):
            if task and not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        if self._ws is not None:
            await self._ws.close()
            self._ws = None
        if self._http is not None:
            await self._http.aclose()
            self._http = None

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def send(self, envelope: Envelope) -> None:
        """
        POST an envelope to the relay.

        Raises ``RelayError`` if the HTTP request fails or the relay
        returns a non-OK response.
        """
        if self._http is None:
            raise RelayError("not connected — call connect() first")
        payload: dict[str, Any] = {
            "to": envelope.to,
            "ct": base64.b64encode(envelope.ciphertext).decode(),
            "ts": envelope.timestamp,
        }
        # Phase 1: carry stealth-address fields when present.
        if envelope.ephemeral_pub is not None:
            payload["R"] = base64.b64encode(envelope.ephemeral_pub).decode()
        if envelope.one_time_addr is not None:
            payload["addr"] = base64.b64encode(envelope.one_time_addr).decode()
        try:
            resp = await self._http.post(f"{self._http_base}/send", json=payload)
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise RelayError(f"send failed: {exc}") from exc
        data = resp.json()
        if not data.get("ok"):
            raise RelayError(f"relay rejected envelope: {data}")

    async def receive(self) -> Envelope:
        """
        Block until the next message envelope arrives.

        Raises ``RelayError`` if the relay connection has been closed.
        """
        if not self._connected and self._queue.empty():
            raise RelayError("not connected — call connect() first")
        item = await self._queue.get()
        if item is None:
            raise RelayError("relay connection closed")
        return item

    # ------------------------------------------------------------------
    # Async context manager
    # ------------------------------------------------------------------

    async def __aenter__(self) -> RelayClient:
        await self.connect()
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()

    # ------------------------------------------------------------------
    # Async iterator — yields envelopes until disconnect
    # ------------------------------------------------------------------

    def __aiter__(self) -> RelayClient:
        return self

    async def __anext__(self) -> Envelope:
        try:
            return await self.receive()
        except RelayError as exc:
            raise StopAsyncIteration from exc

    # ------------------------------------------------------------------
    # Background tasks (private)
    # ------------------------------------------------------------------

    async def _listen(self) -> None:
        """Read relay-pushed envelopes from the WebSocket and queue them."""
        try:
            async for raw in self._ws:
                if not isinstance(raw, str):
                    continue
                try:
                    msg = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                # Skip relay control frames (pong, error) and anything without ct
                if "ct" not in msg or msg.get("type"):
                    continue
                try:
                    ciphertext = base64.b64decode(msg["ct"])
                    # Phase 1 stealth fields are optional; decode when present.
                    ephemeral_pub = base64.b64decode(msg["R"]) if "R" in msg else None
                    one_time_addr = base64.b64decode(msg["addr"]) if "addr" in msg else None
                except ValueError:
                    continue
                await self._queue.put(
                    Envelope(
                        to=msg.get("to", ""),
                        ciphertext=ciphertext,
                        timestamp=int(msg.get("ts", 0)),
                        ephemeral_pub=ephemeral_pub,
                        one_time_addr=one_time_addr,
                    )
                )
        except (ConnectionClosed, asyncio.CancelledError):
            pass
        finally:
            # Signal any blocked receive() that the connection is gone
            await self._queue.put(None)

    async def _keepalive(self) -> None:
        """Send periodic pings so the relay WebSocket loop stays unblocked."""
        try:
            while True:
                await asyncio.sleep(self._ping_interval)
                if self._ws is not None:
                    await self._ws.send(json.dumps({"type": "ping"}))
        except (ConnectionClosed, asyncio.CancelledError):
            pass
