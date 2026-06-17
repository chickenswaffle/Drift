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

Phase 3 (Tor): pass ``socks_proxy=(host, port)`` and both the WebSocket
subscription and the HTTP /send + /burn calls route through that SOCKS5
proxy — i.e. through a Tor circuit. Nothing above this layer changes; the
bytes are identical, they just travel anonymised. The proxy is opaque here:
this module does not start Tor, it only dials through whatever SOCKS5
endpoint it is handed (see drift.transport.tor).
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
from dataclasses import dataclass, field
from typing import Any, NamedTuple

import httpx
import websockets
from websockets.exceptions import ConnectionClosed


def _ws_to_http(url: str) -> str:
    """ws:// → http://, wss:// → https:// (the relay's HTTP base)."""
    return url.replace("wss://", "https://", 1).replace("ws://", "http://", 1)


def _http_to_ws(url: str) -> str:
    """http:// → ws://, https:// → wss:// (a federation peer's WS base)."""
    return url.replace("https://", "wss://", 1).replace("http://", "ws://", 1).rstrip("/")


class RelayError(Exception):
    """Raised when the relay rejects a request or the connection is lost."""


class BurnFrame(NamedTuple):
    """A burn tombstone received from the relay via WebSocket."""
    scope: str                # "message" or "conversation"
    message_id: str | None    # base64 one-time addr for message scope; None otherwise
    token: str | None         # HMAC-SHA256 hex token — clients verify before honouring


@dataclass
class Envelope:
    """
    A message blob as seen by the transport layer.

    ``ciphertext`` is opaque bytes — the transport layer base64-encodes them for
    JSON transit and decodes them on receipt. Nothing here knows what the bytes
    contain.

    Phase 3b (sealed sender): the *only* metadata the relay sees besides the
    opaque ciphertext is the recipient's one-time stealth address, used to detect
    and route the message. The sender's ephemeral key and the Double Ratchet
    header — which previously rode in the clear and let the relay link a sender's
    messages — are now sealed *inside* ``ciphertext`` by the session layer (see
    drift.crypto.sealed). The transport layer never interprets any of it.

      ``one_time_addr`` — A_once, the recipient's one-time stealth address
    """

    to: str            # destination/routing key — opaque to transport
    ciphertext: bytes  # opaque sealed blob — R || sealed_header || content (Phase 3b)
    timestamp: int = field(default_factory=lambda: int(time.time()))
    one_time_addr: bytes | None = None    # A_once — recipient one-time stealth address
    # Optional FMD detection flag (audit M4). Present only when the recipient has
    # published an FMD detection key; bound to ``one_time_addr``. Lets an
    # FMD-subscribed relay pre-filter the firehose. Absent → unchanged behaviour.
    fmd_flag: bytes | None = None
    # Optional longer replay retention (Phase 11 rooms). When set, asks the relay
    # to keep this blob in its replay buffer for up to this many seconds (capped
    # server-side) so a client joining a room can rewind the catch-up windows.
    # Absent → the relay's default short TTL. The relay learns nothing from this
    # beyond "keep this one blob a little longer".
    ttl_seconds: int | None = None


class RelayClient:
    """
    Async client for the DRIFT reference relay.

    Typical usage::

        async with RelayClient("ws://localhost:8765", my_addr) as client:
            # Send a blob to a peer
            await client.send(Envelope(to=their_addr, ciphertext=ct))

            # Block until a message arrives (or connection drops)
            envelope = await client.receive()

    ``relay_url`` is the WebSocket base URL (``ws://…`` or ``wss://…``). It may
    be a comma-separated list of relays (Phase 4 federation): the client tries
    them in order on connect and, if the active relay drops mid-conversation,
    automatically fails over to the next. After connecting it also fetches the
    relay's federation peer list and folds those in as extra failover targets,
    so the mesh keeps you online even as individual nodes come and go.

    The HTTP base URL is derived automatically from whichever relay is active.
    """

    def __init__(
        self,
        relay_url: str,
        listen_addr: str,
        *,
        ping_interval: float = 30.0,
        socks_proxy: tuple[str, int] | None = None,
        fmd_secret_keys: list[bytes] | None = None,
    ) -> None:
        # A relay list (Phase 4). A single URL is just a one-element list, so the
        # non-federated path is unchanged. Trailing slashes are trimmed so the
        # derived ws/http URLs are well-formed.
        self._relays: list[str] = [
            u.strip().rstrip("/") for u in relay_url.split(",") if u.strip()
        ]
        if not self._relays:
            raise RelayError("no relay URL provided")
        self._listen_addr = listen_addr
        self._active_idx = 0
        self._ping_interval = ping_interval
        # Optional SOCKS5 proxy (host, port) — when set, every WS/HTTP byte is
        # routed through it (Phase 3: a Tor circuit). None → direct connect.
        self._socks_proxy = socks_proxy
        # Optional FMD detection secret sub-keys (audit M4). When set, we ask the
        # relay to pre-filter the firehose to flags that match this key (+ its
        # 2^-k false positives). None → we scan everything ourselves (unchanged).
        self._fmd_secret_keys = fmd_secret_keys

        self._ws: Any = None
        self._http: httpx.AsyncClient | None = None
        # None sentinel signals a disconnect to receive()
        self._queue: asyncio.Queue[Envelope | BurnFrame | None] = asyncio.Queue()
        self._listener: asyncio.Task[None] | None = None
        self._pinger: asyncio.Task[None] | None = None
        self._connected = False
        # Set by close(): suppresses failover on a *deliberate* shutdown so a
        # clean close still surfaces as "connection closed", not a reconnect.
        self._closing = False

    # -- active-relay derived URLs --------------------------------------

    @property
    def _active_relay(self) -> str:
        return self._relays[self._active_idx]

    @property
    def _ws_url(self) -> str:
        return f"{self._active_relay}/ws/{self._listen_addr}"

    @property
    def _http_base(self) -> str:
        return _ws_to_http(self._active_relay)

    @property
    def relays(self) -> list[str]:
        """All relays known for failover (seeds + discovered peers)."""
        return list(self._relays)

    @property
    def node_count(self) -> int:
        """How many relay nodes are reachable for this session."""
        return len(self._relays)

    @property
    def is_onion(self) -> bool:
        """True when the active relay is a Tor onion service."""
        return ".onion" in self._active_relay

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """
        Subscribe to a relay, trying each known relay in order until one works.

        Raises ``RelayError`` only if *every* relay is unreachable. After a
        successful connect it fetches the relay's federation peers and folds
        them into the failover list.
        """
        last_exc: Exception | None = None
        for idx in range(len(self._relays)):
            try:
                await self._open(idx)
            except Exception as exc:  # noqa: BLE001 — try the next relay
                last_exc = exc
                continue
            await self._discover_peers()
            return
        raise RelayError(
            f"could not connect to any relay {self._relays}: {last_exc}"
        )

    async def _dial(self, ws_url: str) -> Any:
        """Open one WebSocket (direct, or through the SOCKS5/Tor proxy)."""
        if self._socks_proxy is not None:
            from drift.transport.tor import open_socks_websocket

            host, port = self._socks_proxy
            return await open_socks_websocket(ws_url, host, port)
        return await websockets.connect(ws_url)

    async def _open(self, idx: int) -> None:
        """
        Connect to relay ``idx`` and start its listener + pinger.

        On failure the partially-built HTTP client is cleaned up and the error
        propagates so the caller can try the next relay.
        """
        url = self._relays[idx]
        ws_url = f"{url}/ws/{self._listen_addr}"
        if self._socks_proxy is not None:
            host, port = self._socks_proxy
            http = httpx.AsyncClient(proxy=f"socks5://{host}:{port}")
        else:
            http = httpx.AsyncClient()
        try:
            ws = await self._dial(ws_url)
        except Exception as exc:
            await http.aclose()
            raise RelayError(f"could not connect to relay at {ws_url}: {exc}") from exc

        self._http = http
        self._ws = ws
        self._active_idx = idx
        self._connected = True
        # FMD opt-in (audit M4): hand the relay our detection sub-keys so it
        # pre-filters the firehose. Re-sent on every (re)connect/failover.
        if self._fmd_secret_keys:
            key_b64 = base64.b64encode(b"".join(self._fmd_secret_keys)).decode()
            await ws.send(json.dumps({"type": "fmd", "key": key_b64}))
        self._listener = asyncio.create_task(self._listen(), name="relay-listener")
        self._pinger = asyncio.create_task(self._keepalive(), name="relay-pinger")

    async def _discover_peers(self) -> None:
        """
        Fetch the relay's federation peer list and add them as failover targets.

        Best-effort: a relay without federation, or any error, simply leaves the
        relay list as-is.
        """
        if self._http is None:
            return
        try:
            resp = await self._http.get(f"{self._http_base}/federation/peers", timeout=3.0)
            data = resp.json()
        except Exception:  # noqa: BLE001 — discovery is optional
            return
        if not isinstance(data, dict):
            return
        for peer in data.get("peers", []):
            if not isinstance(peer, str):
                continue
            ws_peer = _http_to_ws(peer)
            if ws_peer not in self._relays:
                self._relays.append(ws_peer)

    async def _failover(self) -> bool:
        """
        Reconnect to the next working relay after the active one dropped.

        Returns True if a standby relay accepted us, False if none did (or there
        is only one relay, i.e. no federation). Tears the dead connection down
        before dialling, so we never leak the old socket/pinger.
        """
        if len(self._relays) <= 1:
            return False
        await self._teardown_active()
        start = self._active_idx
        n = len(self._relays)
        for offset in range(1, n):
            idx = (start + offset) % n
            try:
                await self._open(idx)
            except Exception:  # noqa: BLE001, S112 — try the next standby
                continue
            return True
        return False

    async def _teardown_active(self) -> None:
        """Cancel tasks and close the current relay connection (for failover)."""
        for task in (self._pinger, self._listener):
            if task and not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        if self._ws is not None:
            try:
                await self._ws.close()
            except Exception:  # noqa: BLE001, S110 — socket already dead
                pass
            self._ws = None
        if self._http is not None:
            await self._http.aclose()
            self._http = None

    async def close(self) -> None:
        """Cancel background tasks and close connections."""
        self._closing = True
        self._connected = False
        await self._teardown_active()

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
        # Sealed sender (Phase 3b): the recipient's one-time address is the only
        # metadata on the wire besides the opaque ciphertext. The ephemeral key
        # and ratchet header are sealed inside ``ct`` by the session layer.
        if envelope.one_time_addr is not None:
            payload["addr"] = base64.b64encode(envelope.one_time_addr).decode()
        # FMD detection flag (audit M4): only present when the recipient has an
        # FMD key; lets an FMD-subscribed relay pre-filter. Absent → no overhead.
        if envelope.fmd_flag is not None:
            payload["fmd"] = base64.b64encode(envelope.fmd_flag).decode()
        # Rooms: request longer replay retention (capped server-side).
        if envelope.ttl_seconds is not None:
            payload["ttl_seconds"] = envelope.ttl_seconds
        try:
            resp = await self._http.post(f"{self._http_base}/send", json=payload)
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise RelayError(f"send failed: {exc}") from exc
        data = resp.json()
        if not data.get("ok"):
            raise RelayError(f"relay rejected envelope: {data}")

    async def receive(self) -> Envelope | BurnFrame:
        """
        Block until the next message envelope or burn tombstone arrives.

        If the active relay drops, transparently fails over to the next relay in
        the federation and keeps reading. Raises ``RelayError`` only when the
        connection was deliberately closed or every relay is exhausted.
        """
        if not self._connected and self._queue.empty():
            raise RelayError("not connected — call connect() first")
        while True:
            item = await self._queue.get()
            if item is None:
                # The listener signalled a disconnect. Unless we're shutting
                # down, try to fail over to a standby relay and keep going.
                if not self._closing and await self._failover():
                    continue
                raise RelayError("relay connection closed")
            return item

    async def post_burn(
        self,
        token: str,
        scope: str,
        message_id: str | None,
        channel: str,
    ) -> None:
        """POST a burn request to the relay's /burn endpoint."""
        if self._http is None:
            raise RelayError("not connected — call connect() first")
        payload: dict[str, Any] = {"token": token, "scope": scope, "channel": channel}
        if message_id is not None:
            payload["message_id"] = message_id
        try:
            resp = await self._http.post(f"{self._http_base}/burn", json=payload)
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise RelayError(f"burn failed: {exc}") from exc

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

    async def __anext__(self) -> Envelope | BurnFrame:
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
                # Burn tombstone — put in queue for Session to handle.
                if msg.get("type") == "BURNED":
                    await self._queue.put(BurnFrame(
                        scope=msg.get("scope") or "conversation",
                        message_id=msg.get("message_id") or None,
                        token=msg.get("token") or None,
                    ))
                    continue
                # Skip other relay control frames (pong, error) and anything without ct.
                if "ct" not in msg or msg.get("type"):
                    continue
                try:
                    ciphertext = base64.b64decode(msg["ct"])
                    # Sealed sender: the one-time address is the only clear
                    # metadata; everything else is inside the opaque ciphertext.
                    one_time_addr = base64.b64decode(msg["addr"]) if "addr" in msg else None
                    fmd_flag = base64.b64decode(msg["fmd"]) if "fmd" in msg else None
                except ValueError:
                    continue
                await self._queue.put(
                    Envelope(
                        to=msg.get("to", ""),
                        ciphertext=ciphertext,
                        timestamp=int(msg.get("ts", 0)),
                        one_time_addr=one_time_addr,
                        fmd_flag=fmd_flag,
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
