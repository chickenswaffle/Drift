"""
drift.transport.room_session — live transport for Sovereign Rooms (Phase 11)

A :class:`RoomSession` is the network layer for a room. It is *not* a new relay
construct: it rides the existing ``/send`` + ``/ws/{addr}`` infrastructure
exactly like 1:1 and group traffic. The only things that make a room a room live
in :mod:`drift.crypto.rooms`; here we just:

  - subscribe to the room's **rotating** addresses — the current window plus the
    previous :data:`~drift.crypto.rooms.CATCHUP_WINDOWS` (so a late joiner catches
    up), refreshing as the 10-minute window advances;
  - decrypt + dedupe inbound envelopes, surfacing :class:`RoomMessage`s;
  - seal + post outbound messages, requesting a longer relay TTL so the catch-up
    windows actually have something to replay.

Room shards (Part E)
--------------------
If the room is *sharded* across federation peers, each shard has its own address
schedule (:func:`~drift.crypto.rooms.shard_address`) on its own relay. The
session subscribes to **every** shard and merges the streams locally, so no
single relay sees the whole room and taking one down does not kill it. Outbound
messages round-robin across shards to spread the traffic.

The relay still sees only ``{to: <rotating addr>, ct: <opaque blob>}`` — never a
room name, never who is in it, nothing that says "this is a room".
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import AsyncGenerator, Callable
from dataclasses import dataclass

from drift.crypto import Identity
from drift.crypto import rooms as rooms_crypto
from drift.crypto.rooms import Room, RoomKeys, RoomMessage
from drift.transport.client import BurnFrame, Envelope, RelayClient
from drift.transport.tor import TorClient

logger = logging.getLogger("drift.room")

EventHook = Callable[[str, str], None]

# How long to ask the relay to retain a room blob: long enough that a joiner
# scanning the catch-up windows finds it. Capped server-side at RECENT_MAX_TTL.
ROOM_RETENTION_SECONDS = rooms_crypto.WINDOW_SECONDS * (rooms_crypto.CATCHUP_WINDOWS + 1)

# Cap the dedup set so a long-lived session doesn't grow without bound.
_SEEN_CAP = 4096


@dataclass(frozen=True)
class _Target:
    """One (relay, address) the session listens on or sends to."""

    relay: str
    addr: bytes

    @property
    def channel(self) -> str:
        """The relay routing key (``to`` / ``/ws/{addr}``) — the address as hex."""
        return self.addr.hex()


class RoomSession:
    """A live room conversation over rotating stealth addresses."""

    def __init__(
        self,
        identity: Identity,
        room: Room,
        relay_url: str,
        *,
        ping_interval: float = 30.0,
        on_event: EventHook | None = None,
        tor_client: TorClient | None = None,
    ) -> None:
        self._identity = identity
        self._room = room
        self._keys: RoomKeys = room.keys()
        self._ephemeral = rooms_crypto.new_ephemeral()
        self._on_event = on_event
        self._tor_client = tor_client
        self._ping_interval = ping_interval
        self._socks = tor_client.socks_proxy if tor_client is not None else None

        # An unsharded room uses the single relay; a sharded room uses its own
        # federation relay list (falling back to the connection relay if a shard
        # entry is blank). Shard index → relay url.
        self._shard_relays: list[str] = list(room.shards)
        self._relay_url = relay_url

        # (relay, channel) → live RelayClient + its reader task. Keyed by the
        # hex channel so window rotation can add/drop addresses incrementally.
        self._clients: dict[tuple[str, str], RelayClient] = {}
        self._readers: dict[tuple[str, str], asyncio.Task[None]] = {}
        self._senders: dict[str, RelayClient] = {}  # one send client per relay

        self._queue: asyncio.Queue[RoomMessage] = asyncio.Queue()
        self._seen: set[bytes] = set()
        self._round_robin = 0
        self._refresh_task: asyncio.Task[None] | None = None
        self._closing = False

    # ------------------------------------------------------------------ props
    @property
    def room(self) -> Room:
        return self._room

    @property
    def keys(self) -> RoomKeys:
        return self._keys

    @property
    def session_tag(self) -> str:
        """This client's own pseudonym for the session (the 4-char display tag)."""
        tag = rooms_crypto.sender_tag(self._keys.auth_key(), self._ephemeral) \
            if self._keys.can_post() else b"\x00" * rooms_crypto.SENDER_TAG_LEN
        return rooms_crypto.display_tag(tag)

    def can_post(self) -> bool:
        return self._keys.can_post()

    def _emit(self, kind: str, detail: str = "") -> None:
        if self._on_event is not None:
            self._on_event(kind, detail)

    # ------------------------------------------------------------------ addressing
    @property
    def _is_sharded(self) -> bool:
        return len(self._shard_relays) > 1

    def _shard_relay(self, index: int) -> str:
        relay = self._shard_relays[index] if index < len(self._shard_relays) else ""
        return relay or self._relay_url

    def _listen_targets(self, now: float | None = None) -> set[_Target]:
        """Every (relay, addr) to subscribe to right now: all shards × all
        catch-up windows (or the single address schedule when unsharded)."""
        wins = rooms_crypto.scan_windows(int(now) if now is not None else None)
        scan = self._keys.scan_key
        targets: set[_Target] = set()
        if self._is_sharded:
            for i in range(len(self._shard_relays)):
                relay = self._shard_relay(i)
                for w in wins:
                    targets.add(_Target(relay, rooms_crypto.shard_address(scan, i, w)))
        else:
            for w in wins:
                targets.add(_Target(self._relay_url, rooms_crypto.room_address(scan, w)))
        return targets

    def _send_target(self, now: float | None = None) -> _Target:
        """The single (relay, addr) to post the next message to.

        Unsharded: the current window's room address. Sharded: round-robin across
        shards so the room's traffic is spread over the federation."""
        win = rooms_crypto.current_window(int(now) if now is not None else None)
        scan = self._keys.scan_key
        if self._is_sharded:
            i = self._round_robin % len(self._shard_relays)
            self._round_robin += 1
            return _Target(self._shard_relay(i), rooms_crypto.shard_address(scan, i, win))
        return _Target(self._relay_url, rooms_crypto.room_address(scan, win))

    # ------------------------------------------------------------------ lifecycle
    async def connect(self) -> None:
        await self._refresh()
        # Tolerating dead shards keeps the room alive when *some* relays are
        # reachable, but connecting to *nothing* is a real failure — surface it
        # so the UI shows "offline" rather than a false "secure".
        if not self._clients:
            from drift.transport.client import RelayError
            raise RelayError("could not subscribe to any room address")
        if self._tor_client is not None:
            self._emit("tor", str(self._tor_client.num_hops))
        self._emit("nodes", str(max(1, len(set(self._shard_relays)) or 1)))
        self._refresh_task = asyncio.create_task(self._refresh_loop(), name="room-refresh")

    async def __aenter__(self) -> RoomSession:
        await self.connect()
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()

    async def close(self) -> None:
        self._closing = True
        if self._refresh_task is not None:
            self._refresh_task.cancel()
        for task in list(self._readers.values()):
            task.cancel()
        for client in list(self._clients.values()):
            await client.close()
        for client in list(self._senders.values()):
            await client.close()
        self._clients.clear()
        self._readers.clear()
        self._senders.clear()

    def _make_client(self, relay: str, channel: str) -> RelayClient:
        return RelayClient(
            relay, channel, ping_interval=self._ping_interval, socks_proxy=self._socks
        )

    async def _refresh(self) -> None:
        """Reconcile live subscriptions with the addresses we *should* be on now:
        open clients for new windows, drop clients for windows that have aged out
        of the catch-up horizon."""
        desired = self._listen_targets()
        desired_keys = {(t.relay, t.channel) for t in desired}

        for t in desired:
            key = (t.relay, t.channel)
            if key in self._clients:
                continue
            client = self._make_client(t.relay, t.channel)
            try:
                await client.connect()
            except Exception as exc:  # noqa: BLE001 — a dead shard must not kill the room
                logger.debug("room: could not subscribe %s on %s: %s", t.channel[:12], t.relay, exc)
                continue
            self._clients[key] = client
            self._readers[key] = asyncio.create_task(
                self._reader(client, t.addr), name=f"room-reader-{t.channel[:8]}"
            )

        # Drop subscriptions that have rotated out of the catch-up window.
        for key in list(self._clients):
            if key not in desired_keys:
                reader = self._readers.pop(key, None)
                if reader is not None:
                    reader.cancel()
                client = self._clients.pop(key)
                await client.close()

    async def _refresh_loop(self) -> None:
        """Wake near each 10-minute window boundary and re-reconcile."""
        try:
            while not self._closing:
                now = time.time()
                sleep = rooms_crypto.WINDOW_SECONDS - (now % rooms_crypto.WINDOW_SECONDS) + 1.0
                await asyncio.sleep(sleep)
                await self._refresh()
        except asyncio.CancelledError:
            pass

    # ------------------------------------------------------------------ receiving
    async def _reader(self, client: RelayClient, addr: bytes) -> None:
        """Drain one address's socket: decrypt, dedupe, enqueue room messages."""
        try:
            async for item in client:
                if isinstance(item, BurnFrame):
                    continue
                msg = rooms_crypto.open_room_message(self._keys, addr, item.ciphertext)
                if msg is None:
                    continue
                if msg.message_id in self._seen:
                    continue
                self._seen.add(msg.message_id)
                if len(self._seen) > _SEEN_CAP:  # bound memory; oldest-ish drop
                    self._seen = set(list(self._seen)[-_SEEN_CAP // 2:])
                self._emit("recv", msg.tag_label)
                await self._queue.put(msg)
        except asyncio.CancelledError:
            pass
        except Exception as exc:  # noqa: BLE001 — one socket dying must not kill the room
            logger.debug("room: reader stopped: %s", exc)

    async def messages(self) -> AsyncGenerator[RoomMessage, None]:
        """Yield decrypted room messages as they arrive across all shards/windows."""
        while not self._closing:
            yield await self._queue.get()

    # ------------------------------------------------------------------ sending
    async def _sender_for(self, relay: str) -> RelayClient:
        """A connected client on ``relay`` used purely to POST /send (the WS it
        also opens is harmless; we reuse one per relay)."""
        client = self._senders.get(relay)
        if client is None:
            # Subscribe it to the current window address so it is a normal,
            # indistinguishable participant rather than a send-only oddity. The
            # POST /send target is independent of this subscription.
            channel = rooms_crypto.room_address(
                self._keys.scan_key, rooms_crypto.current_window()
            ).hex()
            client = self._make_client(relay, channel)
            await client.connect()
            self._senders[relay] = client
        return client

    async def send_to_room(self, text: str, *, display_name: str | None = None) -> None:
        """Seal ``text`` and post it to the room's current (shard) address.

        Raises if this holder cannot post (an invite room with no token)."""
        if not self._keys.can_post():
            self._emit("error", "read-only: posting needs an invite token")
            raise rooms_crypto.RoomError("cannot post to this room (no invite token)")
        target = self._send_target()
        msg = rooms_crypto.seal_room_message(
            self._keys, text,
            ephemeral=self._ephemeral, room_addr=target.addr,
            display_name=display_name,
            identity=self._identity if display_name else None,
        )
        envelope = Envelope(
            to=target.channel,
            ciphertext=rooms_crypto.pack_envelope(msg),
            ttl_seconds=ROOM_RETENTION_SECONDS,
        )
        client = await self._sender_for(target.relay)
        await client.send(envelope)
        self._emit("send", f"room · {target.channel[:8]}…")
