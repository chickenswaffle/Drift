"""
relay.server — DRIFT reference relay

The relay is intentionally dumb. It:
  - Accepts message blobs over WebSocket
  - Routes them to connected clients
  - Does NOT read, decrypt, log, or store message content
  - Deletes messages after delivery (or after TTL)
  - Never learns who sent what to whom (sealed sender, Phase 3)

Phase 0: simple hub — clients connect by contact code prefix,
         relay fans out to matching connections.

Phase 4: federation — relays gossip blobs to each other.

Run locally:
    python -m relay.server
    # or
    uvicorn relay.server:app --host 0.0.0.0 --port 8765
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from collections import defaultdict
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse

from relay.federation import ANNOUNCE_TTL, DEFAULT_DEDUP_SIZE, Federation

logger = logging.getLogger("drift.relay")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


@asynccontextmanager
async def _lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """On startup: load known peers (peers.json + DRIFT_PEERS) and announce."""
    federation.load_peers()
    if federation.peers:
        logger.info("federation: %d known peer(s): %s", len(federation.peers),
                    ", ".join(federation.peers))
        await federation.announce_self()
    yield


app = FastAPI(
    title="DRIFT relay",
    description="Dumb message relay — routes ciphertext, reads nothing.",
    version="0.1.0",
    lifespan=_lifespan,
)

# ---------------------------------------------------------------------------
# In-memory store (Phase 0)
# Replace with Redis in Phase 4 for persistence + federation.
# ---------------------------------------------------------------------------

# channel → set of live WebSocket connections subscribed to that channel
_subscribers: dict[str, set[WebSocket]] = defaultdict(set)

# channel → recent envelopes, replayed to every NEW subscriber.
#
# Why a replay buffer and not a per-recipient mailbox: DRIFT uses a shared
# firehose channel (every client subscribes to the same one and scans
# locally). The sender is therefore always a live subscriber, so "did this
# reach a live socket?" is *always* true and cannot gate offline queueing —
# the old delivered==0 mailbox never fired, and any message sent before the
# peer's socket finished subscribing was lost. Instead we keep a short,
# bounded, TTL'd buffer of recent envelopes and replay it to each new
# subscriber: a client that connects late (or a hair after its peer hit send)
# still receives recent traffic and scans it. The relay learns nothing new —
# it already broadcasts this same opaque firehose to everyone; this only lets
# a late socket catch up. Recipients dedupe locally (by one-time address).
_recent: dict[str, list[dict[str, Any]]] = defaultdict(list)

# How long an envelope stays replayable, and the per-channel cap (bounds
# memory and how far a late joiner can rewind).
#
# The window is deliberately SHORT. It exists to close the connection-setup
# race (a sender hits send in the sub-second gap before its peer's socket
# finishes subscribing) and to cover a peer who opens the chat a few seconds
# later — not to be a durable inbox. A long window would replay a whole prior
# conversation into a freshly reopened session; because the Phase-2 ratchet is
# bootstrapped deterministically per session and not persisted, those stale
# envelopes collide with the new ratchet. Durable, arbitrary-time offline
# delivery is Phase 4 (Redis mailbox keyed to a persisted ratchet epoch).
RECENT_TTL = 30.0    # seconds — covers the subscribe race + brief late-join
RECENT_MAX = 500     # envelopes per channel

# Max simultaneous WebSocket subscribers, across all channels. None = unlimited
# (the full relay). The Pi-Zero node sets this to a small number (see node.py).
MAX_CONNECTIONS: int | None = None


def _prune_recent(channel: str) -> None:
    """Drop expired / overflow envelopes from a channel's replay buffer."""
    cutoff = time.time() - RECENT_TTL
    buf = [e for e in _recent[channel] if e["_relay_ts"] >= cutoff]
    if len(buf) > RECENT_MAX:
        buf = buf[-RECENT_MAX:]
    _recent[channel] = buf


def _connection_count() -> int:
    """Total live WebSocket subscribers across every channel."""
    return sum(len(v) for v in _subscribers.values())


# ---------------------------------------------------------------------------
# Federation (Phase 4a)
#
# The relay is now one node of a gossip mesh. ``_deliver_local`` is the single
# place a blob is fanned out to this node's subscribers + replay buffer; both
# the /send path and inbound gossip from peers funnel through it, so a federated
# blob is indistinguishable from a directly-submitted one once it lands here.
# ---------------------------------------------------------------------------


async def _deliver_local(envelope: dict[str, Any]) -> int:
    """Fan a blob out to local subscribers and record it in the replay buffer."""
    to_addr = envelope.get("to", "")
    if not to_addr:
        return 0
    # Stamp a *local* receive time so the replay-buffer TTL works regardless of
    # how the blob arrived. A gossiped blob carries the origin relay's _relay_ts
    # (or none at all); each node times its own buffer from when it saw the blob.
    envelope.setdefault("_relay_ts", time.time())
    subscribers = _subscribers.get(to_addr, set())
    delivered = 0
    for ws in list(subscribers):
        try:
            await ws.send_text(json.dumps(envelope))
            delivered += 1
        except Exception:
            subscribers.discard(ws)
    _recent[to_addr].append(envelope)
    _prune_recent(to_addr)
    return delivered


# ---------------------------------------------------------------------------
# Beacons (Phase 6) — ephemeral discoverable handles
#
# The relay indexes a beacon by lookup_hash = SHA256(prefix ‖ handle), which the
# client computes; the plaintext handle never reaches the relay. The stored payload is
# opaque (only a handle-knower can decrypt it). Beacons auto-expire and are
# *deleted* on expiry, never served stale.
# ---------------------------------------------------------------------------

BEACON_MAX_TTL = 600  # seconds (10 min), enforced regardless of the request

# lookup_hash → {"payload": <base64 str>, "expires_at": <unix int>}
_beacons: dict[str, dict[str, Any]] = {}

# A lookup hash is SHA256 hex: 64 lowercase hex chars.
_LOOKUP_HASH_RE = re.compile(r"^[0-9a-f]{64}$")


def _prune_beacons() -> None:
    """Delete expired beacons so a GET after expiry 404s rather than serving stale."""
    now = time.time()
    for h in [h for h, b in _beacons.items() if b["expires_at"] <= now]:
        del _beacons[h]


async def _store_beacon(beacon: dict[str, Any]) -> None:
    """Store a beacon locally (the federation deliver-beacon callback)."""
    lookup = beacon.get("lookup_hash")
    payload = beacon.get("payload")
    expires_at = beacon.get("expires_at")
    if not (isinstance(lookup, str) and _LOOKUP_HASH_RE.match(lookup)
            and isinstance(payload, str) and isinstance(expires_at, (int, float))):
        return
    if expires_at <= time.time():
        return
    _beacons[lookup] = {"payload": payload, "expires_at": int(expires_at)}


# This node's externally-reachable base URL (so peers can re-announce it and we
# never gossip a blob back to ourselves). Set via DRIFT_SELF_URL.
SELF_URL = os.environ.get("DRIFT_SELF_URL") or None

federation = Federation(
    self_url=SELF_URL,
    peers_file=os.environ.get("DRIFT_PEERS_FILE", "peers.json"),
    dedup_size=DEFAULT_DEDUP_SIZE,
    deliver=_deliver_local,
    deliver_beacon=_store_beacon,
)


# ---------------------------------------------------------------------------
# WebSocket endpoint
# ---------------------------------------------------------------------------

@app.websocket("/ws/{listen_addr}")
async def websocket_endpoint(websocket: WebSocket, listen_addr: str) -> None:
    """
    A client connects by providing the address it wants to listen on.

    Phase 0: the address is the recipient's base58 public key prefix.
    Phase 1: the address is the one-time stealth address.

    The relay doesn't care what the address means — it's just a routing key.
    """
    await websocket.accept()

    # Resource cap for low-power nodes: refuse new subscribers past the limit.
    # The full relay leaves MAX_CONNECTIONS=None (unlimited).
    if MAX_CONNECTIONS is not None and _connection_count() >= MAX_CONNECTIONS:
        await websocket.send_text(json.dumps({"type": "error", "error": "node at capacity"}))
        await websocket.close(code=1013)  # 1013 = "try again later"
        logger.info("Refused subscriber addr=%.12s… (at capacity %d)", listen_addr, MAX_CONNECTIONS)
        return

    _subscribers[listen_addr].add(websocket)

    logger.info(
        "Client subscribed addr=%.12s… total=%d", listen_addr, len(_subscribers[listen_addr])
    )

    # Replay recent traffic so a late-joining socket catches up. We do NOT
    # pop: the buffer is shared by all subscribers (other late joiners still
    # need it) and expires on its own TTL. Recipients dedupe by one-time
    # address, so replaying a message a connected peer already saw is a no-op.
    _prune_recent(listen_addr)
    for envelope in list(_recent[listen_addr]):
        try:
            await websocket.send_text(json.dumps(envelope))
        except Exception:
            logger.debug("Failed to replay recent envelope to %s", listen_addr)
            break

    try:
        while True:
            # Clients can send pings to keep the connection alive
            raw = await websocket.receive_text()
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                await websocket.send_text(json.dumps({"error": "invalid json"}))
                continue

            if msg.get("type") == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))

    except WebSocketDisconnect:
        _subscribers[listen_addr].discard(websocket)
        logger.info("Client disconnected addr=%.12s…", listen_addr)


# ---------------------------------------------------------------------------
# HTTP endpoints
# ---------------------------------------------------------------------------

@app.post("/send")
async def send_message(envelope: dict[str, Any]) -> JSONResponse:
    """
    POST a message envelope to the relay.

    Expected body (sealed sender — Phase 3b):
        {
            "to":   "<channel>",     // firehose routing key (opaque to relay)
            "ct":   "<base64>",      // opaque sealed blob (opaque to relay)
            "ts":   1234567890,      // unix timestamp (for TTL)
            "addr": "<base64>"       // recipient one-time stealth address
        }

    The relay never inspects "ct" or "addr". The sender's ephemeral key and the
    Double Ratchet header used to ride here in the clear ("R"/"hdr"); as of
    sealed sender they are encrypted inside "ct", so the relay can no longer
    group a sender's messages by ratchet header. Only the recipient, scanning
    with their private scan key, can tell which one-time address is theirs.

    We rebuild the forwarded record from known fields only, so the relay never
    re-broadcasts arbitrary client-supplied JSON to other clients.
    """
    to_addr = envelope.get("to", "")
    if not to_addr:
        return JSONResponse({"error": "missing 'to' field"}, status_code=400)

    record: dict[str, Any] = {
        "to": to_addr,
        "ct": envelope.get("ct", ""),
        "ts": envelope.get("ts", 0),
        "_relay_ts": time.time(),
        "_id": str(uuid4()),
    }
    # Carry the recipient's one-time address through untouched (routing/detection).
    if "addr" in envelope:
        record["addr"] = envelope["addr"]

    envelope = record

    # Replicate to the federation FIRST so the blob survives this node dying.
    # submit() floods peers at the starting TTL and reports how many accepted;
    # we want at least min_replicas before acknowledging the client (best-effort
    # — a solo relay with no peers simply replicates to 0 and still serves).
    replicated = await federation.submit(envelope)

    # Then fan out to this node's own subscribers + replay buffer. The buffer is
    # the safety net for a peer that subscribes a moment later; `delivered` is
    # never a reliable "recipient got it" signal because the sender is itself a
    # live subscriber on the shared firehose.
    delivered = await _deliver_local(envelope)

    return JSONResponse({"ok": True, "delivered": delivered, "replicated": replicated})


# ---------------------------------------------------------------------------
# Federation endpoints (Phase 4a)
# ---------------------------------------------------------------------------

@app.post("/federation/gossip")
async def federation_gossip(body: dict[str, Any]) -> JSONResponse:
    """
    Receive a blob gossiped by a peer relay.

    Body: ``{"envelope": {...}, "ttl": <int>}``. Deduped by content id; a blob
    we've already seen is dropped silently (``accepted: false``). A fresh blob
    is delivered locally and forwarded onward at ttl-1.
    """
    envelope = body.get("envelope")
    ttl = int(body.get("ttl", 0))
    if not isinstance(envelope, dict) or not envelope.get("to"):
        return JSONResponse({"error": "missing envelope"}, status_code=400)
    accepted = await federation.handle_gossip(envelope, ttl)
    return JSONResponse({"ok": True, "accepted": accepted})


@app.post("/federation/announce")
async def federation_announce(body: dict[str, Any]) -> JSONResponse:
    """
    A relay announces itself. We record it as a peer and re-announce onward
    (capped at 2 hops). Body: ``{"url": "<relay base url>", "ttl": <int>}``.
    """
    url = body.get("url", "")
    ttl = int(body.get("ttl", ANNOUNCE_TTL))
    if not isinstance(url, str) or not url:
        return JSONResponse({"error": "missing url"}, status_code=400)
    learned = await federation.handle_announce(url, ttl)
    return JSONResponse({"ok": True, "learned": learned, "peers": federation.peers})


@app.get("/federation/peers")
async def federation_peers() -> JSONResponse:
    """Public peer list, used by clients and new relays to bootstrap."""
    return JSONResponse({"peers": federation.peers})


@app.post("/federation/beacon")
async def federation_beacon(body: dict[str, Any]) -> JSONResponse:
    """Receive a beacon gossiped by a peer relay (dedup, store, forward)."""
    beacon = body.get("beacon")
    ttl = int(body.get("ttl", 0))
    if not isinstance(beacon, dict) or not beacon.get("lookup_hash"):
        return JSONResponse({"error": "missing beacon"}, status_code=400)
    accepted = await federation.handle_beacon_gossip(beacon, ttl)
    return JSONResponse({"ok": True, "accepted": accepted})


# ---------------------------------------------------------------------------
# Beacon endpoints (Phase 6)
# ---------------------------------------------------------------------------

@app.post("/beacon")
async def light_beacon(body: dict[str, Any]) -> JSONResponse:
    """
    Light a beacon. Body: ``{lookup_hash, payload, ttl_seconds}``.

    ``lookup_hash`` is a domain-separated SHA256 of the handle — the relay never
    sees the handle itself. The TTL
    is capped at BEACON_MAX_TTL server-side regardless of the request. The
    beacon is stored locally and replicated to federation peers.
    """
    lookup = body.get("lookup_hash", "")
    payload = body.get("payload", "")
    if not isinstance(lookup, str) or not _LOOKUP_HASH_RE.match(lookup):
        return JSONResponse({"error": "lookup_hash must be 64 lowercase hex chars"},
                            status_code=400)
    if not isinstance(payload, str) or not payload:
        return JSONResponse({"error": "payload is required"}, status_code=400)
    try:
        requested = int(body.get("ttl_seconds", BEACON_MAX_TTL))
    except (TypeError, ValueError):
        return JSONResponse({"error": "ttl_seconds must be an integer"}, status_code=400)
    ttl = max(1, min(requested, BEACON_MAX_TTL))  # hard cap
    expires_at = int(time.time()) + ttl

    record = {"lookup_hash": lookup, "payload": payload, "expires_at": expires_at}
    await _store_beacon(record)
    await federation.submit_beacon(record)
    return JSONResponse({"ok": True, "expires_at": expires_at, "ttl_seconds": ttl})


@app.get("/beacon/{lookup_hash}")
async def get_beacon(lookup_hash: str) -> JSONResponse:
    """Return a beacon's payload if live, 404 if absent or expired (and deleted)."""
    _prune_beacons()
    beacon = _beacons.get(lookup_hash)
    if beacon is None:
        return JSONResponse({"error": "beacon not found or expired"}, status_code=404)
    return JSONResponse({"payload": beacon["payload"], "expires_at": beacon["expires_at"]})


@app.delete("/beacon/{lookup_hash}")
async def extinguish_beacon(lookup_hash: str) -> JSONResponse:
    """Delete a beacon early (the holder extinguishing it). Idempotent."""
    _beacons.pop(lookup_hash, None)
    return JSONResponse({"ok": True})


# HMAC-SHA256 token is 32 bytes = 64 lowercase hex characters.
_BURN_TOKEN_RE = re.compile(r"^[0-9a-f]{64}$")


@app.post("/burn")
async def burn_request(body: dict[str, Any]) -> JSONResponse:
    """
    POST a burn request to erase messages from the relay buffer and notify
    connected clients via a tombstone.

    Expected body:
        {
            "token":      "<64 hex chars>",        // HMAC-SHA256 burn token
            "scope":      "message"|"conversation",
            "channel":    "<channel name>",
            "message_id": "<base64 addr>"          // required for scope=message
        }

    The relay does NOT verify the HMAC (it has no shared secret). Clients
    verify the token end-to-end before honouring the tombstone.

    NOTE: The stealth firehose is shared by all users; a conversation-scope
    burn clears all recent traffic on the channel, not just the requesting
    pair's messages. The 30 s RECENT_TTL limits the blast radius.
    (Phase 4 will add per-recipient storage.)
    """
    token = body.get("token", "")
    scope = body.get("scope", "")
    channel = body.get("channel", "")
    message_id: str | None = body.get("message_id") or None

    if not isinstance(token, str) or not _BURN_TOKEN_RE.match(token):
        return JSONResponse({"error": "token must be 64 lowercase hex characters"}, status_code=400)
    if scope not in ("message", "conversation"):
        return JSONResponse({"error": "scope must be 'message' or 'conversation'"}, status_code=400)
    if not channel:
        return JSONResponse({"error": "channel is required"}, status_code=400)
    if scope == "message" and not message_id:
        return JSONResponse({"error": "message_id required for scope=message"}, status_code=400)

    # Erase matching blobs from the replay buffer.
    if scope == "conversation":
        _recent[channel] = []
    else:
        _recent[channel] = [
            e for e in _recent[channel] if e.get("addr") != message_id
        ]

    # Broadcast a tombstone (with token so recipients can verify) to all
    # live subscribers. Token is NOT written to server logs below.
    tombstone: dict[str, Any] = {
        "type": "BURNED",
        "scope": scope,
        "token": token,
        "ts": int(time.time()),
    }
    if message_id:
        tombstone["message_id"] = message_id

    subscribers = _subscribers.get(channel, set())
    notified = 0
    for ws in list(subscribers):
        try:
            await ws.send_text(json.dumps(tombstone))
            notified += 1
        except Exception:
            subscribers.discard(ws)

    logger.info("burn request processed channel=%.12s… scope=%s", channel, scope)
    return JSONResponse({"ok": True, "notified": notified})


@app.get("/health")
async def health() -> JSONResponse:
    return JSONResponse({
        "status": "ok",
        "subscriptions": _connection_count(),
        "recent": sum(len(v) for v in _recent.values()),
        "federation": federation.status(),
    })


@app.get("/")
async def root() -> JSONResponse:
    return JSONResponse({
        "name": "DRIFT relay",
        "version": "0.1.0",
        "notice": "This relay routes opaque ciphertext. It cannot read message content.",
    })


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import os

    import uvicorn

    # reload=True restarts uvicorn on every file save, which drops every live
    # WebSocket — clients then see "relay closed connection". Keep the relay
    # stable by default; opt into autoreload with DRIFT_RELAY_RELOAD=1 only when
    # actively editing the relay itself.
    reload = bool(os.environ.get("DRIFT_RELAY_RELOAD"))
    uvicorn.run("relay.server:app", host="0.0.0.0", port=8765, reload=reload)  # noqa: S104
