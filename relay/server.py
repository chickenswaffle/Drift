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
import time
from collections import defaultdict
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse

logger = logging.getLogger("drift.relay")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

app = FastAPI(
    title="DRIFT relay",
    description="Dumb message relay — routes ciphertext, reads nothing.",
    version="0.1.0",
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


def _prune_recent(channel: str) -> None:
    """Drop expired / overflow envelopes from a channel's replay buffer."""
    cutoff = time.time() - RECENT_TTL
    buf = [e for e in _recent[channel] if e["_relay_ts"] >= cutoff]
    if len(buf) > RECENT_MAX:
        buf = buf[-RECENT_MAX:]
    _recent[channel] = buf


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

    Expected body (Phase 0):
        {
            "to":  "<addr>",         // routing key (opaque to relay)
            "ct":  "<base64>",       // ciphertext (opaque to relay)
            "ts":  1234567890        // unix timestamp (for TTL)
        }

    Phase 1 stealth fields (optional, opaque to relay):
        "R":    "<base64>",          // sender's ephemeral public key
        "addr": "<base64>"           // derived one-time stealth address

    Phase 2 ratchet field (optional, opaque to relay):
        "hdr":  "<base64>"           // serialized Double Ratchet header

    The relay never inspects "ct", "R", "addr", or "hdr" — it routes and
    forgets. Only the recipient, scanning with their private scan key, can
    tell which one-time address (and therefore which message) is theirs.

    We rebuild the forwarded record from known fields only, so the relay
    never re-broadcasts arbitrary client-supplied JSON to other clients.
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
    # Carry Phase 1 stealth-address fields through untouched, if present.
    if "R" in envelope:
        record["R"] = envelope["R"]
    if "addr" in envelope:
        record["addr"] = envelope["addr"]
    # Carry the Phase 2 ratchet header through untouched, if present.
    if "hdr" in envelope:
        record["hdr"] = envelope["hdr"]

    envelope = record
    subscribers = _subscribers.get(to_addr, set())
    delivered = 0

    for ws in list(subscribers):
        try:
            await ws.send_text(json.dumps(envelope))
            delivered += 1
        except Exception:
            subscribers.discard(ws)

    # Always record into the replay buffer so a peer that subscribes a moment
    # later (or was briefly offline) still receives this. Delivery to live
    # sockets above is the fast path; the buffer is the safety net. Both are
    # needed because the sender is itself a live subscriber on the firehose,
    # so `delivered` is never a reliable signal that the *recipient* got it.
    _recent[to_addr].append(envelope)
    _prune_recent(to_addr)

    return JSONResponse({"ok": True, "delivered": delivered})


@app.get("/health")
async def health() -> JSONResponse:
    return JSONResponse({
        "status": "ok",
        "subscriptions": sum(len(v) for v in _subscribers.values()),
        "recent": sum(len(v) for v in _recent.values()),
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
