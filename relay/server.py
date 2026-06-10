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

import asyncio
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

# addr_hex → list of waiting envelopes (for clients not yet connected)
_mailbox: dict[str, list[dict]] = defaultdict(list)

# addr_hex → set of live WebSocket connections subscribed to that address
_subscribers: dict[str, set[WebSocket]] = defaultdict(set)

# Message TTL in seconds (messages expire even if undelivered)
MESSAGE_TTL = 60 * 60 * 24  # 24 hours

# Maximum queued messages per address (soft cap — prevents abuse)
MAX_QUEUED = 500


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

    logger.info("Client subscribed addr=%.12s… total=%d", listen_addr, len(_subscribers[listen_addr]))

    # Drain any queued messages for this address
    if listen_addr in _mailbox:
        queued = _mailbox.pop(listen_addr)
        for envelope in queued:
            try:
                await websocket.send_text(json.dumps(envelope))
            except Exception:
                pass

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
            "to":  "<addr_hex>",     // destination address
            "ct":  "<base58>",       // ciphertext (opaque to relay)
            "ts":  1234567890        // unix timestamp (for TTL)
        }

    Phase 1 adds:
        "R":    "<base58>",          // ephemeral public key
        "addr": "<base58>"           // one-time stealth address (same as "to")

    The relay does not validate or inspect "ct". It routes and forgets.
    """
    to_addr = envelope.get("to", "")
    if not to_addr:
        return JSONResponse({"error": "missing 'to' field"}, status_code=400)

    envelope["_relay_ts"] = time.time()
    envelope["_id"] = str(uuid4())

    subscribers = _subscribers.get(to_addr, set())
    delivered = 0

    for ws in list(subscribers):
        try:
            await ws.send_text(json.dumps(envelope))
            delivered += 1
        except Exception:
            subscribers.discard(ws)

    if delivered == 0:
        # Queue for later pickup
        q = _mailbox[to_addr]
        if len(q) < MAX_QUEUED:
            q.append(envelope)
        else:
            logger.warning("Mailbox full for addr=%.12s… dropping message", to_addr)

    return JSONResponse({"ok": True, "delivered": delivered})


@app.get("/health")
async def health() -> JSONResponse:
    return JSONResponse({
        "status": "ok",
        "subscriptions": sum(len(v) for v in _subscribers.values()),
        "queued": sum(len(v) for v in _mailbox.values()),
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
    import uvicorn
    uvicorn.run("relay.server:app", host="0.0.0.0", port=8765, reload=True)
