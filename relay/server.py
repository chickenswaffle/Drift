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
import base64
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

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse

from drift.crypto.burn import TOKEN_TTL_SECONDS, BurnTokenError, parse_burn_token
from drift.crypto.fmd import FMDKeypair, fmd_test
from relay.federation import ANNOUNCE_TTL, DEFAULT_DEDUP_SIZE, Federation, LRUSet
from relay.ratelimit import TokenBucket
from relay.witness import (
    MAX_CERTS,
    WitnessChain,
    fingerprint,
    load_or_create_relay_identity,
    relay_pubkey_b58,
    verify_chain_report,
)

logger = logging.getLogger("drift.relay")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


@asynccontextmanager
async def _lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """On startup: load peers + announce, and start the WITNESS heartbeat."""
    federation.load_peers()
    if federation.peers:
        logger.info("federation: %d known peer(s): %s", len(federation.peers),
                    ", ".join(federation.peers))
        await federation.announce_self()
    # WITNESS: seal a fresh, signed blindness certificate every period. A gap in
    # this heartbeat is the canary — it means the relay went dark (see witness.py).
    witness_task = asyncio.create_task(_witness_loop())
    try:
        yield
    finally:
        witness_task.cancel()
        try:
            await witness_task
        except asyncio.CancelledError:
            pass


async def _witness_loop() -> None:
    """Seal one blindness certificate per period, chaining onto the last."""
    while True:
        await asyncio.sleep(witness_chain.period_seconds)
        cert = witness_chain.generate()
        logger.info(
            "witness: sealed certificate ts=%d routed=%d chain_len=%d",
            cert.timestamp, cert.messages_routed, len(witness_chain),
        )


app = FastAPI(
    title="DRIFT relay",
    description="Dumb message relay — routes ciphertext, reads nothing.",
    version="0.1.0",
    lifespan=_lifespan,
)

# ---------------------------------------------------------------------------
# Rate limiting (see relay/ratelimit.py for the privacy stance)
#
# Generous per-IP budgets — Tor exit sharing means one IP is many users — plus
# a *global* per-address budget on the OTPK-consuming prekey fetch, because a
# drain attacker can rotate circuits for a fresh IP but cannot rotate the
# victim's address. Tunable per deployment; DRIFT_RELAY_RATE_LIMITS=off
# disables the whole layer (e.g. for load tests).
# ---------------------------------------------------------------------------


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _rate_limits_on() -> bool:
    flag = os.environ.get("DRIFT_RELAY_RATE_LIMITS", "on").strip().lower()
    return flag not in {"off", "0", "false", "no"}


# /send floods: 10 msg/s sustained, burst 200 — orders of magnitude above chat.
_send_bucket = TokenBucket(
    rate=_env_float("DRIFT_RELAY_SEND_RATE", 10.0),
    burst=_env_float("DRIFT_RELAY_SEND_BURST", 200.0),
)
# /burn + prekey publish/replenish: 1/s sustained, burst 30 per IP.
_burn_bucket = TokenBucket(
    rate=_env_float("DRIFT_RELAY_BURN_RATE", 1.0),
    burst=_env_float("DRIFT_RELAY_BURN_BURST", 30.0),
)
_prekey_write_bucket = TokenBucket(
    rate=_env_float("DRIFT_RELAY_PREKEY_WRITE_RATE", 1.0),
    burst=_env_float("DRIFT_RELAY_PREKEY_WRITE_BURST", 30.0),
)
# OTPK-consuming fetch, per (IP, target): one contact needs ~1 fetch ever.
_prekey_fetch_ip_bucket = TokenBucket(
    rate=_env_float("DRIFT_RELAY_PREKEY_FETCH_RATE", 1.0 / 30.0),
    burst=_env_float("DRIFT_RELAY_PREKEY_FETCH_BURST", 20.0),
)
# OTPK-consuming fetch, per target address across ALL IPs (anti circuit-rotate):
# burst 30 new conversations, then 6/min sustained — auto-replenish outpaces it.
_prekey_fetch_addr_bucket = TokenBucket(
    rate=_env_float("DRIFT_RELAY_PREKEY_ADDR_RATE", 0.1),
    burst=_env_float("DRIFT_RELAY_PREKEY_ADDR_BURST", 30.0),
)


def _client_key(request: Request) -> str:
    """Bucket key for the caller. In-RAM only — never logged (see ratelimit.py)."""
    client = request.client
    return client.host if client else "unknown"


def _rate_limited() -> JSONResponse:
    return JSONResponse(
        {"error": "rate limited — slow down"},
        status_code=429,
        headers={"Retry-After": "30"},
    )


# ---------------------------------------------------------------------------
# In-memory store (Phase 0)
# Replace with Redis in Phase 4 for persistence + federation.
# ---------------------------------------------------------------------------

# channel → set of live WebSocket connections subscribed to that channel
_subscribers: dict[str, set[WebSocket]] = defaultdict(set)

# Per-connection FMD detection key (audit M4). A subscriber that opts into FMD
# pre-filtering sends its (downgraded) detection sub-keys; we then forward only
# envelopes whose flag matches — plus the scheme's 2^-k false positives. A
# subscriber NOT in this map is in classic mode: it receives the whole firehose
# and scans locally (unchanged behaviour). The relay never sees message content;
# FMD only lets it learn a probabilistic, p-sized guess at which envelopes might
# be for this subscriber — that probabilistic signal is the documented cost of
# the efficiency gain (see DESIGN.md "Fuzzy Message Detection").
_fmd_filters: dict[WebSocket, FMDKeypair] = {}


def _set_fmd_filter(ws: WebSocket, key_b64: str | None) -> int:
    """Register (or clear) a subscriber's FMD detection key. Returns sub-key count."""
    if not key_b64:
        _fmd_filters.pop(ws, None)
        return 0
    try:
        raw = base64.b64decode(key_b64)
    except (ValueError, TypeError):
        return 0
    if not raw or len(raw) % 32 != 0:
        return 0
    subkeys = [raw[i:i + 32] for i in range(0, len(raw), 32)]
    _fmd_filters[ws] = FMDKeypair(secret_keys=subkeys, public_keys=[])
    return len(subkeys)


def _passes_fmd(ws: WebSocket, envelope: dict[str, Any]) -> bool:
    """Whether ``envelope`` should be forwarded to subscriber ``ws``.

    Classic subscribers (no FMD key) always pass. For an FMD subscriber, a
    flagged envelope is forwarded only if it tests positive against their key;
    an **unflagged** envelope always passes (fail-open) — the sender may simply
    not have the recipient's FMD key, and FMD must never cause a real message to
    be dropped. It is an efficiency filter on flagged traffic, not a gate.
    """
    key = _fmd_filters.get(ws)
    if key is None:
        return True
    flag_b64 = envelope.get("fmd")
    addr_b64 = envelope.get("addr")
    if not flag_b64 or not addr_b64:
        return True  # nothing to test → fail open (never drop a possible message)
    try:
        return fmd_test(base64.b64decode(flag_b64), key, base64.b64decode(addr_b64))
    except Exception:  # noqa: BLE001 — a malformed flag must not drop a real message
        return True

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

# Hard cap on a single sealed blob (audit L3). The base64 "ct" field is bounded
# so a client can't park RECENT_MAX oversized blobs per channel in memory. 64 KiB
# of base64 (~48 KiB binary) is far larger than any real DRIFT message, which is
# a sealed ratchet header plus a short ciphertext.
MAX_CT_B64_LEN = 64 * 1024

# Phase 11 (sovereign rooms): a sender may request a *longer* retention per
# envelope via /send's "ttl_seconds", so a client joining a room can rewind the
# previous catch-up windows (rooms.CATCHUP_WINDOWS × 10 min). The relay caps it
# hard server-side — it never learns the blob is a "room" message, only that
# this one blob asked to live a little longer. Default stays RECENT_TTL.
RECENT_MAX_TTL = 1800.0   # 30 min — the hard server-side cap on requested TTL

# Max simultaneous WebSocket subscribers, across all channels. None = unlimited
# (the full relay). The Pi-Zero node sets this to a small number (see node.py).
MAX_CONNECTIONS: int | None = None


def _prune_recent(channel: str) -> None:
    """Drop expired / overflow envelopes from a channel's replay buffer.

    Each envelope expires on its own TTL: the default ``RECENT_TTL``, or a
    longer per-envelope ``_ttl`` a sender requested (room messages, capped at
    ``RECENT_MAX_TTL``). This is the only change rooms need — the relay still
    cannot tell a room blob from a 1:1 blob; it just honours a longer-lived one.
    """
    now = time.time()
    buf = [
        e for e in _recent[channel]
        if e["_relay_ts"] + e.get("_ttl", RECENT_TTL) >= now
    ]
    if len(buf) > RECENT_MAX:
        buf = buf[-RECENT_MAX:]
    _recent[channel] = buf


def _connection_count() -> int:
    """Total live WebSocket subscribers across every channel."""
    return sum(len(v) for v in _subscribers.values())


def _is_32_byte_b64(value: Any) -> bool:
    """True iff ``value`` is base64 that decodes to exactly 32 bytes (audit L3 —
    a one-time stealth address). The relay validates the shape without learning
    anything: every address is a uniform 32-byte routing tag."""
    if not isinstance(value, str):
        return False
    try:
        # binascii.Error (invalid base64) subclasses ValueError.
        return len(base64.b64decode(value, validate=True)) == 32
    except ValueError:
        return False


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
    # WITNESS: count this routed envelope into the current period's certificate
    # (a Merkle leaf over a public field id — reveals nothing the firehose didn't).
    witness_chain.record_envelope(envelope)
    subscribers = _subscribers.get(to_addr, set())
    delivered = 0
    for ws in list(subscribers):
        # FMD pre-filter (audit M4): an FMD subscriber only gets flag-matching
        # envelopes (+ false positives); classic subscribers get everything.
        if not _passes_fmd(ws, envelope):
            continue
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

# Hard TTL cap enforced regardless of the request (env-overridable). 24 h by
# default: the old 10-minute value was policy for *guessable human handles*,
# which clients still clamp to 600 s themselves (beacon.MAX_TTL_SECONDS).
# High-entropy invite handles (drift.crypto.invite, 128-bit random) are safe at
# 24 h because grinding the handle is infeasible however long the blob lives.
BEACON_MAX_TTL = int(os.environ.get("DRIFT_BEACON_MAX_TTL", str(24 * 3600)))

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


# ---------------------------------------------------------------------------
# Prekeys (X3DH, audit H3) — published bundles for asynchronous key agreement
#
# The relay stores a contact's *public* prekey bundle indexed by their base58
# scan key. It is self-authenticating (the signed prekey carries an Ed25519
# signature the fetcher verifies), so no auth is needed to publish. A GET hands
# out exactly one one-time prekey and atomically removes it — a one-time prekey
# must never be served twice. When the store is exhausted the bundle is returned
# without an OTPK (weaker but valid X3DH per spec). Bundles expire after 30 days
# if not replenished. The relay never sees a private key and learns nothing about
# message content — only that some contact has prekeys available.
# ---------------------------------------------------------------------------

PREKEY_MAX_TTL = 30 * 24 * 3600  # 30 days, server-side expiry

# addr(base58 scan) → {bundle fields, "one_time": [{"id","pub"},…], "stored_at"}
_prekeys: dict[str, dict[str, Any]] = {}

# Required public-bundle fields (everything except the one-time prekey list).
_PREKEY_BUNDLE_FIELDS = (
    "identity_key", "identity_dh_key", "signed_prekey",
    "signed_prekey_sig", "signed_prekey_id",
)


def _prune_prekeys() -> None:
    """Drop prekey bundles past their 30-day TTL."""
    now = time.time()
    for addr in [a for a, b in _prekeys.items() if b["stored_at"] + PREKEY_MAX_TTL <= now]:
        del _prekeys[addr]


def _clean_one_time_list(raw: Any) -> list[dict[str, Any]]:
    """Validate a client-supplied one-time prekey list into ``[{id,pub},…]``."""
    out: list[dict[str, Any]] = []
    if not isinstance(raw, list):
        return out
    for item in raw:
        if (
            isinstance(item, dict)
            and isinstance(item.get("id"), int)
            and isinstance(item.get("pub"), str)
            and item["pub"]
        ):
            out.append({"id": item["id"], "pub": item["pub"]})
    return out


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
# WITNESS (Phase 10) — live, signed, hash-chained proof of relay blindness.
#
# The relay's long-term Ed25519 identity (generated on first start, saved
# chmod 600) signs a fresh blindness certificate every period. The genesis
# certificate is created at construction, so /witness/* works immediately; the
# periodic heartbeat is driven by _witness_loop in the lifespan.
# ---------------------------------------------------------------------------

RELAY_IDENTITY_FILE = os.environ.get("DRIFT_RELAY_IDENTITY", "relay_identity.json")
# Append-only witness log so the chain (and its continuity proof) survives a
# restart instead of resetting to genesis. Override with DRIFT_WITNESS_LOG.
WITNESS_LOG_FILE = os.environ.get("DRIFT_WITNESS_LOG", "witness_chain.jsonl")
witness_chain = WitnessChain(
    load_or_create_relay_identity(RELAY_IDENTITY_FILE), log_path=WITNESS_LOG_FILE
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
            elif msg.get("type") == "fmd":
                # Opt into FMD pre-filtering (audit M4). The ack lets the client
                # (or a test) know filtering is active before it relies on it.
                n = _set_fmd_filter(websocket, msg.get("key"))
                await websocket.send_text(json.dumps({"type": "fmd_ack", "subkeys": n}))
                logger.info("FMD pre-filter enabled addr=%.12s… (%d sub-keys)", listen_addr, n)

    except WebSocketDisconnect:
        _subscribers[listen_addr].discard(websocket)
        _fmd_filters.pop(websocket, None)
        logger.info("Client disconnected addr=%.12s…", listen_addr)


# ---------------------------------------------------------------------------
# HTTP endpoints
# ---------------------------------------------------------------------------

@app.post("/send")
async def send_message(envelope: dict[str, Any], request: Request) -> JSONResponse:
    """
    POST a message envelope to the relay.

    Expected body (sealed sender — Phase 3b):
        {
            "to":   "<channel>",     // firehose routing key (opaque to relay)
            "ct":   "<base64>",      // opaque sealed blob (opaque to relay)
            "ts":   1234567890,      // unix timestamp (for TTL)
            "addr": "<base64>",      // recipient one-time stealth address
            "ttl_seconds": 1800      // OPTIONAL: request longer replay retention
                                     //   (rooms; capped at RECENT_MAX_TTL)
        }

    The relay never inspects "ct" or "addr". The sender's ephemeral key and the
    Double Ratchet header used to ride here in the clear ("R"/"hdr"); as of
    sealed sender they are encrypted inside "ct", so the relay can no longer
    group a sender's messages by ratchet header. Only the recipient, scanning
    with their private scan key, can tell which one-time address is theirs.

    We rebuild the forwarded record from known fields only, so the relay never
    re-broadcasts arbitrary client-supplied JSON to other clients.
    """
    if _rate_limits_on() and not _send_bucket.allow(_client_key(request)):
        return _rate_limited()
    to_addr = envelope.get("to", "")
    if not to_addr:
        return JSONResponse({"error": "missing 'to' field"}, status_code=400)

    # Size + shape validation (audit L3). Without this a client can park up to
    # RECENT_MAX large blobs per channel in memory. The relay still never reads
    # the blob — it only bounds its size and checks the routing address decodes
    # to a 32-byte stealth address.
    ct = envelope.get("ct", "")
    if not isinstance(ct, str) or len(ct) > MAX_CT_B64_LEN:
        return JSONResponse(
            {"error": f"'ct' missing or larger than {MAX_CT_B64_LEN} chars"},
            status_code=413,
        )
    if "addr" in envelope and not _is_32_byte_b64(envelope["addr"]):
        return JSONResponse(
            {"error": "'addr' must be base64 of a 32-byte address"}, status_code=400
        )

    record: dict[str, Any] = {
        "to": to_addr,
        "ct": envelope.get("ct", ""),
        "ts": envelope.get("ts", 0),
        "_relay_ts": time.time(),
        "_id": str(uuid4()),
    }
    # Optional longer retention (Phase 11 rooms): clamp to (0, RECENT_MAX_TTL].
    # Only stored when a sane positive value is requested; otherwise the default
    # RECENT_TTL applies via _prune_recent. The relay learns nothing from this
    # beyond "keep this one blob a bit longer".
    try:
        requested_ttl = float(envelope.get("ttl_seconds", 0) or 0)
    except (TypeError, ValueError):
        requested_ttl = 0.0
    if requested_ttl > 0:
        record["_ttl"] = min(requested_ttl, RECENT_MAX_TTL)
    # Carry the recipient's one-time address through untouched (routing/detection).
    if "addr" in envelope:
        record["addr"] = envelope["addr"]
    # Carry the optional FMD detection flag (audit M4) so FMD subscribers can be
    # pre-filtered. The relay only ever runs fmd_test on it — never reads content.
    if "fmd" in envelope:
        record["fmd"] = envelope["fmd"]

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


@app.get("/beacon/pubkey")
async def beacon_pubkey() -> JSONResponse:
    """The relay's long-term Ed25519 public key (base58) — an alias of
    ``/witness/pubkey``. Clients fetch this before computing a beacon lookup hash
    so the hash is bound to *this* relay (audit M3). Declared before the
    ``/beacon/{lookup_hash}`` route so the literal path wins.
    """
    rid = witness_chain.relay_id
    return JSONResponse({
        "algorithm": "ed25519",
        "pubkey_b58": relay_pubkey_b58(rid),
        "fingerprint": fingerprint(rid),
    })


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


# ---------------------------------------------------------------------------
# Prekey endpoints (X3DH, audit H3)
# ---------------------------------------------------------------------------

@app.post("/prekeys/{contact_addr}")
async def publish_prekeys(
    contact_addr: str, body: dict[str, Any], request: Request
) -> JSONResponse:
    """
    Publish a public prekey bundle, indexed by the publisher's base58 scan key.

    Body: the bundle's public fields plus ``one_time_prekeys: [{id, pub}, …]``.
    No authentication — the bundle is self-authenticating (the signed prekey
    carries an Ed25519 signature the fetcher verifies). Replaces any existing
    bundle for this address.
    """
    if _rate_limits_on() and not _prekey_write_bucket.allow(_client_key(request)):
        return _rate_limited()
    if not contact_addr:
        return JSONResponse({"error": "missing contact_addr"}, status_code=400)
    missing = [f for f in _PREKEY_BUNDLE_FIELDS if not body.get(f)]
    if missing:
        return JSONResponse(
            {"error": f"missing bundle field(s): {', '.join(missing)}"}, status_code=400
        )
    record = {f: body[f] for f in _PREKEY_BUNDLE_FIELDS}
    record["one_time"] = _clean_one_time_list(body.get("one_time_prekeys"))
    record["stored_at"] = time.time()
    _prekeys[contact_addr] = record
    return JSONResponse({"ok": True, "one_time_count": len(record["one_time"])})


@app.get("/prekeys/{contact_addr}")
async def fetch_prekeys(contact_addr: str, request: Request) -> JSONResponse:
    """
    Fetch a contact's bundle, consuming one one-time prekey atomically.

    Returns the signed prekey + identity keys plus exactly one OTPK, which is
    removed from the store so it can never be served twice. If none remain,
    ``one_time_prekey`` is ``null`` (a weaker but valid X3DH per spec). 404 if no
    bundle is published (or it has expired).

    Rate limited twice over — per (IP, target) *and* per target across all IPs —
    because each fetch consumes an OTPK: unthrottled, an attacker could drain a
    victim's pool (rotating Tor circuits for fresh IPs) and force their future
    handshakes onto the weaker OTPK-less path. The global per-address budget
    (burst 30, then 6/min) is far below what auto-replenish tops back up.
    """
    if _rate_limits_on():
        ip_ok = _prekey_fetch_ip_bucket.allow(f"{_client_key(request)}|{contact_addr}")
        addr_ok = _prekey_fetch_addr_bucket.allow(contact_addr)
        if not (ip_ok and addr_ok):
            return _rate_limited()
    _prune_prekeys()
    record = _prekeys.get(contact_addr)
    if record is None:
        return JSONResponse({"error": "no prekey bundle for this contact"}, status_code=404)
    otpk = record["one_time"].pop(0) if record["one_time"] else None  # atomic remove
    response = {f: record[f] for f in _PREKEY_BUNDLE_FIELDS}
    response["one_time_prekey"] = otpk["pub"] if otpk else None
    response["one_time_prekey_id"] = otpk["id"] if otpk else None
    return JSONResponse(response)


@app.post("/prekeys/{contact_addr}/replenish")
async def replenish_prekeys(
    contact_addr: str, body: dict[str, Any], request: Request
) -> JSONResponse:
    """
    Append more one-time prekeys to an existing bundle. Body:
    ``{one_time_prekeys: [{id, pub}, …]}``. 404 if no bundle is published yet
    (publish the full bundle first).
    """
    if _rate_limits_on() and not _prekey_write_bucket.allow(_client_key(request)):
        return _rate_limited()
    _prune_prekeys()
    record = _prekeys.get(contact_addr)
    if record is None:
        return JSONResponse({"error": "no prekey bundle to replenish"}, status_code=404)
    record["one_time"].extend(_clean_one_time_list(body.get("one_time_prekeys")))
    record["stored_at"] = time.time()  # replenishing refreshes the 30-day TTL
    return JSONResponse({"ok": True, "one_time_count": len(record["one_time"])})


@app.get("/prekeys/{contact_addr}/status")
async def prekeys_status(contact_addr: str) -> JSONResponse:
    """Non-consuming counts for ``drift prekeys`` (does not remove an OTPK)."""
    _prune_prekeys()
    record = _prekeys.get(contact_addr)
    if record is None:
        return JSONResponse({"error": "no prekey bundle for this contact"}, status_code=404)
    return JSONResponse({
        "signed_prekey_id": record["signed_prekey_id"],
        "one_time_count": len(record["one_time"]),
        "stored_at": record["stored_at"],
    })


# Single-use burn-token nonces seen recently (audit M2). Bounded LRU, same dedup
# pattern as federation envelope ids — a token whose nonce is already here is a
# replay and is rejected. Sized generously; nonces also age out implicitly because
# a token older than TOKEN_TTL_SECONDS is rejected on its timestamp regardless.
_burn_nonces_seen = LRUSet(DEFAULT_DEDUP_SIZE)


@app.post("/burn")
async def burn_request(body: dict[str, Any], request: Request) -> JSONResponse:
    """
    POST a burn request to erase messages from the relay buffer and notify
    connected clients via a tombstone.

    Expected body:
        {
            "token":      "<nonce>.<ts>.<mac>",     // single-use burn token (M2)
            "scope":      "message"|"conversation",
            "channel":    "<channel name>",
            "message_id": "<base64 addr>"          // required for scope=message
        }

    The relay does NOT verify the HMAC (it has no shared secret). Clients
    verify the token end-to-end before honouring the tombstone — that is the
    security boundary, not anything the relay does.

    What the relay *does* enforce (audit M2): tokens are single-use. It reads the
    nonce and timestamp out of the token (both MAC-bound, so a client would reject
    any tombstone where they were altered), rejects tokens older than
    ``TOKEN_TTL_SECONDS``, and rejects a nonce it has already seen — so a captured
    token cannot be replayed to re-broadcast a tombstone.

    Relay-side erasure is therefore deliberately minimal and addr-scoped (audit
    H2). The firehose is shared by every user, and stealth addresses are
    unlinkable *by design*, so the relay cannot tell which buffered blobs belong
    to one conversation without breaking the core privacy property. It used to
    honour a conversation-scope burn by wiping the whole channel's replay buffer
    — which let *any* unauthenticated caller erase every user's recent traffic
    with one request. The relay now only ever deletes the single blob whose
    one-time address is explicitly named (message scope); a conversation-scope
    burn does not touch the shared buffer at all. Conversation erasure happens
    end-to-end: each client verifies the token and deletes its own copy on the
    tombstone, and any blob left in the relay's buffer expires on its short
    RECENT_TTL. See DESIGN.md ("Burn requests") for the full tradeoff.
    """
    if _rate_limits_on() and not _burn_bucket.allow(_client_key(request)):
        return _rate_limited()
    token = body.get("token", "")
    scope = body.get("scope", "")
    channel = body.get("channel", "")
    message_id: str | None = body.get("message_id") or None

    try:
        nonce_hex, ts, _mac = parse_burn_token(token)
    except BurnTokenError:
        return JSONResponse({"error": "token must be 'nonce.timestamp.mac'"}, status_code=400)
    if scope not in ("message", "conversation"):
        return JSONResponse({"error": "scope must be 'message' or 'conversation'"}, status_code=400)
    if not channel:
        return JSONResponse({"error": "channel is required"}, status_code=400)
    if scope == "message" and not message_id:
        return JSONResponse({"error": "message_id required for scope=message"}, status_code=400)

    # Single-use enforcement (audit M2): reject stale/future tokens on their
    # MAC-bound timestamp, then reject any nonce already seen (replay). The MAC
    # itself is verified end-to-end by the receiving client, not here.
    if abs(int(time.time()) - ts) > TOKEN_TTL_SECONDS:
        return JSONResponse({"error": "token expired or timestamp out of range"}, status_code=400)
    if nonce_hex in _burn_nonces_seen:
        return JSONResponse({"error": "token already used (replay rejected)"}, status_code=409)
    _burn_nonces_seen.add(nonce_hex)

    # Erase only the exact named blob from the replay buffer. A conversation-scope
    # burn intentionally mutates nothing here (the relay can't identify a
    # conversation's blobs without defeating unlinkability, and a blanket wipe was
    # an unauthenticated channel-wide DoS); it relies on the end-to-end-verified
    # tombstone below plus the buffer's own TTL.
    if scope == "message":
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
        "witness": "/cannot-see",
    })


@app.get("/capabilities")
async def capabilities() -> JSONResponse:
    """What this relay speaks (PROTOCOL.md §14 — Extensions).

    The core protocol plus advertised extensions. Extensions are additive and
    never load-bearing for security: a client that recognizes none of them
    proceeds on the core protocol unchanged. The reference relay always ships
    WITNESS, so it is always advertised.
    """
    return JSONResponse({
        "protocol": "DRIFT-P/1",
        "extensions": ["drift-ext/witness/1"],
    })


# ---------------------------------------------------------------------------
# WITNESS endpoints (Phase 10)
# ---------------------------------------------------------------------------

@app.get("/witness/current")
async def witness_current() -> JSONResponse:
    """The most recent blindness certificate, as JSON."""
    return JSONResponse(witness_chain.current().to_dict())


@app.get("/witness/chain")
async def witness_chain_endpoint(limit: int = MAX_CERTS) -> JSONResponse:
    """The last ``limit`` certificates (oldest → newest; capped at 24 hours)."""
    limit = max(1, min(limit, MAX_CERTS))
    certs = witness_chain.chain(limit)
    return JSONResponse({
        "count": len(certs),
        "certificates": [c.to_dict() for c in certs],
    })


@app.get("/witness/verify")
async def witness_verify() -> JSONResponse:
    """A machine-readable verification report over this relay's whole chain."""
    report = verify_chain_report(
        witness_chain.chain(), expected_relay_id=witness_chain.relay_id
    )
    return JSONResponse(report)


@app.get("/witness/pubkey")
async def witness_pubkey() -> JSONResponse:
    """The relay's Ed25519 public key (base58) + a human-readable fingerprint."""
    rid = witness_chain.relay_id
    return JSONResponse({
        "algorithm": "ed25519",
        "pubkey_b58": relay_pubkey_b58(rid),
        "fingerprint": fingerprint(rid),
    })


@app.get("/cannot-see")
async def cannot_see() -> HTMLResponse:
    """A plain-English, terminal-styled rendering of the current certificate."""
    return HTMLResponse(_render_cannot_see())


def _render_cannot_see() -> str:
    """Render the current blindness certificate as a striking HTML page.

    Pure inline styles, no frameworks — matrix green on near-black, the zero
    counts in bright white, the legal-demand answer in dim red. This is the page
    a surveillance request lands on when it walks up to the relay.
    """
    cert = witness_chain.current()
    rid = witness_chain.relay_id
    generated = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(cert.timestamp))
    merkle = cert.envelope_merkle_root.hex()
    prev = cert.previous_cert_hash.hex()
    chain_len = len(witness_chain)
    fp = fingerprint(rid)
    pub = relay_pubkey_b58(rid)
    routed = f"{cert.messages_routed:,}"

    zero = '<span style="color:#ffffff;font-weight:bold">ZERO</span>'
    nothing = '<span style="color:#7a1f1f;font-weight:bold">[NOTHING]</span>'

    body = (
        "DRIFT RELAY WITNESS STATEMENT\n"
        f"Generated: {generated} UTC\n"
        "\n"
        f"In the last {cert.period_seconds} seconds, this relay routed {routed} messages.\n"
        "\n"
        "Here is what I know about those messages:\n"
        "\n"
        f"  Sender identities:          {zero}\n"
        f"  Recipient identities:       {zero}\n"
        f"  Message contents:           {zero}\n"
        f"  Linked conversations:       {zero}\n"
        "\n"
        "Here is what I can produce in response to a legal demand\n"
        'for "all messages sent by Alice":\n'
        "\n"
        f"  {nothing}\n"
        "\n"
        "Not because I am refusing.\n"
        "Because I structurally cannot.\n"
        "The protocol makes it impossible.\n"
        "\n"
        f"Merkle root of routed envelopes: {merkle[:12]}…\n"
        "This statement is signed. Verify at /witness/verify.\n"
        f"Previous statement: {prev[:12]}… "
        f"({chain_len} statements in unbroken chain)\n"
        "\n"
        f"Signed by relay Ed25519 key: {fp}\n"
        f'<span style="color:#1f6f2f">  full key: {pub}</span>'
    )

    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        "<title>DRIFT RELAY — what I cannot see</title>\n"
        "</head>\n"
        '<body style="margin:0;background:#0a0a0a;color:#00ff41;'
        "font-family:'SF Mono',Menlo,Consolas,monospace;font-size:15px;"
        'line-height:1.55;text-shadow:0 0 6px rgba(0,255,65,0.4);">\n'
        '<div style="max-width:780px;margin:0 auto;padding:48px 24px;">\n'
        f'<pre style="margin:0;white-space:pre-wrap;word-break:break-word;">{body}</pre>\n'
        "</div>\n"
        "</body>\n"
        "</html>\n"
    )


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
