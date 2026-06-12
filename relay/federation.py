"""
relay.federation — relay-to-relay gossip (Phase 4a)

Turns a single relay into one node of a federated mesh. There is no longer a
single server to kill, subpoena, or take down: every relay gossips the opaque
blobs it receives to its peers, so a message that reaches *any* node propagates
to the whole reachable network.

What this module is responsible for
-----------------------------------
- **Known peers** — a set of peer relay URLs, persisted to ``peers.json`` and
  seeded from the ``DRIFT_PEERS`` env var.
- **Content-addressed dedup** — every blob has a SHA256 id derived from its
  client-supplied fields (not the relay's per-hop uuid), so the same blob
  arriving by two gossip paths is recognised and dropped. Ids live in a bounded
  LRU (default 10k) so memory can't grow without bound.
- **TTL gossip** — a blob is forwarded to all peers with a hop counter that
  starts at 5 and decrements each hop; at 0 it stops. This floods the mesh
  without looping forever.
- **Announce** — a relay announces itself to a peer; the peer records it and
  re-announces onward, capped at 2 hops (announcements shouldn't flood as far
  as data).
- **Replication** — :meth:`Federation.submit` returns how many peers accepted a
  blob so the origin relay can wait for ≥2 replicas before it tells the client
  "200 OK".

What this module never does
---------------------------
Read, decrypt, or interpret a blob. Federation moves the same opaque ciphertext
the relay already routes; the E2E layers (stealth + Double Ratchet, and Tor
underneath) are entirely independent of it. The dedup id is a hash of already-
public wire fields — it reveals nothing the relay didn't already forward.

Testability
-----------
All network I/O goes through two injectable callables — ``sender`` (POST to a
peer) and ``deliver`` (hand a blob to the local relay) — so two Federation
instances can be wired directly to each other in-process, with no sockets and
no live network. The server supplies httpx-backed defaults.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

logger = logging.getLogger("drift.relay.federation")

# Gossip flood radius: a data blob is forwarded at most this many hops.
DEFAULT_GOSSIP_TTL = 5
# Announcements travel less far than data — just enough to introduce a node.
ANNOUNCE_TTL = 2
# How many ids to remember for dedup before evicting the oldest.
DEFAULT_DEDUP_SIZE = 10_000
# Replication target before the origin relay acknowledges a client send.
DEFAULT_MIN_REPLICAS = 2

# sender(peer_url, path, payload) -> True if the peer accepted (HTTP 2xx).
Sender = Callable[[str, str, dict[str, Any]], Awaitable[bool]]
# deliver(envelope) -> number of local subscribers the blob reached.
Deliver = Callable[[dict[str, Any]], Awaitable[int]]


# ---------------------------------------------------------------------------
# Content addressing
# ---------------------------------------------------------------------------

# The wire fields that define a blob's identity. Deliberately excludes the
# relay's own per-hop bookkeeping (_id uuid, _relay_ts) so the *same* client
# blob hashes identically on every relay it visits — that is what makes
# cross-relay dedup work. Since sealed sender (Phase 3b) the only fields are the
# opaque ciphertext, the one-time address, and the timestamp.
_ID_FIELDS = ("to", "ct", "ts", "addr")


def blob_id(envelope: dict[str, Any]) -> str:
    """
    Deterministic SHA256 id for a blob, over its client-supplied fields only.

    Independent of which relay computes it, so a blob that reaches a node twice
    (via two gossip paths) collides and is dropped.
    """
    canonical = {k: envelope[k] for k in _ID_FIELDS if k in envelope}
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode()).hexdigest()


def _beacon_id(beacon: dict[str, Any]) -> str:
    """Dedup id for a beacon — namespaced by its lookup hash (Phase 6)."""
    return "beacon:" + str(beacon.get("lookup_hash", ""))


# ---------------------------------------------------------------------------
# Bounded LRU set (dedup cache)
# ---------------------------------------------------------------------------


class LRUSet:
    """A set with a maximum size that evicts the least-recently-added id."""

    def __init__(self, capacity: int) -> None:
        self._capacity = max(1, capacity)
        self._items: OrderedDict[str, None] = OrderedDict()

    @property
    def capacity(self) -> int:
        return self._capacity

    def set_capacity(self, capacity: int) -> None:
        """Shrink/grow the cache (used to tune a low-power node down to 1k)."""
        self._capacity = max(1, capacity)
        while len(self._items) > self._capacity:
            self._items.popitem(last=False)

    def __contains__(self, key: str) -> bool:
        return key in self._items

    def add(self, key: str) -> None:
        if key in self._items:
            self._items.move_to_end(key)
            return
        self._items[key] = None
        if len(self._items) > self._capacity:
            self._items.popitem(last=False)

    def __len__(self) -> int:
        return len(self._items)


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------


def to_http(url: str) -> str:
    """Normalise a peer/relay URL to its http(s) base for federation POSTs."""
    return url.replace("wss://", "https://", 1).replace("ws://", "http://", 1).rstrip("/")


def to_ws(url: str) -> str:
    """Normalise a peer/relay URL to its ws(s) base for client subscription."""
    return url.replace("https://", "wss://", 1).replace("http://", "ws://", 1).rstrip("/")


# ---------------------------------------------------------------------------
# Federation
# ---------------------------------------------------------------------------


class Federation:
    """
    The gossip state and protocol for one relay node.

    ``self_url`` is this node's externally reachable base URL (used so peers can
    announce it onward and so we never gossip a blob back to ourselves).
    """

    def __init__(
        self,
        *,
        self_url: str | None = None,
        peers: list[str] | None = None,
        peers_file: str | Path | None = None,
        dedup_size: int = DEFAULT_DEDUP_SIZE,
        gossip_ttl: int = DEFAULT_GOSSIP_TTL,
        min_replicas: int = DEFAULT_MIN_REPLICAS,
        sender: Sender | None = None,
        deliver: Deliver | None = None,
        deliver_beacon: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
    ) -> None:
        self._self_url = to_http(self_url) if self_url else None
        self._peers_file = Path(peers_file) if peers_file else None
        self._gossip_ttl = gossip_ttl
        self._min_replicas = min_replicas
        self._seen = LRUSet(dedup_size)
        self._sender: Sender = sender or _httpx_sender
        self._deliver = deliver
        # Phase 6: a beacon (ephemeral discoverable handle) gossips like a blob.
        self._deliver_beacon = deliver_beacon

        self._peers: set[str] = set()
        for url in peers or []:
            self._add_peer_url(url)

        # Lightweight metrics surfaced via /health.
        self._gossip_sent = 0
        self._gossip_received = 0
        self._dropped_duplicates = 0
        self._last_replica_count = 0

    # -- peers -----------------------------------------------------------

    @property
    def peers(self) -> list[str]:
        """Known peer base URLs (http form), sorted for stable output."""
        return sorted(self._peers)

    def set_self_url(self, url: str) -> None:
        """Set this node's external URL (e.g. its .onion) after construction."""
        self._self_url = to_http(url) if url else None

    def set_dedup_capacity(self, capacity: int) -> None:
        """Resize the dedup LRU (a low-power node tunes this down to ~1k)."""
        self._seen.set_capacity(capacity)

    def _add_peer_url(self, url: str) -> bool:
        """Add a peer (normalised); never add ourselves. True if newly added."""
        norm = to_http(url)
        if not norm or (self._self_url and norm == self._self_url):
            return False
        if norm in self._peers:
            return False
        self._peers.add(norm)
        return True

    def add_peer(self, url: str) -> bool:
        """Public peer add that also persists the updated list."""
        added = self._add_peer_url(url)
        if added:
            self.save_peers()
        return added

    def load_peers(self) -> None:
        """Seed peers from peers.json (if present) and the DRIFT_PEERS env var."""
        if self._peers_file and self._peers_file.exists():
            try:
                data = json.loads(self._peers_file.read_text())
                for url in data.get("peers", []):
                    self._add_peer_url(url)
            except (OSError, json.JSONDecodeError) as exc:
                logger.warning("federation: could not read %s: %s", self._peers_file, exc)
        env = os.environ.get("DRIFT_PEERS", "")
        for url in (u.strip() for u in env.split(",")):
            if url:
                self._add_peer_url(url)

    def save_peers(self) -> None:
        """Persist the known-peer list to peers.json (best-effort)."""
        if not self._peers_file:
            return
        try:
            self._peers_file.write_text(json.dumps({"peers": self.peers}, indent=2))
        except OSError as exc:
            logger.warning("federation: could not write %s: %s", self._peers_file, exc)

    # -- metrics ---------------------------------------------------------

    def status(self) -> dict[str, Any]:
        """Federation summary for the /health endpoint."""
        return {
            "peers": len(self._peers),
            "peer_urls": self.peers,
            "seen_ids": len(self._seen),
            "dedup_capacity": self._seen.capacity,
            "gossip_sent": self._gossip_sent,
            "gossip_received": self._gossip_received,
            "dropped_duplicates": self._dropped_duplicates,
            # "Replication lag": shortfall of the last submit against the target
            # (0 when we replicated to at least min_replicas, or have no peers).
            "replication_lag": max(0, min(self._min_replicas, len(self._peers))
                                   - self._last_replica_count),
        }

    # -- gossip ----------------------------------------------------------

    async def submit(self, envelope: dict[str, Any]) -> int:
        """
        Ingest a blob that arrived from a *client* and replicate it to peers.

        Marks the blob seen (so the gossip echo from peers is dropped), then
        floods it to every peer at the starting TTL. Returns the number of peers
        that accepted it — the origin relay waits for ≥ min_replicas of these
        before acknowledging the client.
        """
        cid = blob_id(envelope)
        self._seen.add(cid)
        replicas = await self._gossip(envelope, self._gossip_ttl)
        self._last_replica_count = replicas
        return replicas

    async def handle_gossip(self, envelope: dict[str, Any], ttl: int) -> bool:
        """
        Handle a blob gossiped to us by a peer.

        Returns False (and does nothing) if we've already seen this blob —
        content-addressed dedup, dropped silently. Otherwise delivers it to our
        local subscribers and, if the TTL allows, forwards it onward at ttl-1.
        """
        self._gossip_received += 1
        cid = blob_id(envelope)
        if cid in self._seen:
            self._dropped_duplicates += 1
            return False
        self._seen.add(cid)
        if self._deliver is not None:
            await self._deliver(envelope)
        if ttl > 1:
            await self._gossip(envelope, ttl - 1)
        return True

    async def _gossip(self, envelope: dict[str, Any], ttl: int) -> int:
        """POST the blob to every peer at the given TTL; count acceptances."""
        if ttl <= 0 or not self._peers:
            return 0
        payload = {"envelope": envelope, "ttl": ttl}
        results = await asyncio.gather(
            *(self._sender(peer, "/federation/gossip", payload) for peer in self.peers),
            return_exceptions=True,
        )
        accepted = sum(1 for r in results if r is True)
        self._gossip_sent += accepted
        return accepted

    # -- beacons (Phase 6) ----------------------------------------------

    async def submit_beacon(self, beacon: dict[str, Any]) -> int:
        """
        A beacon arrived from a client → replicate it to peers.

        ``beacon`` carries ``{lookup_hash, payload, expires_at}``; the absolute
        ``expires_at`` is gossiped so every relay expires it at the same instant.
        Deduped by lookup_hash so the gossip echo is dropped.
        """
        self._seen.add(_beacon_id(beacon))
        return await self._gossip_beacon(beacon, self._gossip_ttl)

    async def handle_beacon_gossip(self, beacon: dict[str, Any], ttl: int) -> bool:
        """Handle a beacon gossiped by a peer (dedup, store locally, forward)."""
        self._gossip_received += 1
        bid = _beacon_id(beacon)
        if bid in self._seen:
            self._dropped_duplicates += 1
            return False
        self._seen.add(bid)
        if self._deliver_beacon is not None:
            await self._deliver_beacon(beacon)
        if ttl > 1:
            await self._gossip_beacon(beacon, ttl - 1)
        return True

    async def _gossip_beacon(self, beacon: dict[str, Any], ttl: int) -> int:
        if ttl <= 0 or not self._peers:
            return 0
        payload = {"beacon": beacon, "ttl": ttl}
        results = await asyncio.gather(
            *(self._sender(peer, "/federation/beacon", payload) for peer in self.peers),
            return_exceptions=True,
        )
        accepted = sum(1 for r in results if r is True)
        self._gossip_sent += accepted
        return accepted

    # -- announce --------------------------------------------------------

    async def handle_announce(self, url: str, ttl: int) -> bool:
        """
        Record an announcing peer and propagate the announcement onward.

        Returns True if the peer was newly learned. Propagation is capped by
        ``ttl`` (starts at ANNOUNCE_TTL) so announcements don't flood as far as
        data blobs.
        """
        added = self.add_peer(url)
        if ttl > 1:
            # Tell our *other* peers about the newcomer, one hop shorter.
            payload = {"url": url, "ttl": ttl - 1}
            targets = [p for p in self.peers if p != to_http(url)]
            await asyncio.gather(
                *(self._sender(peer, "/federation/announce", payload) for peer in targets),
                return_exceptions=True,
            )
        return added

    async def announce_self(self) -> None:
        """Announce this node to all known peers (called on startup)."""
        if not self._self_url or not self._peers:
            return
        payload = {"url": self._self_url, "ttl": ANNOUNCE_TTL}
        await asyncio.gather(
            *(self._sender(peer, "/federation/announce", payload) for peer in self.peers),
            return_exceptions=True,
        )


# ---------------------------------------------------------------------------
# Default httpx-backed sender
# ---------------------------------------------------------------------------


async def _httpx_sender(peer_url: str, path: str, payload: dict[str, Any]) -> bool:
    """Default sender: POST JSON to a peer's federation endpoint over HTTP."""
    import httpx

    url = f"{to_http(peer_url)}{path}"
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(url, json=payload)
            return resp.status_code < 300
    except httpx.HTTPError as exc:
        logger.debug("federation: gossip to %s failed: %s", url, exc)
        return False
