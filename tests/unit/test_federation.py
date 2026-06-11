"""
tests/unit/test_federation.py — relay-to-relay gossip (Phase 4a)

No sockets, no live network: two Federation instances are wired directly to
each other through an in-process fake "network" (the injectable sender), so we
exercise the real gossip/dedup/announce logic without binding a port.

Run: pytest tests/unit/test_federation.py -v
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from relay.federation import (
    ANNOUNCE_TTL,
    DEFAULT_GOSSIP_TTL,
    Federation,
    LRUSet,
    blob_id,
    to_http,
    to_ws,
)


def _blob(ct: str = "ciphertext", addr: str = "addr1") -> dict[str, Any]:
    return {"to": "drift-stealth-v1", "ct": ct, "ts": 1, "addr": addr, "_id": "uuid-x"}


# --------------------------------------------------------------------------- #
# In-process fake network
# --------------------------------------------------------------------------- #


class FakeNet:
    """Routes Federation sender() calls to the target node's handlers."""

    def __init__(self) -> None:
        self.nodes: dict[str, Federation] = {}

    def register(self, url: str, fed: Federation) -> None:
        self.nodes[to_http(url)] = fed

    async def send(self, peer_url: str, path: str, payload: dict[str, Any]) -> bool:
        fed = self.nodes.get(to_http(peer_url))
        if fed is None:
            return False
        if path == "/federation/gossip":
            await fed.handle_gossip(payload["envelope"], payload["ttl"])
            return True
        if path == "/federation/announce":
            await fed.handle_announce(payload["url"], payload["ttl"])
            return True
        return False


def _node(net: FakeNet, url: str, peers: list[str], delivered: list[dict[str, Any]]) -> Federation:
    fed = Federation(
        self_url=url,
        peers=peers,
        sender=net.send,
        deliver=lambda env: _record(delivered, env),
    )
    net.register(url, fed)
    return fed


async def _record(sink: list[dict[str, Any]], env: dict[str, Any]) -> int:
    sink.append(env)
    return 1


# --------------------------------------------------------------------------- #
# Content addressing
# --------------------------------------------------------------------------- #


def test_blob_id_ignores_relay_bookkeeping() -> None:
    a = {"to": "x", "ct": "y", "ts": 1, "_id": "uuid-a", "_relay_ts": 100.0}
    b = {"to": "x", "ct": "y", "ts": 1, "_id": "uuid-b", "_relay_ts": 999.0}
    assert blob_id(a) == blob_id(b)


def test_blob_id_differs_on_content() -> None:
    assert blob_id(_blob(ct="one")) != blob_id(_blob(ct="two"))


def test_to_http_and_ws_roundtrip() -> None:
    assert to_http("ws://r:8765/") == "http://r:8765"
    assert to_ws("https://r:8765") == "wss://r:8765"


# --------------------------------------------------------------------------- #
# LRU dedup cache
# --------------------------------------------------------------------------- #


class TestLRUSet:
    def test_evicts_oldest_past_capacity(self) -> None:
        lru = LRUSet(3)
        for k in ("a", "b", "c", "d"):
            lru.add(k)
        assert "a" not in lru        # evicted
        assert "d" in lru and len(lru) == 3

    def test_readd_refreshes_recency(self) -> None:
        lru = LRUSet(2)
        lru.add("a")
        lru.add("b")
        lru.add("a")               # 'a' is now most-recent
        lru.add("c")               # evicts 'b', not 'a'
        assert "a" in lru and "c" in lru and "b" not in lru

    def test_set_capacity_shrinks(self) -> None:
        lru = LRUSet(10)
        for k in "abcdef":
            lru.add(k)
        lru.set_capacity(2)
        assert len(lru) == 2


# --------------------------------------------------------------------------- #
# Gossip
# --------------------------------------------------------------------------- #


class TestGossip:
    @pytest.mark.asyncio
    async def test_blob_gossips_to_peer(self) -> None:
        net = FakeNet()
        a_recv: list[dict[str, Any]] = []
        b_recv: list[dict[str, Any]] = []
        a = _node(net, "http://a", ["http://b"], a_recv)
        _node(net, "http://b", ["http://a"], b_recv)

        replicas = await a.submit(_blob())

        assert replicas == 1                 # replicated to one peer (B)
        assert len(b_recv) == 1              # B received it via gossip
        assert b_recv[0]["ct"] == "ciphertext"

    @pytest.mark.asyncio
    async def test_duplicate_blob_delivered_once(self) -> None:
        net = FakeNet()
        b_recv: list[dict[str, Any]] = []
        a = _node(net, "http://a", ["http://b"], [])
        _node(net, "http://b", ["http://a"], b_recv)

        blob = _blob()
        await a.submit(blob)
        await a.submit(blob)                 # same content again

        # B saw the blob exactly once — the second copy is deduped silently.
        assert len(b_recv) == 1

    @pytest.mark.asyncio
    async def test_three_node_flood_reaches_all(self) -> None:
        # a → b → c (a doesn't know c directly). TTL must carry it the 2nd hop.
        net = FakeNet()
        b_recv: list[dict[str, Any]] = []
        c_recv: list[dict[str, Any]] = []
        a = _node(net, "http://a", ["http://b"], [])
        _node(net, "http://b", ["http://a", "http://c"], b_recv)
        _node(net, "http://c", ["http://b"], c_recv)

        await a.submit(_blob())

        assert len(b_recv) == 1
        assert len(c_recv) == 1              # reached via B's onward gossip

    @pytest.mark.asyncio
    async def test_ttl_zero_stops_forwarding(self) -> None:
        net = FakeNet()
        b_recv: list[dict[str, Any]] = []
        c_recv: list[dict[str, Any]] = []
        _node(net, "http://a", ["http://b"], [])
        b = _node(net, "http://b", ["http://a", "http://c"], b_recv)
        _node(net, "http://c", ["http://b"], c_recv)

        # Arrive at B with TTL=1 → B delivers locally but does NOT forward.
        await b.handle_gossip(_blob(), ttl=1)
        assert len(b_recv) == 1
        assert len(c_recv) == 0

    @pytest.mark.asyncio
    async def test_submit_starts_at_default_ttl(self) -> None:
        seen_ttls: list[int] = []

        async def spy(peer: str, path: str, payload: dict[str, Any]) -> bool:
            seen_ttls.append(payload["ttl"])
            return True

        a = Federation(self_url="http://a", peers=["http://b"], sender=spy)
        await a.submit(_blob())
        assert seen_ttls == [DEFAULT_GOSSIP_TTL]


# --------------------------------------------------------------------------- #
# Replication guarantee
# --------------------------------------------------------------------------- #


class TestReplication:
    @pytest.mark.asyncio
    async def test_replicates_to_at_least_two_peers(self) -> None:
        net = FakeNet()
        a = _node(net, "http://a", ["http://b", "http://c"], [])
        _node(net, "http://b", ["http://a"], [])
        _node(net, "http://c", ["http://a"], [])

        replicas = await a.submit(_blob())
        assert replicas >= 2

    @pytest.mark.asyncio
    async def test_replication_lag_reported(self) -> None:
        net = FakeNet()
        # Two peers known, but only one reachable → lag of 1 against target 2.
        a = Federation(self_url="http://a", peers=["http://b", "http://gone"], sender=net.send)
        _node(net, "http://b", ["http://a"], [])
        await a.submit(_blob())
        status = a.status()
        assert status["peers"] == 2
        assert status["replication_lag"] == 1


# --------------------------------------------------------------------------- #
# Announce
# --------------------------------------------------------------------------- #


class TestAnnounce:
    @pytest.mark.asyncio
    async def test_announce_adds_peer(self) -> None:
        net = FakeNet()
        b = _node(net, "http://b", [], [])
        learned = await b.handle_announce("http://newcomer", ttl=ANNOUNCE_TTL)
        assert learned is True
        assert "http://newcomer" in b.peers

    @pytest.mark.asyncio
    async def test_announce_propagates_one_more_hop(self) -> None:
        net = FakeNet()
        # B knows C. A newcomer announces to B with ttl=2 → B re-announces to C.
        _node(net, "http://b", ["http://c"], [])
        c = _node(net, "http://c", ["http://b"], [])
        b = net.nodes["http://b"]

        await b.handle_announce("http://newcomer", ttl=ANNOUNCE_TTL)
        assert "http://newcomer" in c.peers   # learned via B's propagation

    @pytest.mark.asyncio
    async def test_announce_does_not_loop_back_to_announcer(self) -> None:
        sent_to: list[str] = []

        async def spy(peer: str, path: str, payload: dict[str, Any]) -> bool:
            sent_to.append(peer)
            return True

        b = Federation(self_url="http://b", peers=["http://newcomer"], sender=spy)
        await b.handle_announce("http://newcomer", ttl=ANNOUNCE_TTL)
        # Must not re-announce the newcomer back to itself.
        assert "http://newcomer" not in sent_to


# --------------------------------------------------------------------------- #
# Peer persistence
# --------------------------------------------------------------------------- #


class TestPeerPersistence:
    def test_save_and_load_roundtrip(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        pf = tmp_path / "peers.json"
        a = Federation(self_url="http://a", peers=["http://b"], peers_file=pf)
        a.add_peer("http://c")
        assert pf.exists()

        b = Federation(self_url="http://a", peers_file=pf)
        b.load_peers()
        assert "http://b" in b.peers
        assert "http://c" in b.peers

    def test_load_seeds_from_env(self, tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        monkeypatch.setenv("DRIFT_PEERS", "http://x, http://y")
        a = Federation(self_url="http://a", peers_file=tmp_path / "none.json")
        a.load_peers()
        assert "http://x" in a.peers
        assert "http://y" in a.peers

    def test_never_adds_self_as_peer(self) -> None:
        a = Federation(self_url="http://a")
        assert a.add_peer("http://a") is False
        assert a.add_peer("ws://a") is False    # same node, different scheme
        assert a.peers == []

    def test_save_writes_valid_json(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        pf = tmp_path / "peers.json"
        a = Federation(self_url="http://a", peers=["http://b", "http://c"], peers_file=pf)
        a.save_peers()
        data = json.loads(pf.read_text())
        assert sorted(data["peers"]) == ["http://b", "http://c"]
