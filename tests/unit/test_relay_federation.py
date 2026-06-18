"""
tests/unit/test_relay_federation.py — relay federation endpoints (Phase 4a)

Drives the FastAPI relay with the synchronous TestClient (no running server).
The module-global federation is swapped for a fresh, network-free instance per
test so gossip/announce never touch a real peer or write peers.json.

Run: pytest tests/unit/test_relay_federation.py -v
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

import relay.server as server
from relay.federation import Federation


@pytest.fixture(autouse=True)
def _fresh_relay() -> Any:
    """Reset relay state and install a fresh, peer-recording federation."""
    server._recent.clear()
    server._subscribers.clear()
    sent: list[tuple[str, str, dict[str, Any]]] = []

    async def _record(peer: str, path: str, payload: dict[str, Any]) -> bool:
        sent.append((peer, path, payload))
        return True

    server.federation = Federation(
        self_url="http://self",
        peers=[],
        peers_file=None,           # no disk writes
        sender=_record,
        deliver=server._deliver_local,
    )
    server.federation._sent = sent  # type: ignore[attr-defined]  # for assertions
    server.MAX_CONNECTIONS = None
    yield
    server.MAX_CONNECTIONS = None


@pytest.fixture()
def client() -> TestClient:
    return TestClient(server.app)


_CHANNEL = "drift-stealth-v1"


def _blob() -> dict[str, Any]:
    return {"to": _CHANNEL, "ct": "aGk=", "ts": 1, "addr": "YWRkcg=="}


# --------------------------------------------------------------------------- #
# /federation/peers
# --------------------------------------------------------------------------- #


def test_peers_empty_initially(client: TestClient) -> None:
    r = client.get("/federation/peers")
    assert r.status_code == 200
    assert r.json() == {"peers": []}


def test_announce_adds_peer_and_lists_it(client: TestClient) -> None:
    r = client.post("/federation/announce", json={"url": "http://peer1", "ttl": 2})
    assert r.status_code == 200
    body = r.json()
    assert body["learned"] is True
    assert "http://peer1" in body["peers"]

    r2 = client.get("/federation/peers")
    assert "http://peer1" in r2.json()["peers"]


def test_announce_rejects_missing_url(client: TestClient) -> None:
    r = client.post("/federation/announce", json={"ttl": 2})
    assert r.status_code == 400


# --------------------------------------------------------------------------- #
# /federation/gossip
# --------------------------------------------------------------------------- #


def test_gossip_delivers_to_local_subscriber(client: TestClient) -> None:
    with client.websocket_connect(f"/ws/{_CHANNEL}") as ws:
        r = client.post("/federation/gossip", json={"envelope": _blob(), "ttl": 3})
        assert r.status_code == 200
        assert r.json()["accepted"] is True
        msg = ws.receive_json()
        assert msg["ct"] == "aGk="


def test_gossip_dedups_repeat(client: TestClient) -> None:
    first = client.post("/federation/gossip", json={"envelope": _blob(), "ttl": 3})
    second = client.post("/federation/gossip", json={"envelope": _blob(), "ttl": 3})
    assert first.json()["accepted"] is True
    assert second.json()["accepted"] is False     # deduped


def test_gossip_rejects_missing_envelope(client: TestClient) -> None:
    r = client.post("/federation/gossip", json={"ttl": 3})
    assert r.status_code == 400


# --------------------------------------------------------------------------- #
# /send replication + /health
# --------------------------------------------------------------------------- #


def test_send_reports_replication_count(client: TestClient) -> None:
    # Two peers known → /send replicates to both (recording sender accepts all).
    server.federation.add_peer("http://peer1")
    server.federation.add_peer("http://peer2")
    r = client.post("/send", json={"to": _CHANNEL, "ct": "aGk=", "ts": 1})
    assert r.status_code == 200
    assert r.json()["replicated"] == 2


# --------------------------------------------------------------------------- #
# /send size + shape validation (audit L3)
# --------------------------------------------------------------------------- #


def test_send_rejects_oversized_ct(client: TestClient) -> None:
    big = "A" * (server.MAX_CT_B64_LEN + 1)
    r = client.post("/send", json={"to": _CHANNEL, "ct": big, "ts": 1})
    assert r.status_code == 413


def test_send_accepts_ct_at_cap(client: TestClient) -> None:
    ok = "A" * server.MAX_CT_B64_LEN
    r = client.post("/send", json={"to": _CHANNEL, "ct": ok, "ts": 1})
    assert r.status_code == 200


def test_send_rejects_malformed_addr(client: TestClient) -> None:
    import base64

    # An address that doesn't decode to exactly 32 bytes is rejected.
    short = base64.b64encode(b"too short").decode()
    r = client.post("/send", json={"to": _CHANNEL, "ct": "aGk=", "addr": short, "ts": 1})
    assert r.status_code == 400


def test_send_accepts_valid_32_byte_addr(client: TestClient) -> None:
    import base64

    addr = base64.b64encode(bytes(range(32))).decode()
    r = client.post("/send", json={"to": _CHANNEL, "ct": "aGk=", "addr": addr, "ts": 1})
    assert r.status_code == 200


def test_health_includes_federation_status(client: TestClient) -> None:
    server.federation.add_peer("http://peer1")
    r = client.get("/health")
    assert r.status_code == 200
    fed = r.json()["federation"]
    assert fed["peers"] == 1
    assert "replication_lag" in fed
    assert "seen_ids" in fed


# --------------------------------------------------------------------------- #
# MAX_CONNECTIONS cap (node resource limit)
# --------------------------------------------------------------------------- #


def test_connection_cap_refuses_excess(client: TestClient) -> None:
    server.MAX_CONNECTIONS = 1
    with client.websocket_connect(f"/ws/{_CHANNEL}"):
        # First subscriber occupies the only slot; a second is refused at accept
        # with an "at capacity" error frame before the socket is closed.
        with client.websocket_connect(f"/ws/{_CHANNEL}") as ws2:
            data = ws2.receive_json()
            assert data.get("error") == "node at capacity"
