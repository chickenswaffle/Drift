"""
tests/unit/test_relay_beacon.py — relay beacon endpoints + federation (Phase 6)

Drives the FastAPI relay with the synchronous TestClient. Verifies the relay
indexes beacons by lookup_hash only (never the plaintext handle), caps the TTL,
deletes on expiry/extinguish, and gossips beacons to peers like message blobs.

Run: pytest tests/unit/test_relay_beacon.py -v
"""

from __future__ import annotations

import base64
import time
from typing import Any

import pytest
from fastapi.testclient import TestClient

import relay.server as server
from drift.crypto import Identity
from drift.crypto.beacon import create_beacon, lookup_hash, resolve_beacon
from relay.federation import Federation

# Fixed stand-in relay pubkey for hash consistency between create_beacon and
# lookup_hash (audit M3). The relay stores under whatever hash the client sends,
# so any consistent value works here; the real pubkey is exercised separately in
# TestBeaconPubkey.
_RELAY_PK = bytes(range(32))


@pytest.fixture(autouse=True)
def _fresh_relay() -> Any:
    """Reset relay state + install a fresh, peer-recording federation."""
    server._beacons.clear()
    sent: list[tuple[str, str, dict[str, Any]]] = []

    async def _record(peer: str, path: str, payload: dict[str, Any]) -> bool:
        sent.append((peer, path, payload))
        return True

    server.federation = Federation(
        self_url="http://self", peers=[], peers_file=None,
        sender=_record, deliver=server._deliver_local, deliver_beacon=server._store_beacon,
    )
    server.federation._sent = sent  # type: ignore[attr-defined]
    yield


@pytest.fixture()
def client() -> TestClient:
    return TestClient(server.app)


def _light(client: TestClient, handle: str, ttl: int = 300) -> tuple[str, str, Identity]:
    """Light a beacon via the relay; return (lookup_hash, payload_b64, identity)."""
    idy = Identity.generate()
    b = create_beacon(idy, handle, ttl, _RELAY_PK)
    payload_b64 = base64.b64encode(b.encrypted).decode()
    r = client.post("/beacon", json={
        "lookup_hash": b.lookup_hash, "payload": payload_b64, "ttl_seconds": ttl,
    })
    assert r.status_code == 200
    return b.lookup_hash, payload_b64, idy


# --------------------------------------------------------------------------- #
# POST / GET / DELETE
# --------------------------------------------------------------------------- #


class TestBeaconLifecycle:
    def test_post_then_get_round_trips(self, client: TestClient) -> None:
        digest, payload_b64, idy = _light(client, "Diego552")
        r = client.get(f"/beacon/{digest}")
        assert r.status_code == 200
        assert r.json()["payload"] == payload_b64
        # And the fetched payload resolves back to the real contact code.
        info = resolve_beacon("Diego552", base64.b64decode(r.json()["payload"]))
        assert info is not None and info.contact_code == idy.contact_code()

    def test_get_unknown_is_404(self, client: TestClient) -> None:
        assert client.get(f"/beacon/{lookup_hash('nobody', _RELAY_PK)}").status_code == 404

    def test_delete_extinguishes(self, client: TestClient) -> None:
        digest, _, _ = _light(client, "Diego552")
        assert client.delete(f"/beacon/{digest}").status_code == 200
        assert client.get(f"/beacon/{digest}").status_code == 404


# --------------------------------------------------------------------------- #
# Relay blindness — the plaintext handle is never stored or returned
# --------------------------------------------------------------------------- #


class TestRelayBlindness:
    def test_relay_state_holds_only_lookup_hash(self, client: TestClient) -> None:
        _light(client, "SuperSecretHandle")
        # The handle string appears nowhere in the relay's beacon state.
        assert "SuperSecretHandle" not in repr(server._beacons)
        assert all(len(h) == 64 for h in server._beacons)  # all keys are sha256 hex

    def test_lookup_hash_is_client_sha256(self, client: TestClient) -> None:
        digest, _, _ = _light(client, "Diego552")
        assert digest == lookup_hash("Diego552", _RELAY_PK)
        assert digest in server._beacons


# --------------------------------------------------------------------------- #
# TTL cap + expiry deletion
# --------------------------------------------------------------------------- #


class TestTTL:
    def test_ttl_capped_server_side(self, client: TestClient) -> None:
        idy = Identity.generate()
        b = create_beacon(idy, "Diego552", 3600, _RELAY_PK)  # client clamps too; force raw post
        over = server.BEACON_MAX_TTL + 3600
        r = client.post("/beacon", json={
            "lookup_hash": b.lookup_hash,
            "payload": base64.b64encode(b.encrypted).decode(),
            "ttl_seconds": over,  # ask for more than the cap
        })
        assert r.status_code == 200
        # Server clamps storage to BEACON_MAX_TTL regardless of the request.
        assert r.json()["ttl_seconds"] == server.BEACON_MAX_TTL
        assert r.json()["expires_at"] <= int(time.time()) + server.BEACON_MAX_TTL

    def test_ttl_cap_env_overridable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # BEACON_MAX_TTL is read from $DRIFT_BEACON_MAX_TTL at import time; the
        # default is 24 h for high-entropy invite handles (clients still clamp
        # human handles to beacon.MAX_TTL_SECONDS themselves).
        import importlib

        assert server.BEACON_MAX_TTL == 24 * 3600
        monkeypatch.setenv("DRIFT_BEACON_MAX_TTL", "600")
        reloaded = importlib.reload(server)
        try:
            assert reloaded.BEACON_MAX_TTL == 600
        finally:
            monkeypatch.delenv("DRIFT_BEACON_MAX_TTL")
            importlib.reload(server)

    def test_expiry_deletes_not_hides(self, client: TestClient) -> None:
        digest, _, _ = _light(client, "Diego552", ttl=300)
        # Force the stored entry to be already expired, then GET.
        server._beacons[digest]["expires_at"] = int(time.time()) - 1
        assert client.get(f"/beacon/{digest}").status_code == 404
        assert digest not in server._beacons  # deleted, not just hidden


# --------------------------------------------------------------------------- #
# Relay pubkey endpoint (audit M3)
# --------------------------------------------------------------------------- #


class TestBeaconPubkey:
    def test_beacon_pubkey_matches_witness_pubkey(self, client: TestClient) -> None:
        # /beacon/pubkey is an alias of /witness/pubkey; clients fetch it before
        # computing the relay-specific lookup hash.
        bp = client.get("/beacon/pubkey")
        wp = client.get("/witness/pubkey")
        assert bp.status_code == 200
        assert bp.json()["pubkey_b58"] == wp.json()["pubkey_b58"]
        assert bp.json()["algorithm"] == "ed25519"

    def test_beacon_pubkey_not_shadowed_by_lookup_route(self, client: TestClient) -> None:
        # The literal /beacon/pubkey must win over /beacon/{lookup_hash}: a real
        # lookup hash is 64 hex chars, "pubkey" is not, so it can't collide — but
        # guard the routing order regardless.
        assert "pubkey_b58" in client.get("/beacon/pubkey").json()


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #


class TestValidation:
    def test_bad_lookup_hash_rejected(self, client: TestClient) -> None:
        r = client.post("/beacon", json={"lookup_hash": "tooshort", "payload": "x"})
        assert r.status_code == 400

    def test_missing_payload_rejected(self, client: TestClient) -> None:
        r = client.post("/beacon", json={"lookup_hash": "a" * 64})
        assert r.status_code == 400


# --------------------------------------------------------------------------- #
# Federation
# --------------------------------------------------------------------------- #


class TestFederation:
    def test_post_replicates_to_peers(self, client: TestClient) -> None:
        server.federation.add_peer("http://peer1")
        _light(client, "Diego552")
        sent = server.federation._sent  # type: ignore[attr-defined]
        # The beacon was gossiped to the peer's /federation/beacon endpoint.
        beacon_gossips = [c for c in sent if c[1] == "/federation/beacon"]
        assert beacon_gossips and beacon_gossips[0][2]["beacon"]["lookup_hash"]

    def test_gossip_endpoint_stores_and_dedups(self, client: TestClient) -> None:
        idy = Identity.generate()
        b = create_beacon(idy, "Diego552", 300, _RELAY_PK)
        record = {
            "lookup_hash": b.lookup_hash,
            "payload": base64.b64encode(b.encrypted).decode(),
            "expires_at": b.expires_at,
        }
        first = client.post("/federation/beacon", json={"beacon": record, "ttl": 5})
        second = client.post("/federation/beacon", json={"beacon": record, "ttl": 5})
        assert first.json()["accepted"] is True
        assert second.json()["accepted"] is False  # deduped
        # Stored locally → discoverable here.
        assert client.get(f"/beacon/{b.lookup_hash}").status_code == 200


def test_beacon_lit_on_relay_a_resolvable_via_relay_b() -> None:
    """
    Two relay nodes wired in-process: a beacon submitted to A gossips to B and is
    resolvable from B's store — discoverability survives federation.
    """
    store_a: dict[str, dict[str, Any]] = {}
    store_b: dict[str, dict[str, Any]] = {}

    async def deliver_a(beacon: dict[str, Any]) -> None:
        store_a[beacon["lookup_hash"]] = beacon

    async def deliver_b(beacon: dict[str, Any]) -> None:
        store_b[beacon["lookup_hash"]] = beacon

    fed_a = Federation(self_url="http://a", peers=["http://b"], deliver_beacon=deliver_a)
    fed_b = Federation(self_url="http://b", peers=["http://a"], deliver_beacon=deliver_b)

    async def route(target_fed: Federation, peer: str, path: str, payload: dict[str, Any]) -> bool:
        if path == "/federation/beacon":
            await target_fed.handle_beacon_gossip(payload["beacon"], payload["ttl"])
            return True
        return False

    fed_a._sender = lambda peer, path, payload: route(fed_b, peer, path, payload)  # type: ignore[assignment]
    fed_b._sender = lambda peer, path, payload: route(fed_a, peer, path, payload)  # type: ignore[assignment]

    import asyncio

    idy = Identity.generate()
    b = create_beacon(idy, "Diego552", 300, _RELAY_PK)
    record = {
        "lookup_hash": b.lookup_hash,
        "payload": base64.b64encode(b.encrypted).decode(),
        "expires_at": b.expires_at,
    }
    asyncio.run(fed_a.submit_beacon(record))

    # B received the beacon via gossip and can serve it; it resolves correctly.
    assert b.lookup_hash in store_b
    encrypted = base64.b64decode(store_b[b.lookup_hash]["payload"])
    info = resolve_beacon("Diego552", encrypted)
    assert info is not None and info.contact_code == idy.contact_code()
