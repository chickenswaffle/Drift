"""
tests/unit/test_relay_prekeys.py — relay prekey endpoints (X3DH, audit H3)

Drives the FastAPI relay with the synchronous TestClient. Verifies bundle
publish/fetch, atomic one-time-prekey consumption, replenishment, the
non-consuming status endpoint, and 30-day server-side expiry.
"""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

import relay.server as server
from drift.crypto import Identity
from drift.crypto.x3dh import PreKeyBundle, generate_prekey_bundle, x3dh_receive, x3dh_send


@pytest.fixture(autouse=True)
def _clear_prekeys() -> None:
    server._prekeys.clear()


@pytest.fixture
def client() -> TestClient:
    return TestClient(server.app)


def _publish(client: TestClient, num_one_time: int = 3) -> tuple[str, Identity, object]:
    identity = Identity.generate()
    _, privates = generate_prekey_bundle(identity, num_one_time=num_one_time)
    addr = identity.scan_keypair.public_b58()
    resp = client.post(f"/prekeys/{addr}", json=privates.publish_payload(identity))
    assert resp.status_code == 200
    return addr, identity, privates


class TestPublishFetch:
    def test_publish_then_fetch_round_trips(self, client: TestClient) -> None:
        addr, bob, privates = _publish(client, num_one_time=3)
        data = client.get(f"/prekeys/{addr}").json()
        bundle = PreKeyBundle.from_dict(data)
        # A fetched bundle drives a real handshake the publisher can complete.
        alice = Identity.generate()
        result_s, header = x3dh_send(alice, bundle)
        result_r = x3dh_receive(bob, privates, header)
        assert result_s.master_secret == result_r.master_secret

    def test_fetch_unknown_is_404(self, client: TestClient) -> None:
        assert client.get("/prekeys/nope").status_code == 404

    def test_missing_fields_rejected(self, client: TestClient) -> None:
        resp = client.post("/prekeys/someaddr", json={"identity_key": "x"})
        assert resp.status_code == 400


class TestOneTimeConsumption:
    def test_each_fetch_consumes_a_distinct_otpk(self, client: TestClient) -> None:
        addr, _, _ = _publish(client, num_one_time=2)
        id1 = client.get(f"/prekeys/{addr}").json()["one_time_prekey_id"]
        id2 = client.get(f"/prekeys/{addr}").json()["one_time_prekey_id"]
        assert id1 is not None and id2 is not None
        assert id1 != id2  # never served the same OTPK twice

    def test_exhausted_store_returns_null_otpk(self, client: TestClient) -> None:
        addr, _, _ = _publish(client, num_one_time=1)
        client.get(f"/prekeys/{addr}")  # consume the only one
        data = client.get(f"/prekeys/{addr}").json()
        assert data["one_time_prekey"] is None
        assert data["one_time_prekey_id"] is None
        # The signed prekey is still served — X3DH without an OTPK is valid.
        assert data["signed_prekey"]


class TestReplenish:
    def test_replenish_adds_more_otpks(self, client: TestClient) -> None:
        addr, identity, privates = _publish(client, num_one_time=1)
        from drift.crypto import b58encode
        from drift.crypto.x3dh import replenish_one_time

        new_ids = replenish_one_time(privates, count=5)
        payload = {
            "one_time_prekeys": [
                {"id": i, "pub": b58encode(privates.one_time[i].public_bytes())}
                for i in new_ids
            ]
        }
        resp = client.post(f"/prekeys/{addr}/replenish", json=payload)
        assert resp.status_code == 200
        assert resp.json()["one_time_count"] == 6  # 1 original + 5 new

    def test_replenish_unknown_is_404(self, client: TestClient) -> None:
        resp = client.post("/prekeys/nope/replenish", json={"one_time_prekeys": []})
        assert resp.status_code == 404


class TestStatus:
    def test_status_is_non_consuming(self, client: TestClient) -> None:
        addr, _, _ = _publish(client, num_one_time=3)
        s1 = client.get(f"/prekeys/{addr}/status").json()
        s2 = client.get(f"/prekeys/{addr}/status").json()
        assert s1["one_time_count"] == 3
        assert s2["one_time_count"] == 3  # status never removes an OTPK

    def test_status_unknown_is_404(self, client: TestClient) -> None:
        assert client.get("/prekeys/nope/status").status_code == 404


class TestExpiry:
    def test_bundle_expires_after_ttl(self, client: TestClient) -> None:
        addr, _, _ = _publish(client, num_one_time=1)
        # Age the stored record past the 30-day TTL.
        server._prekeys[addr]["stored_at"] = time.time() - server.PREKEY_MAX_TTL - 1
        assert client.get(f"/prekeys/{addr}").status_code == 404
