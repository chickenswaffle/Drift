"""
tests/unit/test_relay_ratelimit.py — relay flood control (token buckets)

Covers the TokenBucket mechanics (burst, refill, LRU bound) and the endpoint
enforcement: /send floods, the OTPK-drain double budget on GET /prekeys, and
the DRIFT_RELAY_RATE_LIMITS=off escape hatch. Endpoint tests swap in tiny
buckets so they don't need hundreds of requests to hit a limit.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import relay.server as server
from drift.crypto import Identity
from drift.crypto.x3dh import generate_prekey_bundle
from relay.ratelimit import TokenBucket


@pytest.fixture(autouse=True)
def _clean_state() -> None:
    server._prekeys.clear()
    server._recent.clear()
    server._subscribers.clear()
    for bucket in (
        server._send_bucket,
        server._burn_bucket,
        server._prekey_write_bucket,
        server._prekey_fetch_ip_bucket,
        server._prekey_fetch_addr_bucket,
    ):
        bucket.clear()


@pytest.fixture
def client() -> TestClient:
    return TestClient(server.app)


def _publish(client: TestClient, num_one_time: int = 3) -> str:
    identity = Identity.generate()
    _, privates = generate_prekey_bundle(identity, num_one_time=num_one_time)
    addr = identity.scan_keypair.public_b58()
    resp = client.post(f"/prekeys/{addr}", json=privates.publish_payload(identity))
    assert resp.status_code == 200
    return addr


class TestTokenBucket:
    def test_burst_then_refusal(self) -> None:
        bucket = TokenBucket(rate=0.0, burst=3)
        assert all(bucket.allow("k", now=0.0) for _ in range(3))
        assert not bucket.allow("k", now=0.0)  # burst spent, no refill

    def test_refill_restores_tokens(self) -> None:
        bucket = TokenBucket(rate=1.0, burst=2)
        assert bucket.allow("k", now=0.0)
        assert bucket.allow("k", now=0.0)
        assert not bucket.allow("k", now=0.0)
        assert bucket.allow("k", now=1.5)  # 1.5s * 1/s refill > 1 token

    def test_refill_caps_at_burst(self) -> None:
        bucket = TokenBucket(rate=100.0, burst=2)
        assert bucket.allow("k", now=0.0)
        # A long idle period must not bank more than `burst` tokens.
        assert bucket.allow("k", now=1000.0)
        assert bucket.allow("k", now=1000.0)
        assert not bucket.allow("k", now=1000.0)

    def test_keys_are_independent(self) -> None:
        bucket = TokenBucket(rate=0.0, burst=1)
        assert bucket.allow("a", now=0.0)
        assert not bucket.allow("a", now=0.0)
        assert bucket.allow("b", now=0.0)  # a's exhaustion never touches b

    def test_lru_bound_evicts_oldest(self) -> None:
        bucket = TokenBucket(rate=0.0, burst=1, max_keys=2)
        bucket.allow("a", now=0.0)
        bucket.allow("b", now=0.0)
        bucket.allow("c", now=0.0)  # evicts a
        assert len(bucket) == 2
        # Evicted key returns with a fresh (full) bucket — bounded memory is the
        # tradeoff; an attacker cycling 4096+ keys is caught by the global budgets.
        assert bucket.allow("a", now=0.0)

    def test_clock_going_backwards_never_mints_tokens(self) -> None:
        bucket = TokenBucket(rate=1.0, burst=1)
        assert bucket.allow("k", now=100.0)
        assert not bucket.allow("k", now=50.0)  # negative elapsed → no refill


class TestSendFloodControl:
    def test_flood_gets_429_with_retry_after(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(server, "_send_bucket", TokenBucket(rate=0.0, burst=2))
        body = {"to": "chan", "ct": "aGk="}
        assert client.post("/send", json=body).status_code == 200
        assert client.post("/send", json=body).status_code == 200
        resp = client.post("/send", json=body)
        assert resp.status_code == 429
        assert resp.headers["Retry-After"] == "30"

    def test_off_switch_disables_limits(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("DRIFT_RELAY_RATE_LIMITS", "off")
        monkeypatch.setattr(server, "_send_bucket", TokenBucket(rate=0.0, burst=1))
        body = {"to": "chan", "ct": "aGk="}
        for _ in range(5):
            assert client.post("/send", json=body).status_code == 200


class TestPrekeyDrainControl:
    def test_drain_hits_global_addr_budget(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Generous per-IP budget, tiny per-address budget: even an attacker who
        # rotates circuits (fresh IPs) is stopped by the address-keyed bucket.
        monkeypatch.setattr(
            server, "_prekey_fetch_addr_bucket", TokenBucket(rate=0.0, burst=2)
        )
        addr = _publish(client, num_one_time=10)
        assert client.get(f"/prekeys/{addr}").status_code == 200
        assert client.get(f"/prekeys/{addr}").status_code == 200
        assert client.get(f"/prekeys/{addr}").status_code == 429
        # The 429 must NOT have consumed an OTPK: 10 published, only 2 served.
        status = client.get(f"/prekeys/{addr}/status").json()
        assert status["one_time_count"] == 8

    def test_per_ip_budget_is_scoped_to_target(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            server, "_prekey_fetch_ip_bucket", TokenBucket(rate=0.0, burst=1)
        )
        addr_a = _publish(client)
        addr_b = _publish(client)
        assert client.get(f"/prekeys/{addr_a}").status_code == 200
        assert client.get(f"/prekeys/{addr_a}").status_code == 429
        # Exhausting the budget for one target never blocks a different one.
        assert client.get(f"/prekeys/{addr_b}").status_code == 200

    def test_status_endpoint_is_never_limited(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            server, "_prekey_fetch_addr_bucket", TokenBucket(rate=0.0, burst=0)
        )
        addr = _publish(client)
        # Non-consuming status stays available even when fetches are throttled.
        assert client.get(f"/prekeys/{addr}/status").status_code == 200


class TestWriteBudgets:
    def test_burn_flood_gets_429(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(server, "_burn_bucket", TokenBucket(rate=0.0, burst=1))
        client.post("/burn", json={})  # spends the budget (400 is fine)
        assert client.post("/burn", json={}).status_code == 429

    def test_publish_flood_gets_429(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            server, "_prekey_write_bucket", TokenBucket(rate=0.0, burst=1)
        )
        _publish(client)
        identity = Identity.generate()
        _, privates = generate_prekey_bundle(identity, num_one_time=1)
        addr = identity.scan_keypair.public_b58()
        resp = client.post(f"/prekeys/{addr}", json=privates.publish_payload(identity))
        assert resp.status_code == 429
