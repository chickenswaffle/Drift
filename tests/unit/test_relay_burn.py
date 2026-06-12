"""
tests/unit/test_relay_burn.py — unit tests for the relay /burn endpoint

Uses FastAPI's synchronous TestClient (no running server needed).

Run: pytest tests/unit/test_relay_burn.py -v
"""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from relay.server import _recent, _subscribers, app

_VALID_TOKEN = "a" * 64  # 64 hex chars — shape-valid, HMAC not verified by relay
_CHANNEL = "drift-stealth-v1"


@pytest.fixture(autouse=True)
def _clear_state() -> None:
    """Reset relay in-memory state between tests."""
    _recent.clear()
    _subscribers.clear()


@pytest.fixture()
def client() -> TestClient:
    return TestClient(app)


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #

def test_burn_rejects_missing_token(client: TestClient) -> None:
    r = client.post("/burn", json={"scope": "conversation", "channel": _CHANNEL})
    assert r.status_code == 400
    assert "token" in r.json()["error"]


def test_burn_rejects_short_token(client: TestClient) -> None:
    r = client.post("/burn", json={"token": "abc", "scope": "conversation", "channel": _CHANNEL})
    assert r.status_code == 400


def test_burn_rejects_non_hex_token(client: TestClient) -> None:
    r = client.post("/burn", json={"token": "z" * 64, "scope": "conversation", "channel": _CHANNEL})
    assert r.status_code == 400


def test_burn_rejects_invalid_scope(client: TestClient) -> None:
    r = client.post("/burn", json={"token": _VALID_TOKEN, "scope": "all", "channel": _CHANNEL})
    assert r.status_code == 400
    assert "scope" in r.json()["error"]


def test_burn_rejects_missing_channel(client: TestClient) -> None:
    r = client.post("/burn", json={"token": _VALID_TOKEN, "scope": "conversation"})
    assert r.status_code == 400
    assert "channel" in r.json()["error"]


def test_burn_message_scope_requires_message_id(client: TestClient) -> None:
    r = client.post("/burn", json={"token": _VALID_TOKEN, "scope": "message", "channel": _CHANNEL})
    assert r.status_code == 400
    assert "message_id" in r.json()["error"]


# --------------------------------------------------------------------------- #
# Conversation burn
# --------------------------------------------------------------------------- #

def test_burn_conversation_does_not_touch_shared_buffer(client: TestClient) -> None:
    # Audit H2: a conversation-scope burn must NOT wipe the shared firehose
    # buffer (that was an unauthenticated channel-wide DoS). The relay leaves the
    # buffer alone — conversation erasure is end-to-end via the verified
    # tombstone plus the buffer's own TTL.
    _recent[_CHANNEL].append({"_relay_ts": time.time(), "ct": "blob", "_id": "x"})
    _recent[_CHANNEL].append({"_relay_ts": time.time(), "ct": "blob2", "_id": "y"})
    r = client.post("/burn", json={
        "token": _VALID_TOKEN, "scope": "conversation", "channel": _CHANNEL,
    })
    assert r.status_code == 200
    assert r.json()["ok"] is True
    assert len(_recent[_CHANNEL]) == 2  # untouched


def test_anonymous_burn_cannot_drop_another_users_queued_message(client: TestClient) -> None:
    # Audit H2 regression: an attacker who does not know a victim's one-time
    # address cannot evict the victim's queued message — neither via a
    # conversation-scope burn (no longer wipes anything) nor a message-scope burn
    # naming an address the attacker doesn't hold.
    victim_addr = "dmljdGlt"   # b64 "victim"
    ts = time.time()
    _recent[_CHANNEL].append({"_relay_ts": ts, "ct": "secret", "addr": victim_addr, "_id": "v"})

    # (1) Channel-wide conversation burn from an anonymous caller: no effect.
    r = client.post("/burn", json={
        "token": _VALID_TOKEN, "scope": "conversation", "channel": _CHANNEL,
    })
    assert r.status_code == 200
    assert any(e.get("addr") == victim_addr for e in _recent[_CHANNEL])

    # (2) Message burn for an address the attacker guessed/owns, not the victim's.
    r = client.post("/burn", json={
        "token": _VALID_TOKEN, "scope": "message",
        "channel": _CHANNEL, "message_id": "YXR0YWNrZXI=",  # b64 "attacker"
    })
    assert r.status_code == 200
    assert any(e.get("addr") == victim_addr for e in _recent[_CHANNEL])


def test_burn_conversation_returns_ok_with_no_subscribers(client: TestClient) -> None:
    r = client.post("/burn", json={
        "token": _VALID_TOKEN, "scope": "conversation", "channel": _CHANNEL,
    })
    assert r.status_code == 200
    assert r.json()["notified"] == 0


# --------------------------------------------------------------------------- #
# Message-scope burn
# --------------------------------------------------------------------------- #

def test_burn_message_removes_matching_addr(client: TestClient) -> None:
    target = "dGVzdA=="   # b64 "test"
    other = "b3RoZXI="   # b64 "other"
    ts = time.time()
    _recent[_CHANNEL].append({"_relay_ts": ts, "ct": "x", "addr": target, "_id": "1"})
    _recent[_CHANNEL].append({"_relay_ts": ts, "ct": "y", "addr": other, "_id": "2"})
    r = client.post("/burn", json={
        "token": _VALID_TOKEN, "scope": "message",
        "channel": _CHANNEL, "message_id": target,
    })
    assert r.status_code == 200
    remaining = _recent[_CHANNEL]
    assert len(remaining) == 1
    assert remaining[0]["addr"] == other


def test_burn_message_leaves_other_addrs_intact(client: TestClient) -> None:
    target = "dGVzdA=="
    ts = time.time()
    _recent[_CHANNEL].append({"_relay_ts": ts, "ct": "x", "addr": "aGVsbG8=", "_id": "1"})
    _recent[_CHANNEL].append({"_relay_ts": ts, "ct": "y", "addr": "d29ybGQ=", "_id": "2"})
    r = client.post("/burn", json={
        "token": _VALID_TOKEN, "scope": "message",
        "channel": _CHANNEL, "message_id": target,
    })
    assert r.status_code == 200
    assert len(_recent[_CHANNEL]) == 2  # nothing removed — target not in buffer
