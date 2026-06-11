"""
tests/unit/test_node.py — Pi Zero mesh node (Phase 4b)

Confirms the lightweight node tunes the shared relay down to its small resource
limits, runs purely in memory (no Redis), and creates/saves a Tor onion address
through an injected (mocked) controller — no live tor, no live network in CI.

Run: pytest tests/unit/test_node.py -v
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

import relay.node as node
import relay.server as server


@pytest.fixture(autouse=True)
def _restore_relay_limits() -> Any:
    """Snapshot and restore the shared relay tunables around each test."""
    saved = (
        server.RECENT_TTL,
        server.RECENT_MAX,
        server.MAX_CONNECTIONS,
        server.federation._seen.capacity,
    )
    yield
    server.RECENT_TTL, server.RECENT_MAX, server.MAX_CONNECTIONS, cap = saved
    server.federation.set_dedup_capacity(cap)


# --------------------------------------------------------------------------- #
# Resource limits
# --------------------------------------------------------------------------- #


class TestNodeLimits:
    def test_constants_are_smaller_than_full_relay(self) -> None:
        assert node.NODE_RECENT_TTL == 300.0     # vs 30s full relay
        assert node.NODE_MAX_CONNECTIONS == 50   # vs unlimited
        assert node.NODE_LRU_SIZE == 1_000       # vs 10_000
        # And genuinely smaller than the full relay's dedup default.
        from relay.federation import DEFAULT_DEDUP_SIZE
        assert node.NODE_LRU_SIZE < DEFAULT_DEDUP_SIZE

    def test_apply_node_limits_retunes_shared_relay(self) -> None:
        node.apply_node_limits()
        assert server.RECENT_TTL == 300.0
        assert server.RECENT_MAX == node.NODE_RECENT_MAX
        assert server.MAX_CONNECTIONS == 50
        assert server.federation._seen.capacity == 1_000

    def test_longer_replay_window_than_full_relay(self) -> None:
        node.apply_node_limits()
        # 5-minute durable-ish window on the node vs the full relay's 30s race fix.
        assert server.RECENT_TTL > 30.0


# --------------------------------------------------------------------------- #
# No Redis — pure in-memory
# --------------------------------------------------------------------------- #


class TestNoRedis:
    def test_node_and_relay_sources_never_import_redis(self) -> None:
        for mod in (node, server):
            src = Path(mod.__file__).read_text()
            assert "import redis" not in src
            assert "from redis" not in src

    def test_federation_is_in_memory(self) -> None:
        # The dedup cache is a plain in-process LRU — no external backing store.
        from relay.federation import LRUSet
        assert isinstance(server.federation._seen, LRUSet)


# --------------------------------------------------------------------------- #
# Onion service
# --------------------------------------------------------------------------- #


class TestOnionService:
    def test_create_onion_service_with_injected_controller(self) -> None:
        controller = MagicMock()
        controller.create_ephemeral_hidden_service.return_value = MagicMock(
            service_id="abcdef1234567890"
        )
        onion, ctrl = node.create_onion_service(8765, controller=controller)

        assert onion == "abcdef1234567890.onion"
        assert ctrl is controller
        # Mapped the onion's virtual port 80 to the local relay port.
        controller.create_ephemeral_hidden_service.assert_called_once_with(
            {80: 8765}, await_publication=True
        )

    def test_create_onion_service_wraps_failure(self) -> None:
        controller = MagicMock()
        controller.create_ephemeral_hidden_service.side_effect = RuntimeError("tor sad")
        with pytest.raises(node.OnionError, match="failed to create onion service"):
            node.create_onion_service(8765, controller=controller)

    def test_save_onion_address_writes_file(self, tmp_path: Path) -> None:
        target = tmp_path / "node_address.txt"
        node.save_onion_address("abcdef.onion", target)
        assert target.read_text().strip() == "abcdef.onion"

    def test_onion_self_url(self) -> None:
        assert node._onion_self_url("abcdef.onion") == "http://abcdef.onion"


# --------------------------------------------------------------------------- #
# Node serves and federates with its small limits
# --------------------------------------------------------------------------- #


class TestNodeServes:
    def test_node_capped_relay_refuses_excess_connections(self) -> None:
        from fastapi.testclient import TestClient

        server._subscribers.clear()
        node.apply_node_limits()
        server.MAX_CONNECTIONS = 1   # shrink further so the test is cheap

        client = TestClient(server.app)
        with client.websocket_connect("/ws/drift-stealth-v1"):
            with client.websocket_connect("/ws/drift-stealth-v1") as ws2:
                assert ws2.receive_json().get("error") == "node at capacity"
