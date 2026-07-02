"""
tests/unit/test_relay_capabilities.py — the extension-advertisement endpoint

PROTOCOL.md §14: relays advertise the core protocol version plus the
extensions they speak at GET /capabilities. Extensions are additive and never
load-bearing — a client recognizing none of them proceeds on the core.

Run: pytest tests/unit/test_relay_capabilities.py -v
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from relay.server import app


def test_capabilities_advertises_core_and_witness() -> None:
    with TestClient(app) as client:
        resp = client.get("/capabilities")
    assert resp.status_code == 200
    data = resp.json()
    assert data["protocol"] == "DRIFT-P/1"
    # The reference relay always ships WITNESS, so it is always advertised.
    assert "drift-ext/witness/1" in data["extensions"]
    # Every advertised identifier is well-formed: registered (drift-ext/) or
    # vendor (x-<vendor>-) namespace, with a version segment.
    for ext in data["extensions"]:
        assert ext.startswith(("drift-ext/", "x-")), ext
        assert ext.rsplit("/", 1)[-1].isdigit(), ext
