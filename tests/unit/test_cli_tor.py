"""
tests/unit/test_cli_tor.py — CLI Tor bootstrap policy (Phase 3)

Covers the --no-tor / --tor-only decision logic in the headless path without
touching Tor or the relay: drift.transport.tor.bootstrap is mocked.

Run: pytest tests/unit/test_cli_tor.py -v
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from drift.cli import _bootstrap_tor_cli
from drift.transport.tor import TorClient, TorUnavailableError


def _client() -> TorClient:
    return TorClient(socks_host="127.0.0.1", socks_port=9050, backend="mock")


@pytest.mark.asyncio
async def test_no_tor_returns_none_without_bootstrapping() -> None:
    with patch("drift.transport.tor.bootstrap", AsyncMock()) as boot:
        result = await _bootstrap_tor_cli(use_tor=False, tor_only=False)
    assert result is None
    boot.assert_not_called()


@pytest.mark.asyncio
async def test_success_returns_client() -> None:
    client = _client()
    with patch("drift.transport.tor.bootstrap", AsyncMock(return_value=client)):
        result = await _bootstrap_tor_cli(use_tor=True, tor_only=False)
    assert result is client


@pytest.mark.asyncio
async def test_failure_without_tor_only_falls_back_to_clearnet() -> None:
    with patch(
        "drift.transport.tor.bootstrap",
        AsyncMock(side_effect=TorUnavailableError("no backend")),
    ):
        result = await _bootstrap_tor_cli(use_tor=True, tor_only=False)
    # None → proceed on clearnet.
    assert result is None


@pytest.mark.asyncio
async def test_failure_with_tor_only_aborts() -> None:
    with patch(
        "drift.transport.tor.bootstrap",
        AsyncMock(side_effect=TorUnavailableError("no backend")),
    ):
        result = await _bootstrap_tor_cli(use_tor=True, tor_only=True)
    # False → caller must refuse to connect.
    assert result is False
