"""
tests/unit/test_tor.py — unit tests for drift.transport.tor (Phase 3)

Network-free and backend-free: the Tor bootstrap and the SOCKS5 socket layer
are mocked, so these run in CI with neither a Tor daemon, arti, nor python-socks
installed. The contract under test is the *plumbing* — progress reporting,
timeout/fallback behaviour, and that a circuit's SOCKS5 endpoint is threaded
into the transport — not the Tor network itself.

Run: pytest tests/unit/test_tor.py -v
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from drift.transport import tor
from drift.transport.tor import (
    TorBootstrapError,
    TorClient,
    TorError,
    TorUnavailableError,
)


def _fake_client(port: int = 9999, hops: int = 3) -> TorClient:
    return TorClient(socks_host="127.0.0.1", socks_port=port, backend="mock", num_hops=hops)


# ---------------------------------------------------------------------------
# TorClient
# ---------------------------------------------------------------------------


class TestTorClient:
    def test_socks_url_and_proxy(self) -> None:
        c = _fake_client(port=9050)
        assert c.socks_url == "socks5://127.0.0.1:9050"
        assert c.socks_proxy == ("127.0.0.1", 9050)

    def test_default_hops(self) -> None:
        c = TorClient(socks_host="127.0.0.1", socks_port=9050, backend="stem")
        assert c.num_hops == tor.TOR_DEFAULT_HOPS == 3

    @pytest.mark.asyncio
    async def test_close_kills_stem_handle(self) -> None:
        handle = MagicMock()
        handle.kill = MagicMock()
        c = TorClient(socks_host="127.0.0.1", socks_port=1, backend="stem", _handle=handle)
        await c.close()
        handle.kill.assert_called_once()
        # Idempotent — second close is a no-op, doesn't kill again.
        await c.close()
        handle.kill.assert_called_once()

    @pytest.mark.asyncio
    async def test_close_swallows_backend_errors(self) -> None:
        handle = MagicMock()
        handle.kill = MagicMock(side_effect=RuntimeError("already dead"))
        c = TorClient(socks_host="127.0.0.1", socks_port=1, backend="stem", _handle=handle)
        await c.close()  # must not raise


# ---------------------------------------------------------------------------
# bootstrap() — success / progress
# ---------------------------------------------------------------------------


class TestBootstrap:
    @pytest.mark.asyncio
    async def test_returns_client_from_backend(self) -> None:
        client = _fake_client()
        with patch.object(tor, "_run_backend", AsyncMock(return_value=client)):
            result = await tor.bootstrap(backend="stem")
        assert result is client

    @pytest.mark.asyncio
    async def test_reports_progress_0_and_100(self) -> None:
        seen: list[int] = []

        async def fake_backend(name, on_progress, socks_port, timeout):  # type: ignore[no-untyped-def]
            on_progress(42, "Bootstrapped 42% (loading_descriptors)")
            return _fake_client()

        with patch.object(tor, "_run_backend", fake_backend):
            await tor.bootstrap(backend="stem", on_progress=lambda p, m: seen.append(p))

        # Brackets the run with 0 (starting) and 100 (established), 42 in between.
        assert seen[0] == 0
        assert seen[-1] == 100
        assert 42 in seen

    @pytest.mark.asyncio
    async def test_timeout_raises_bootstrap_error(self) -> None:
        async def slow_backend(name, on_progress, socks_port, timeout):  # type: ignore[no-untyped-def]
            await asyncio.sleep(10)
            return _fake_client()

        with patch.object(tor, "_run_backend", slow_backend):
            with pytest.raises(TorBootstrapError, match="did not bootstrap within"):
                await tor.bootstrap(backend="stem", timeout=0.05)

    @pytest.mark.asyncio
    async def test_no_backend_raises_unavailable(self) -> None:
        with patch.object(tor, "_resolve_backends", return_value=()):
            with pytest.raises(TorUnavailableError, match="no Tor backend installed"):
                await tor.bootstrap()

    @pytest.mark.asyncio
    async def test_falls_back_to_next_backend(self) -> None:
        client = _fake_client()

        async def picky(name, on_progress, socks_port, timeout):  # type: ignore[no-untyped-def]
            if name == "arti":
                raise TorUnavailableError("arti not installed")
            return client

        with (
            patch.object(tor, "_resolve_backends", return_value=("arti", "stem")),
            patch.object(tor, "_run_backend", picky),
        ):
            result = await tor.bootstrap()
        assert result is client

    @pytest.mark.asyncio
    async def test_all_backends_fail_raises_unavailable(self) -> None:
        async def always_fail(name, on_progress, socks_port, timeout):  # type: ignore[no-untyped-def]
            raise TorUnavailableError("nope")

        with (
            patch.object(tor, "_resolve_backends", return_value=("arti", "stem")),
            patch.object(tor, "_run_backend", always_fail),
        ):
            with pytest.raises(TorUnavailableError, match="no working Tor backend"):
                await tor.bootstrap()

    def test_unavailable_is_a_tor_error(self) -> None:
        # Callers catch the TorError base for the graceful fallback.
        assert issubclass(TorUnavailableError, TorError)
        assert issubclass(TorBootstrapError, TorError)


# ---------------------------------------------------------------------------
# stem timeout — the bootstrap budget must bound the (uncancellable) thread
# ---------------------------------------------------------------------------


class TestStemTimeout:
    def test_budget_passed_into_stem(self) -> None:
        """_launch_stem must hand the bootstrap budget to stem itself. The
        thread it runs in can't be cancelled, so stem's own timeout is what
        actually reaps tor within the caller's deadline (a Tor-hostile network
        stalls mid-handshake — stem must not hang past this)."""
        import sys
        import types

        captured: dict[str, object] = {}

        def fake_launch(**kwargs):  # type: ignore[no-untyped-def]
            captured.update(kwargs)
            return MagicMock()  # stands in for the tor subprocess handle

        fake_stem_process = types.ModuleType("stem.process")
        fake_stem_process.launch_tor_with_config = fake_launch  # type: ignore[attr-defined]
        fake_stem = types.ModuleType("stem")
        fake_stem.process = fake_stem_process  # type: ignore[attr-defined]

        with patch.dict(sys.modules, {"stem": fake_stem, "stem.process": fake_stem_process}):
            client = tor._launch_stem(None, 9051, timeout=17.0)

        assert captured["timeout"] == 17
        assert client.socks_port == 9051

    @pytest.mark.asyncio
    async def test_outer_wait_for_exceeds_stem_budget(self) -> None:
        """The outer asyncio backstop must allow a grace beyond the stem budget,
        so stem's inner timeout fires and cleans up first."""
        seen: dict[str, float] = {}

        async def capture_backend(name, on_progress, socks_port, timeout):  # type: ignore[no-untyped-def]
            seen["timeout"] = timeout
            return _fake_client()

        with patch.object(tor, "_run_backend", capture_backend):
            await tor.bootstrap(backend="stem", timeout=12.0)
        assert seen["timeout"] == 12.0


# ---------------------------------------------------------------------------
# Backend resolution
# ---------------------------------------------------------------------------


class TestResolveBackends:
    def test_explicit_backend_forced(self) -> None:
        assert tor._resolve_backends("stem") == ("stem",)
        assert tor._resolve_backends("arti") == ("arti",)

    def test_auto_prefers_arti_then_stem(self) -> None:
        with patch.object(tor, "_backend_installed", lambda n: True):
            assert tor._resolve_backends(None) == ("arti", "stem")

    def test_auto_empty_when_none_installed(self) -> None:
        with patch.object(tor, "_backend_installed", lambda n: False):
            assert tor._resolve_backends(None) == ()


# ---------------------------------------------------------------------------
# SOCKS5 WebSocket transport
# ---------------------------------------------------------------------------


class TestOpenSocksWebsocket:
    @pytest.mark.asyncio
    async def test_connects_socket_through_proxy_then_ws(self) -> None:
        fake_sock = MagicMock()
        fake_ws = MagicMock()

        proxy = MagicMock()
        proxy.connect = AsyncMock(return_value=fake_sock)
        proxy_cls = MagicMock()
        proxy_cls.from_url = MagicMock(return_value=proxy)

        # python_socks may not be installed; inject a fake module tree.
        ps_mod = MagicMock()
        ps_mod.Proxy = proxy_cls

        with (
            patch.dict(
                "sys.modules",
                {"python_socks.async_.asyncio": ps_mod},
            ),
            patch("websockets.connect", AsyncMock(return_value=fake_ws)) as ws_connect,
        ):
            result = await tor.open_socks_websocket(
                "ws://relay.local:8765/ws/chan", "127.0.0.1", 9050
            )

        assert result is fake_ws
        proxy_cls.from_url.assert_called_once_with("socks5://127.0.0.1:9050")
        proxy.connect.assert_awaited_once_with(dest_host="relay.local", dest_port=8765)
        # The proxied socket is handed to websockets via sock=.
        _, kwargs = ws_connect.call_args
        assert kwargs["sock"] is fake_sock

    @pytest.mark.asyncio
    async def test_get_session_uses_client_endpoint(self) -> None:
        fake_ws = MagicMock()
        client = _fake_client(port=9050)
        with patch.object(
            tor, "open_socks_websocket", AsyncMock(return_value=fake_ws)
        ) as osw:
            result = await tor.get_session(client, "ws://r:8765/ws/c")
        assert result is fake_ws
        osw.assert_awaited_once_with("ws://r:8765/ws/c", "127.0.0.1", 9050)

    @pytest.mark.asyncio
    async def test_missing_python_socks_raises_unavailable(self) -> None:
        # Force the import inside open_socks_websocket to fail.
        with patch.dict("sys.modules", {"python_socks.async_.asyncio": None}):
            with pytest.raises(TorUnavailableError, match="python-socks not installed"):
                await tor.open_socks_websocket("ws://r:8765/ws/c", "127.0.0.1", 9050)


# ---------------------------------------------------------------------------
# Session integration — a circuit threaded through the session layer
# ---------------------------------------------------------------------------


class TestSessionThroughTor:
    """
    The session stays oblivious to Tor: it only forwards the SOCKS5 endpoint to
    the transport and reports the circuit to the UI. These tests confirm that
    wiring with the RelayClient mocked, so no relay or Tor daemon is needed.
    """

    def _identities(self):  # type: ignore[no-untyped-def]
        from drift.crypto import Identity

        return Identity.generate(), Identity.generate()

    def test_tor_client_threads_socks_proxy_to_relay(self) -> None:
        from drift.transport.session import Session

        me, peer = self._identities()
        client = _fake_client(port=9050, hops=3)

        with patch("drift.transport.session.RelayClient") as relay_cls:
            Session(me, peer.contact_code(), "ws://localhost:8765", tor_client=client)

        _, kwargs = relay_cls.call_args
        assert kwargs["socks_proxy"] == ("127.0.0.1", 9050)

    def test_no_tor_client_means_no_proxy(self) -> None:
        from drift.transport.session import Session

        me, peer = self._identities()
        with patch("drift.transport.session.RelayClient") as relay_cls:
            Session(me, peer.contact_code(), "ws://localhost:8765")

        _, kwargs = relay_cls.call_args
        assert kwargs["socks_proxy"] is None

    @pytest.mark.asyncio
    async def test_connect_emits_tor_event(self) -> None:
        from drift.transport.session import Session

        me, peer = self._identities()
        client = _fake_client(port=9050, hops=3)
        events: list[tuple[str, str]] = []

        with patch("drift.transport.session.RelayClient") as relay_cls:
            relay_cls.return_value.connect = AsyncMock()
            relay_cls.return_value.publish_prekey_bundle = AsyncMock()
            session = Session(
                me,
                peer.contact_code(),
                "ws://localhost:8765",
                tor_client=client,
                on_event=lambda k, d: events.append((k, d)),
            )
            await session.connect()

        # The session reports the circuit (public hop count) to the UI ticker.
        assert ("tor", "3") in events

    @pytest.mark.asyncio
    async def test_connect_without_tor_emits_no_tor_event(self) -> None:
        from drift.transport.session import Session

        me, peer = self._identities()
        events: list[tuple[str, str]] = []

        with patch("drift.transport.session.RelayClient") as relay_cls:
            relay_cls.return_value.connect = AsyncMock()
            relay_cls.return_value.publish_prekey_bundle = AsyncMock()
            session = Session(
                me,
                peer.contact_code(),
                "ws://localhost:8765",
                on_event=lambda k, d: events.append((k, d)),
            )
            await session.connect()

        assert not any(kind == "tor" for kind, _ in events)
