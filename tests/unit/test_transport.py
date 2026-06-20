"""
tests/unit/test_transport.py — unit tests for drift.transport.client

All tests are network-free. The WebSocket and HTTP layers are mocked
so these run without a live relay.

Run: pytest tests/unit/test_transport.py -v
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
from collections.abc import AsyncIterator
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from drift.transport.client import Envelope, RelayClient, RelayError

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


def _make_relay_msg(to: str, ct_bytes: bytes, ts: int = 0) -> str:
    """Build the JSON string the relay pushes down the WebSocket."""
    return json.dumps({
        "to": to,
        "ct": base64.b64encode(ct_bytes).decode(),
        "ts": ts,
        "_relay_ts": time.time(),
        "_id": "test-id-1",
    })


class FakeWebSocket:
    """
    Minimal stand-in for a websockets ClientConnection.

    Preload ``messages`` with raw JSON strings to be yielded by the async
    iterator.  ``sent`` records everything the client sent back.
    """

    def __init__(self, messages: list[str] | None = None) -> None:
        self._messages = list(messages or [])
        self.sent: list[str] = []
        self.closed = False

    async def send(self, data: str) -> None:
        self.sent.append(data)

    async def close(self) -> None:
        self.closed = True

    def __aiter__(self) -> AsyncIterator[str]:
        return self._aiter()

    async def _aiter(self) -> AsyncIterator[str]:
        for msg in self._messages:
            yield msg


class _FakeWSConnect:
    """Context-manager / awaitable that returns a FakeWebSocket."""

    def __init__(self, ws: FakeWebSocket) -> None:
        self._ws = ws

    def __await__(self):  # type: ignore[override]
        async def _inner() -> FakeWebSocket:
            return self._ws
        return _inner().__await__()


def _mock_http_send_ok(delivered: int = 1) -> AsyncMock:
    """Return an httpx.AsyncClient mock whose post() returns ok=True."""
    response = MagicMock(spec=httpx.Response)
    response.raise_for_status = MagicMock()
    response.json.return_value = {"ok": True, "delivered": delivered}

    # GET is used by RelayClient._discover_peers (federation peer fetch).
    peers_resp = MagicMock(spec=httpx.Response)
    peers_resp.json.return_value = {"peers": []}

    client = AsyncMock(spec=httpx.AsyncClient)
    client.post = AsyncMock(return_value=response)
    client.get = AsyncMock(return_value=peers_resp)
    client.aclose = AsyncMock()
    return client


# ---------------------------------------------------------------------------
# Envelope
# ---------------------------------------------------------------------------


class TestEnvelope:
    def test_timestamp_defaults_to_now(self) -> None:
        before = int(time.time())
        env = Envelope(to="addr", ciphertext=b"ct")
        after = int(time.time())
        assert before <= env.timestamp <= after

    def test_explicit_fields(self) -> None:
        env = Envelope(to="alice", ciphertext=b"\x01\x02", timestamp=9999)
        assert env.to == "alice"
        assert env.ciphertext == b"\x01\x02"
        assert env.timestamp == 9999


# ---------------------------------------------------------------------------
# RelayClient.send
# ---------------------------------------------------------------------------


class TestSend:
    @pytest.fixture
    def client(self) -> RelayClient:
        return RelayClient("ws://localhost:8765", "myaddr")

    @pytest.mark.asyncio
    async def test_send_posts_correct_payload(self, client: RelayClient) -> None:
        fake_http = _mock_http_send_ok()
        client._http = fake_http
        client._connected = True

        env = Envelope(to="bobaddr", ciphertext=b"secret", timestamp=1000)
        await client.send(env)

        fake_http.post.assert_awaited_once()
        _, kwargs = fake_http.post.call_args
        payload = kwargs["json"]
        assert payload["to"] == "bobaddr"
        assert payload["ts"] == 1000
        # ciphertext must arrive as base64
        assert base64.b64decode(payload["ct"]) == b"secret"

    @pytest.mark.asyncio
    async def test_send_uses_http_url(self, client: RelayClient) -> None:
        fake_http = _mock_http_send_ok()
        client._http = fake_http
        client._connected = True

        await client.send(Envelope(to="x", ciphertext=b"y"))

        url = fake_http.post.call_args[0][0]
        assert url == "http://localhost:8765/send"

    @pytest.mark.asyncio
    async def test_send_wss_url_maps_to_https(self) -> None:
        c = RelayClient("wss://relay.example.com", "addr")
        assert c._http_base == "https://relay.example.com"

    @pytest.mark.asyncio
    async def test_send_raises_relay_error_on_http_failure(self, client: RelayClient) -> None:
        bad_http = AsyncMock(spec=httpx.AsyncClient)
        bad_http.post = AsyncMock(side_effect=httpx.ConnectError("refused"))
        bad_http.aclose = AsyncMock()
        client._http = bad_http
        client._connected = True

        with pytest.raises(RelayError, match="send failed"):
            await client.send(Envelope(to="x", ciphertext=b"y"))

    @pytest.mark.asyncio
    async def test_send_raises_relay_error_on_ok_false(self, client: RelayClient) -> None:
        response = MagicMock(spec=httpx.Response)
        response.raise_for_status = MagicMock()
        response.json.return_value = {"ok": False, "error": "missing to"}
        bad_http = AsyncMock(spec=httpx.AsyncClient)
        bad_http.post = AsyncMock(return_value=response)
        bad_http.aclose = AsyncMock()
        client._http = bad_http
        client._connected = True

        with pytest.raises(RelayError, match="relay rejected"):
            await client.send(Envelope(to="x", ciphertext=b"y"))

    @pytest.mark.asyncio
    async def test_send_raises_when_not_connected(self, client: RelayClient) -> None:
        with pytest.raises(RelayError, match="not connected"):
            await client.send(Envelope(to="x", ciphertext=b"y"))


# ---------------------------------------------------------------------------
# RelayClient._listen / receive
# ---------------------------------------------------------------------------


class TestReceive:
    @pytest.mark.asyncio
    async def test_receive_decodes_envelope(self) -> None:
        ct = b"hello encrypted world"
        ws = FakeWebSocket([_make_relay_msg("myaddr", ct, ts=42)])
        client = RelayClient("ws://localhost:8765", "myaddr")
        client._ws = ws
        client._connected = True

        listen_task = asyncio.create_task(client._listen())
        envelope = await asyncio.wait_for(client.receive(), timeout=2.0)
        await listen_task

        assert envelope.ciphertext == ct
        assert envelope.to == "myaddr"
        assert envelope.timestamp == 42

    @pytest.mark.asyncio
    async def test_receive_ignores_pong_frames(self) -> None:
        ct = b"real message"
        ws = FakeWebSocket([
            json.dumps({"type": "pong"}),
            _make_relay_msg("myaddr", ct),
        ])
        client = RelayClient("ws://localhost:8765", "myaddr")
        client._ws = ws
        client._connected = True

        listen_task = asyncio.create_task(client._listen())
        envelope = await asyncio.wait_for(client.receive(), timeout=2.0)
        await listen_task

        assert envelope.ciphertext == ct

    @pytest.mark.asyncio
    async def test_receive_ignores_malformed_json(self) -> None:
        ct = b"good"
        ws = FakeWebSocket([
            "this is not json!!!",
            _make_relay_msg("addr", ct),
        ])
        client = RelayClient("ws://localhost:8765", "addr")
        client._ws = ws
        client._connected = True

        listen_task = asyncio.create_task(client._listen())
        envelope = await asyncio.wait_for(client.receive(), timeout=2.0)
        await listen_task

        assert envelope.ciphertext == ct

    @pytest.mark.asyncio
    async def test_receive_ignores_frames_without_ct(self) -> None:
        ct = b"payload"
        ws = FakeWebSocket([
            json.dumps({"to": "addr", "ts": 0}),      # no "ct"
            _make_relay_msg("addr", ct),
        ])
        client = RelayClient("ws://localhost:8765", "addr")
        client._ws = ws
        client._connected = True

        listen_task = asyncio.create_task(client._listen())
        envelope = await asyncio.wait_for(client.receive(), timeout=2.0)
        await listen_task

        assert envelope.ciphertext == ct

    @pytest.mark.asyncio
    async def test_receive_raises_on_disconnect(self) -> None:
        ws = FakeWebSocket([])  # no messages — iterator ends immediately
        client = RelayClient("ws://localhost:8765", "addr")
        client._ws = ws
        client._connected = True

        listen_task = asyncio.create_task(client._listen())
        await listen_task

        with pytest.raises(RelayError, match="connection closed"):
            await asyncio.wait_for(client.receive(), timeout=2.0)

    @pytest.mark.asyncio
    async def test_receive_multiple_messages_in_order(self) -> None:
        payloads = [b"first", b"second", b"third"]
        ws = FakeWebSocket([_make_relay_msg("addr", p) for p in payloads])
        client = RelayClient("ws://localhost:8765", "addr")
        client._ws = ws
        client._connected = True

        listen_task = asyncio.create_task(client._listen())
        received = [
            (await asyncio.wait_for(client.receive(), timeout=2.0)).ciphertext
            for _ in payloads
        ]
        await listen_task

        assert received == payloads


# ---------------------------------------------------------------------------
# Async iterator interface
# ---------------------------------------------------------------------------


class TestAsyncIterator:
    @pytest.mark.asyncio
    async def test_aiter_yields_envelopes_then_stops(self) -> None:
        payloads = [b"a", b"b"]
        ws = FakeWebSocket([_make_relay_msg("addr", p) for p in payloads])
        client = RelayClient("ws://localhost:8765", "addr")
        client._ws = ws
        client._connected = True

        listen_task = asyncio.create_task(client._listen())
        collected = []
        async for env in client:
            collected.append(env.ciphertext)
        await listen_task

        assert collected == payloads


# ---------------------------------------------------------------------------
# connect() / close()
# ---------------------------------------------------------------------------


class TestLifecycle:
    @pytest.mark.asyncio
    async def test_context_manager_calls_close(self) -> None:
        ws = FakeWebSocket([])
        fake_http = _mock_http_send_ok()

        with (
            patch("drift.transport.client.websockets.connect", return_value=_FakeWSConnect(ws)),
            patch("drift.transport.client.httpx.AsyncClient", return_value=fake_http),
        ):
            async with RelayClient("ws://localhost:8765", "addr") as client:
                assert client._connected is True

        assert ws.closed is True
        fake_http.aclose.assert_awaited()

    @pytest.mark.asyncio
    async def test_connect_raises_relay_error_on_ws_failure(self) -> None:
        async def bad_connect(*_a: object, **_kw: object) -> None:
            raise OSError("connection refused")

        with patch("drift.transport.client.websockets.connect", side_effect=bad_connect):
            client = RelayClient("ws://localhost:8765", "addr")
            with pytest.raises(RelayError, match="could not connect"):
                await client.connect()

    @pytest.mark.asyncio
    async def test_http_base_url_derived_from_ws_url(self) -> None:
        client = RelayClient("ws://relay.local:9000", "addr")
        assert client._http_base == "http://relay.local:9000"
        assert client._ws_url == "ws://relay.local:9000/ws/addr"


# ---------------------------------------------------------------------------
# Phase 3 — SOCKS5 (Tor) routing
# ---------------------------------------------------------------------------


class TestSocksProxy:
    @pytest.mark.asyncio
    async def test_no_proxy_uses_plain_websocket(self) -> None:
        """Without a proxy, connect() takes the direct websockets path."""
        ws = FakeWebSocket([])
        fake_http = _mock_http_send_ok()
        with (
            patch(
                "drift.transport.client.websockets.connect",
                return_value=_FakeWSConnect(ws),
            ) as plain_connect,
            patch("drift.transport.client.httpx.AsyncClient", return_value=fake_http),
            patch("drift.transport.tor.open_socks_websocket") as socks_connect,
        ):
            client = RelayClient("ws://localhost:8765", "addr")
            await client.connect()
            await client.close()

        plain_connect.assert_called_once()
        socks_connect.assert_not_called()

    @pytest.mark.asyncio
    async def test_proxy_routes_ws_through_socks(self) -> None:
        """With a proxy, the WS handshake goes through tor.open_socks_websocket."""
        ws = FakeWebSocket([])
        fake_http = _mock_http_send_ok()
        with (
            patch(
                "drift.transport.client.websockets.connect",
                return_value=_FakeWSConnect(ws),
            ) as plain_connect,
            patch("drift.transport.client.httpx.AsyncClient", return_value=fake_http),
            patch(
                "drift.transport.tor.open_socks_websocket",
                AsyncMock(return_value=ws),
            ) as socks_connect,
        ):
            client = RelayClient(
                "ws://localhost:8765", "addr", socks_proxy=("127.0.0.1", 9050)
            )
            await client.connect()
            await client.close()

        plain_connect.assert_not_called()
        socks_connect.assert_awaited_once_with(
            "ws://localhost:8765/ws/addr", "127.0.0.1", 9050
        )

    @pytest.mark.asyncio
    async def test_proxy_configures_httpx_socks(self) -> None:
        """HTTP /send + /burn traffic shares the same SOCKS5 proxy."""
        ws = FakeWebSocket([])
        fake_http = _mock_http_send_ok()
        with (
            patch("drift.transport.client.httpx.AsyncClient", return_value=fake_http) as mk_http,
            patch(
                "drift.transport.tor.open_socks_websocket",
                AsyncMock(return_value=ws),
            ),
        ):
            client = RelayClient(
                "ws://localhost:8765", "addr", socks_proxy=("127.0.0.1", 9050)
            )
            await client.connect()
            await client.close()

        _, kwargs = mk_http.call_args
        assert kwargs.get("proxy") == "socks5://127.0.0.1:9050"


# ---------------------------------------------------------------------------
# Phase 4 — multi-relay failover
# ---------------------------------------------------------------------------


class TestFailover:
    def test_parses_comma_separated_relays(self) -> None:
        c = RelayClient("ws://r1:8765 , ws://r2:8765/", "addr")
        assert c.relays == ["ws://r1:8765", "ws://r2:8765"]
        assert c.node_count == 2

    def test_single_relay_no_failover_targets(self) -> None:
        c = RelayClient("ws://only:8765", "addr")
        assert c.node_count == 1

    def test_is_onion_detects_onion_relay(self) -> None:
        c = RelayClient("ws://abcdef.onion:8765", "addr")
        assert c.is_onion is True
        assert RelayClient("ws://clearnet:8765", "addr").is_onion is False

    @pytest.mark.asyncio
    async def test_fails_over_to_secondary_on_disconnect(self) -> None:
        """Primary drops mid-conversation → client reconnects to the secondary."""
        client = RelayClient("ws://r1:8765,ws://r2:8765", "addr")

        ws1 = FakeWebSocket([_make_relay_msg("addr", b"from-r1")])  # then ends → drop
        ws2 = FakeWebSocket([_make_relay_msg("addr", b"from-r2")])
        dials = {"ws://r1:8765/ws/addr": ws1, "ws://r2:8765/ws/addr": ws2}

        async def fake_dial(ws_url: str) -> FakeWebSocket:
            return dials[ws_url]

        with (
            patch.object(client, "_dial", fake_dial),
            patch.object(client, "_discover_peers", AsyncMock()),
            patch("drift.transport.client.httpx.AsyncClient", return_value=_mock_http_send_ok()),
        ):
            await client.connect()
            assert client._active_idx == 0

            first = await asyncio.wait_for(client.receive(), timeout=2.0)
            # ws1's iterator has ended → next receive triggers failover to r2.
            second = await asyncio.wait_for(client.receive(), timeout=2.0)
            await client.close()

        assert first.ciphertext == b"from-r1"
        assert second.ciphertext == b"from-r2"
        assert client._active_idx == 1   # now on the secondary

    @pytest.mark.asyncio
    async def test_connect_tries_relays_in_order(self) -> None:
        """First relay refuses; client transparently connects to the second."""
        client = RelayClient("ws://dead:8765,ws://live:8765", "addr")
        ws_live = FakeWebSocket([])

        async def fake_dial(ws_url: str) -> FakeWebSocket:
            if "dead" in ws_url:
                raise OSError("connection refused")
            return ws_live

        with (
            patch.object(client, "_dial", fake_dial),
            patch.object(client, "_discover_peers", AsyncMock()),
            patch("drift.transport.client.httpx.AsyncClient", return_value=_mock_http_send_ok()),
        ):
            await client.connect()
            assert client._active_idx == 1
            await client.close()

    @pytest.mark.asyncio
    async def test_connect_raises_when_all_relays_down(self) -> None:
        client = RelayClient("ws://a:8765,ws://b:8765", "addr")

        async def fake_dial(ws_url: str) -> FakeWebSocket:
            raise OSError("refused")

        with (
            patch.object(client, "_dial", fake_dial),
            patch("drift.transport.client.httpx.AsyncClient", return_value=_mock_http_send_ok()),
        ):
            with pytest.raises(RelayError, match="could not connect to any relay"):
                await client.connect()

    @pytest.mark.asyncio
    async def test_discover_peers_adds_failover_targets(self) -> None:
        client = RelayClient("ws://r1:8765", "addr")
        ws1 = FakeWebSocket([])

        peers_resp = MagicMock(spec=httpx.Response)
        peers_resp.json.return_value = {"peers": ["http://r2:8765", "https://r3:8765"]}
        http = _mock_http_send_ok()
        http.get = AsyncMock(return_value=peers_resp)

        async def fake_dial(ws_url: str) -> FakeWebSocket:
            return ws1

        with (
            patch.object(client, "_dial", fake_dial),
            patch("drift.transport.client.httpx.AsyncClient", return_value=http),
        ):
            await client.connect()
            await client.close()

        # Discovered peers are normalised to ws(s) and appended for failover.
        assert "ws://r2:8765" in client.relays
        assert "wss://r3:8765" in client.relays


# ---------------------------------------------------------------------------
# Bounded seen-address dedup (audit L1)
# ---------------------------------------------------------------------------

def test_bounded_addr_set_evicts_oldest_over_capacity() -> None:
    from drift.transport.session import _BoundedAddrSet

    s = _BoundedAddrSet(capacity=3)
    a, b, c, d = (bytes([i]) * 32 for i in range(4))
    for addr in (a, b, c):
        s.add(addr)
    assert a in s and b in s and c in s
    s.add(d)  # over capacity → oldest (a) evicted
    assert len(s) == 3
    assert a not in s
    assert b in s and c in s and d in s


def test_bounded_addr_set_membership_and_idempotent_add() -> None:
    from drift.transport.session import _BoundedAddrSet

    s = _BoundedAddrSet(capacity=2)
    x = b"\x01" * 32
    s.add(x)
    s.add(x)  # re-adding an existing member must not grow the set
    assert len(s) == 1
    assert x in s
    assert b"\x02" * 32 not in s


# ---------------------------------------------------------------------------
# A forged inbound must not tear down a live session (audit §2 HIGH)
# ---------------------------------------------------------------------------


class _FakeFirehose:
    """Async-iterable RelayClient stand-in: yield preloaded items, then stop."""

    def __init__(self, items: list) -> None:
        self._items = list(items)

    def __aiter__(self) -> AsyncIterator:
        async def _gen() -> AsyncIterator:
            for item in self._items:
                yield item
        return _gen()


@pytest.mark.asyncio
async def test_forged_inbound_does_not_kill_session() -> None:
    from drift.crypto import Identity
    from drift.transport.session import STEALTH_CHANNEL, PairwiseRatchet, Session

    alice = Identity.generate()
    bob = Identity.generate()

    # Alice → Bob: two genuine, sealed, stealth-addressed envelopes.
    alice_ch = PairwiseRatchet(alice, bob.contact_code())
    addr_a, blob_a, _ = alice_ch.encrypt(b"tampered-one")   # send #0
    addr_b, blob_b, _ = alice_ch.encrypt(b"genuine-two")    # send #1

    # A corrupted copy of #0: the front (ephemeral + addr) is intact so it still
    # scan-matches Bob, but a flipped inner byte fails the sealed-header AEAD —
    # exactly the replay a relay/wire attacker would use to force an InvalidTag.
    corrupt = bytearray(blob_a)
    corrupt[50] ^= 0x01

    firehose = [
        Envelope(to=STEALTH_CHANNEL, ciphertext=bytes(corrupt), one_time_addr=addr_a),
        Envelope(to=STEALTH_CHANNEL, ciphertext=blob_b, one_time_addr=addr_b),
        Envelope(to=STEALTH_CHANNEL, ciphertext=blob_a, one_time_addr=addr_a),
    ]

    bob_session = Session(bob, alice.contact_code(), "ws://localhost:8765")
    bob_session._client = _FakeFirehose(firehose)  # type: ignore[assignment]

    # InvalidTag must NOT escape the receive loop: the comprehension completes.
    received = [text async for text in bob_session.messages()]

    # The forged copy was dropped, the genuine follow-up decrypted, and the later
    # genuine copy of #0 still decrypted — the corrupt copy never poisoned its
    # one-time-address dedup slot. The session stayed alive throughout.
    assert received == ["genuine-two", "tampered-one"]
