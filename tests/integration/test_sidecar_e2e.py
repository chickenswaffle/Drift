"""
tests/integration/test_sidecar_e2e.py — the hermetic sidecar smoke test

Spawns two *real* sidecar subprocesses (``python -m drift.sidecar``), each with
its own isolated $DRIFT_CONFIG home, against the in-process relay from
test_e2e. This exercises the exact seam the desktop app uses — the newline-
delimited JSON-RPC wire protocol, not the Sidecar class — end to end:

  init → invite (create/resolve/one-time) → chat_open → send/receive → burn

Requires the relay extras: pip install -e ".[dev]"
Run: pytest tests/integration/test_sidecar_e2e.py -v
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import sys
from pathlib import Path
from typing import Any

import pytest
import uvicorn

import relay.server as relay_module
from drift.crypto import Identity
from relay.server import app as relay_app


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
async def relay_url() -> Any:
    """In-process relay on a free port, module state cleared (see test_e2e)."""
    relay_module._recent.clear()
    relay_module._subscribers.clear()
    relay_module._prekeys.clear()
    relay_module._beacons.clear()

    port = _free_port()
    config = uvicorn.Config(relay_app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    for _ in range(100):
        if server.started:
            break
        await asyncio.sleep(0.05)
    else:
        server.should_exit = True
        await task
        raise RuntimeError("relay did not start within 5 s")

    yield f"ws://127.0.0.1:{port}"

    server.should_exit = True
    await task


class SidecarProc:
    """One live ``python -m drift.sidecar`` child, spoken to over stdio."""

    def __init__(self, config_dir: Path) -> None:
        self.config_dir = config_dir
        self._proc: asyncio.subprocess.Process | None = None
        self._next_id = 0
        self._pending: dict[int, asyncio.Future[dict[str, Any]]] = {}
        self.events: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self._reader: asyncio.Task[None] | None = None

    async def start(self) -> None:
        env = {**os.environ, "DRIFT_CONFIG": str(self.config_dir)}
        self._proc = await asyncio.create_subprocess_exec(
            sys.executable, "-m", "drift.sidecar",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            env=env,
        )
        self._reader = asyncio.create_task(self._read_loop())
        ready = await asyncio.wait_for(self.events.get(), timeout=15.0)
        assert ready["event"] == "ready"

    async def _read_loop(self) -> None:
        assert self._proc is not None and self._proc.stdout is not None
        while True:
            line = await self._proc.stdout.readline()
            if not line:
                break
            frame = json.loads(line)
            if "id" in frame and frame["id"] in self._pending:
                self._pending.pop(frame["id"]).set_result(frame)
            elif "event" in frame:
                self.events.put_nowait(frame)

    async def call(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """RPC round-trip; raises AssertionError with the error string on ok=false."""
        resp = await self.call_raw(method, params)
        assert resp["ok"], f"{method}: {resp.get('error')}"
        result: dict[str, Any] = resp["result"]
        return result

    async def call_raw(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        assert self._proc is not None and self._proc.stdin is not None
        self._next_id += 1
        req_id = self._next_id
        fut: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
        self._pending[req_id] = fut
        line = json.dumps({"id": req_id, "method": method, "params": params or {}})
        self._proc.stdin.write(line.encode() + b"\n")
        await self._proc.stdin.drain()
        return await asyncio.wait_for(fut, timeout=15.0)

    async def next_event(self, name: str, timeout: float = 10.0) -> dict[str, Any]:
        """The next event of type ``name``, skipping others (status chatter)."""
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            frame = await asyncio.wait_for(self.events.get(), timeout=max(0.1, remaining))
            if frame["event"] == name:
                return frame

    async def stop(self) -> None:
        if self._proc is not None and self._proc.stdin is not None:
            self._proc.stdin.close()
            try:
                await asyncio.wait_for(self._proc.wait(), timeout=5.0)
            except TimeoutError:
                self._proc.kill()
        if self._reader is not None:
            self._reader.cancel()


@pytest.fixture
async def two_sidecars(tmp_path: Path) -> Any:
    a = SidecarProc(tmp_path / "a")
    b = SidecarProc(tmp_path / "b")
    await a.start()
    await b.start()
    yield a, b
    await a.stop()
    await b.stop()


def _initiator_first(
    a: SidecarProc, code_a: str, b: SidecarProc, code_b: str
) -> tuple[SidecarProc, SidecarProc]:
    """Order (sender, receiver) so the sender is the ratchet initiator (the
    lower static spend key) — only the initiator may send the first message."""
    _, spend_a = Identity.parse_contact_code(code_a)
    _, spend_b = Identity.parse_contact_code(code_b)
    return (a, b) if spend_a < spend_b else (b, a)


@pytest.mark.asyncio
async def test_two_sidecars_exchange_message(relay_url: str, two_sidecars: Any) -> None:
    """The smoke test: two frozen-app-equivalent sidecars, full X3DH + Double
    Ratchet + stealth addressing, one message across the wire."""
    a, b = two_sidecars
    code_a = (await a.call("init"))["contact_code"]
    code_b = (await b.call("init"))["contact_code"]
    await a.call("contacts_add", {"name": "peer", "code": code_b})
    await b.call("contacts_add", {"name": "peer", "code": code_a})

    sender, receiver = _initiator_first(a, code_a, b, code_b)
    await sender.call("chat_open", {"contact": "peer", "relay_url": relay_url})
    await receiver.call("chat_open", {"contact": "peer", "relay_url": relay_url})

    await sender.call("chat_send", {"convo": "peer", "text": "hello across sidecars"})

    evt = await receiver.next_event("message")
    assert evt["data"] == {"convo": "peer", "dir": "in", "text": "hello across sidecars"}


@pytest.mark.asyncio
async def test_invite_flow_end_to_end(relay_url: str, two_sidecars: Any) -> None:
    """Disappearing contact code: minted by A, redeemed once by B, then gone."""
    a, b = two_sidecars
    code_a = (await a.call("init"))["contact_code"]
    await b.call("init")

    minted = await a.call("invite_create", {"ttl_seconds": 60, "relay_url": relay_url})
    assert minted["code"].startswith("driftinvite:")
    assert minted["ttl_seconds"] == 60

    resolved = await b.call(
        "invite_resolve", {"name": "alice", "code": minted["code"], "relay_url": relay_url}
    )
    assert resolved["contact_code"] == code_a
    assert "alice" in resolved["contacts"]
    assert resolved["safety_number"]

    # One-time: the first resolve deleted the beacon — a second redeem fails,
    # indistinguishably from expiry.
    again = await b.call_raw(
        "invite_resolve", {"name": "alice2", "code": minted["code"], "relay_url": relay_url}
    )
    assert again["ok"] is False
    assert again["error"] == "invite not found, expired, or already used"


@pytest.mark.asyncio
async def test_extinguish_kills_unredeemed_invite(relay_url: str, two_sidecars: Any) -> None:
    a, b = two_sidecars
    await a.call("init")
    await b.call("init")
    minted = await a.call("invite_create", {"ttl_seconds": 60, "relay_url": relay_url})
    await a.call("invite_extinguish", {"code": minted["code"], "relay_url": relay_url})
    resp = await b.call_raw(
        "invite_resolve", {"name": "alice", "code": minted["code"], "relay_url": relay_url}
    )
    assert resp["ok"] is False


@pytest.mark.asyncio
async def test_burn_last_message_reaches_peer(relay_url: str, two_sidecars: Any) -> None:
    """chat_burn posts a tombstone the peer's client verifies and surfaces as a
    'burn' event (and the relay echoes it to the burner too)."""
    a, b = two_sidecars
    code_a = (await a.call("init"))["contact_code"]
    code_b = (await b.call("init"))["contact_code"]
    await a.call("contacts_add", {"name": "peer", "code": code_b})
    await b.call("contacts_add", {"name": "peer", "code": code_a})

    sender, receiver = _initiator_first(a, code_a, b, code_b)
    await sender.call("chat_open", {"contact": "peer", "relay_url": relay_url})
    await receiver.call("chat_open", {"contact": "peer", "relay_url": relay_url})

    await sender.call("chat_send", {"convo": "peer", "text": "soon to vanish"})
    await receiver.next_event("message")

    await sender.call("chat_burn", {"convo": "peer", "scope": "message"})

    evt = await receiver.next_event("burn")
    assert evt["data"]["convo"] == "peer"
    assert evt["data"]["scope"] == "message"
    # The relay broadcasts to every subscriber — the burner sees it too.
    echo = await sender.next_event("burn")
    assert echo["data"]["scope"] == "message"
