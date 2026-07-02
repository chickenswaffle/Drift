"""
tests/unit/test_sidecar.py — the JSON-RPC bridge the desktop app talks to

Drives the Sidecar class directly (no subprocess, no relay): dispatch
semantics, error hygiene (unexpected exceptions must not leak their repr to
the UI), boundary validation, the contact/invite/vault handlers, and the
per-conversation lock behavior under concurrent send/close.

Network-touching handlers (invite_create against a live relay, chat_open) are
covered by the integration suite; here they're exercised only up to their
local validation.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

import drift.sidecar as sidecar_mod
from drift import storage
from drift.crypto import Identity, b58encode, panic
from drift.sidecar import Sidecar, _Conversation, _RoomConversation

_FAST = panic.KDFParams(time_cost=1, memory_cost=8, parallelism=1)


@pytest.fixture
def store(tmp_path, monkeypatch):  # type: ignore[no-untyped-def]
    """Redirect storage at an isolated temp config dir (never touch ~)."""
    monkeypatch.setattr(panic, "DEFAULT_PARAMS", _FAST)
    monkeypatch.setattr(storage, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(storage, "IDENTITY_FILE", tmp_path / "identity.json")
    monkeypatch.setattr(storage, "CONTACTS_DIR", tmp_path / "contacts")
    monkeypatch.setattr(storage, "GROUPS_DIR", tmp_path / "groups")
    monkeypatch.setattr(storage, "ROOMS_DIR", tmp_path / "rooms")
    monkeypatch.setattr(storage, "PREKEYS_DIR", tmp_path / "prekeys")
    monkeypatch.setattr(storage, "VAULT_FILE", tmp_path / "vault.bin")
    monkeypatch.setattr(storage, "SETTINGS_FILE", tmp_path / "settings.json")
    monkeypatch.delenv("DRIFT_RELAY_URL", raising=False)
    return tmp_path


@pytest.fixture
def frames(monkeypatch) -> list[dict[str, Any]]:  # type: ignore[no-untyped-def]
    """Capture every frame the sidecar would write to stdout."""
    out: list[dict[str, Any]] = []
    monkeypatch.setattr(sidecar_mod, "_write_frame", out.append)
    return out


async def call(
    sc: Sidecar, frames: list[dict[str, Any]], method: str, params: dict[str, Any] | None = None
) -> dict[str, Any]:
    await sc.dispatch({"id": 1, "method": method, "params": params or {}})
    return frames[-1]


def make_sidecar() -> Sidecar:
    return Sidecar(asyncio.get_event_loop())


# --------------------------------------------------------------------------- #
# Dispatch + error hygiene
# --------------------------------------------------------------------------- #


class TestDispatch:
    async def test_ping(self, frames) -> None:  # type: ignore[no-untyped-def]
        resp = await call(make_sidecar(), frames, "ping")
        assert resp == {"id": 1, "ok": True, "result": {"pong": True}}

    async def test_unknown_method_rejected(self, frames) -> None:  # type: ignore[no-untyped-def]
        resp = await call(make_sidecar(), frames, "definitely_not_a_method")
        assert resp["ok"] is False
        assert "unknown method" in resp["error"]

    async def test_internal_errors_are_generic(self, frames, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        """An unexpected exception must not leak its type or message to the UI."""
        sc = make_sidecar()

        async def boom(_: dict[str, Any]) -> dict[str, Any]:
            raise RuntimeError("secret-/private/path-detail")

        monkeypatch.setitem(sc._handlers, "status", boom)
        resp = await call(sc, frames, "status")
        assert resp["ok"] is False
        assert "RuntimeError" not in resp["error"]
        assert "secret" not in resp["error"]
        assert resp["error"] == "internal error — see sidecar log"


# --------------------------------------------------------------------------- #
# Boundary validation
# --------------------------------------------------------------------------- #


class TestValidation:
    async def test_fmd_set_rejects_out_of_range(self, store, frames) -> None:  # type: ignore[no-untyped-def]
        sc = make_sidecar()
        for bad in (-0.1, 1.5, float("nan")):
            resp = await call(sc, frames, "fmd_set", {"rate": bad})
            assert resp["ok"] is False, bad
        resp = await call(sc, frames, "fmd_set", {"rate": "junk"})
        assert resp["ok"] is False

    async def test_fmd_set_accepts_valid_rate(self, store, frames) -> None:  # type: ignore[no-untyped-def]
        resp = await call(make_sidecar(), frames, "fmd_set", {"rate": 2 ** -6})
        assert resp["ok"] is True

    async def test_init_rejects_bad_duress_mode(self, store, frames) -> None:  # type: ignore[no-untyped-def]
        resp = await call(
            make_sidecar(), frames, "init",
            {"passphrase": "x", "duress_passphrase": "y", "duress_mode": "explode"},
        )
        assert resp["ok"] is False
        assert "duress_mode" in resp["error"]

    async def test_group_create_rejects_non_list_members(self, store, frames) -> None:  # type: ignore[no-untyped-def]
        sc = make_sidecar()
        await call(sc, frames, "init")
        resp = await call(sc, frames, "group_create", {"name": "g", "members": "alice"})
        assert resp["ok"] is False
        assert "list" in resp["error"]

    async def test_group_create_rejects_over_cap(self, store, frames) -> None:  # type: ignore[no-untyped-def]
        sc = make_sidecar()
        await call(sc, frames, "init")
        resp = await call(
            sc, frames, "group_create",
            {"name": "g", "members": [f"m{i}" for i in range(11)]},
        )
        assert resp["ok"] is False
        assert "10" in resp["error"]

    async def test_chat_burn_rejects_bad_scope(self, frames) -> None:  # type: ignore[no-untyped-def]
        resp = await call(make_sidecar(), frames, "chat_burn", {"convo": "x", "scope": "galaxy"})
        assert resp["ok"] is False

    async def test_invite_resolve_failures_indistinguishable(self, store, frames) -> None:  # type: ignore[no-untyped-def]
        """Garbage codes fail with the same message as expired/used ones —
        locally, before any relay traffic."""
        sc = make_sidecar()
        await call(sc, frames, "init")
        for bad in ("nope", "drift:abc", "driftinvite:tooshort", "driftinvite:0OIl"):
            resp = await call(sc, frames, "invite_resolve", {"name": "n", "code": bad})
            assert resp["ok"] is False, bad
            assert resp["error"] == "invite not found, expired, or already used"


# --------------------------------------------------------------------------- #
# Contacts
# --------------------------------------------------------------------------- #


class TestContacts:
    async def test_add_and_remove(self, store, frames) -> None:  # type: ignore[no-untyped-def]
        sc = make_sidecar()
        await call(sc, frames, "init")
        code = Identity.generate().contact_code()
        resp = await call(sc, frames, "contacts_add", {"name": "bob", "code": code})
        assert resp["ok"] is True and "bob" in resp["result"]["contacts"]
        resp = await call(sc, frames, "contacts_remove", {"name": "bob"})
        assert resp["ok"] is True and resp["result"]["contacts"] == {}

    async def test_remove_unknown_is_noop(self, store, frames) -> None:  # type: ignore[no-untyped-def]
        sc = make_sidecar()
        await call(sc, frames, "init")
        resp = await call(sc, frames, "contacts_remove", {"name": "ghost"})
        assert resp["ok"] is True and resp["result"]["contacts"] == {}

    async def test_remove_requires_name(self, store, frames) -> None:  # type: ignore[no-untyped-def]
        resp = await call(make_sidecar(), frames, "contacts_remove", {})
        assert resp["ok"] is False

    async def test_contacts_shape_has_code_and_verified(self, store, frames) -> None:  # type: ignore[no-untyped-def]
        sc = make_sidecar()
        await call(sc, frames, "init")
        code = Identity.generate().contact_code()
        resp = await call(sc, frames, "contacts_add", {"name": "bob", "code": code})
        assert resp["result"]["contacts"]["bob"] == {"code": code, "verified": False}

    async def test_contact_verify_roundtrip(self, store, frames) -> None:  # type: ignore[no-untyped-def]
        """Verify sets the attestation bit; unverify clears it; the flag
        survives a fresh contacts_list read (it is persisted)."""
        sc = make_sidecar()
        await call(sc, frames, "init")
        code = Identity.generate().contact_code()
        await call(sc, frames, "contacts_add", {"name": "bob", "code": code})

        resp = await call(sc, frames, "contact_verify", {"name": "bob"})
        assert resp["ok"] is True
        assert resp["result"]["contacts"]["bob"]["verified"] is True

        resp = await call(sc, frames, "contacts_list")
        assert resp["result"]["contacts"]["bob"]["verified"] is True

        resp = await call(sc, frames, "contact_verify", {"name": "bob", "verified": False})
        assert resp["result"]["contacts"]["bob"]["verified"] is False

    async def test_contact_verify_unknown_or_missing_name(self, store, frames) -> None:  # type: ignore[no-untyped-def]
        sc = make_sidecar()
        await call(sc, frames, "init")
        resp = await call(sc, frames, "contact_verify", {"name": "ghost"})
        assert resp["ok"] is False
        resp = await call(sc, frames, "contact_verify", {})
        assert resp["ok"] is False


# --------------------------------------------------------------------------- #
# Vault / panic
# --------------------------------------------------------------------------- #


class TestPanic:
    async def test_panic_requires_vault(self, store, frames) -> None:  # type: ignore[no-untyped-def]
        sc = make_sidecar()
        await call(sc, frames, "init")  # identity but no vault
        resp = await call(sc, frames, "panic_lock")
        assert resp["ok"] is False
        assert "vault" in resp["error"]

    async def test_panic_shreds_working_copy(self, store, frames) -> None:  # type: ignore[no-untyped-def]
        sc = make_sidecar()
        await call(sc, frames, "init", {"passphrase": "pw"})
        assert storage.identity_exists()
        resp = await call(sc, frames, "panic_lock")
        assert resp["ok"] is True and resp["result"]["locked"] is True
        assert not storage.identity_exists()  # plaintext gone
        assert storage.vault_exists()         # sealed vault still there
        # And the passphrase still opens it.
        resp = await call(sc, frames, "unlock", {"passphrase": "pw"})
        assert resp["ok"] is True and resp["result"]["ok"] is True


# --------------------------------------------------------------------------- #
# Cover level
# --------------------------------------------------------------------------- #


class TestCover:
    async def test_roundtrip_and_junk(self, store, frames) -> None:  # type: ignore[no-untyped-def]
        sc = make_sidecar()
        resp = await call(sc, frames, "cover_get")
        assert resp["result"]["cover_level"] == "off"
        resp = await call(sc, frames, "cover_set", {"level": "high"})
        assert resp["result"]["cover_level"] == "high"
        resp = await call(sc, frames, "cover_get")
        assert resp["result"]["cover_level"] == "high"
        resp = await call(sc, frames, "cover_set", {"level": "maximum-overdrive"})
        assert resp["ok"] is False


# --------------------------------------------------------------------------- #
# Relay + Tor
# --------------------------------------------------------------------------- #


class TestRelayAndTor:
    async def test_relay_roundtrip(self, store, frames) -> None:  # type: ignore[no-untyped-def]
        sc = make_sidecar()
        resp = await call(sc, frames, "relay_get")
        assert resp["result"]["relay_url"] == "ws://127.0.0.1:8765"
        resp = await call(sc, frames, "relay_set", {"relay_url": "wss://my.relay:443"})
        assert resp["result"]["relay_url"] == "wss://my.relay:443"
        resp = await call(sc, frames, "relay_get")
        assert resp["result"]["relay_url"] == "wss://my.relay:443"

    async def test_relay_set_rejects_bad_url(self, store, frames) -> None:  # type: ignore[no-untyped-def]
        resp = await call(make_sidecar(), frames, "relay_set", {"relay_url": "http://nope"})
        assert resp["ok"] is False

    async def test_relay_url_flows_into_status(self, store, frames) -> None:  # type: ignore[no-untyped-def]
        sc = make_sidecar()
        await call(sc, frames, "relay_set", {"relay_url": "wss://r:443"})
        resp = await call(sc, frames, "status")
        assert resp["result"]["relay_url"] == "wss://r:443"

    async def test_tor_set_roundtrip_and_status(self, store, frames, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        # Report a backend as present so the mode isn't force-clamped anywhere.
        from drift.transport import tor
        monkeypatch.setattr(tor, "available", lambda: True)
        sc = make_sidecar()
        resp = await call(sc, frames, "tor_get")
        assert resp["result"]["tor_mode"] == "off"
        assert resp["result"]["tor_active"] is False
        resp = await call(sc, frames, "tor_set", {"mode": "prefer"})
        assert resp["result"]["tor_mode"] == "prefer"
        assert resp["result"]["tor_available"] is True
        resp = await call(sc, frames, "tor_status")
        assert resp["result"]["tor_mode"] == "prefer"

    async def test_tor_set_rejects_junk(self, store, frames) -> None:  # type: ignore[no-untyped-def]
        resp = await call(make_sidecar(), frames, "tor_set", {"mode": "onion-everything"})
        assert resp["ok"] is False

    async def test_ensure_tor_off_is_none(self, store, frames) -> None:  # type: ignore[no-untyped-def]
        sc = make_sidecar()
        assert await sc._ensure_tor() is None

    async def test_ensure_tor_require_no_backend_raises(self, store, frames, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        from drift.sidecar import RpcError
        from drift.transport import tor
        monkeypatch.setattr(tor, "available", lambda: False)
        sc = make_sidecar()
        await call(sc, frames, "tor_set", {"mode": "require"})
        with pytest.raises(RpcError):
            await sc._ensure_tor()

    async def test_ensure_tor_prefer_no_backend_ok(self, store, frames, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        from drift.transport import tor
        monkeypatch.setattr(tor, "available", lambda: False)
        sc = make_sidecar()
        await call(sc, frames, "tor_set", {"mode": "prefer"})
        assert await sc._ensure_tor() is None  # clearnet, no raise

    async def test_invite_resolve_routes_beacon_over_tor(self, store, frames, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        """When a circuit is up, invite/beacon HTTP must carry the same SOCKS
        proxy — otherwise enabling Tor still leaks the IP on invite resolve."""
        from drift.transport import beacon_http

        sc = make_sidecar()
        await call(sc, frames, "init")

        class _FakeCircuit:
            socks_proxy = ("127.0.0.1", 9999)

        async def fake_ensure_tor() -> Any:
            return _FakeCircuit()

        seen: dict[str, Any] = {}

        async def fake_pubkey(http_base: str, socks: Any = None) -> bytes:
            seen["pubkey"] = socks
            return bytes(range(32))

        async def fake_get(http_base: str, digest: str, socks: Any = None) -> bytes | None:
            seen["get"] = socks
            return None  # forces the indistinguishable failure; we only assert routing

        monkeypatch.setattr(sc, "_ensure_tor", fake_ensure_tor)
        monkeypatch.setattr(beacon_http, "fetch_relay_pubkey", fake_pubkey)
        monkeypatch.setattr(beacon_http, "get_beacon", fake_get)

        code = f"driftinvite:{b58encode(bytes(16))}"
        resp = await call(sc, frames, "invite_resolve", {"name": "x", "code": code})
        assert resp["ok"] is False  # beacon absent → expected failure
        assert seen["pubkey"] == ("127.0.0.1", 9999)
        assert seen["get"] == ("127.0.0.1", 9999)


# --------------------------------------------------------------------------- #
# Conversation locks + burn routing
# --------------------------------------------------------------------------- #


class _FakeSession:
    """Stands in for a transport Session: slow send, recorded burns."""

    def __init__(self) -> None:
        self.closed = False
        self.sent: list[str] = []
        self.burned: list[str] = []

    async def send(self, text: str) -> None:
        await asyncio.sleep(0.01)  # widen the race window
        if self.closed:
            raise RuntimeError("send after close")
        self.sent.append(text)

    async def burn_last_message(self) -> None:
        self.burned.append("message")

    async def burn_conversation(self) -> None:
        self.burned.append("conversation")

    async def __aexit__(self, *exc: object) -> None:
        self.closed = True


class TestConvoLocks:
    async def test_concurrent_send_and_close_serialized(self, frames) -> None:  # type: ignore[no-untyped-def]
        """chat_close must not pull the session out from under an in-flight
        send — the per-convo lock serializes them (either order is legal)."""
        sc = make_sidecar()
        session = _FakeSession()
        sc._convos["bob"] = _Conversation("bob", session, asyncio.get_event_loop())

        await asyncio.gather(
            sc.dispatch({"id": 1, "method": "chat_send",
                         "params": {"convo": "bob", "text": "hi"}}),
            sc.dispatch({"id": 2, "method": "chat_close", "params": {"convo": "bob"}}),
        )
        by_id = {f["id"]: f for f in frames if "id" in f}
        assert by_id[2]["ok"] is True
        if by_id[1]["ok"]:
            assert session.sent == ["hi"]      # send won the lock, then close
        else:
            assert "no open conversation" in by_id[1]["error"]  # close won

    async def test_chat_burn_requires_open_convo(self, frames) -> None:  # type: ignore[no-untyped-def]
        resp = await call(make_sidecar(), frames, "chat_burn", {"convo": "ghost"})
        assert resp["ok"] is False
        assert "no open conversation" in resp["error"]

    async def test_chat_burn_is_1to1_only(self, frames) -> None:  # type: ignore[no-untyped-def]
        sc = make_sidecar()
        sc._convos["lobby"] = _RoomConversation(
            "lobby", _FakeSession(), asyncio.get_event_loop())
        resp = await call(sc, frames, "chat_burn", {"convo": "lobby"})
        assert resp["ok"] is False
        assert "1:1" in resp["error"]

    async def test_chat_burn_routes_scope(self, frames) -> None:  # type: ignore[no-untyped-def]
        sc = make_sidecar()
        session = _FakeSession()
        sc._convos["bob"] = _Conversation("bob", session, asyncio.get_event_loop())
        resp = await call(sc, frames, "chat_burn", {"convo": "bob", "scope": "message"})
        assert resp["ok"] is True
        resp = await call(sc, frames, "chat_burn", {"convo": "bob", "scope": "conversation"})
        assert resp["ok"] is True
        assert session.burned == ["message", "conversation"]
