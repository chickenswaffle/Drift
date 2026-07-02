"""
tests/unit/test_settings_relay_tor.py — relay URL + Tor mode persistence

The desktop app lets the user point DRIFT at their own relay and choose a Tor
routing mode; both persist in settings.json alongside fmd_rate/cover_level.
These are the storage-layer contracts (validation, defaults, round-trip) plus
the tor.available() backend probe.
"""

from __future__ import annotations

import pytest

from drift import storage
from drift.transport import beacon_http, tor


@pytest.fixture
def cfg(tmp_path, monkeypatch):  # type: ignore[no-untyped-def]
    monkeypatch.setattr(storage, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(storage, "SETTINGS_FILE", tmp_path / "settings.json")
    monkeypatch.delenv("DRIFT_RELAY_URL", raising=False)
    return tmp_path


class TestRelayUrl:
    def test_default_localhost(self, cfg) -> None:  # type: ignore[no-untyped-def]
        assert storage.get_relay_url() == "ws://127.0.0.1:8765"

    def test_env_default(self, cfg, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        monkeypatch.setenv("DRIFT_RELAY_URL", "wss://relay.example:9000")
        assert storage.get_relay_url() == "wss://relay.example:9000"

    def test_roundtrip(self, cfg) -> None:  # type: ignore[no-untyped-def]
        assert storage.set_relay_url("wss://my.relay:443") == "wss://my.relay:443"
        assert storage.get_relay_url() == "wss://my.relay:443"

    def test_trailing_slash_stripped(self, cfg) -> None:  # type: ignore[no-untyped-def]
        assert storage.set_relay_url("ws://host:8765/") == "ws://host:8765"

    def test_rejects_non_websocket(self, cfg) -> None:  # type: ignore[no-untyped-def]
        for bad in ("https://host", "host:8765", "ws://", ""):
            with pytest.raises(storage.StorageError):
                storage.set_relay_url(bad)

    def test_stored_overrides_env(self, cfg, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        monkeypatch.setenv("DRIFT_RELAY_URL", "wss://env.relay:9000")
        storage.set_relay_url("wss://chosen.relay:443")
        assert storage.get_relay_url() == "wss://chosen.relay:443"


class TestTorMode:
    def test_default_off(self, cfg) -> None:  # type: ignore[no-untyped-def]
        assert storage.get_tor_mode() == "off"

    def test_roundtrip(self, cfg) -> None:  # type: ignore[no-untyped-def]
        for mode in ("prefer", "require", "off"):
            assert storage.set_tor_mode(mode) == mode
            assert storage.get_tor_mode() == mode

    def test_rejects_junk(self, cfg) -> None:  # type: ignore[no-untyped-def]
        with pytest.raises(storage.StorageError):
            storage.set_tor_mode("supersecret")

    def test_junk_on_disk_reads_as_off(self, cfg) -> None:  # type: ignore[no-untyped-def]
        (cfg / "settings.json").write_text('{"tor_mode": "banana"}')
        assert storage.get_tor_mode() == "off"

    def test_relay_and_tor_coexist(self, cfg) -> None:  # type: ignore[no-untyped-def]
        storage.set_relay_url("wss://r:443")
        storage.set_tor_mode("require")
        storage.set_fmd_rate(0.25)
        assert storage.get_relay_url() == "wss://r:443"
        assert storage.get_tor_mode() == "require"
        assert storage.get_fmd_rate() == 0.25


class TestTorAvailable:
    def test_returns_bool(self) -> None:
        assert isinstance(tor.available(), bool)

    def test_true_when_a_backend_present(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        monkeypatch.setattr(tor, "_backend_installed", lambda name: name == "stem")
        assert tor.available() is True

    def test_false_when_no_backend(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        monkeypatch.setattr(tor, "_backend_installed", lambda name: False)
        assert tor.available() is False


class TestResolveTorBinary:
    def test_default_is_path_tor(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        monkeypatch.delenv("DRIFT_TOR_BINARY", raising=False)
        monkeypatch.delattr(tor.sys, "_MEIPASS", raising=False)
        assert tor.resolve_tor_binary() == "tor"

    def test_env_override_wins(self, tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        binpath = tmp_path / "mytor"
        binpath.write_text("#!/bin/sh\n")
        monkeypatch.setenv("DRIFT_TOR_BINARY", str(binpath))
        assert tor.resolve_tor_binary() == str(binpath)

    def test_env_override_ignored_if_missing(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        monkeypatch.setenv("DRIFT_TOR_BINARY", "/no/such/tor")
        monkeypatch.delattr(tor.sys, "_MEIPASS", raising=False)
        assert tor.resolve_tor_binary() == "tor"

    def test_bundled_next_to_frozen_sidecar(self, tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        monkeypatch.delenv("DRIFT_TOR_BINARY", raising=False)
        name = "tor.exe" if tor.os.name == "nt" else "tor"
        (tmp_path / name).write_text("#!/bin/sh\n")
        monkeypatch.setattr(tor.sys, "_MEIPASS", str(tmp_path), raising=False)
        assert tor.resolve_tor_binary() == str(tmp_path / name)

    def test_env_beats_bundled(self, tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        name = "tor.exe" if tor.os.name == "nt" else "tor"
        (tmp_path / name).write_text("bundled")
        monkeypatch.setattr(tor.sys, "_MEIPASS", str(tmp_path), raising=False)
        override = tmp_path / "override-tor"
        override.write_text("override")
        monkeypatch.setenv("DRIFT_TOR_BINARY", str(override))
        assert tor.resolve_tor_binary() == str(override)


class TestBeaconHttpSocks:
    """Beacon/invite HTTP must ride the Tor circuit when one is active, or
    enabling Tor still leaks the client IP to the relay on every invite."""

    def test_direct_client_has_no_proxy(self) -> None:
        client = beacon_http._client(None)
        try:
            assert client._mounts == {} or all(
                t is None for t in client._mounts.values()
            )
        finally:
            pass  # not entered as a context manager; nothing to close

    def test_socks_client_mounts_a_proxy(self) -> None:
        # A SOCKS proxy produces a routed transport (httpx mounts it for all://).
        client = beacon_http._client(("127.0.0.1", 9050))
        assert any(t is not None for t in client._mounts.values())
