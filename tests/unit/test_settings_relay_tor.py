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
from drift.transport import tor


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
