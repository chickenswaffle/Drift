"""
tests/unit/test_build_sidecar.py — the frozen-sidecar PyInstaller arg builder

The freeze script (apps/desktop/sidecar/build_sidecar.py) bundles Tor into the
sidecar: the Python backends always, and a real tor binary when one is
provided. These guard the two contracts that make Tor work in a shipped build —
the backends are collected, and a provided binary (plus its sibling libs) is
embedded at the unpack root where tor.resolve_tor_binary() looks.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_SCRIPT = (
    Path(__file__).resolve().parents[2]
    / "apps" / "desktop" / "sidecar" / "build_sidecar.py"
)


def _load():  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location("build_sidecar", _SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


bs = _load()


class TestBackendsAlwaysCollected:
    def test_tor_python_backends_collected(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        args = bs.build_pyinstaller_args(
            dist=tmp_path / "d", work=tmp_path / "w", tor_binary=None, pyi_arch=None
        )
        joined = " ".join(args)
        for backend in ("stem", "python_socks"):
            assert backend in args
        assert "socksio" in args
        # No binary provided → no --add-binary for tor.
        assert "--add-binary" not in args
        assert joined.endswith("drift_sidecar_entry.py")


class TestTorBinaryBundling:
    def test_add_binary_present_when_provided(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        torbin = tmp_path / "tor"
        torbin.write_text("#!/bin/sh\n")
        args = bs.tor_add_binary_args(str(torbin))
        assert "--add-binary" in args
        # Destination is the bundle root (".").
        pair = args[args.index("--add-binary") + 1]
        assert pair.endswith((":.", ";."))
        assert str(torbin) in pair

    def test_missing_binary_is_a_hard_error(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        with pytest.raises(SystemExit):
            bs.tor_add_binary_args(str(tmp_path / "nope"))

    def test_none_binary_is_empty(self) -> None:
        assert bs.tor_add_binary_args(None) == []

    def test_sibling_libs_co_bundled(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        torbin = tmp_path / "tor"
        torbin.write_text("#!/bin/sh\n")
        (tmp_path / "libevent.so.2").write_text("x")
        (tmp_path / "libssl.dylib").write_text("x")
        (tmp_path / "README.txt").write_text("not a lib")
        args = bs.tor_add_binary_args(str(torbin))
        blob = " ".join(args)
        assert "libevent.so.2" in blob
        assert "libssl.dylib" in blob
        assert "README.txt" not in blob  # only shared libs ride along

    def test_build_args_include_binary_when_provided(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        torbin = tmp_path / "tor"
        torbin.write_text("#!/bin/sh\n")
        args = bs.build_pyinstaller_args(
            dist=tmp_path / "d", work=tmp_path / "w",
            tor_binary=str(torbin), pyi_arch=None,
        )
        assert "--add-binary" in args
