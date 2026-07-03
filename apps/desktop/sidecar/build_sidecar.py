#!/usr/bin/env python3
"""Freeze drift.sidecar into a standalone binary for Tauri to bundle.

Produces ``src-tauri/binaries/drift-sidecar-<target-triple>[.exe]`` — the name
Tauri's ``externalBin`` resolver expects. Run on each OS (locally or in CI) with
DRIFT installed in the active environment (``pip install -e ".[dev,tor]"``).

    python apps/desktop/sidecar/build_sidecar.py

Override the triple with $TARGET_TRIPLE (CI on cross builds); otherwise it is
taken from ``rustc -Vv``.

Tor
---
The frozen sidecar bundles Tor so a shipped app needs no system Tor:

  - The Python backends (``stem`` + the SOCKS libs) are collected into the
    binary, so ``drift.transport.tor.available()`` is true in a packaged build.
  - A real ``tor`` executable is embedded via ``--add-binary`` when
    ``$DRIFT_TOR_BINARY`` points at one (CI extracts it from the Tor Expert
    Bundle). It lands at the root of PyInstaller's unpack dir, exactly where
    ``tor.resolve_tor_binary()`` looks. Any shared libs sitting next to that
    binary (a dynamically-linked expert-bundle tor) are embedded alongside it.

Without ``$DRIFT_TOR_BINARY`` the freeze still succeeds — the backends are
bundled but no tor binary is, so a shipped build falls back to the user's own
system tor (and the UI reports Tor unavailable if there is none).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent  # apps/desktop/sidecar
DESKTOP = HERE.parent  # apps/desktop
REPO = DESKTOP.parent.parent  # repo root
ENTRY = HERE / "drift_sidecar_entry.py"
OUT = DESKTOP / "src-tauri" / "binaries"

# Shared-library suffixes we co-bundle next to a dynamically-linked tor binary.
_LIB_SUFFIXES = (".so", ".dylib", ".dll")


def host_triple() -> str:
    # rustc is resolved from PATH on the build machine, by design.
    out = subprocess.run(
        ["rustc", "-Vv"],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    for line in out.splitlines():
        if line.startswith("host:"):
            return line.split(":", 1)[1].strip()
    raise SystemExit("could not determine host triple from `rustc -Vv`")


def _is_lib(path: Path) -> bool:
    return any(s in path.suffixes or path.name.endswith(s) for s in _LIB_SUFFIXES)


def tor_add_binary_args(tor_binary: str | None) -> list[str]:
    """``--add-binary`` args that embed a tor executable (and its sibling shared
    libs) at the root of the bundle, where ``tor.resolve_tor_binary`` looks.

    Returns an empty list when no tor binary is provided — the freeze still
    produces a working sidecar, just one that relies on system tor at runtime.
    PyInstaller's ``src:dest`` separator is ``;`` on Windows, ``:`` elsewhere.
    """
    if not tor_binary:
        return []
    binp = Path(tor_binary)
    if not binp.exists():
        raise SystemExit(f"$DRIFT_TOR_BINARY does not exist: {tor_binary}")
    sep = ";" if os.name == "nt" else ":"
    # The executable must land as bare "tor"/"tor.exe" at the unpack root.
    dest_name = "tor.exe" if os.name == "nt" else "tor"
    staged = binp.parent / dest_name
    args = ["--add-binary", f"{staged if staged.exists() else binp}{sep}."]
    # Co-bundle any shared libs shipped alongside it (expert-bundle tor).
    for sib in sorted(binp.parent.iterdir()):
        if sib.is_file() and sib != binp and _is_lib(sib):
            args += ["--add-binary", f"{sib}{sep}."]
    return args


def build_pyinstaller_args(
    *, dist: Path, work: Path, tor_binary: str | None, pyi_arch: str | None
) -> list[str]:
    """The full PyInstaller command line. Split out so it can be unit-tested."""
    args = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--onefile",
        "--noconfirm",
        "--clean",
        "--name",
        "drift-sidecar",
        "--distpath",
        str(dist),
        "--workpath",
        str(work),
        "--specpath",
        str(HERE),
        # drift imports several modules lazily (transport.session, crypto.panic);
        # grab the whole package plus the websocket client so nothing is missed.
        "--collect-submodules",
        "drift",
        "--collect-submodules",
        "websockets",
        "--hidden-import",
        "drift.transport.session",
        "--hidden-import",
        "drift.crypto.panic",
        # Tor backends: stem (drives the bundled tor binary) + the SOCKS libs
        # httpx/python-socks use to route beacon + WebSocket traffic through it.
        # Collected unconditionally so tor.available() is true in a packaged
        # build; the tor *binary* below is what makes it actually connect.
        "--collect-submodules",
        "stem",
        "--collect-submodules",
        "python_socks",
        "--hidden-import",
        "socksio",
        "--hidden-import",
        "httpx_socks",
    ]
    args += tor_add_binary_args(tor_binary)
    # macOS universal builds: emit a fat (x86_64 + arm64) binary in one pass.
    # Requires every collected native lib to itself be universal2.
    if pyi_arch:
        args += ["--target-arch", pyi_arch]
    args.append(str(ENTRY))
    return args


def main() -> None:
    triple = os.environ.get("TARGET_TRIPLE") or host_triple()
    work = HERE / "build"
    dist = HERE / "dist"
    tor_binary = os.environ.get("DRIFT_TOR_BINARY")
    args = build_pyinstaller_args(
        dist=dist,
        work=work,
        tor_binary=tor_binary,
        pyi_arch=os.environ.get("DRIFT_PYI_TARGET_ARCH"),
    )
    if tor_binary:
        print(f"bundling tor binary: {tor_binary}")
    else:
        print("no $DRIFT_TOR_BINARY — sidecar will rely on system tor at runtime")
    subprocess.run(args, cwd=str(REPO), check=True)  # noqa: S603
    OUT.mkdir(parents=True, exist_ok=True)
    is_windows = "windows" in triple
    ext = ".exe" if is_windows else ""
    src = dist / f"drift-sidecar{ext}"
    dst = OUT / f"drift-sidecar-{triple}{ext}"
    shutil.copy2(src, dst)
    print(f"sidecar binary -> {dst}")


if __name__ == "__main__":
    main()
