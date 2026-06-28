#!/usr/bin/env python3
"""Freeze drift.sidecar into a standalone binary for Tauri to bundle.

Produces ``src-tauri/binaries/drift-sidecar-<target-triple>[.exe]`` — the name
Tauri's ``externalBin`` resolver expects. Run on each OS (locally or in CI) with
DRIFT installed in the active environment (``pip install -e ".[dev]"``).

    python apps/desktop/sidecar/build_sidecar.py

Override the triple with $TARGET_TRIPLE (CI on cross builds); otherwise it is
taken from ``rustc -Vv``.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent          # apps/desktop/sidecar
DESKTOP = HERE.parent                            # apps/desktop
REPO = DESKTOP.parent.parent                     # repo root
ENTRY = HERE / "drift_sidecar_entry.py"
OUT = DESKTOP / "src-tauri" / "binaries"


def host_triple() -> str:
    out = subprocess.run(["rustc", "-Vv"], capture_output=True, text=True, check=True).stdout
    for line in out.splitlines():
        if line.startswith("host:"):
            return line.split(":", 1)[1].strip()
    raise SystemExit("could not determine host triple from `rustc -Vv`")


def main() -> None:
    triple = os.environ.get("TARGET_TRIPLE") or host_triple()
    work = HERE / "build"
    dist = HERE / "dist"
    args = [
        sys.executable, "-m", "PyInstaller",
        "--onefile", "--noconfirm", "--clean",
        "--name", "drift-sidecar",
        "--distpath", str(dist),
        "--workpath", str(work),
        "--specpath", str(HERE),
        # drift imports several modules lazily (transport.session, crypto.panic);
        # grab the whole package plus the websocket client so nothing is missed.
        "--collect-submodules", "drift",
        "--collect-submodules", "websockets",
        "--hidden-import", "drift.transport.session",
        "--hidden-import", "drift.crypto.panic",
    ]
    # macOS universal builds: emit a fat (x86_64 + arm64) binary in one pass.
    # Requires every collected native lib to itself be universal2.
    pyi_arch = os.environ.get("DRIFT_PYI_TARGET_ARCH")
    if pyi_arch:
        args += ["--target-arch", pyi_arch]
    args.append(str(ENTRY))
    subprocess.run(args, cwd=str(REPO), check=True)
    OUT.mkdir(parents=True, exist_ok=True)
    is_windows = "windows" in triple
    ext = ".exe" if is_windows else ""
    src = dist / f"drift-sidecar{ext}"
    dst = OUT / f"drift-sidecar-{triple}{ext}"
    shutil.copy2(src, dst)
    print(f"sidecar binary -> {dst}")


if __name__ == "__main__":
    main()
