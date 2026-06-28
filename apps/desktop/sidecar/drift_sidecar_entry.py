"""PyInstaller entry point — freezes drift.sidecar into a standalone binary.

This is what the packaged desktop app spawns instead of a system Python, so the
installer is self-contained. See build_sidecar.py.
"""
from drift.sidecar import main

if __name__ == "__main__":
    main()
