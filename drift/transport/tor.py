"""
drift.transport.tor — Tor bootstrap + SOCKS5 transport (Phase 3)

This module turns Tor on. Once a circuit is up, every byte the relay client
sends or receives is routed through it, so the relay (and anyone watching the
wire) sees a Tor exit address instead of the user's real IP.

Two backends, tried in order:

  arti  — Rust Tor, embedded in-process via the ``arti`` PyPI bindings. No
          system daemon required. Preferred when present.
  stem  — drives a *system* ``tor`` binary through the stem controller library,
          exposing its SOCKS5 port. The reliable, widely-installed fallback.

Both are *optional* dependencies (the ``tor`` extra). This module imports with
neither installed — every backend import is lazy — so CI and a default install
keep working without Tor on the machine. If no backend is available,
:func:`bootstrap` raises :class:`TorUnavailableError`, which callers translate
into the "connecting direct" fallback.

Iron rule (Phase 3): **Tor is transport only.** It carries already-encrypted
bytes; it never sees plaintext or key material. The E2E layer (stealth +
Double Ratchet) runs *before* anything touches the circuit. The two layers are
independent — losing one does not weaken the other.

Public surface
--------------
- :func:`bootstrap` — start Tor, wait for the circuit, return a :class:`TorClient`.
- :func:`get_session` — open a relay WebSocket through a client's circuit.
- :func:`open_socks_websocket` — low-level: a WebSocket over a SOCKS5 proxy.
- :class:`TorClient` — a live circuit handle (SOCKS5 endpoint + hop count).
- :class:`TorError` / :class:`TorBootstrapError` / :class:`TorUnavailableError`.
"""

from __future__ import annotations

import asyncio
import importlib.util
import logging
import os
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger("drift.transport.tor")

# A Tor circuit is three relays by convention: guard → middle → exit. We surface
# this so the UI can draw the three anonymised hops; it is not a tuning knob.
TOR_DEFAULT_HOPS = 3

# How long we wait for a circuit before giving up and offering a direct connect.
DEFAULT_BOOTSTRAP_TIMEOUT = 30.0

# (percent, human-readable status line) — e.g. (42, "Bootstrapped 42% (loading_descriptors)").
ProgressCallback = Callable[[int, str], None]


class TorError(Exception):
    """Base class for all Tor transport failures."""


class TorBootstrapError(TorError):
    """Tor started but did not reach a usable circuit (timed out or errored)."""


class TorUnavailableError(TorError):
    """No Tor backend is installed/usable on this machine."""


@dataclass
class TorClient:
    """
    A handle to a live Tor circuit.

    The only thing the transport layer needs from it is a SOCKS5 endpoint to
    proxy through; ``num_hops`` is cosmetic telemetry for the UI. ``backend``
    records which implementation is in use ("arti" / "stem"). ``_handle`` is the
    backend-specific object (an arti client or a stem subprocess) kept alive for
    the circuit's lifetime and torn down by :meth:`close`.
    """

    socks_host: str
    socks_port: int
    backend: str
    num_hops: int = TOR_DEFAULT_HOPS
    _handle: Any = field(default=None, repr=False)

    @property
    def socks_url(self) -> str:
        """The ``socks5://host:port`` URL httpx and python-socks consume."""
        return f"socks5://{self.socks_host}:{self.socks_port}"

    @property
    def socks_proxy(self) -> tuple[str, int]:
        """``(host, port)`` tuple for the relay client."""
        return (self.socks_host, self.socks_port)

    async def close(self) -> None:
        """Tear down the circuit / stop the backend. Safe to call repeatedly."""
        handle = self._handle
        self._handle = None
        if handle is None:
            return
        try:
            # stem subprocess
            if hasattr(handle, "kill"):
                await asyncio.to_thread(handle.kill)
            # arti client (best-effort; API still maturing)
            elif hasattr(handle, "close"):
                result = handle.close()
                if asyncio.iscoroutine(result):
                    await result
        except Exception:  # noqa: BLE001 — shutdown must never raise
            logger.debug("tor: backend shutdown raised (ignored)", exc_info=True)


# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------


def _backend_installed(name: str) -> bool:
    """True if the Python package for a backend is importable (no daemon check)."""
    return importlib.util.find_spec(name) is not None


def resolve_tor_binary() -> str:
    """The ``tor`` executable stem should launch, in priority order:

      1. ``$DRIFT_TOR_BINARY`` — an explicit path (packaging / testing).
      2. A ``tor``/``tor.exe`` bundled next to a **frozen** sidecar. PyInstaller
         onefile unpacks data to ``sys._MEIPASS``; the desktop build drops the
         Tor Expert Bundle's binary there so a shipped app needs no system Tor.
      3. Bare ``tor`` — resolved on ``PATH`` at launch (dev / a user's own Tor).

    Returns a command string suitable for stem's ``tor_cmd``.
    """
    override = os.environ.get("DRIFT_TOR_BINARY")
    if override and Path(override).exists():
        return override
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        name = "tor.exe" if os.name == "nt" else "tor"
        bundled = Path(meipass) / name
        if bundled.exists():
            return str(bundled)
    return "tor"


def available() -> bool:
    """True if any Tor backend (arti or stem) is importable in this build.

    A packaged sidecar frozen without the ``tor`` extra returns ``False`` — the
    GUI surfaces that instead of pretending Tor is one bootstrap away. No daemon
    or circuit check: this only reports whether the code *could* try.
    """
    return _backend_installed("arti") or _backend_installed("stem")


def _resolve_backends(backend: str | None) -> tuple[str, ...]:
    """
    Decide which backends to try, in order.

    An explicit ``backend`` forces exactly that one. Otherwise prefer arti
    (embedded, no daemon) then fall back to stem (system tor).
    """
    if backend is not None:
        return (backend,)
    return tuple(b for b in ("arti", "stem") if _backend_installed(b))


async def bootstrap(
    *,
    timeout: float = DEFAULT_BOOTSTRAP_TIMEOUT,
    on_progress: ProgressCallback | None = None,
    backend: str | None = None,
    socks_port: int | None = None,
) -> TorClient:
    """
    Start Tor and wait for a usable circuit.

    Reports bootstrap progress (0–100%) through ``on_progress`` so the UI can
    render ``Bootstrapping Tor... 42%``. Returns a :class:`TorClient` once the
    circuit is up.

    Raises :class:`TorUnavailableError` if no backend is installed and
    :class:`TorBootstrapError` if a backend is present but the circuit does not
    come up within ``timeout`` seconds — callers turn either into the graceful
    "connecting direct" fallback (unless ``--tor-only`` was given).
    """
    backends = _resolve_backends(backend)
    if not backends:
        raise TorUnavailableError(
            "no Tor backend installed — `pip install 'drift-messenger[tor]'` "
            "(needs the arti bindings, or stem + a system tor binary)"
        )
    if on_progress is not None:
        on_progress(0, "Starting Tor")
    try:
        return await asyncio.wait_for(
            _bootstrap_any(backends, on_progress, socks_port), timeout
        )
    except TimeoutError as exc:
        raise TorBootstrapError(
            f"Tor did not bootstrap within {timeout:.0f}s"
        ) from exc


async def _bootstrap_any(
    backends: tuple[str, ...],
    on_progress: ProgressCallback | None,
    socks_port: int | None,
) -> TorClient:
    """Try each backend in turn; return the first circuit, else raise."""
    errors: list[str] = []
    for name in backends:
        try:
            client = await _run_backend(name, on_progress, socks_port)
            if on_progress is not None:
                on_progress(100, "Tor circuit established")
            logger.info("tor: circuit up via %s on %s", name, client.socks_url)
            return client
        except (TorUnavailableError, TorBootstrapError) as exc:
            logger.debug("tor: backend %s unavailable: %s", name, exc)
            errors.append(f"{name}: {exc}")
    raise TorUnavailableError("no working Tor backend (" + "; ".join(errors) + ")")


async def _run_backend(
    backend: str,
    on_progress: ProgressCallback | None,
    socks_port: int | None,
) -> TorClient:
    """Dispatch to a concrete backend. This is the seam tests mock."""
    if backend == "stem":
        return await asyncio.to_thread(_launch_stem, on_progress, socks_port)
    if backend == "arti":
        return await _launch_arti(on_progress, socks_port)
    raise TorUnavailableError(f"unknown Tor backend {backend!r}")


_BOOTSTRAP_RE = re.compile(r"Bootstrapped (\d+)%")


def _launch_stem(
    on_progress: ProgressCallback | None,
    socks_port: int | None,
) -> TorClient:
    """
    Launch a system ``tor`` via stem and return a circuit handle (blocking).

    Runs in a worker thread (see :func:`_run_backend`). stem reports bootstrap
    progress as log lines we parse for the percentage. Raises
    :class:`TorUnavailableError` if stem or the tor binary is missing, and
    :class:`TorBootstrapError` if the daemon fails to come up.
    """
    try:
        import stem.process
    except ImportError as exc:  # pragma: no cover - exercised via _resolve_backends
        raise TorUnavailableError("stem not installed") from exc

    port = socks_port or _free_port()

    def _handler(line: str) -> None:
        match = _BOOTSTRAP_RE.search(line)
        if match and on_progress is not None:
            on_progress(int(match.group(1)), line.strip())

    tor_cmd = resolve_tor_binary()
    try:
        process = stem.process.launch_tor_with_config(
            config={"SocksPort": str(port), "Log": ["NOTICE stdout"]},
            tor_cmd=tor_cmd,
            init_msg_handler=_handler,
            take_ownership=True,
        )
    except OSError as exc:
        # tor binary missing → treat as "unavailable" so we fall back / warn.
        raise TorUnavailableError(f"could not launch tor ({tor_cmd}): {exc}") from exc
    except Exception as exc:  # noqa: BLE001 — stem raises bare on bootstrap failure
        raise TorBootstrapError(f"tor failed to bootstrap: {exc}") from exc

    return TorClient(
        socks_host="127.0.0.1",
        socks_port=port,
        backend="stem",
        _handle=process,
    )


async def _launch_arti(
    on_progress: ProgressCallback | None,
    socks_port: int | None,
) -> TorClient:
    """
    Bring up an embedded arti client exposing a local SOCKS5 port.

    arti's Python bindings are young and the surface varies by version, so this
    probes for the expected entry point and raises :class:`TorUnavailableError`
    if it isn't there — letting :func:`_bootstrap_any` fall back to stem rather
    than guessing at an API.
    """
    try:
        import arti
    except ImportError as exc:  # pragma: no cover - exercised via _resolve_backends
        raise TorUnavailableError("arti not installed") from exc

    start = getattr(arti, "start_proxy", None) or getattr(arti, "launch", None)
    if start is None:  # pragma: no cover - depends on installed arti version
        raise TorUnavailableError(
            "installed arti build exposes no known proxy entry point"
        )

    port = socks_port or _free_port()
    if on_progress is not None:
        on_progress(10, "Starting arti")
    try:
        result = start(socks_port=port)
        handle = await result if asyncio.iscoroutine(result) else result
    except Exception as exc:  # noqa: BLE001 - normalise any arti failure
        raise TorBootstrapError(f"arti failed to bootstrap: {exc}") from exc

    return TorClient(
        socks_host="127.0.0.1",
        socks_port=port,
        backend="arti",
        _handle=handle,
    )


def _free_port() -> int:
    """Ask the OS for a free localhost TCP port for the SOCKS listener."""
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


# ---------------------------------------------------------------------------
# SOCKS5 WebSocket transport
# ---------------------------------------------------------------------------


async def open_socks_websocket(
    ws_url: str,
    socks_host: str,
    socks_port: int,
    **connect_kwargs: Any,
) -> Any:
    """
    Open a WebSocket to ``ws_url`` tunnelled through a SOCKS5 proxy.

    Connects a raw socket to the destination *via* the proxy (python-socks),
    then hands that socket to ``websockets`` so the WS handshake runs inside the
    Tor circuit. The relay never learns the client's real address.

    Requires the ``tor`` extra (python-socks); raises :class:`TorUnavailableError`
    if it is missing.
    """
    try:
        from python_socks.async_.asyncio import Proxy
    except ImportError as exc:
        raise TorUnavailableError(
            "python-socks not installed — `pip install 'drift-messenger[tor]'`"
        ) from exc

    import websockets

    parsed = urlparse(ws_url)
    secure = parsed.scheme == "wss"
    host = parsed.hostname or "localhost"
    port = parsed.port or (443 if secure else 80)

    proxy = Proxy.from_url(f"socks5://{socks_host}:{socks_port}")
    sock = await proxy.connect(dest_host=host, dest_port=port)

    if secure:
        import ssl

        connect_kwargs.setdefault("ssl", ssl.create_default_context())
        connect_kwargs.setdefault("server_hostname", host)

    return await websockets.connect(ws_url, sock=sock, **connect_kwargs)


async def get_session(tor_client: TorClient, url: str, **connect_kwargs: Any) -> Any:
    """
    Open a relay WebSocket through ``tor_client``'s circuit.

    Convenience wrapper over :func:`open_socks_websocket` using the client's
    SOCKS5 endpoint. Returns the live WebSocket connection.
    """
    return await open_socks_websocket(
        url, tor_client.socks_host, tor_client.socks_port, **connect_kwargs
    )
