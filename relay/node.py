"""
relay.node — DRIFT lightweight mesh node (Phase 4b)

A stripped-down relay built to run on a low-power, always-on device — a
Raspberry Pi Zero W / Zero 2 W tucked behind a router, a spare SBC, an old
phone. It speaks the *same* federation protocol as the full relay (see
relay.federation), so a node is a first-class member of the mesh: blobs gossip
to and from it like any other peer. There is no Redis and no external state —
everything is in memory, sized for a device with a few hundred MB of RAM.

Differences from the full relay (relay.server)
----------------------------------------------
  replay buffer TTL   5 min   (vs 30 s)   — a home node is the durable-ish hop
  max connections     50      (vs ∞)      — protect a tiny device from overload
  dedup LRU           1 000   (vs 10 000) — bound memory hard
  storage             RAM only            — never imports redis

Tor by default
--------------
A home node has no public IP and no port forwarding. So on startup it asks the
local tor daemon (via stem) for an **ephemeral onion service**, which gives it a
stable ``<id>.onion`` address reachable from anywhere on the Tor network with
zero router config. The address is printed on first boot and saved to
``node_address.txt`` so you can hand it to peers as a bootstrap URL.

Run it::

    python -m relay.node

Onion creation is best-effort: with no tor daemon available (e.g. CI, or a quick
local test) the node logs a warning and serves on its local port instead — it
still federates, it just isn't reachable as an onion.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

import relay.server as server

logger = logging.getLogger("drift.relay.node")

# ---------------------------------------------------------------------------
# Resource limits — deliberately small for a Pi Zero-class device.
# ---------------------------------------------------------------------------

NODE_RECENT_TTL = 300.0       # 5 min replay window (full relay: 30 s)
NODE_RECENT_MAX = 200         # envelopes per channel (full relay: 500)
NODE_MAX_CONNECTIONS = 50     # simultaneous subscribers (full relay: unlimited)
NODE_LRU_SIZE = 1_000         # dedup cache entries (full relay: 10 000)

NODE_PORT = int(os.environ.get("DRIFT_NODE_PORT", "8765"))

# Where the node's onion address is recorded on first boot.
NODE_ADDRESS_FILE = Path(os.environ.get("DRIFT_NODE_ADDRESS_FILE", "node_address.txt"))

# The virtual port the onion service exposes (maps to the local relay port).
ONION_VIRTUAL_PORT = 80


class OnionError(Exception):
    """Raised when an ephemeral onion service could not be created."""


# ---------------------------------------------------------------------------
# Resource tuning
# ---------------------------------------------------------------------------


def apply_node_limits() -> None:
    """
    Re-tune the shared relay app down to node-scale limits.

    The node reuses ``relay.server``'s FastAPI app and handlers, so we apply the
    smaller caps by overriding the module-level tunables the handlers read at
    call time. Pure in-memory — touches no Redis, no disk.
    """
    server.RECENT_TTL = NODE_RECENT_TTL
    server.RECENT_MAX = NODE_RECENT_MAX
    server.MAX_CONNECTIONS = NODE_MAX_CONNECTIONS
    server.federation.set_dedup_capacity(NODE_LRU_SIZE)
    logger.info(
        "node limits: ttl=%.0fs max_conn=%d lru=%d",
        NODE_RECENT_TTL, NODE_MAX_CONNECTIONS, NODE_LRU_SIZE,
    )


# ---------------------------------------------------------------------------
# Onion service
# ---------------------------------------------------------------------------


def _connect_controller() -> Any:
    """Connect+authenticate to the local tor control port. Raises OnionError."""
    try:
        from stem.control import Controller
    except ImportError as exc:  # pragma: no cover - exercised when stem absent
        raise OnionError("stem not installed — `pip install 'drift-messenger[tor]'`") from exc
    try:
        controller = Controller.from_port()
        controller.authenticate()
        return controller
    except Exception as exc:  # noqa: BLE001 — stem raises a variety of errors
        raise OnionError(f"could not reach tor control port: {exc}") from exc


def create_onion_service(
    local_port: int = NODE_PORT,
    controller: Any | None = None,
    *,
    virtual_port: int = ONION_VIRTUAL_PORT,
) -> tuple[str, Any]:
    """
    Create an ephemeral onion service mapping ``virtual_port`` → ``local_port``.

    Returns ``(onion_address, controller)``. The controller must stay alive for
    the service to persist, so the caller keeps a reference. A ``controller`` can
    be injected (tests pass a fake); otherwise one is opened to the local tor.
    Raises :class:`OnionError` on any failure.
    """
    ctrl = controller or _connect_controller()
    try:
        response = ctrl.create_ephemeral_hidden_service(
            {virtual_port: local_port}, await_publication=True
        )
    except Exception as exc:  # noqa: BLE001 — normalise any stem failure
        raise OnionError(f"failed to create onion service: {exc}") from exc
    onion = f"{response.service_id}.onion"
    logger.info("onion service published: %s", onion)
    return onion, ctrl


def save_onion_address(onion: str, path: Path | str | None = None) -> Path:
    """Write the node's onion address to disk (node_address.txt by default)."""
    target = Path(path) if path is not None else NODE_ADDRESS_FILE
    target.write_text(onion + "\n")
    return target


def _onion_self_url(onion: str) -> str:
    """The federation self-URL peers use to reach this node's onion service."""
    return f"http://{onion}"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Run the lightweight node: apply limits, publish onion, serve + federate."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    apply_node_limits()

    # Best-effort onion exposure. On success, peers reach us at the .onion; we
    # set it as our federation self-URL so announcements advertise it. On
    # failure (no tor) we keep serving locally and still federate over the seeds.
    controller: Any | None = None
    try:
        onion, controller = create_onion_service(NODE_PORT)
        save_onion_address(onion)
        server.federation.set_self_url(_onion_self_url(onion))
        print(f"\n  ⬡ DRIFT mesh node online\n  .onion address: {onion}")
        print(f"  saved to: {NODE_ADDRESS_FILE}\n")
        print("  Share this as a bootstrap peer:  drift chat <name> "
              f"--relay ws://{onion}\n")
    except OnionError as exc:
        logger.warning("onion service unavailable — serving locally only: %s", exc)
        print("\n  ⬡ DRIFT mesh node online (no onion — tor not reachable)\n")

    # Bootstrap peers (DRIFT_PEERS / peers.json) are loaded and announced by the
    # relay app's lifespan on startup, so we just run the server here.
    import uvicorn

    try:
        uvicorn.run(
            server.app,
            host="127.0.0.1",          # onion maps here; never bind public
            port=NODE_PORT,
            log_level="info",
            limit_concurrency=NODE_MAX_CONNECTIONS,
        )
    finally:
        if controller is not None:
            try:
                controller.close()
            except Exception:  # noqa: BLE001 — shutdown must not raise
                logger.debug("node: controller close raised (ignored)", exc_info=True)


if __name__ == "__main__":
    main()
