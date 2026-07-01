"""
drift.transport.beacon_http — the beacon HTTP endpoints, as a tiny client.

The relay serves beacons (and their invite cousins — same wire format) over
plain HTTP next to its WebSocket message endpoint:

  GET    /beacon/pubkey          → the relay's long-term Ed25519 pubkey (b58)
  POST   /beacon                 → light one    {lookup_hash, payload, ttl_seconds}
  GET    /beacon/{lookup_hash}   → fetch one    {payload}
  DELETE /beacon/{lookup_hash}   → extinguish (idempotent)

This module exists so the sidecar and the CLI share one implementation instead
of the sidecar importing the CLI. Pure transport — no cryptography; callers
build payloads with :mod:`drift.crypto.beacon` / :mod:`drift.crypto.invite`.
"""

from __future__ import annotations

import base64
from typing import Any

import httpx

from drift.crypto import b58decode
from drift.crypto.beacon import BeaconPayload

_TIMEOUT = 10.0


def relay_http(ws_url: str) -> str:
    """ws(s):// → http(s):// relay base for the beacon HTTP endpoints."""
    return ws_url.replace("wss://", "https://", 1).replace("ws://", "http://", 1).rstrip("/")


async def fetch_relay_pubkey(http_base: str) -> bytes | None:
    """The relay's long-term Ed25519 pubkey (raw bytes) for the M3
    relay-specific lookup hash. ``None`` if the relay can't be reached or
    doesn't expose the endpoint."""
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{http_base}/beacon/pubkey", timeout=_TIMEOUT)
        if resp.status_code != 200:
            return None
        return b58decode(resp.json()["pubkey_b58"])
    except (httpx.HTTPError, KeyError, ValueError):
        return None


async def post_beacon(http_base: str, payload: BeaconPayload) -> dict[str, Any]:
    """POST a lit beacon. Returns the relay's response — its ``expires_at`` /
    ``ttl_seconds`` are the truth (the relay may clamp harder than we did).
    Raises :class:`httpx.HTTPError` on failure."""
    body = {
        "lookup_hash": payload.lookup_hash,
        "payload": base64.b64encode(payload.encrypted).decode(),
        "ttl_seconds": payload.ttl_seconds,
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(f"{http_base}/beacon", json=body, timeout=_TIMEOUT)
        resp.raise_for_status()
        return dict(resp.json())


async def get_beacon(http_base: str, lookup_hash: str) -> bytes | None:
    """Fetch a beacon's encrypted payload by lookup hash. ``None`` if absent,
    expired, unreachable, or malformed — the caller treats all alike."""
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{http_base}/beacon/{lookup_hash}", timeout=_TIMEOUT)
        if resp.status_code != 200:
            return None
        return base64.b64decode(resp.json()["payload"])
    except (httpx.HTTPError, KeyError, ValueError):
        return None


async def delete_beacon(http_base: str, lookup_hash: str) -> None:
    """Extinguish a beacon. Idempotent and best-effort: errors are swallowed —
    on a blind relay a failed delete just means the blob lives to its TTL."""
    try:
        async with httpx.AsyncClient() as client:
            await client.delete(f"{http_base}/beacon/{lookup_hash}", timeout=5.0)
    except httpx.HTTPError:
        pass
