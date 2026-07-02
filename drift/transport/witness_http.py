"""
drift.transport.witness_http — the WITNESS endpoints, as a tiny client.

The relay publishes its proof-of-blindness next to the message endpoint:

  GET /witness/pubkey           → {"pubkey_b58": …}   the relay's Ed25519 key
  GET /witness/chain?limit=N    → {"certificates": […]} oldest → newest
  GET /witness/current          → the newest certificate

This module exists so the sidecar and the CLI share one implementation instead
of the sidecar importing the CLI (the beacon_http precedent). Pure transport
plus one convenience verifier; all cryptographic checking is
:func:`relay.witness.verify_chain_report` — the same code the relay ships,
re-run independently by the client.

Tor: every call takes an optional ``socks`` proxy ``(host, port)`` so witness
polling rides the same circuit as chat when Tor is active — otherwise watching
the canary would leak the client's IP to the relay once a minute.
"""

from __future__ import annotations

from typing import Any

import httpx

from drift.crypto import b58decode
from drift.transport.beacon_http import Socks, _client, relay_http
from relay.witness import PERIOD_SECONDS, WitnessCertificate, verify_chain_report

_TIMEOUT = 10.0
_CHAIN_TIMEOUT = 30.0

__all__ = [
    "fetch_witness_pubkey",
    "fetch_pubkey_and_chain",
    "fetch_current_cert",
    "witness_status",
    "relay_http",
]


async def fetch_witness_pubkey(http_base: str, socks: Socks = None) -> bytes:
    """The relay's witness Ed25519 pubkey (raw bytes). Raises
    ``httpx.HTTPError`` on network failure, ``KeyError``/``ValueError`` on a
    malformed response."""
    async with _client(socks) as client:
        resp = await client.get(f"{http_base}/witness/pubkey", timeout=_TIMEOUT)
        resp.raise_for_status()
    return b58decode(resp.json()["pubkey_b58"])


async def fetch_pubkey_and_chain(
    http_base: str, *, limit: int = 1440, socks: Socks = None
) -> tuple[bytes, list[dict[str, Any]]]:
    """The relay's pubkey plus its last ``limit`` raw certificates (oldest →
    newest). Raises like :func:`fetch_witness_pubkey`."""
    async with _client(socks) as client:
        pk = await client.get(f"{http_base}/witness/pubkey", timeout=_TIMEOUT)
        pk.raise_for_status()
        chain = await client.get(
            f"{http_base}/witness/chain", params={"limit": limit}, timeout=_CHAIN_TIMEOUT
        )
        chain.raise_for_status()
    certs = chain.json().get("certificates", [])
    return b58decode(pk.json()["pubkey_b58"]), list(certs)


async def fetch_current_cert(http_base: str, socks: Socks = None) -> dict[str, Any]:
    """The newest raw certificate. Raises like :func:`fetch_witness_pubkey`."""
    async with _client(socks) as client:
        resp = await client.get(f"{http_base}/witness/current", timeout=_TIMEOUT)
        resp.raise_for_status()
    return dict(resp.json())


async def witness_status(
    relay_url: str, *, limit: int = 60, socks: Socks = None
) -> dict[str, Any]:
    """One-shot canary check: fetch the recent chain and verify it end to end.

    Always returns a dict (never raises): ``supported`` is False when the relay
    doesn't publish witness certificates (a signal in itself) or can't be
    reached; ``verified`` is the full :func:`verify_chain_report` conjunction —
    signatures, hash-chain continuity, period coverage, and zero-knowledge
    claims. ``latest`` carries the newest certificate's public fields so a UI
    can render "what this relay cannot see" from the certificate itself.
    """
    http_base = relay_http(relay_url)
    try:
        expected_id, raw_certs = await fetch_pubkey_and_chain(
            http_base, limit=limit, socks=socks
        )
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            return {
                "supported": False,
                "verified": False,
                "error": "relay publishes no witness proof",
            }
        return {"supported": False, "verified": False, "error": "relay error"}
    except httpx.HTTPError:
        return {"supported": False, "verified": False, "error": "relay unreachable"}

    try:
        certs = [WitnessCertificate.from_dict(c) for c in raw_certs]
    except (KeyError, ValueError):
        return {
            "supported": True,
            "verified": False,
            "error": "malformed certificate in chain",
        }

    report = verify_chain_report(certs, expected_relay_id=expected_id)
    latest = certs[-1] if certs else None
    return {
        "supported": True,
        "verified": bool(report["ok"]),
        "count": report["count"],
        "signatures_valid": report["signatures_valid"],
        "chain_intact": report["chain_intact"],
        "coverage_complete": report["coverage_complete"],
        "blindness_held": report["blindness_held"],
        "fingerprint": report["fingerprint"],
        "merkle_root": report["current_merkle_root"],
        "period_seconds": PERIOD_SECONDS,
        "errors": list(report["errors"]) if isinstance(report["errors"], list) else [],
        "latest": None
        if latest is None
        else {
            "timestamp": latest.timestamp,
            "messages_routed": latest.messages_routed,
            "sender_identities_known": latest.sender_identities_known,
            "recipient_identities_known": latest.recipient_identities_known,
            "contents_readable": latest.contents_readable,
            "conversations_linked": latest.conversations_linked,
            "cert_hash": latest.cert_hash().hex(),
            "statement": latest.statement,
        },
    }
