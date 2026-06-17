"""
tests/unit/test_witness.py — WITNESS: signed, hash-chained proof of blindness

Covers certificate generation + signing, the genesis constant, hash-chain and
period-coverage verification (valid chain, corrupted signature, injected gap),
the Merkle tree (known set + empty period), the /cannot-see HTML page, the
``drift witness verify`` CLI path against a fake relay with a gap, and a full
24-hour window verifying completely.

Run: pytest tests/unit/test_witness.py -v
"""

from __future__ import annotations

import hashlib
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

import relay.server as server
from relay.witness import (
    EMPTY_PERIOD_ROOT,
    GENESIS_PREV_HASH,
    PERIOD_SECONDS,
    WitnessCertificate,
    WitnessChain,
    merkle_root,
    verify_chain,
    verify_chain_report,
)

BASE_TS = 1_700_000_000  # a fixed, arbitrary unix time for deterministic chains


def _chain(start: int = BASE_TS) -> WitnessChain:
    """A fresh witness chain with its own throwaway Ed25519 key."""
    return WitnessChain(Ed25519PrivateKey.generate(), start_time=start)


def _envelope(i: int) -> dict[str, Any]:
    return {"to": "chan", "ct": f"ct{i}", "ts": i, "addr": f"addr{i}", "_id": str(i)}


# --------------------------------------------------------------------------- #
# Certificate generation + signing
# --------------------------------------------------------------------------- #


class TestCertificateGeneration:
    def test_fields_are_correct(self) -> None:
        chain = _chain()
        for i in range(3):
            chain.record_envelope(_envelope(i))
        cert = chain.generate(now=BASE_TS + PERIOD_SECONDS)

        assert cert.version == "drift-witness-v1"
        assert cert.relay_id == chain.relay_id
        assert cert.period_seconds == PERIOD_SECONDS
        assert cert.messages_routed == 3
        # The four "known" counters are structurally zero.
        assert cert.sender_identities_known == 0
        assert cert.recipient_identities_known == 0
        assert cert.contents_readable == 0
        assert cert.conversations_linked == 0
        assert cert.statement  # human-readable statement present

    def test_signature_is_valid(self) -> None:
        chain = _chain()
        cert = chain.generate(now=BASE_TS + PERIOD_SECONDS)
        assert cert.verify_signature()

    def test_previous_hash_matches_prior_cert(self) -> None:
        chain = _chain()
        genesis = chain.current()
        cert = chain.generate(now=BASE_TS + PERIOD_SECONDS)
        assert cert.previous_cert_hash == genesis.cert_hash()

    def test_tampering_breaks_the_signature(self) -> None:
        chain = _chain()
        cert = chain.generate(now=BASE_TS + PERIOD_SECONDS)
        cert.messages_routed += 1  # alter a signed field
        assert not cert.verify_signature()

    def test_roundtrip_through_dict(self) -> None:
        chain = _chain()
        cert = chain.generate(now=BASE_TS + PERIOD_SECONDS)
        restored = WitnessCertificate.from_dict(cert.to_dict())
        assert restored.cert_hash() == cert.cert_hash()
        assert restored.verify_signature()


# --------------------------------------------------------------------------- #
# Genesis
# --------------------------------------------------------------------------- #


class TestGenesis:
    def test_genesis_previous_hash_is_the_constant(self) -> None:
        genesis = _chain().current()
        assert genesis.previous_cert_hash == GENESIS_PREV_HASH
        assert genesis.previous_cert_hash == hashlib.sha256(b"drift-witness-genesis-v1").digest()

    def test_genesis_is_empty_but_signed(self) -> None:
        genesis = _chain().current()
        assert genesis.messages_routed == 0
        assert genesis.envelope_merkle_root == EMPTY_PERIOD_ROOT
        assert genesis.verify_signature()


# --------------------------------------------------------------------------- #
# Merkle tree
# --------------------------------------------------------------------------- #


class TestMerkle:
    def test_empty_period_uses_the_constant(self) -> None:
        assert merkle_root([]) == EMPTY_PERIOD_ROOT
        assert merkle_root([]) == hashlib.sha256(b"empty-period").digest()
        # And a period with no routed envelopes lands on it too.
        cert = _chain().generate(now=BASE_TS + PERIOD_SECONDS)
        assert cert.envelope_merkle_root == EMPTY_PERIOD_ROOT

    def test_two_leaves_is_hash_of_concatenation(self) -> None:
        a, b = hashlib.sha256(b"a").digest(), hashlib.sha256(b"b").digest()
        assert merkle_root([a, b]) == hashlib.sha256(a + b).digest()

    def test_odd_level_duplicates_last(self) -> None:
        a = hashlib.sha256(b"a").digest()
        b = hashlib.sha256(b"b").digest()
        c = hashlib.sha256(b"c").digest()
        # three leaves: pair (a,b), promote c → (c,c); then combine the two parents
        left = hashlib.sha256(a + b).digest()
        right = hashlib.sha256(c + c).digest()
        assert merkle_root([a, b, c]) == hashlib.sha256(left + right).digest()

    def test_known_envelope_set_produces_expected_root(self) -> None:
        chain = _chain()
        envs = [_envelope(i) for i in range(5)]
        for e in envs:
            chain.record_envelope(e)
        cert = chain.generate(now=BASE_TS + PERIOD_SECONDS)
        # _id is "0".."4", so each leaf is SHA256(str(_id).encode()).
        leaves = [hashlib.sha256(str(i).encode()).digest() for i in range(5)]
        assert cert.envelope_merkle_root == merkle_root(leaves)


# --------------------------------------------------------------------------- #
# Chain verification
# --------------------------------------------------------------------------- #


def _grow(chain: WitnessChain, periods: int) -> None:
    """Generate ``periods`` more certificates at one-period spacing."""
    for k in range(1, periods + 1):
        chain.generate(now=BASE_TS + k * PERIOD_SECONDS)


class TestChainVerification:
    def test_valid_chain_passes(self) -> None:
        chain = _chain()
        _grow(chain, 10)
        report = verify_chain_report(chain.chain(), expected_relay_id=chain.relay_id)
        assert report["ok"]
        assert report["signatures_valid"]
        assert report["chain_intact"]
        assert report["coverage_complete"]
        assert report["blindness_held"]
        assert report["rooted_at_genesis"]

    def test_single_corrupted_signature_fails(self) -> None:
        chain = _chain()
        _grow(chain, 5)
        certs = chain.chain()
        # Corrupt the *last* cert's signature so only the signature check trips
        # (no downstream cert links to it).
        bad = bytearray(certs[-1].relay_signature)
        bad[0] ^= 0xFF
        certs[-1].relay_signature = bytes(bad)
        report = verify_chain_report(certs)
        assert not report["ok"]
        assert not report["signatures_valid"]
        assert not verify_chain(certs)

    def test_hash_chain_break_is_detected(self) -> None:
        chain = _chain()
        _grow(chain, 5)
        certs = chain.chain()
        certs[3].previous_cert_hash = b"\x00" * 32  # snap the link
        report = verify_chain_report(certs)
        assert not report["ok"]
        assert not report["chain_intact"]
        assert report["first_break"] == 3

    def test_injected_gap_is_detected(self) -> None:
        # A relay that goes dark for a window then resumes: the chain still links
        # (each new cert chains onto the last) but a 60s window is missing.
        chain = _chain()
        chain.generate(now=BASE_TS + 60)
        chain.generate(now=BASE_TS + 120)
        chain.generate(now=BASE_TS + 240)  # skipped the BASE_TS+180 window
        report = verify_chain_report(chain.chain(), expected_relay_id=chain.relay_id)
        assert report["chain_intact"]      # hashes still link
        assert report["signatures_valid"]
        assert not report["coverage_complete"]
        assert not report["ok"]
        gap = report["gap"]
        assert gap is not None
        assert gap["missing_from"] == BASE_TS + 120 + PERIOD_SECONDS
        assert gap["missing_until"] == BASE_TS + 240

    def test_full_24h_window_verifies_completely(self) -> None:
        # Genesis + 1439 generated = 1440 certificates = a full 24-hour window.
        chain = _chain()
        _grow(chain, 1439)
        certs = chain.chain()
        assert len(certs) == 1440
        report = verify_chain_report(certs, expected_relay_id=chain.relay_id)
        assert report["ok"]
        assert report["count"] == 1440
        assert report["coverage_complete"]
        assert report["rooted_at_genesis"]


# --------------------------------------------------------------------------- #
# /cannot-see HTML endpoint
# --------------------------------------------------------------------------- #


class TestCannotSeePage:
    def test_returns_html_with_zero_counts(self) -> None:
        client = TestClient(server.app)
        r = client.get("/cannot-see")
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]
        body = r.text
        # The four zero-counts and the legal-demand answer are present.
        assert body.count("ZERO") == 4
        assert "[NOTHING]" in body
        assert "WITNESS STATEMENT" in body
        # Terminal styling — matrix green on near-black, pure inline styles.
        assert "#00ff41" in body
        assert "#0a0a0a" in body

    def test_witness_endpoints_are_live(self) -> None:
        client = TestClient(server.app)
        assert client.get("/witness/current").status_code == 200
        assert client.get("/witness/chain").json()["count"] >= 1
        assert client.get("/witness/verify").json()["ok"] is True
        pk = client.get("/witness/pubkey").json()
        assert pk["algorithm"] == "ed25519"
        assert pk["fingerprint"] and pk["pubkey_b58"]


# --------------------------------------------------------------------------- #
# `drift witness verify` CLI path (against a fake relay with an injected gap)
# --------------------------------------------------------------------------- #


class _FakeResp:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, Any]:
        return self._payload


class _FakeClient:
    """An httpx.AsyncClient stand-in that serves a given WitnessChain."""

    def __init__(self, chain: WitnessChain) -> None:
        self._chain = chain

    async def __aenter__(self) -> _FakeClient:
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False

    async def get(self, url: str, params: Any = None, timeout: Any = None) -> _FakeResp:
        from relay.witness import fingerprint, relay_pubkey_b58

        rid = self._chain.relay_id
        if url.endswith("/witness/pubkey"):
            return _FakeResp({
                "algorithm": "ed25519",
                "pubkey_b58": relay_pubkey_b58(rid),
                "fingerprint": fingerprint(rid),
            })
        if "/witness/chain" in url:
            certs = self._chain.chain()
            return _FakeResp({
                "count": len(certs),
                "certificates": [c.to_dict() for c in certs],
            })
        raise AssertionError(f"unexpected url {url}")


async def test_cli_verify_passes_on_clean_chain(monkeypatch: pytest.MonkeyPatch) -> None:
    import httpx

    from drift.cli import _witness_verify_async

    chain = _chain()
    _grow(chain, 5)
    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: _FakeClient(chain))
    assert await _witness_verify_async("ws://relay") is True


async def test_cli_verify_detects_gap(monkeypatch: pytest.MonkeyPatch) -> None:
    import httpx

    from drift.cli import _witness_verify_async

    chain = _chain()
    chain.generate(now=BASE_TS + 60)
    chain.generate(now=BASE_TS + 120)
    chain.generate(now=BASE_TS + 240)  # missing window
    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: _FakeClient(chain))
    assert await _witness_verify_async("ws://relay") is False
