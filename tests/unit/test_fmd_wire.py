"""
tests/unit/test_fmd_wire.py — FMD wired end to end (audit M4)

Covers the wiring that connects the FMD primitive (test_fmd.py) to the wire:

  - the FMD detection key rides as an optional 3rd contact-code segment, and is
    derived deterministically from the identity (FMD off → 2-segment code,
    unchanged);
  - a sender attaches an `fmd_flag` (bound to the one-time address) only when the
    recipient published an FMD key — zero overhead otherwise;
  - the `/send` payload carries `fmd` only when present;
  - the relay's pre-filter (`_passes_fmd`) forwards matches + false positives,
    fails open on unflagged traffic, and passes everything for classic
    subscribers;
  - the privacy tradeoff: holding the recipient's *coarse* relay key, the relay
    sees an identical "True" for genuine matches and false positives and cannot
    tell them apart — only the recipient, with the finer key, distinguishes.
"""

from __future__ import annotations

import base64
import os
from unittest.mock import AsyncMock

import pytest

from drift.crypto import Identity
from drift.crypto.fmd import fmd_flag, fmd_test, subkeys_for_rate
from drift.transport.client import Envelope, RelayClient
from drift.transport.session import PairwiseRatchet

# ---------------------------------------------------------------------------
# Contact code carries the FMD key (and is unchanged when FMD is off)
# ---------------------------------------------------------------------------

class TestContactCodeFMD:
    def test_off_is_two_segments_and_no_pubs(self) -> None:
        code = Identity.generate().contact_code()
        assert code.count(".") == 1  # drift:<scan>.<spend>
        assert Identity.parse_fmd_pubs(code) is None

    def test_on_roundtrips_the_pubs(self) -> None:
        me = Identity.generate()
        key = me.fmd_keypair(subkeys_for_rate(0.25))  # 2 sub-keys
        code = me.contact_code(fmd_pubs=key.public_keys)
        assert code.count(".") == 2
        # scan/spend still parse exactly as before (back-compat)
        scan, spend = Identity.parse_contact_code(code)
        assert scan == me.scan_keypair.public_bytes()
        assert spend == me.spend_keypair.public_bytes()
        assert Identity.parse_fmd_pubs(code) == key.public_keys

    def test_fmd_key_is_deterministic(self) -> None:
        me = Identity.generate()
        assert me.fmd_keypair(4).public_keys == me.fmd_keypair(4).public_keys
        # …and a coarser key is a prefix of a finer one (downgrade property).
        assert me.fmd_keypair(2).secret_keys == me.fmd_keypair(8).secret_keys[:2]

    def test_zero_subkeys_is_empty(self) -> None:
        assert Identity.generate().fmd_keypair(0).public_keys == []


# ---------------------------------------------------------------------------
# Sender attaches a flag only for an FMD recipient
# ---------------------------------------------------------------------------

class TestSenderFlag:
    def test_no_flag_for_classic_recipient(self) -> None:
        me, peer = Identity.generate(), Identity.generate()
        ch = PairwiseRatchet(me, peer.contact_code())  # 2-segment code
        _, _, flag = ch.encrypt(b"hi")
        assert flag is None

    def test_flag_for_fmd_recipient_validates_against_addr(self) -> None:
        me, peer = Identity.generate(), Identity.generate()
        key = peer.fmd_keypair(subkeys_for_rate(0.25))
        ch = PairwiseRatchet(me, peer.contact_code(fmd_pubs=key.public_keys))
        addr, _blob, flag = ch.encrypt(b"hi")
        assert flag is not None
        # The flag is bound to the one-time address; the recipient always matches.
        assert fmd_test(flag, key, addr) is True


# ---------------------------------------------------------------------------
# Wire format: /send carries `fmd` only when present
# ---------------------------------------------------------------------------

def _mock_ok_http() -> AsyncMock:
    http = AsyncMock()
    resp = AsyncMock()
    resp.raise_for_status = lambda: None
    resp.json = lambda: {"ok": True}
    http.post = AsyncMock(return_value=resp)
    return http


class TestSendWire:
    @pytest.mark.asyncio
    async def test_no_fmd_field_when_absent(self) -> None:
        client = RelayClient("ws://localhost:8765", "addr")
        client._http = _mock_ok_http()
        client._connected = True
        await client.send(Envelope(to="c", ciphertext=b"x", one_time_addr=b"a" * 32))
        payload = client._http.post.call_args.kwargs["json"]
        assert "fmd" not in payload  # FMD off → byte-for-byte the old wire format

    @pytest.mark.asyncio
    async def test_fmd_field_present_when_flagged(self) -> None:
        client = RelayClient("ws://localhost:8765", "addr")
        client._http = _mock_ok_http()
        client._connected = True
        await client.send(
            Envelope(to="c", ciphertext=b"x", one_time_addr=b"a" * 32, fmd_flag=b"flag")
        )
        payload = client._http.post.call_args.kwargs["json"]
        assert base64.b64decode(payload["fmd"]) == b"flag"


# ---------------------------------------------------------------------------
# Relay pre-filter logic (no network)
# ---------------------------------------------------------------------------

class TestRelayFilter:
    def _envelope(self, addr: bytes, flag: bytes | None) -> dict:
        env = {"to": "ch", "ct": "x", "addr": base64.b64encode(addr).decode()}
        if flag is not None:
            env["fmd"] = base64.b64encode(flag).decode()
        return env

    def test_classic_subscriber_gets_everything(self) -> None:
        from relay import server

        ws = object()  # never registered → classic mode
        assert server._passes_fmd(ws, self._envelope(os.urandom(32), b"anything")) is True

    def test_fmd_subscriber_filters_flagged_traffic(self) -> None:
        from relay import server

        me = Identity.generate()
        key = me.fmd_keypair(10)  # rate ~2^-10 → false positives vanishingly rare
        ws = object()
        n = server._set_fmd_filter(ws, base64.b64encode(b"".join(key.secret_keys)).decode())
        assert n == 10
        try:
            # True positive (flagged for me) is forwarded.
            addr_t = os.urandom(32)
            assert server._passes_fmd(ws, self._envelope(addr_t, fmd_flag(addr_t, key.public_keys)))
            # Flagged for someone else → filtered out (prob 2^-10).
            other = Identity.generate().fmd_keypair(10)
            addr_o = os.urandom(32)
            assert not server._passes_fmd(
                ws, self._envelope(addr_o, fmd_flag(addr_o, other.public_keys))
            )
            # Unflagged traffic → fail open (never drop a possible message).
            assert server._passes_fmd(ws, self._envelope(os.urandom(32), None))
        finally:
            server._set_fmd_filter(ws, None)  # clear global state


# ---------------------------------------------------------------------------
# Statistical false-positive rate + the privacy tradeoff
# ---------------------------------------------------------------------------

class TestPrivacyTradeoff:
    def test_false_positive_rate_is_about_2_to_minus_k(self) -> None:
        me = Identity.generate()
        k = 2  # native rate 1/4
        key = me.fmd_keypair(k)
        trials, hits = 2000, 0
        for _ in range(trials):
            other = Identity.generate().fmd_keypair(k)
            addr = os.urandom(32)
            if fmd_test(fmd_flag(addr, other.public_keys), key, addr):
                hits += 1
        rate = hits / trials
        assert 0.18 < rate < 0.32  # ~0.25, generous band for randomness

    def test_relay_cannot_distinguish_true_from_false_positive(self) -> None:
        me = Identity.generate()
        relay_key = me.fmd_keypair(1)  # coarse key handed to the relay (rate 1/2)
        full_key = me.fmd_keypair(8)   # the finer key only I hold

        # A genuine flag for me: the relay's coarse test passes, and so does mine.
        addr_t = os.urandom(32)
        true_flag = fmd_flag(addr_t, full_key.public_keys)
        assert fmd_test(true_flag, relay_key, addr_t) is True
        assert fmd_test(true_flag, full_key, addr_t) is True

        # Find a false positive: a flag made for someone *else* that nonetheless
        # passes the relay's 1-sub-key test (exists at rate 1/2). Skip the
        # ~2^-7 candidates that fluke past the full 8-sub-key test too — the
        # property demonstrated below needs an FP the *recipient* rejects.
        stranger = Identity.generate().fmd_keypair(8)
        fp = None
        for _ in range(1000):
            a = os.urandom(32)
            f = fmd_flag(a, stranger.public_keys)
            if fmd_test(f, relay_key, a) and not fmd_test(f, full_key, a):
                fp = (a, f)
                break
        assert fp is not None, "a 1/2-rate key should yield a false positive quickly"
        a_fp, f_fp = fp

        # The relay's view is byte-identical 'True' for the genuine flag and the
        # false positive — with only the coarse key it CANNOT tell them apart.
        assert fmd_test(f_fp, relay_key, a_fp) is True
        # But I, holding the finer key, reject the false positive — only the
        # recipient distinguishes a true match from relay-visible noise.
        assert fmd_test(f_fp, full_key, a_fp) is False
