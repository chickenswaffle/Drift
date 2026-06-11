"""
tests/unit/test_sealed.py — sealed sender blob (Phase 3b)

Unit tests for drift.crypto.sealed: the seal/parse/open round-trip, the
address binding, and tamper-rejection. Pure crypto — no network.

Run: pytest tests/unit/test_sealed.py -v
"""

from __future__ import annotations

import pytest
from cryptography.exceptions import InvalidTag

from drift.crypto.sealed import SEAL_INFO, open_header, parse, seal

_KEY = b"k" * 32
_EPK = b"R" * 32
_HEADER = b"ratchet-header-bytes"
_CONTENT = b"\x00\x01ratchet-ciphertext-with-nonce-and-tag"
_ADDR = b"A" * 32


# --------------------------------------------------------------------------- #
# Round-trip
# --------------------------------------------------------------------------- #


class TestRoundTrip:
    def test_seal_parse_open(self) -> None:
        blob = seal(_KEY, _EPK, _HEADER, _CONTENT, address=_ADDR)
        epk, sealed_header, content = parse(blob)
        assert epk == _EPK
        assert content == _CONTENT
        assert open_header(_KEY, sealed_header, address=_ADDR) == _HEADER

    def test_ephemeral_key_is_recoverable_without_key(self) -> None:
        # R must be parseable with no secret — the recipient needs it to derive
        # the stealth secret before it can open anything.
        blob = seal(_KEY, _EPK, _HEADER, _CONTENT, address=_ADDR)
        epk, _, _ = parse(blob)
        assert epk == _EPK

    def test_header_is_not_in_the_clear(self) -> None:
        # The plaintext ratchet header must not appear anywhere in the blob.
        blob = seal(_KEY, _EPK, _HEADER, _CONTENT, address=_ADDR)
        assert _HEADER not in blob

    def test_distinct_nonces_make_distinct_blobs(self) -> None:
        # Random nonce per seal → two seals of the same inputs differ.
        a = seal(_KEY, _EPK, _HEADER, _CONTENT, address=_ADDR)
        b = seal(_KEY, _EPK, _HEADER, _CONTENT, address=_ADDR)
        assert a != b

    def test_empty_content_roundtrips(self) -> None:
        blob = seal(_KEY, _EPK, _HEADER, b"", address=_ADDR)
        epk, sealed_header, content = parse(blob)
        assert content == b""
        assert open_header(_KEY, sealed_header, address=_ADDR) == _HEADER


# --------------------------------------------------------------------------- #
# Address binding
# --------------------------------------------------------------------------- #


class TestAddressBinding:
    def test_wrong_address_fails_to_open(self) -> None:
        blob = seal(_KEY, _EPK, _HEADER, _CONTENT, address=_ADDR)
        _, sealed_header, _ = parse(blob)
        # The relay can't move the sealed blob onto a different one-time address.
        with pytest.raises(InvalidTag):
            open_header(_KEY, sealed_header, address=b"B" * 32)

    def test_wrong_key_fails_to_open(self) -> None:
        blob = seal(_KEY, _EPK, _HEADER, _CONTENT, address=_ADDR)
        _, sealed_header, _ = parse(blob)
        with pytest.raises(InvalidTag):
            open_header(b"x" * 32, sealed_header, address=_ADDR)


# --------------------------------------------------------------------------- #
# Tamper rejection
# --------------------------------------------------------------------------- #


class TestTamper:
    def test_flipped_sealed_header_byte_raises(self) -> None:
        blob = seal(_KEY, _EPK, _HEADER, _CONTENT, address=_ADDR)
        epk, sealed_header, _ = parse(blob)
        corrupt = bytearray(sealed_header)
        corrupt[-1] ^= 0xFF
        with pytest.raises(InvalidTag):
            open_header(_KEY, bytes(corrupt), address=_ADDR)


# --------------------------------------------------------------------------- #
# Framing validation
# --------------------------------------------------------------------------- #


class TestFraming:
    def test_too_short_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="too short"):
            parse(b"\x00" * 10)

    def test_truncated_sealed_header_raises(self) -> None:
        # Claims a sealed-header length longer than the remaining bytes.
        import struct
        blob = _EPK + struct.pack(">H", 9999) + b"short"
        with pytest.raises(ValueError, match="truncated"):
            parse(blob)

    def test_bad_ephemeral_length_rejected_on_seal(self) -> None:
        with pytest.raises(ValueError, match="ephemeral_pub must be"):
            seal(_KEY, b"too-short", _HEADER, _CONTENT, address=_ADDR)


def test_seal_info_is_domain_separated() -> None:
    # Distinct from the stealth message-key info, so the sealing key can't
    # collide with any other derived key.
    assert SEAL_INFO == b"drift-sealed-sender-v1"
    assert SEAL_INFO != b"drift-v1-msg"
