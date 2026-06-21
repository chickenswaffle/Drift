"""
tests/unit/test_cover.py — cover traffic (Phase 4)

Verifies the cover-traffic primitives: the off/low/high dial, the Poisson
inter-arrival scheduler (positive, random, correct mean rate), dummy envelopes
(right shape, random, wire-sized like a real message), and the uniform-size
plaintext padding (fixed length, message-bound, tolerant round-trip, oversize
rejection). Pure crypto — no network.

Run: pytest tests/unit/test_cover.py -v
"""

from __future__ import annotations

import pytest

from drift.crypto.cover import (
    COVER_MESSAGE_SIZE,
    COVER_PAYLOAD_SIZE,
    CoverLevel,
    make_dummy_envelope,
    next_interval,
    pad_to_cover_size,
    unpad_from_cover,
)

# --------------------------------------------------------------------------- #
# The dial
# --------------------------------------------------------------------------- #


def test_cover_level_values() -> None:
    assert {lvl.value for lvl in CoverLevel} == {"off", "low", "high"}


def test_cover_level_parse() -> None:
    assert CoverLevel.parse("OFF") is CoverLevel.OFF
    assert CoverLevel.parse(" Low ") is CoverLevel.LOW
    assert CoverLevel.parse("high") is CoverLevel.HIGH
    with pytest.raises(ValueError, match="off, low, or high"):
        CoverLevel.parse("medium")


# --------------------------------------------------------------------------- #
# Poisson scheduler
# --------------------------------------------------------------------------- #


def test_next_interval_positive_random_and_off_raises() -> None:
    draws = [next_interval(CoverLevel.LOW) for _ in range(50)]
    assert all(d > 0 for d in draws)
    assert len(set(draws)) > 1  # a real random process, not a constant
    with pytest.raises(ValueError, match="cover is off"):
        next_interval(CoverLevel.OFF)


def test_next_interval_mean_rate_matches_the_dial() -> None:
    # The exponential mean is 1/λ: ~20 s for LOW, ~5 s for HIGH. Average a large
    # sample and allow a wide (flaky-safe) tolerance band.
    n = 4000
    low_mean = sum(next_interval(CoverLevel.LOW) for _ in range(n)) / n
    high_mean = sum(next_interval(CoverLevel.HIGH) for _ in range(n)) / n
    assert 16.0 < low_mean < 24.0, low_mean
    assert 4.0 < high_mean < 6.0, high_mean
    assert high_mean < low_mean  # HIGH fires more often than LOW


# --------------------------------------------------------------------------- #
# Dummy envelopes
# --------------------------------------------------------------------------- #


def test_dummy_envelope_shape_is_wire_identical() -> None:
    dummy = make_dummy_envelope()
    assert len(dummy.one_time_addr) == 32
    assert len(dummy.ciphertext) == COVER_PAYLOAD_SIZE
    # A dummy's ciphertext is sized like a real *padded* blob, necessarily larger
    # than the padded plaintext it would carry.
    assert COVER_PAYLOAD_SIZE > COVER_MESSAGE_SIZE


def test_dummy_envelope_is_independently_random() -> None:
    a, b = make_dummy_envelope(), make_dummy_envelope()
    assert a.one_time_addr != b.one_time_addr
    assert a.ciphertext != b.ciphertext


# --------------------------------------------------------------------------- #
# Uniform message size (padding)
# --------------------------------------------------------------------------- #


def test_padding_is_fixed_length_and_round_trips() -> None:
    for msg in (b"", b"hi", b"a longer message that still fits comfortably"):
        padded = pad_to_cover_size(msg)
        assert len(padded) == COVER_MESSAGE_SIZE  # uniform regardless of input
        assert unpad_from_cover(padded) == msg    # exact recovery
    # Tolerant: a message that was never cover-padded is returned verbatim, so the
    # receive path can unpad every message without knowing the sender's setting.
    assert unpad_from_cover(b"plain text") == b"plain text"
    assert unpad_from_cover(b"\x00" * COVER_MESSAGE_SIZE) == b"\x00" * COVER_MESSAGE_SIZE


def test_padding_rejects_oversize_messages() -> None:
    with pytest.raises(ValueError, match="too long for cover mode"):
        pad_to_cover_size(b"x" * COVER_MESSAGE_SIZE)
