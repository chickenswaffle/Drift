"""
tests/unit/test_fmd.py — Fuzzy Message Detection (Phase 5)

Verifies the FMD2 construction: true positives are *always* detected (no false
negatives), and the false-positive rate for a stranger's key sits within
statistical tolerance of the configured 2^-n. Pure crypto — no network.

Run: pytest tests/unit/test_fmd.py -v
"""

from __future__ import annotations

import math

import pytest

from drift.crypto.fmd import (
    FMDKeypair,
    fmd_flag,
    fmd_test,
    generate_fmd_key,
    subkeys_for_rate,
)

# --------------------------------------------------------------------------- #
# Rate → sub-key mapping
# --------------------------------------------------------------------------- #


class TestRateMapping:
    def test_zero_rate_is_off(self) -> None:
        assert subkeys_for_rate(0.0) == 0
        assert generate_fmd_key(0.0).num_subkeys == 0

    @pytest.mark.parametrize("rate,expected_n", [
        (0.5, 1), (0.25, 2), (0.125, 3), (0.0625, 4), (0.1, 3), (0.01, 7),
    ])
    def test_rounds_to_nearest_power_of_two(self, rate: float, expected_n: int) -> None:
        assert subkeys_for_rate(rate) == expected_n

    def test_native_rate_is_power_of_two(self) -> None:
        kp = generate_fmd_key(0.0625)
        assert kp.num_subkeys == 4
        assert kp.false_positive_rate == pytest.approx(0.0625)


# --------------------------------------------------------------------------- #
# True positives — never missed
# --------------------------------------------------------------------------- #


class TestTruePositives:
    def test_recipient_always_detects_own_flag(self) -> None:
        kp = generate_fmd_key(0.0625)
        for i in range(300):
            msg = f"message-{i}".encode()
            flag = fmd_flag(msg, kp.public_keys)
            assert fmd_test(flag, kp, msg) is True

    def test_true_positive_across_rates(self) -> None:
        for rate in (0.5, 0.25, 0.125, 0.0625, 0.03125):
            kp = generate_fmd_key(rate)
            msg = b"hello"
            assert fmd_test(fmd_flag(msg, kp.public_keys), kp, msg) is True


# --------------------------------------------------------------------------- #
# False positives — statistically ~ 2^-n
# --------------------------------------------------------------------------- #


class TestFalsePositives:
    @pytest.mark.parametrize("n,trials", [(2, 2500), (3, 3000), (4, 3500)])
    def test_false_positive_rate_within_tolerance(self, n: int, trials: int) -> None:
        rate = 2.0 ** -n
        sender = generate_fmd_key(rate)        # flags are made for the sender's pubkey
        hits = 0
        for i in range(trials):
            stranger = generate_fmd_key(rate)  # a different recipient tests the flag
            msg = f"m{i}".encode()
            flag = fmd_flag(msg, sender.public_keys)
            if fmd_test(flag, stranger, msg):
                hits += 1
        empirical = hits / trials
        # 4σ binomial tolerance — flaky-safe but still catches a broken rate.
        sigma = math.sqrt(rate * (1 - rate) / trials)
        assert abs(empirical - rate) < 4 * sigma, f"n={n}: {empirical:.4f} vs {rate:.4f}"


# --------------------------------------------------------------------------- #
# Message binding & downgrade
# --------------------------------------------------------------------------- #


class TestBinding:
    def test_flag_bound_to_its_message(self) -> None:
        # A flag tested against the wrong message degrades to the false-positive
        # rate (2^-n). Use a high-precision key so a wrong-message match is
        # ~2^-20 — negligible — making the binding effectively a hard reject.
        kp = generate_fmd_key(2.0 ** -20)
        flag = fmd_flag(b"the real message", kp.public_keys)
        assert fmd_test(flag, kp, b"the real message") is True
        assert fmd_test(flag, kp, b"a different message") is False

    def test_downgrade_keeps_true_positives(self) -> None:
        kp = generate_fmd_key(0.015625)  # n=6
        relay_key = kp.downgrade(0.25)   # k=2 → coarser rate the relay uses
        assert relay_key.num_subkeys == 2
        msg = b"detect me"
        flag = fmd_flag(msg, kp.public_keys)
        # The coarser key still always matches the genuine recipient.
        assert fmd_test(flag, relay_key, msg) is True

    def test_downgrade_raises_false_positive_rate(self) -> None:
        kp = generate_fmd_key(0.0625)    # n=4 → FP 1/16
        coarse = kp.downgrade(0.5)       # k=1 → FP 1/2
        assert coarse.false_positive_rate == pytest.approx(0.5)


# --------------------------------------------------------------------------- #
# Robustness
# --------------------------------------------------------------------------- #


def test_empty_detection_pub_rejected() -> None:
    with pytest.raises(ValueError, match="FMD off"):
        fmd_flag(b"m", [])


def test_off_key_never_matches() -> None:
    off = generate_fmd_key(0.0)
    # An FMD-off key (no sub-keys) can't be tested against and always returns False.
    real = generate_fmd_key(0.25)
    flag = fmd_flag(b"m", real.public_keys)
    assert fmd_test(flag, off, b"m") is False


def test_malformed_flag_returns_false() -> None:
    kp = generate_fmd_key(0.25)
    assert fmd_test(b"too-short", kp, b"m") is False


def test_keypair_is_frozen() -> None:
    kp = generate_fmd_key(0.25)
    assert isinstance(kp, FMDKeypair)
    with pytest.raises(Exception):  # noqa: B017 — frozen dataclass
        kp.secret_keys = []  # type: ignore[misc]
