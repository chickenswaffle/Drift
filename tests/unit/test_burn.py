"""
tests/unit/test_burn.py — burn token generation and verification

Burn tokens are single-use (audit M2): each carries a fresh nonce + timestamp
bound into the MAC, so two tokens for the same conversation differ and a stale
token fails verification.

Run: pytest tests/unit/test_burn.py -v
"""

from __future__ import annotations

import os
import time

import pytest

from drift.crypto.burn import (
    MAC_HEX_LEN,
    NONCE_HEX_LEN,
    TOKEN_TTL_SECONDS,
    BurnTokenError,
    generate_burn_token,
    parse_burn_token,
    verify_burn_token,
)


@pytest.fixture()
def secret() -> bytes:
    return os.urandom(32)


def test_token_shape_is_nonce_ts_mac(secret: bytes) -> None:
    token = generate_burn_token(secret, "conversation")
    nonce_hex, ts, mac = parse_burn_token(token)
    assert len(nonce_hex) == NONCE_HEX_LEN
    assert len(mac) == MAC_HEX_LEN
    assert isinstance(ts, int)
    assert abs(int(time.time()) - ts) < 5


def test_same_inputs_produce_different_tokens(secret: bytes) -> None:
    # The whole point of M2: a fresh random nonce each time, so the conversation
    # token is no longer a stable fingerprint.
    t1 = generate_burn_token(secret, "conversation")
    t2 = generate_burn_token(secret, "conversation")
    assert t1 != t2


def test_pinned_nonce_and_timestamp_reproduce_token(secret: bytes) -> None:
    nonce = os.urandom(16)
    t1 = generate_burn_token(secret, "conversation", nonce=nonce, timestamp=1000)
    t2 = generate_burn_token(secret, "conversation", nonce=nonce, timestamp=1000)
    assert t1 == t2


def test_verify_correct_token(secret: bytes) -> None:
    token = generate_burn_token(secret, "conversation")
    assert verify_burn_token(secret, token, "conversation") is True


def test_verify_correct_token_with_message_id(secret: bytes) -> None:
    mid = "abc123+/=="
    token = generate_burn_token(secret, "message", mid)
    assert verify_burn_token(secret, token, "message", mid) is True


def test_verify_wrong_scope_fails(secret: bytes) -> None:
    token = generate_burn_token(secret, "conversation")
    assert verify_burn_token(secret, token, "message") is False


def test_verify_wrong_message_id_fails(secret: bytes) -> None:
    token = generate_burn_token(secret, "message", "addr1")
    assert verify_burn_token(secret, token, "message", "addr2") is False


def test_verify_wrong_secret_fails(secret: bytes) -> None:
    token = generate_burn_token(secret, "conversation")
    other = os.urandom(32)
    assert verify_burn_token(other, token, "conversation") is False


def test_different_scopes_produce_different_tokens(secret: bytes) -> None:
    nonce = os.urandom(16)
    t_conv = generate_burn_token(secret, "conversation", nonce=nonce, timestamp=1000)
    t_msg = generate_burn_token(secret, "message", nonce=nonce, timestamp=1000)
    assert t_conv != t_msg


def test_different_secrets_produce_different_tokens() -> None:
    s1, s2 = os.urandom(32), os.urandom(32)
    nonce = os.urandom(16)
    assert generate_burn_token(s1, "conversation", nonce=nonce, timestamp=1) != generate_burn_token(
        s2, "conversation", nonce=nonce, timestamp=1
    )


# --- freshness / replay (audit M2) ------------------------------------------

def test_expired_token_fails_verification(secret: bytes) -> None:
    old = int(time.time()) - TOKEN_TTL_SECONDS - 1
    token = generate_burn_token(secret, "conversation", timestamp=old)
    assert verify_burn_token(secret, token, "conversation") is False


def test_token_at_edge_of_window_still_valid(secret: bytes) -> None:
    now = 1_000_000
    token = generate_burn_token(secret, "conversation", timestamp=now - TOKEN_TTL_SECONDS)
    assert verify_burn_token(secret, token, "conversation", now=now) is True


def test_future_token_outside_window_fails(secret: bytes) -> None:
    future = int(time.time()) + TOKEN_TTL_SECONDS + 60
    token = generate_burn_token(secret, "conversation", timestamp=future)
    assert verify_burn_token(secret, token, "conversation") is False


def test_tampered_timestamp_fails_mac(secret: bytes) -> None:
    # Re-timestamping a captured token within the freshness window must still
    # fail: the timestamp is MAC-bound.
    nonce_hex, ts, mac = parse_burn_token(
        generate_burn_token(secret, "conversation", timestamp=1_000_000)
    )
    forged = f"{nonce_hex}.{ts + 1}.{mac}"
    assert verify_burn_token(secret, forged, "conversation", now=1_000_000) is False


# --- malformed input ---------------------------------------------------------

def test_verify_rejects_malformed_token(secret: bytes) -> None:
    assert verify_burn_token(secret, "tooshort", "conversation") is False
    assert verify_burn_token(secret, "a" * 64, "conversation") is False  # old format
    assert verify_burn_token(secret, "a.b.c", "conversation") is False


def test_parse_rejects_malformed() -> None:
    for bad in ["", "a.b", "a.b.c.d", "x" * 32 + ".notanint." + "f" * 64]:
        with pytest.raises(BurnTokenError):
            parse_burn_token(bad)


def test_none_and_empty_message_id_are_equivalent(secret: bytes) -> None:
    """generate_burn_token treats None and '' the same for message_id."""
    nonce = os.urandom(16)
    t_none = generate_burn_token(secret, "message", None, nonce=nonce, timestamp=1)
    t_empty = generate_burn_token(secret, "message", "", nonce=nonce, timestamp=1)
    assert t_none == t_empty
    assert verify_burn_token(secret, t_none, "message", None, now=1) is True
    assert verify_burn_token(secret, t_none, "message", "", now=1) is True
