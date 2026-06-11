"""
tests/unit/test_burn.py — burn token generation and verification

Run: pytest tests/unit/test_burn.py -v
"""

from __future__ import annotations

import os

import pytest

from drift.crypto.burn import TOKEN_HEX_LEN, generate_burn_token, verify_burn_token


@pytest.fixture()
def secret() -> bytes:
    return os.urandom(32)


def test_token_is_64_hex_chars(secret: bytes) -> None:
    token = generate_burn_token(secret, "conversation")
    assert len(token) == TOKEN_HEX_LEN
    assert all(c in "0123456789abcdef" for c in token)


def test_same_inputs_produce_same_token(secret: bytes) -> None:
    t1 = generate_burn_token(secret, "conversation")
    t2 = generate_burn_token(secret, "conversation")
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
    t_conv = generate_burn_token(secret, "conversation")
    t_msg = generate_burn_token(secret, "message")
    assert t_conv != t_msg


def test_different_secrets_produce_different_tokens() -> None:
    s1, s2 = os.urandom(32), os.urandom(32)
    assert generate_burn_token(s1, "conversation") != generate_burn_token(s2, "conversation")


def test_verify_rejects_wrong_length_token(secret: bytes) -> None:
    assert verify_burn_token(secret, "tooshort", "conversation") is False
    assert verify_burn_token(secret, "a" * 63, "conversation") is False
    assert verify_burn_token(secret, "a" * 65, "conversation") is False


def test_none_and_empty_message_id_are_equivalent(secret: bytes) -> None:
    """generate_burn_token treats None and '' the same for message_id."""
    t_none = generate_burn_token(secret, "message", None)
    t_empty = generate_burn_token(secret, "message", "")
    assert t_none == t_empty
    assert verify_burn_token(secret, t_none, "message", None) is True
    assert verify_burn_token(secret, t_none, "message", "") is True
