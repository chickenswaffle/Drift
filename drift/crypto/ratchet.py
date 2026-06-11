"""
drift.crypto.ratchet — Signal Double Ratchet (Phase 2)

Reference: https://signal.org/docs/specifications/doubleratchet/

Provides per-message forward secrecy and post-compromise security on top of
the Phase 0/1 building blocks:

  - DH ratchet   — each party advertises a fresh X25519 ratchet public key in
                   every message header; whenever the peer's key changes, both
                   sides turn the DH ratchet, mixing a new shared secret into
                   the root key.
  - Symmetric ratchet — within a chain, each message key is derived from a
                   one-way KDF step on the chain key, then the chain key is
                   advanced and the old one discarded. Past message keys can
                   never be reconstructed from a later chain key.

KDFs
----
Every KDF here is HKDF-SHA256 from the `cryptography` library. We never write
our own HMAC or KDF. The root KDF follows the spec (salt = root key, IKM = DH
output); the chain KDF derives 64 bytes from the chain key and splits them into
(next chain key, message key) — equivalent in role to the spec's HMAC chain KDF
but expressed purely through HKDF.

All AEAD is the project's XChaCha20-Poly1305 `encrypt`/`decrypt`; the serialized
header is bound as associated data, so tampering with a header is rejected.
`InvalidTag` is always allowed to propagate (project iron rule).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from drift.crypto import Keypair, decrypt, encrypt

# Maximum number of message keys we will skip (and cache) within a single chain
# before treating a header as hostile. Bounds memory against a flood of
# large-gap message numbers.
MAX_SKIP = 1000

_DH_PUB_LEN = 32
_COUNTER_LEN = 4
_HEADER_LEN = _DH_PUB_LEN + 2 * _COUNTER_LEN


class RatchetError(Exception):
    """Raised on a protocol violation (e.g. too many skipped messages)."""


# ---------------------------------------------------------------------------
# Message header
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Header:
    """
    Per-message ratchet header, sent in the clear alongside the ciphertext.

      dh — our current ratchet public key (32 bytes)
      pn — number of messages in the *previous* sending chain
      n  — this message's number in the current sending chain
    """
    dh: bytes
    pn: int
    n: int

    def to_bytes(self) -> bytes:
        """Canonical wire encoding: dh(32) || pn(4 BE) || n(4 BE)."""
        return (
            self.dh
            + self.pn.to_bytes(_COUNTER_LEN, "big")
            + self.n.to_bytes(_COUNTER_LEN, "big")
        )

    @classmethod
    def from_bytes(cls, raw: bytes) -> Header:
        if len(raw) != _HEADER_LEN:
            raise ValueError(f"header must be {_HEADER_LEN} bytes, got {len(raw)}")
        dh = raw[:_DH_PUB_LEN]
        pn = int.from_bytes(raw[_DH_PUB_LEN:_DH_PUB_LEN + _COUNTER_LEN], "big")
        n = int.from_bytes(raw[_DH_PUB_LEN + _COUNTER_LEN:], "big")
        return cls(dh=dh, pn=pn, n=n)


# ---------------------------------------------------------------------------
# Ratchet state
# ---------------------------------------------------------------------------

@dataclass
class RatchetState:
    """
    The full mutable state of one party's Double Ratchet session.

      root_key            — RK,  the root key (32 bytes)
      sending_chain_key   — CKs, current sending chain key (None until ready)
      receiving_chain_key — CKr, current receiving chain key (None until ready)
      message_keys        — MKSKIPPED: cache of skipped message keys, keyed by
                            (their_ratchet_pub, message_number)
      ratchet_keypair     — DHs, our current X25519 ratchet keypair
      their_ratchet_pub   — DHr, the peer's current ratchet public key
      send_count          — Ns, messages sent in the current sending chain
      recv_count          — Nr, messages received in the current receiving chain
      prev_send_count     — PN, length of the previous sending chain
    """
    root_key: bytes
    sending_chain_key: bytes | None
    receiving_chain_key: bytes | None
    ratchet_keypair: Keypair
    their_ratchet_pub: bytes | None
    send_count: int = 0
    recv_count: int = 0
    prev_send_count: int = 0
    message_keys: dict[tuple[bytes, int], bytes] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# KDFs (HKDF-SHA256 only)
# ---------------------------------------------------------------------------

def _kdf_rk(root_key: bytes, dh_out: bytes) -> tuple[bytes, bytes]:
    """
    Root KDF — per spec: HKDF with salt = root key, IKM = DH output.
    Returns (new_root_key, chain_key).
    """
    out = HKDF(
        algorithm=SHA256(), length=64, salt=root_key, info=b"drift-ratchet-v1-rk"
    ).derive(dh_out)
    return out[:32], out[32:]


def _kdf_ck(chain_key: bytes) -> tuple[bytes, bytes]:
    """
    Chain KDF — one HKDF step over the chain key, split into
    (next_chain_key, message_key). One-way: a later chain key reveals
    nothing about earlier chain keys or message keys.
    """
    out = HKDF(
        algorithm=SHA256(), length=64, salt=None, info=b"drift-ratchet-v1-ck"
    ).derive(chain_key)
    return out[:32], out[32:]


# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------

def init_sender(shared_secret: bytes, their_ratchet_pub: bytes) -> RatchetState:
    """
    Initialise the initiating party (Signal's "Alice").

    The initiator generates a fresh ratchet keypair and immediately turns the
    root ratchet using DH(our new key, their initial ratchet public key),
    producing the first sending chain. The initiator can send right away.
    """
    dhs = Keypair.generate()
    root_key, sending_chain_key = _kdf_rk(shared_secret, dhs.ecdh(their_ratchet_pub))
    return RatchetState(
        root_key=root_key,
        sending_chain_key=sending_chain_key,
        receiving_chain_key=None,
        ratchet_keypair=dhs,
        their_ratchet_pub=their_ratchet_pub,
    )


def init_receiver(shared_secret: bytes, our_ratchet_keypair: Keypair) -> RatchetState:
    """
    Initialise the responding party (Signal's "Bob").

    The responder holds the ratchet keypair whose public half the initiator
    used to bootstrap. It has no sending chain yet — it must receive the
    initiator's first message (and turn the DH ratchet) before it can send.
    """
    return RatchetState(
        root_key=shared_secret,
        sending_chain_key=None,
        receiving_chain_key=None,
        ratchet_keypair=our_ratchet_keypair,
        their_ratchet_pub=None,
    )


# ---------------------------------------------------------------------------
# Encrypt / decrypt
# ---------------------------------------------------------------------------

def ratchet_encrypt(state: RatchetState, plaintext: bytes) -> tuple[Header, bytes]:
    """
    Advance the sending chain and encrypt one message.

    Returns (header, ciphertext). The header carries our ratchet public key
    and message number; it is also bound as AEAD associated data.
    """
    if state.sending_chain_key is None:
        raise RatchetError(
            "no sending chain yet — receive a message before sending"
        )
    state.sending_chain_key, message_key = _kdf_ck(state.sending_chain_key)
    header = Header(
        dh=state.ratchet_keypair.public_bytes(),
        pn=state.prev_send_count,
        n=state.send_count,
    )
    state.send_count += 1
    ciphertext = encrypt(message_key, plaintext, associated_data=header.to_bytes())
    return header, ciphertext


def ratchet_decrypt(state: RatchetState, header: Header, ciphertext: bytes) -> bytes:
    """
    Decrypt one message, advancing / turning ratchets as needed.

    Handles out-of-order delivery via the skipped-message-key cache and turns
    the DH ratchet whenever the header advertises a new peer ratchet key.
    A genuine decryption (authentication) failure raises ``InvalidTag``.
    """
    # 1. A message we already skipped and cached.
    plaintext = _try_skipped_keys(state, header, ciphertext)
    if plaintext is not None:
        return plaintext

    # 2. New peer ratchet key → skip the rest of the old chain, then DH ratchet.
    if header.dh != state.their_ratchet_pub:
        _skip_message_keys(state, header.pn)
        _dh_ratchet(state, header)

    # 3. Skip up to this message's number in the current receiving chain.
    _skip_message_keys(state, header.n)

    # 4. Derive this message's key and decrypt. In normal operation the DH
    #    ratchet above guarantees a receiving chain; its absence means the
    #    chain key was erased (e.g. after secure deletion) — unrecoverable.
    if state.receiving_chain_key is None:
        raise RatchetError("no receiving chain key — message is unrecoverable")
    state.receiving_chain_key, message_key = _kdf_ck(state.receiving_chain_key)
    state.recv_count += 1
    return decrypt(message_key, ciphertext, associated_data=header.to_bytes())


# ---------------------------------------------------------------------------
# Internal ratchet mechanics
# ---------------------------------------------------------------------------

def _try_skipped_keys(
    state: RatchetState, header: Header, ciphertext: bytes
) -> bytes | None:
    """Use (and consume) a cached message key, if one matches this header."""
    key = (header.dh, header.n)
    message_key = state.message_keys.pop(key, None)
    if message_key is None:
        return None
    # InvalidTag propagates — a cached key that fails to authenticate is tamper.
    return decrypt(message_key, ciphertext, associated_data=header.to_bytes())


def _skip_message_keys(state: RatchetState, until: int) -> None:
    """
    Derive and cache message keys for the current receiving chain up to (but
    not including) message number ``until`` — covering out-of-order arrivals.
    """
    if state.recv_count + MAX_SKIP < until:
        raise RatchetError("too many skipped messages")
    if state.receiving_chain_key is None:
        return
    while state.recv_count < until:
        state.receiving_chain_key, message_key = _kdf_ck(state.receiving_chain_key)
        assert state.their_ratchet_pub is not None
        state.message_keys[(state.their_ratchet_pub, state.recv_count)] = message_key
        state.recv_count += 1


def _dh_ratchet(state: RatchetState, header: Header) -> None:
    """
    Turn the DH ratchet on receipt of a new peer ratchet key: derive a fresh
    receiving chain, generate a new local ratchet keypair, and derive a fresh
    sending chain.
    """
    state.prev_send_count = state.send_count
    state.send_count = 0
    state.recv_count = 0
    state.their_ratchet_pub = header.dh

    state.root_key, state.receiving_chain_key = _kdf_rk(
        state.root_key, state.ratchet_keypair.ecdh(header.dh)
    )
    state.ratchet_keypair = Keypair.generate()
    state.root_key, state.sending_chain_key = _kdf_rk(
        state.root_key, state.ratchet_keypair.ecdh(header.dh)
    )
