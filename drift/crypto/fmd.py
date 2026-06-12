"""
drift.crypto.fmd — Fuzzy Message Detection (Phase 5)

A *privacy dial*. Today a DRIFT recipient finds their mail by scanning every
envelope on the firehose locally (stealth scan). FMD lets a recipient instead
hand a relay a **detection key** that matches their messages *and* a tunable
fraction of everyone else's — a false-positive rate `p`. The relay can then
pre-filter the firehose down to "messages that might be yours," so the client
scans far fewer envelopes, at the cost of telling the relay a fuzzy, `p`-sized
anonymity set rather than nothing. `p` is the knob: `p = 0` keeps everything
client-side (today's behaviour); a larger `p` trades anonymity for efficiency.

FMD sits *alongside* the stealth scan — it never replaces the cryptographic
addressing. A flagged message that survives the relay's pre-filter is still
stealth-scanned and ratchet-decrypted exactly as before. FMD only governs
*which subset the relay forwards*; it is not an authentication or content
mechanism and learns nothing about message contents.

Construction
------------
This implements the **FMD2** scheme of Beck, Len, Miers, and Green,
"Fuzzy Message Detection" (ACM CCS 2021, https://eprint.iacr.org/2021/089),
the compact restricted-false-positive variant. It is *composed* from libsodium's
audited ed25519 group operations via PyNaCl (`nacl.bindings`) — the same group
the stealth module already uses. No field or curve arithmetic is implemented
here; the iron rule holds.

Let `G` be the prime-order ed25519 group with generator `B` and order `L`, and
`H_bit : * → {0,1}`, `H_s : * → Z_L` two hashes (SHA-256 low bit, SHA-512
reduced mod L). A key has `n` independent sub-keys, giving a minimum false-
positive rate of `2^-n`.

  KeyGen(n):  x_i ←$ Z_L,  X_i = x_i·B          for i = 1..n
              sk = (x_1..x_n),  pk = (X_1..X_n)

  Flag(pk, msg):
      r ←$ Z_L,  u = r·B
      z ←$ Z_L,  w = z·B
      for i: k_i = H_bit(u, r·X_i, w);  c_i = k_i ⊕ 1
      m = H_s(msg, u, c_1..c_n)
      y = (z − m)·r⁻¹  mod L
      flag = (u, y, c_1..c_n)

  Test(sk, flag, msg):                     # check the first k ≤ n sub-keys → rate 2^-k
      m = H_s(msg, u, c_1..c_n)
      w = m·B + y·u                          # reconstructs the sender's w
      for i = 1..k:
          k_i = H_bit(u, x_i·u, w)
          if k_i ⊕ c_i ≠ 1: return False
      return True

A genuine recipient recovers every `k_i` and so every `k_i ⊕ c_i = 1` → always
detected (no false negatives). For anyone else each bit is `1` with probability
½, so Test passes with probability `2^-k` — the false-positive rate. `msg` is
folded into `m` (hence into `w`), binding a flag to its message so it can't be
lifted onto another. Achievable rates are powers of two; a requested rate is
mapped to the nearest `n = round(-log2(p))`.
"""

from __future__ import annotations

import hashlib
import math
import os
from dataclasses import dataclass

from nacl import bindings as _sodium

# Domain-separation tags for the two hashes. Versioned — changing either breaks
# compatibility with already-issued flags.
_H_BIT_TAG = b"drift-fmd-v1-bit"
_H_SCALAR_TAG = b"drift-fmd-v1-scalar"

# Upper bound on sub-keys (so a degenerate rate request can't allocate forever).
# 2^-32 is already a vanishingly small false-positive rate.
_MAX_SUBKEYS = 32


# ---------------------------------------------------------------------------
# Group helpers (all delegated to libsodium ref10 ed25519 via PyNaCl)
# ---------------------------------------------------------------------------


def _rand_scalar() -> bytes:
    """Uniform scalar in Z_L: reduce 64 random bytes mod L (negligible bias)."""
    return _sodium.crypto_core_ed25519_scalar_reduce(os.urandom(64))


def _base_mul(scalar: bytes) -> bytes:
    return _sodium.crypto_scalarmult_ed25519_base_noclamp(scalar)


def _point_mul(scalar: bytes, point: bytes) -> bytes:
    return _sodium.crypto_scalarmult_ed25519_noclamp(scalar, point)


def _point_add(p: bytes, q: bytes) -> bytes:
    return _sodium.crypto_core_ed25519_add(p, q)


def _scalar_mul(a: bytes, b: bytes) -> bytes:
    return _sodium.crypto_core_ed25519_scalar_mul(a, b)


def _scalar_sub(a: bytes, b: bytes) -> bytes:
    return _sodium.crypto_core_ed25519_scalar_sub(a, b)


def _scalar_invert(a: bytes) -> bytes:
    return _sodium.crypto_core_ed25519_scalar_invert(a)


def _h_bit(u: bytes, shared: bytes, w: bytes) -> int:
    return hashlib.sha256(_H_BIT_TAG + u + shared + w).digest()[0] & 1


def _h_scalar(message: bytes, u: bytes, flag_bits: bytes) -> bytes:
    digest = hashlib.sha512(_H_SCALAR_TAG + u + flag_bits + message).digest()
    return _sodium.crypto_core_ed25519_scalar_reduce(digest)


# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------


def subkeys_for_rate(false_positive_rate: float) -> int:
    """
    Number of sub-keys `n` for a requested false-positive rate.

    Achievable rates are powers of two, so we pick `n = round(-log2(p))`. A rate
    of 0 (or ≤ 0) means "FMD off" → 0 sub-keys.
    """
    if false_positive_rate <= 0:
        return 0
    if false_positive_rate >= 1:
        return 1
    n = round(-math.log2(false_positive_rate))
    return max(1, min(_MAX_SUBKEYS, n))


@dataclass(frozen=True)
class FMDKeypair:
    """
    An FMD detection keypair with `n` sub-keys (native FP rate `2^-n`).

    ``secret_keys`` / ``public_keys`` are lists of 32-byte ed25519 scalars /
    points. The sender needs only ``public_keys``; the detector needs
    ``secret_keys``. A relay is given a *downgraded* key (fewer secret sub-keys)
    to pre-filter at a coarser rate without learning the recipient's full key.
    """

    secret_keys: list[bytes]
    public_keys: list[bytes]

    @property
    def num_subkeys(self) -> int:
        return len(self.secret_keys)

    @property
    def false_positive_rate(self) -> float:
        """The native rate `2^-n` this key tests at."""
        return 2.0 ** (-len(self.secret_keys)) if self.secret_keys else 1.0

    def downgrade(self, false_positive_rate: float) -> FMDKeypair:
        """
        A coarser detection key for a relay: keep only the first `k` sub-keys
        (`k = -log2(p)`), so the relay matches at rate `2^-k ≥ 2^-n`. The
        public key is unchanged (flags are always made at full precision).
        """
        k = min(self.num_subkeys, subkeys_for_rate(false_positive_rate))
        return FMDKeypair(secret_keys=self.secret_keys[:k], public_keys=self.public_keys)


def generate_fmd_key(false_positive_rate: float) -> FMDKeypair:
    """
    Generate an FMD detection keypair tuned to ``false_positive_rate``.

    The rate is the privacy dial: it is mapped to `n = round(-log2(p))` sub-keys
    (achievable rates are powers of two). ``generate_fmd_key(0)`` returns an
    empty keypair (FMD off).
    """
    n = subkeys_for_rate(false_positive_rate)
    secret_keys = [_rand_scalar() for _ in range(n)]
    public_keys = [_base_mul(x) for x in secret_keys]
    return FMDKeypair(secret_keys=secret_keys, public_keys=public_keys)


# ---------------------------------------------------------------------------
# Flag / Test
# ---------------------------------------------------------------------------


def fmd_flag(message: bytes, detection_pub: list[bytes]) -> bytes:
    """
    Produce a detection flag for ``message`` addressed to ``detection_pub``.

    ``detection_pub`` is the recipient's list of public sub-keys. The flag is
    serialized as ``u (32) ‖ y (32) ‖ flag_bits (ceil(n/8))`` with ``n`` packed
    one bit per sub-key. The flag carries no content and binds to ``message``.
    """
    n = len(detection_pub)
    if n == 0:
        raise ValueError("detection_pub is empty (FMD off) — nothing to flag")
    r = _rand_scalar()
    u = _base_mul(r)
    z = _rand_scalar()
    w = _base_mul(z)

    bits = bytearray((n + 7) // 8)
    for i, x_pub in enumerate(detection_pub):
        k_i = _h_bit(u, _point_mul(r, x_pub), w)
        c_i = k_i ^ 1
        if c_i:
            bits[i >> 3] |= 1 << (i & 7)

    m = _h_scalar(message, u, bytes(bits))
    y = _scalar_mul(_scalar_sub(z, m), _scalar_invert(r))
    return u + y + bytes(bits)


def _parse_flag(flag: bytes, n: int) -> tuple[bytes, bytes, bytes]:
    """Split a flag into (u, y, flag_bits); raise ValueError if malformed."""
    expected = 64 + (n + 7) // 8
    if len(flag) < expected:
        raise ValueError("FMD flag too short for the detection key")
    return flag[:32], flag[32:64], flag[64:expected]


def fmd_test(flag: bytes, detection_key: FMDKeypair, message: bytes) -> bool:
    """
    Test whether ``flag`` might be addressed to ``detection_key``.

    Checks every sub-key in ``detection_key`` (so the false-positive rate is the
    key's native `2^-n`; hand a :meth:`FMDKeypair.downgrade` key to test fewer).
    Always ``True`` for the genuine recipient; ``True`` with probability `2^-n`
    for anyone else. ``message`` must be the message the flag was made for.
    """
    secret = detection_key.secret_keys
    k = len(secret)
    if k == 0:
        return False
    try:
        u, y, flag_bits = _parse_flag(flag, k)
    except ValueError:
        return False

    m = _h_scalar(message, u, flag_bits)
    # Reconstruct the sender's w = m·B + y·u.
    w = _point_add(_base_mul(m), _point_mul(y, u))

    for i, x_priv in enumerate(secret):
        c_i = (flag_bits[i >> 3] >> (i & 7)) & 1
        k_i = _h_bit(u, _point_mul(x_priv, u), w)
        if (k_i ^ c_i) != 1:
            return False
    return True
