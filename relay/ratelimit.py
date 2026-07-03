"""
relay.ratelimit — in-memory token buckets for the reference relay.

Flood control for the open HTTP surface, sized for two abuse cases:

  * raw ``/send`` floods parking blobs in every subscriber's firehose, and
  * one-time-prekey **pool draining** — hammering ``GET /prekeys/{addr}``
    until a victim's OTPKs are gone, forcing later handshakes onto the
    weaker OTPK-less X3DH path.

Privacy stance: bucket keys (client IPs, target addresses) live only in
bounded RAM, are never logged or persisted, and vanish on restart or LRU
eviction. This is flood control, not accounting — the relay stays blind.
Limits are deliberately generous because many honest clients share one exit
IP over Tor; the goal is stopping abuse that is orders of magnitude beyond
chat traffic, not shaping normal use.
"""

from __future__ import annotations

import time
from collections import OrderedDict


class TokenBucket:
    """Per-key token buckets with a bounded LRU of keys.

    Each key's bucket holds up to ``burst`` tokens and refills at ``rate``
    tokens/second. ``allow(key)`` spends one token; a key over budget is
    refused until refill. At most ``max_keys`` keys are tracked — the least
    recently seen key is evicted first, so memory stays bounded no matter
    how many distinct clients appear.
    """

    def __init__(self, rate: float, burst: float, max_keys: int = 4096) -> None:
        self.rate = rate
        self.burst = burst
        self.max_keys = max_keys
        # key → (tokens, last_refill_ts); OrderedDict as an LRU.
        self._buckets: OrderedDict[str, tuple[float, float]] = OrderedDict()

    def allow(self, key: str, now: float | None = None) -> bool:
        """Spend one token for ``key``. ``now`` is injectable for tests."""
        ts = time.monotonic() if now is None else now
        tokens, last = self._buckets.pop(key, (self.burst, ts))
        tokens = min(self.burst, tokens + max(0.0, ts - last) * self.rate)
        ok = tokens >= 1.0
        if ok:
            tokens -= 1.0
        self._buckets[key] = (tokens, ts)  # re-insert at LRU tail
        while len(self._buckets) > self.max_keys:
            self._buckets.popitem(last=False)
        return ok

    def clear(self) -> None:
        """Drop all bucket state (tests / operator reset)."""
        self._buckets.clear()

    def __len__(self) -> int:
        return len(self._buckets)
