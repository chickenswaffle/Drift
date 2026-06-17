"""
relay.witness — WITNESS: live cryptographic proof of relay blindness

DRIFT's privacy claims are usually *policy*: "the relay does not log." WITNESS
turns that into *mathematics* the relay can be held to.

Every period (60 s) the relay generates and signs a **blindness certificate** —
a structured, machine-checkable document stating what it provably *cannot* know
about the traffic it just routed (it knows zero sender identities, zero
recipient identities, zero message contents, zero linked conversations — these
are structural facts of sealed sender + stealth addressing + E2E encryption,
not a promise). Each certificate carries the SHA256 hash of the previous one, so
the certificates form a tamper-evident, hash-chained transparency log.

The guarantee is *continuity*:

  - The relay cannot retroactively forge a different history without its
    long-term Ed25519 private key — every certificate is signed.
  - If the relay is ever compelled to start logging, the honest move is to stop
    publishing certificates (it cannot publish a *true* certificate while also
    logging without lying under its own key). The moment it stops, the chain
    develops a gap, and any watcher (``drift witness subscribe``) detects it.

What WITNESS proves: the relay has not deviated from blind routing over the
window of certificates you can fetch. What it does **not** prove: that the relay
will never log in the *future* — only ongoing chain continuity gives that,
moment to moment. See ``docs/witness.md``.

Crypto: Ed25519 (``cryptography``) for relay signing, SHA256 (``hashlib``) for
the Merkle tree and chain hashes. No new primitives — the Merkle tree is a
direct ~20-line binary SHA256 construction.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from drift.crypto import b58decode, b58encode

# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------

WITNESS_VERSION = "drift-witness-v1"

# One certificate per minute; 1440 of them = a rolling 24-hour transparency log.
PERIOD_SECONDS = 60
MAX_CERTS = 1440

# The chain is rooted at a fixed, well-known constant so the very first
# certificate a relay ever signs is verifiable as a genesis (no "previous"
# certificate exists, but its previous_cert_hash is not arbitrary).
GENESIS_PREV_HASH = hashlib.sha256(b"drift-witness-genesis-v1").digest()

# Merkle root used for a period in which the relay routed nothing at all.
EMPTY_PERIOD_ROOT = hashlib.sha256(b"empty-period").digest()

# A certificate's timestamp delta from the previous one is expected to be one
# period. We allow this much slack before calling a larger gap a *missing
# window* (the relay went dark — the canary signal).
COVERAGE_SLACK = 1.5


# ---------------------------------------------------------------------------
# Merkle tree — simple binary SHA256, built directly (iron rule: no library)
# ---------------------------------------------------------------------------

def merkle_root(leaves: list[bytes]) -> bytes:
    """Root of a binary SHA256 Merkle tree over ``leaves``.

    An empty leaf set yields :data:`EMPTY_PERIOD_ROOT`. An odd level duplicates
    its last node (the standard "promote the orphan" rule) before pairing. Each
    parent is ``SHA256(left ‖ right)``. This lets anyone later prove a given
    envelope was routed in a period without the relay revealing anything about
    the envelope's content or its parties.
    """
    if not leaves:
        return EMPTY_PERIOD_ROOT
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [
            hashlib.sha256(level[i] + level[i + 1]).digest()
            for i in range(0, len(level), 2)
        ]
    return level[0]


def _envelope_id(envelope: dict[str, object]) -> bytes:
    """A stable identifier for a routed envelope, derived from public fields.

    Uses the relay's per-message ``_id`` when present; otherwise a content hash
    over the same opaque wire fields federation uses for dedup. Either way this
    touches only fields already public on the firehose — the Merkle leaf reveals
    nothing the relay didn't already broadcast.
    """
    raw = envelope.get("_id")
    if raw:
        return str(raw).encode("utf-8")
    canonical = json.dumps(
        {k: envelope[k] for k in ("to", "ct", "ts", "addr") if k in envelope},
        sort_keys=True, separators=(",", ":"),
    )
    return canonical.encode("utf-8")


# ---------------------------------------------------------------------------
# The certificate
# ---------------------------------------------------------------------------

def build_statement(messages_routed: int) -> str:
    """The human-readable statement embedded in a certificate."""
    return (
        f"In the last {PERIOD_SECONDS} seconds I routed {messages_routed} message(s). "
        "I cannot produce a list of who talked to whom, who sent what, or what any "
        "message said: sender identities are sealed, recipient addresses are one-time "
        "stealth addresses, contents are end-to-end encrypted, and conversations are "
        "unlinkable. This is structural, not a policy I could quietly drop. This "
        "statement is signed with my long-term key and chained to the previous one."
    )


@dataclass
class WitnessCertificate:
    """A single signed, hash-chained blindness certificate.

    ``relay_signature`` is an Ed25519 signature over the canonical encoding of
    every *other* field (see :meth:`signing_payload`); the chain hash
    (:meth:`cert_hash`) then covers the signature too, so neither the body nor
    the signature can be altered without breaking either the signature or the
    next certificate's ``previous_cert_hash``.
    """

    version: str
    relay_id: bytes              # relay's Ed25519 public key (raw 32 bytes)
    timestamp: int               # unix seconds
    period_seconds: int
    messages_routed: int
    sender_identities_known: int        # always 0 — sealed sender
    recipient_identities_known: int     # always 0 — stealth addresses
    contents_readable: int              # always 0 — E2E encrypted
    conversations_linked: int           # always 0 — unlinkable envelopes
    envelope_merkle_root: bytes
    previous_cert_hash: bytes
    relay_signature: bytes = b""
    statement: str = ""

    # -- canonical encoding --------------------------------------------------

    def _base_dict(self, *, include_sig: bool) -> dict[str, object]:
        d: dict[str, object] = {
            "version": self.version,
            "relay_id": self.relay_id.hex(),
            "timestamp": self.timestamp,
            "period_seconds": self.period_seconds,
            "messages_routed": self.messages_routed,
            "sender_identities_known": self.sender_identities_known,
            "recipient_identities_known": self.recipient_identities_known,
            "contents_readable": self.contents_readable,
            "conversations_linked": self.conversations_linked,
            "envelope_merkle_root": self.envelope_merkle_root.hex(),
            "previous_cert_hash": self.previous_cert_hash.hex(),
            "statement": self.statement,
        }
        if include_sig:
            d["relay_signature"] = self.relay_signature.hex()
        return d

    def signing_payload(self) -> bytes:
        """Canonical bytes the relay signs — every field except the signature."""
        return json.dumps(
            self._base_dict(include_sig=False), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

    def canonical_bytes(self) -> bytes:
        """Canonical bytes of the full, signed certificate (what the chain hashes)."""
        return json.dumps(
            self._base_dict(include_sig=True), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

    def cert_hash(self) -> bytes:
        """SHA256 of the canonical bytes — the value the *next* cert chains to."""
        return hashlib.sha256(self.canonical_bytes()).digest()

    # -- (de)serialization ---------------------------------------------------

    def to_dict(self) -> dict[str, object]:
        """JSON-safe form for the HTTP API (adds the derived ``cert_hash``)."""
        d = self._base_dict(include_sig=True)
        d["cert_hash"] = self.cert_hash().hex()
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> WitnessCertificate:
        """Reconstruct a certificate from its JSON form (ignores derived fields)."""
        return cls(
            version=str(d["version"]),
            relay_id=bytes.fromhex(d["relay_id"]),
            timestamp=int(d["timestamp"]),
            period_seconds=int(d["period_seconds"]),
            messages_routed=int(d["messages_routed"]),
            sender_identities_known=int(d["sender_identities_known"]),
            recipient_identities_known=int(d["recipient_identities_known"]),
            contents_readable=int(d["contents_readable"]),
            conversations_linked=int(d["conversations_linked"]),
            envelope_merkle_root=bytes.fromhex(d["envelope_merkle_root"]),
            previous_cert_hash=bytes.fromhex(d["previous_cert_hash"]),
            relay_signature=bytes.fromhex(d["relay_signature"]),
            statement=str(d.get("statement", "")),
        )

    # -- verification --------------------------------------------------------

    def verify_signature(self) -> bool:
        """True iff ``relay_signature`` is a valid signature by ``relay_id``."""
        try:
            pub = Ed25519PublicKey.from_public_bytes(self.relay_id)
            pub.verify(self.relay_signature, self.signing_payload())
        except (InvalidSignature, ValueError):
            return False
        return True

    def blindness_held(self) -> bool:
        """True iff all four "known" counters are zero (the structural claim)."""
        return (
            self.sender_identities_known == 0
            and self.recipient_identities_known == 0
            and self.contents_readable == 0
            and self.conversations_linked == 0
        )


# ---------------------------------------------------------------------------
# Relay long-term identity (Ed25519) — the key that signs every certificate
# ---------------------------------------------------------------------------

def load_or_create_relay_identity(path: Path | str) -> Ed25519PrivateKey:
    """Load the relay's long-term Ed25519 signing key, generating it on first run.

    Mirrors the client identity model: the private key is persisted to
    ``relay_identity.json`` (``chmod 0o600``) and is the relay's stable,
    verifiable identity. The same key signs every certificate forever, so a
    seized or restarted relay that wants to keep an *unbroken* chain must keep
    this key — and a relay that loses it cannot impersonate its past self.
    """
    p = Path(path)
    if p.exists():
        try:
            data = json.loads(p.read_text())
            return Ed25519PrivateKey.from_private_bytes(b58decode(data["ed25519_priv"]))
        except (json.JSONDecodeError, KeyError, ValueError) as exc:
            # Refuse to silently regenerate: a new key would reset the relay's
            # verifiable identity and break its witness chain. The operator must
            # restore or remove the file deliberately.
            raise ValueError(
                f"relay identity at {p} is corrupt or empty ({exc}); refusing to "
                "overwrite it. Restore the file or remove it to mint a new identity."
            ) from exc
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes_raw()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({
        "version": WITNESS_VERSION,
        "ed25519_priv": b58encode(sk.private_bytes_raw()),
        "ed25519_pub": b58encode(pub),
    }, indent=2))
    p.chmod(0o600)
    return sk


# ---------------------------------------------------------------------------
# Human-readable fingerprint for out-of-band identity verification
# ---------------------------------------------------------------------------

_FP_NATURE = (
    "river", "amber", "north", "stone", "ember", "frost", "delta", "harbor",
    "meadow", "summit", "canyon", "willow", "cedar", "marsh", "tundra", "ridge",
)
_FP_COLORS = (
    "amber", "azure", "crimson", "violet", "indigo", "scarlet", "teal", "olive",
    "copper", "silver", "ivory", "ochre", "cobalt", "maroon", "slate", "sage",
)
_FP_ANIMALS = (
    "tiger", "falcon", "otter", "lynx", "raven", "heron", "bison", "viper",
    "marten", "ibex", "stag", "hawk", "wolf", "crane", "orca", "fox",
)


def fingerprint(relay_id: bytes) -> str:
    """A short, human-comparable mnemonic for a relay's public key.

    Deterministic and domain-separated. This is a *convenience* for out-of-band
    comparison; the authoritative identity is the full base58 public key. Two
    different keys could in principle collide on the mnemonic, which is why
    ``drift witness verify`` also prints the full key.
    """
    digest = hashlib.sha256(b"drift-witness-fingerprint-v1" + relay_id).digest()
    return (
        f"{_FP_NATURE[digest[0] % len(_FP_NATURE)]}-"
        f"{_FP_COLORS[digest[1] % len(_FP_COLORS)]}-"
        f"{_FP_ANIMALS[digest[2] % len(_FP_ANIMALS)]}-"
        f"{digest[3] % 100:02d}"
    )


def relay_pubkey_b58(relay_id: bytes) -> str:
    """The relay's Ed25519 public key in base58 (the authoritative identity)."""
    return b58encode(relay_id)


# ---------------------------------------------------------------------------
# The rolling chain
# ---------------------------------------------------------------------------

@dataclass
class _Window:
    """Mutable accumulator for the period currently being witnessed."""
    leaves: list[bytes] = field(default_factory=list)
    count: int = 0


class WitnessChain:
    """Generates and stores the rolling chain of blindness certificates.

    On construction a **genesis** certificate is signed immediately (its
    ``previous_cert_hash`` is :data:`GENESIS_PREV_HASH`), so the chain is never
    empty and ``/witness/current`` works the instant the relay starts. Routed
    envelopes are accumulated via :meth:`record_envelope`; :meth:`generate` (the
    relay calls it once per period) seals the window into the next certificate.
    The last :data:`MAX_CERTS` certificates are kept in a bounded deque.
    """

    def __init__(
        self,
        signing_key: Ed25519PrivateKey,
        *,
        period_seconds: int = PERIOD_SECONDS,
        max_certs: int = MAX_CERTS,
        start_time: int | None = None,
    ) -> None:
        self._sk = signing_key
        self._relay_id = signing_key.public_key().public_bytes_raw()
        self.period_seconds = period_seconds
        self._certs: deque[WitnessCertificate] = deque(maxlen=max_certs)
        self._window = _Window()
        # Sign the genesis certificate up front.
        now = int(time.time()) if start_time is None else int(start_time)
        self._seal(GENESIS_PREV_HASH, now)

    @property
    def relay_id(self) -> bytes:
        return self._relay_id

    # -- recording -----------------------------------------------------------

    def record_envelope(self, envelope: dict[str, object]) -> None:
        """Note that one envelope was routed this period (Merkle leaf + count)."""
        self._window.leaves.append(hashlib.sha256(_envelope_id(envelope)).digest())
        self._window.count += 1

    # -- generation ----------------------------------------------------------

    def _seal(self, previous_hash: bytes, now: int) -> WitnessCertificate:
        """Build, sign, append a certificate for the current window; reset it."""
        cert = WitnessCertificate(
            version=WITNESS_VERSION,
            relay_id=self._relay_id,
            timestamp=now,
            period_seconds=self.period_seconds,
            messages_routed=self._window.count,
            sender_identities_known=0,
            recipient_identities_known=0,
            contents_readable=0,
            conversations_linked=0,
            envelope_merkle_root=merkle_root(self._window.leaves),
            previous_cert_hash=previous_hash,
            statement=build_statement(self._window.count),
        )
        cert.relay_signature = self._sk.sign(cert.signing_payload())
        self._certs.append(cert)
        self._window = _Window()
        return cert

    def generate(self, now: int | None = None) -> WitnessCertificate:
        """Seal the current period into a new certificate chained to the last."""
        ts = int(time.time()) if now is None else int(now)
        return self._seal(self._certs[-1].cert_hash(), ts)

    # -- access --------------------------------------------------------------

    def current(self) -> WitnessCertificate:
        return self._certs[-1]

    def chain(self, limit: int | None = None) -> list[WitnessCertificate]:
        certs = list(self._certs)
        if limit is not None and limit > 0:
            certs = certs[-limit:]
        return certs

    def __len__(self) -> int:
        return len(self._certs)


# ---------------------------------------------------------------------------
# Verification (used by the relay's /witness/verify and by the client CLI)
# ---------------------------------------------------------------------------

def verify_chain_report(
    certs: list[WitnessCertificate],
    *,
    expected_relay_id: bytes | None = None,
    period_seconds: int = PERIOD_SECONDS,
) -> dict[str, object]:
    """Machine-readable verification of a list of certificates (oldest → newest).

    Checks, independently:
      - **signatures_valid** — every certificate's Ed25519 signature verifies
        (and matches ``expected_relay_id`` when given);
      - **chain_intact** — each certificate's ``previous_cert_hash`` equals the
        previous certificate's :meth:`~WitnessCertificate.cert_hash` (no resets,
        no forks);
      - **coverage_complete** — consecutive timestamps advance by ~one period
        (no missing 60-second windows — i.e. the relay never went dark);
      - **blindness_held** — every certificate reports zero knowledge.

    ``ok`` is the conjunction. ``errors`` lists human-readable failures, and
    ``first_break`` / ``gap`` pinpoint the first chain reset / missing window.
    """
    errors: list[str] = []
    report: dict[str, object] = {
        "ok": False,
        "count": len(certs),
        "signatures_valid": False,
        "chain_intact": False,
        "coverage_complete": False,
        "blindness_held": False,
        "rooted_at_genesis": False,
        "relay_id": None,
        "fingerprint": None,
        "current_merkle_root": None,
        "errors": errors,
        "first_break": None,
        "gap": None,
    }

    if not certs:
        errors.append("no certificates to verify")
        return report

    relay_id = certs[-1].relay_id
    report["relay_id"] = relay_pubkey_b58(relay_id)
    report["fingerprint"] = fingerprint(relay_id)
    report["current_merkle_root"] = certs[-1].envelope_merkle_root.hex()

    # Signatures (+ optional pinned identity).
    sigs_ok = True
    for i, cert in enumerate(certs):
        if not cert.verify_signature():
            sigs_ok = False
            errors.append(f"invalid signature on certificate {i}")
        if expected_relay_id is not None and cert.relay_id != expected_relay_id:
            sigs_ok = False
            errors.append(f"certificate {i} signed by an unexpected relay key")
    report["signatures_valid"] = sigs_ok

    # Hash-chain continuity.
    report["rooted_at_genesis"] = certs[0].previous_cert_hash == GENESIS_PREV_HASH
    chain_ok = True
    for i in range(1, len(certs)):
        if certs[i].previous_cert_hash != certs[i - 1].cert_hash():
            chain_ok = False
            report["first_break"] = i
            errors.append(
                f"hash chain break between certificate {i - 1} and {i} "
                "(possible reset or forgery)"
            )
            break
    report["chain_intact"] = chain_ok

    # Period coverage — look for a window the relay failed to witness.
    coverage_ok = True
    for i in range(1, len(certs)):
        delta = certs[i].timestamp - certs[i - 1].timestamp
        if delta > period_seconds * COVERAGE_SLACK:
            coverage_ok = False
            start = certs[i - 1].timestamp + period_seconds
            report["gap"] = {
                "after_index": i - 1,
                "before_index": i,
                "missing_from": start,
                "missing_until": certs[i].timestamp,
            }
            errors.append(
                f"gap detected between certificate {i - 1} and {i} "
                f"(missing window {start} — {certs[i].timestamp})"
            )
            break
    report["coverage_complete"] = coverage_ok

    # Structural blindness claim.
    blind_ok = all(c.blindness_held() for c in certs)
    if not blind_ok:
        errors.append("a certificate reported nonzero knowledge")
    report["blindness_held"] = blind_ok

    report["ok"] = bool(sigs_ok and chain_ok and coverage_ok and blind_ok)
    return report


def verify_chain(certs: list[WitnessCertificate]) -> bool:
    """True iff signatures, hash chain, coverage, and blindness all check out."""
    return bool(verify_chain_report(certs)["ok"])
