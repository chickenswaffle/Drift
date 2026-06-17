"""
drift.crypto.rooms — Sovereign Rooms (Phase 11)

A DRIFT *room* is not a server-side chatroom. There is no row in any database,
no object the relay owns, nothing to subpoena. A room exists purely as
**math**: a shared secret derived from the room name. Anyone who knows the name
can derive the same key material and participate; anyone who does not cannot
find the room, read it, or even prove it exists. The relay sees only a stream
of opaque ciphertext blobs arriving at stealth addresses that rotate every ten
minutes — indistinguishable from ordinary 1:1 traffic.

This reuses the *handle-as-shared-secret* idea from :mod:`drift.crypto.beacon`
(the handle/name IS the password; HKDF stretches it into a key the relay cannot
derive) and takes it further: a whole conversation keyed off a name, with
rotating addresses so the relay cannot even correlate one room's traffic.

No new primitives — everything is HKDF-SHA256, HMAC-SHA256, XChaCha20-Poly1305,
and Ed25519, all already used elsewhere in :mod:`drift.crypto`.

The name IS the password
------------------------
``derive_room_keys("cats")`` and ``derive_room_keys("Cats")`` are **completely
different rooms** with unrelated key material — derivation is case-sensitive and
exact, byte for byte. A short or common room name is a weak room: treat room
names as passwords, not usernames (see DESIGN.md §11).

Key schedule
------------
``room_secret = HKDF(SHA256(room_name), info=b"drift-room-v1", length=64)``

  - ``encrypt_key = room_secret[:32]`` — XChaCha20-Poly1305 key for content
  - ``scan_key    = room_secret[32:]`` — derives the rotating room addresses

Rotating addresses
------------------
A room never uses a fixed relay address (that would let the relay correlate all
of a room's traffic). Instead the address rotates every :data:`WINDOW_SECONDS`
on a deterministic schedule every participant computes independently::

    n = unix_time // WINDOW_SECONDS
    room_addr_n = HKDF(scan_key, info=b"drift-room-addr-" + n.to_bytes(8))

Clients scan the current window plus the previous :data:`CATCHUP_WINDOWS` to
catch up on anything posted while they were away (the relay retains room
envelopes for the same span — see ``relay/server.py`` ``ttl_seconds``).

Security tiers
--------------
- **open**  — anyone who knows the name can read and post. Pure shared secret.
- **invite**— anyone who knows the name can *read*; *posting* requires an
  additional invite token, which derives a separate ``posting_key`` layered on
  top of the room key. A lurker reads; a token-holder posts. Honest clients
  reject a post whose sender tag does not verify under the posting key.
- **dark**  — the name is never typed or stored in plaintext. The room *is* a
  random 64-byte secret, exchanged out of band as a QR code. Undiscoverable by
  anyone who has not scanned it.

Honesty
-------
Rooms are encrypted but **not** forward-secret: anyone who learns the room
secret can decrypt *all* past and future room messages. This is inherent to a
shared-key construction. The sender tag provides *within-session consistency*
(you can tell two messages are from the same sender this session) — it is **not**
an identity and cannot be linked across sessions or to a real person.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass, field
from typing import cast

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from drift.crypto import Identity, b58decode, b58encode, decrypt, encrypt

# --- domain separation (all versioned) ------------------------------------
ROOM_SECRET_INFO = b"drift-room-v1"
ROOM_ADDR_INFO = b"drift-room-addr-"
ROOM_SHARD_INFO = b"drift-room-shard-"
ROOM_POST_INFO = b"drift-room-post-v1"

# --- sizes -----------------------------------------------------------------
ROOM_SECRET_LEN = 64       # encrypt_key(32) ‖ scan_key(32)
POST_SECRET_LEN = 32       # invite-room posting secret (carried by a token)
ADDR_LEN = 32              # rotating room address
EPHEMERAL_LEN = 32         # per-session sender ephemeral (the sender-tag input)
SENDER_TAG_LEN = 32        # HMAC-SHA256 output

# --- rotation schedule -----------------------------------------------------
WINDOW_SECONDS = 600       # the room address rotates every 10 minutes
CATCHUP_WINDOWS = 3        # scan current + previous 3 windows (≈30 min back)

# --- tiers -----------------------------------------------------------------
TIER_OPEN = "open"
TIER_INVITE = "invite"
TIER_DARK = "dark"
TIERS = (TIER_OPEN, TIER_INVITE, TIER_DARK)

# Prefix on the room-descriptor / QR string (what a `dark` room or a sharded
# room is shared as). The decoder rejects anything without it.
QR_PREFIX = "driftroom:"


class RoomError(Exception):
    """Raised on any invalid room operation (bad tier, malformed descriptor…)."""


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

def _hkdf(ikm: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA256 → ``length`` bytes. (No salt — the IKM is already a digest
    or a high-entropy secret.) Same primitive the rest of crypto/ uses."""
    return HKDF(algorithm=SHA256(), length=length, salt=None, info=info).derive(ikm)


def _secret_info(room_version: int) -> bytes:
    """Domain string for the room-secret HKDF. ``v0`` is exactly
    ``b"drift-room-v1"``; a future version suffixes ``-vN`` so old rooms keep
    their key material untouched."""
    if room_version <= 0:
        return ROOM_SECRET_INFO
    return ROOM_SECRET_INFO + f"-v{room_version + 1}".encode()


def derive_room_secret(room_name: str, room_version: int = 0) -> bytes:
    """The 64-byte room secret for ``room_name``.

    ``HKDF(SHA256(room_name), info=b"drift-room-v1", length=64)``. Case- and
    byte-exact: ``"cats"`` and ``"Cats"`` yield unrelated secrets.
    """
    if not room_name:
        raise RoomError("room name cannot be empty")
    ikm = hashlib.sha256(room_name.encode("utf-8")).digest()
    return _hkdf(ikm, _secret_info(room_version), ROOM_SECRET_LEN)


@dataclass(frozen=True)
class RoomKeys:
    """All key material for one room — the cryptographic identity of the room.

    Derived either from a human room name (open/invite) or directly from a
    random 64-byte secret (dark). ``post_secret`` is present only for invite
    rooms where the holder may post.
    """

    room_secret: bytes              # 64 bytes
    tier: str
    post_secret: bytes | None = None

    def __post_init__(self) -> None:
        if len(self.room_secret) != ROOM_SECRET_LEN:
            raise RoomError(f"room secret must be {ROOM_SECRET_LEN} bytes")
        if self.tier not in TIERS:
            raise RoomError(f"unknown room tier {self.tier!r}")
        if self.post_secret is not None and len(self.post_secret) != POST_SECRET_LEN:
            raise RoomError(f"post secret must be {POST_SECRET_LEN} bytes")

    # -- construction -------------------------------------------------------

    @classmethod
    def from_name(
        cls,
        room_name: str,
        *,
        tier: str = TIER_OPEN,
        room_version: int = 0,
        post_secret: bytes | None = None,
    ) -> RoomKeys:
        if tier == TIER_DARK:
            raise RoomError("dark rooms have no name — use RoomKeys.from_secret / generate_dark")
        return cls(derive_room_secret(room_name, room_version), tier, post_secret)

    @classmethod
    def from_secret(
        cls, secret: bytes, *, tier: str = TIER_DARK, post_secret: bytes | None = None
    ) -> RoomKeys:
        return cls(secret, tier, post_secret)

    @classmethod
    def generate_dark(cls) -> RoomKeys:
        """A brand-new dark room: a fresh random 64-byte secret, no name."""
        return cls(os.urandom(ROOM_SECRET_LEN), TIER_DARK)

    # -- derived keys -------------------------------------------------------

    @property
    def encrypt_key(self) -> bytes:
        """XChaCha20-Poly1305 key for message content."""
        return self.room_secret[:32]

    @property
    def scan_key(self) -> bytes:
        """Seed for the rotating room addresses."""
        return self.room_secret[32:]

    @property
    def posting_key(self) -> bytes | None:
        """The invite-room posting key, derived from the invite token's secret,
        or ``None`` if this holder cannot post (a lurker, or a non-invite room)."""
        if self.post_secret is None:
            return None
        return _hkdf(self.post_secret, ROOM_POST_INFO, 32)

    def auth_key(self) -> bytes:
        """The key the sender tag is keyed under.

        Open/dark rooms key the tag under the room secret (everyone with the
        name has it). Invite rooms key it under the posting key, so a valid tag
        *proves the poster holds the invite token*. An invite-room holder with no
        token has no posting key and therefore cannot mint a valid tag.
        """
        if self.tier == TIER_INVITE:
            pk = self.posting_key
            if pk is None:
                raise RoomError("cannot post to an invite room without an invite token")
            return pk
        return self.room_secret

    def can_post(self) -> bool:
        """Whether this holder is able to *produce* an acceptable post."""
        return self.tier != TIER_INVITE or self.post_secret is not None


# ---------------------------------------------------------------------------
# Rotating addresses
# ---------------------------------------------------------------------------

def current_window(now: int | None = None) -> int:
    """The current rotation window index ``unix_time // WINDOW_SECONDS``."""
    return int(now if now is not None else time.time()) // WINDOW_SECONDS


def room_address(scan_key: bytes, window: int) -> bytes:
    """The room's rotating relay address for ``window`` (32 bytes).

    ``HKDF(scan_key, info=b"drift-room-addr-" + window.to_bytes(8))``. Every
    participant computes the same value with no coordination; an outsider
    without ``scan_key`` cannot compute past or future addresses.
    """
    return _hkdf(scan_key, ROOM_ADDR_INFO + window.to_bytes(8, "big"), ADDR_LEN)


def shard_address(scan_key: bytes, shard_index: int, window: int) -> bytes:
    """The address for one *shard* of a federated room (see Part E).

    ``HKDF(scan_key, info=b"drift-room-shard-" + shard_index(4) + window(8))``.
    Distinct from :func:`room_address` and from every other shard, so a relay
    holding one shard sees only a fraction of the room's traffic.
    """
    info = ROOM_SHARD_INFO + shard_index.to_bytes(4, "big") + window.to_bytes(8, "big")
    return _hkdf(scan_key, info, ADDR_LEN)


def scan_windows(now: int | None = None, count: int = CATCHUP_WINDOWS) -> list[int]:
    """Window indices a joining client should scan: current + ``count`` previous.

    Covers the relay's room-message retention span so a client that was away (or
    just opened the room) catches up. Duplicates are harmless — recipients dedupe
    by :attr:`RoomMessage.message_id`.
    """
    cur = current_window(now)
    return [cur - i for i in range(count + 1)]


def current_addresses(keys: RoomKeys, shards: int = 0, now: int | None = None) -> list[bytes]:
    """Every address to *send* to right now: one per shard, or the single
    unsharded address. ``shards <= 1`` means an unsharded room."""
    win = current_window(now)
    if shards and shards > 1:
        return [shard_address(keys.scan_key, i, win) for i in range(shards)]
    return [room_address(keys.scan_key, win)]


def listen_addresses(keys: RoomKeys, shards: int = 0, now: int | None = None) -> list[bytes]:
    """Every address to *subscribe/scan* across the catch-up windows and all
    shards. The set a client must watch to receive the whole room."""
    wins = scan_windows(now)
    addrs: list[bytes] = []
    if shards and shards > 1:
        for i in range(shards):
            addrs += [shard_address(keys.scan_key, i, w) for w in wins]
    else:
        addrs += [room_address(keys.scan_key, w) for w in wins]
    return addrs


# ---------------------------------------------------------------------------
# Sender tags — pseudonymous, within-session consistency (NOT identity)
# ---------------------------------------------------------------------------

def new_ephemeral() -> bytes:
    """A fresh per-session sender ephemeral. Held for the life of a session so
    the sender's tag stays consistent (you can tell their messages apart from
    others'); a new session gets a new ephemeral and thus an unlinkable tag."""
    return os.urandom(EPHEMERAL_LEN)


def sender_tag(auth_key: bytes, ephemeral: bytes) -> bytes:
    """``HMAC-SHA256(auth_key, ephemeral)`` — proof the sender knows the room
    secret (open/dark) or the invite token (invite), bound to a session
    pseudonym. A non-member cannot forge it; two members produce different tags
    (different ephemerals); the *same* member is consistent within a session."""
    return hmac.new(auth_key, ephemeral, hashlib.sha256).digest()


def verify_sender_tag(auth_key: bytes, ephemeral: bytes, tag: bytes) -> bool:
    """Constant-time check that ``tag`` is a valid sender tag for ``ephemeral``."""
    return hmac.compare_digest(sender_tag(auth_key, ephemeral), tag)


def display_tag(tag: bytes) -> str:
    """The short pseudonym shown in the TUI: first 4 hex chars of the tag
    (e.g. ``a3f9``). Consistent per sender per session."""
    return tag.hex()[:4]


# ---------------------------------------------------------------------------
# Messages
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RoomMessage:
    """A decrypted room message (or, before opening, the public routing parts).

    Wire/relay layout of the opaque ``ct`` blob is
    ``ephemeral(32) ‖ sender_tag(32) ‖ ciphertext`` — the relay stores only
    ``{to: room_addr, ct: <blob>}`` and learns nothing else (see
    :func:`pack_envelope`).
    """

    room_addr: bytes        # rotating address it was sent to (public routing)
    sender_tag: bytes       # HMAC(auth_key, ephemeral) — pseudonymous proof
    ephemeral: bytes        # the per-session sender ephemeral
    ciphertext: bytes       # XChaCha20-Poly1305(encrypt_key, inner)
    timestamp: int          # unix seconds (lives *inside* the ciphertext)
    message_id: bytes       # SHA256(ciphertext) — for dedup
    text: str = ""          # decoded plaintext (empty until opened)
    display_name: str | None = None  # verified signed display name, if any
    authorized: bool = True  # invite rooms: did the tag verify under posting_key?

    @property
    def tag_label(self) -> str:
        return display_tag(self.sender_tag)


def seal_room_message(
    keys: RoomKeys,
    text: str,
    *,
    ephemeral: bytes,
    room_addr: bytes,
    now: int | None = None,
    display_name: str | None = None,
    identity: Identity | None = None,
) -> RoomMessage:
    """Build an outgoing room message ready to ship to ``room_addr``.

    The plaintext (timestamp + text, and an optional Ed25519-signed display
    name) is sealed under ``encrypt_key`` with ``ephemeral`` as associated data,
    binding the pseudonym to *this* ciphertext. The sender tag is keyed by the
    tier's auth key (the room secret, or the posting key for invite rooms).
    """
    ts = int(now if now is not None else time.time())
    inner: dict[str, object] = {"ts": ts, "text": text}
    if display_name is not None:
        if identity is None:
            raise RoomError("a signed display name needs an identity to sign with")
        signed = _sign_display_name(identity, display_name, ephemeral)
        inner["name"] = display_name
        inner["name_sig"] = signed["sig"]
        inner["sign_pub"] = signed["sign_pub"]

    plaintext = json.dumps(inner, separators=(",", ":")).encode("utf-8")
    ciphertext = encrypt(keys.encrypt_key, plaintext, associated_data=ephemeral)
    tag = sender_tag(keys.auth_key(), ephemeral)
    return RoomMessage(
        room_addr=room_addr,
        sender_tag=tag,
        ephemeral=ephemeral,
        ciphertext=ciphertext,
        timestamp=ts,
        message_id=hashlib.sha256(ciphertext).digest(),
        text=text,
        display_name=display_name,
    )


def pack_envelope(msg: RoomMessage) -> bytes:
    """The opaque ``ct`` blob the relay stores: ``ephemeral ‖ sender_tag ‖ ct``."""
    return msg.ephemeral + msg.sender_tag + msg.ciphertext


def parse_envelope(blob: bytes) -> tuple[bytes, bytes, bytes] | None:
    """Split a wire blob → ``(ephemeral, sender_tag, ciphertext)`` or ``None``
    if it is too short to be a room envelope."""
    head = EPHEMERAL_LEN + SENDER_TAG_LEN
    if len(blob) <= head:
        return None
    return blob[:EPHEMERAL_LEN], blob[EPHEMERAL_LEN:head], blob[head:]


def open_room_message(keys: RoomKeys, room_addr: bytes, blob: bytes) -> RoomMessage | None:
    """Decrypt and validate an inbound room envelope, or ``None`` if it is not a
    message for this room (wrong key, tampered, malformed).

    Reading needs only ``encrypt_key`` (the room name), so a lurker in an invite
    room can read. The returned message's :attr:`~RoomMessage.authorized` flag
    records whether the sender tag verified under the posting key — for an invite
    room, a holder *with* the token rejects (returns ``None``) an unauthorized
    post; a lurker without the token cannot verify it and surfaces it flagged
    ``authorized=False`` so the UI can mark it.
    """
    parsed = parse_envelope(blob)
    if parsed is None:
        return None
    ephemeral, tag, ciphertext = parsed

    try:
        plaintext = decrypt(keys.encrypt_key, ciphertext, associated_data=ephemeral)
    except (InvalidTag, ValueError):
        return None  # not for this room (or tampered) — indistinguishable, as intended

    try:
        inner = json.loads(plaintext)
        if not isinstance(inner, dict):
            return None
        ts = int(inner["ts"])
        text = str(inner["text"])
    except (KeyError, ValueError, TypeError):
        return None

    # Authorization: open/dark verify under the room secret; invite under the
    # posting key (only possible for a token-holder).
    authorized = True
    if keys.tier == TIER_INVITE:
        pk = keys.posting_key
        if pk is not None:
            if not verify_sender_tag(pk, ephemeral, tag):
                return None  # a member rejects an unauthorized post outright
        else:
            authorized = False  # lurker: cannot verify, surface it flagged
    else:
        if not verify_sender_tag(keys.room_secret, ephemeral, tag):
            return None

    display_name = _verify_display_name(inner, ephemeral)
    return RoomMessage(
        room_addr=room_addr,
        sender_tag=tag,
        ephemeral=ephemeral,
        ciphertext=ciphertext,
        timestamp=ts,
        message_id=hashlib.sha256(ciphertext).digest(),
        text=text,
        display_name=display_name,
        authorized=authorized,
    )


# ---------------------------------------------------------------------------
# Optional signed display names
# ---------------------------------------------------------------------------

def _sign_display_name(identity: Identity, name: str, ephemeral: bytes) -> dict[str, str]:
    """Sign ``name`` bound to this session's ``ephemeral`` so a chosen display
    name cannot be lifted onto another sender's pseudonym."""
    payload = json.dumps(
        {"name": name, "ephemeral": b58encode(ephemeral)},
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    sig = identity.signing_key().sign(payload).signature
    return {"sig": b58encode(sig), "sign_pub": b58encode(identity.verify_key_bytes())}


def _verify_display_name(inner: dict[str, object], ephemeral: bytes) -> str | None:
    """Return the display name iff it carries a valid self-signature bound to
    ``ephemeral``; otherwise ``None`` (an unsigned or forged name is dropped)."""
    if "name" not in inner or "name_sig" not in inner or "sign_pub" not in inner:
        return None
    try:
        name = str(inner["name"])
        payload = json.dumps(
            {"name": name, "ephemeral": b58encode(ephemeral)},
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
        VerifyKey(b58decode(str(inner["sign_pub"]))).verify(
            payload, b58decode(str(inner["name_sig"]))
        )
    except (BadSignatureError, ValueError, TypeError):
        return None
    return name


# ---------------------------------------------------------------------------
# Invite tokens
# ---------------------------------------------------------------------------

def generate_post_secret() -> bytes:
    """A fresh invite-room posting secret (created once, at room creation)."""
    return os.urandom(POST_SECRET_LEN)


def encode_invite_token(post_secret: bytes) -> str:
    """A shareable invite token carrying the posting secret (base58).

    Note (honest): the relay is blind, so it cannot enforce *one-use* tokens —
    every token for a room conveys the same posting capability. ``drift room
    invite`` mints a token bearer per call for distribution convenience, but
    cryptographically they are equivalent. Revoking posting means rotating the
    room to a new posting secret.
    """
    if len(post_secret) != POST_SECRET_LEN:
        raise RoomError(f"post secret must be {POST_SECRET_LEN} bytes")
    return b58encode(post_secret)


def decode_invite_token(token: str) -> bytes:
    """Recover the posting secret from an invite token. Raises on garbage."""
    try:
        secret = b58decode(token.strip())
    except (ValueError, AttributeError) as exc:
        raise RoomError("invalid invite token") from exc
    if len(secret) != POST_SECRET_LEN:
        raise RoomError("invalid invite token")
    return secret


# ---------------------------------------------------------------------------
# Room descriptor / persisted record / QR
# ---------------------------------------------------------------------------

@dataclass
class Room:
    """A locally-stored room the user has joined or created.

    ``label`` and the activity counters are local only (never synced). For
    open/invite rooms the keys derive from ``name``; for dark rooms ``name`` is
    ``None`` and the keys live in ``secret_b58`` (the thing the QR carries).
    ``post_secret_b58`` is set when this holder may post to an invite room.
    ``shards`` is the federation relay list for a sharded room (empty = single
    relay).
    """

    label: str
    tier: str
    name: str | None = None
    secret_b58: str | None = None
    post_secret_b58: str | None = None
    shards: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    last_window: int = 0
    message_count: int = 0

    def __post_init__(self) -> None:
        if self.tier not in TIERS:
            raise RoomError(f"unknown room tier {self.tier!r}")
        if self.tier == TIER_DARK and not self.secret_b58:
            raise RoomError("a dark room needs a stored secret")
        if self.tier != TIER_DARK and not self.name:
            raise RoomError("an open/invite room needs a name")

    @property
    def shard_count(self) -> int:
        return len(self.shards)

    def keys(self) -> RoomKeys:
        """Derive this room's live key material."""
        post = b58decode(self.post_secret_b58) if self.post_secret_b58 else None
        if self.tier == TIER_DARK:
            return RoomKeys.from_secret(b58decode(self.secret_b58 or ""), tier=TIER_DARK)
        if self.secret_b58:  # a named room may still cache its secret
            return RoomKeys.from_secret(
                b58decode(self.secret_b58), tier=self.tier, post_secret=post)
        return RoomKeys.from_name(self.name or "", tier=self.tier, post_secret=post)

    # -- storage serialization ---------------------------------------------

    def to_dict(self) -> dict[str, object]:
        return {
            "label": self.label,
            "tier": self.tier,
            "name": self.name,
            "secret_b58": self.secret_b58,
            "post_secret_b58": self.post_secret_b58,
            "shards": list(self.shards),
            "created_at": self.created_at,
            "last_window": self.last_window,
            "message_count": self.message_count,
        }

    @classmethod
    def from_dict(cls, d: dict[str, object]) -> Room:
        shards_raw = cast("list[object]", d.get("shards") or [])
        return cls(
            label=str(d["label"]),
            tier=str(d["tier"]),
            name=(str(d["name"]) if d.get("name") is not None else None),
            secret_b58=(str(d["secret_b58"]) if d.get("secret_b58") else None),
            post_secret_b58=(str(d["post_secret_b58"]) if d.get("post_secret_b58") else None),
            shards=[str(s) for s in shards_raw],
            created_at=float(cast("float", d.get("created_at", 0.0))),
            last_window=int(cast("int", d.get("last_window", 0))),
            message_count=int(cast("int", d.get("message_count", 0))),
        )

    # -- QR / descriptor (the joinable secret, NOT the local label/activity) --

    def to_qr(self) -> str:
        """A ``driftroom:`` descriptor that lets a scanner join this exact room.

        Carries the tier, the shard list, and the *secret* — for a dark room the
        random secret (the only way in), for a named room the name. The invite
        posting secret is included so a QR can hand out posting rights too. The
        local label and activity counters are *not* included.
        """
        body: dict[str, object] = {"v": 1, "tier": self.tier, "shards": list(self.shards)}
        if self.tier == TIER_DARK:
            body["secret"] = self.secret_b58
        else:
            body["name"] = self.name
        if self.post_secret_b58:
            body["post"] = self.post_secret_b58
        raw = json.dumps(body, separators=(",", ":")).encode("utf-8")
        return QR_PREFIX + b58encode(raw)

    @classmethod
    def from_qr(cls, text: str, *, label: str | None = None) -> Room:
        """Parse a ``driftroom:`` descriptor into a joinable :class:`Room`."""
        text = text.strip()
        if not text.startswith(QR_PREFIX):
            raise RoomError("not a DRIFT room code (must start with 'driftroom:')")
        try:
            body = json.loads(b58decode(text[len(QR_PREFIX):]).decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise RoomError(f"malformed room code: {exc}") from exc
        if not isinstance(body, dict):
            raise RoomError("malformed room code")
        tier = str(body.get("tier", ""))
        if tier not in TIERS:
            raise RoomError(f"unknown room tier {tier!r}")
        shards = [str(s) for s in (body.get("shards") or [])]
        post = str(body["post"]) if body.get("post") else None
        if tier == TIER_DARK:
            secret = str(body.get("secret") or "")
            if not secret:
                raise RoomError("dark room code is missing its secret")
            return cls(
                label=label or _auto_dark_label(secret), tier=TIER_DARK,
                secret_b58=secret, post_secret_b58=post, shards=shards,
            )
        name = str(body.get("name") or "")
        if not name:
            raise RoomError("room code is missing its name")
        return cls(label=label or name, tier=tier, name=name, post_secret_b58=post, shards=shards)


def make_room(
    name: str | None,
    *,
    tier: str = TIER_OPEN,
    label: str | None = None,
    shards: list[str] | None = None,
) -> Room:
    """Construct a new :class:`Room`, generating any secrets the tier needs.

    - open  → keyed by ``name``.
    - invite→ keyed by ``name`` plus a freshly generated posting secret (the
              creator can post and can mint invite tokens).
    - dark  → ``name`` is ignored; a random 64-byte secret is generated and the
              room is shared only via :meth:`Room.to_qr`.
    """
    if tier not in TIERS:
        raise RoomError(f"unknown room tier {tier!r}")
    shards = shards or []
    if tier == TIER_DARK:
        keys = RoomKeys.generate_dark()
        secret_b58 = b58encode(keys.room_secret)
        return Room(
            label=label or _auto_dark_label(secret_b58), tier=TIER_DARK,
            secret_b58=secret_b58, shards=shards,
        )
    if not name:
        raise RoomError("an open/invite room needs a name")
    post_b58 = None
    if tier == TIER_INVITE:
        post_b58 = b58encode(generate_post_secret())
    return Room(label=label or name, tier=tier, name=name, post_secret_b58=post_b58, shards=shards)


def _auto_dark_label(secret_b58: str) -> str:
    """A stable, non-revealing local label for a dark room (no name to show)."""
    short = hashlib.sha256(secret_b58.encode()).hexdigest()[:6]
    return f"dark room {short}"
