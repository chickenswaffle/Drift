"""
drift.transport.session — authenticated session layer

Composes crypto + transport across all three layers:

  Phase 1 — stealth addresses provide unlinkable routing and recipient
            detection: every message is broadcast to a one-time address that
            only the recipient (scanning with their scan key) can recognise.
  Phase 2 — the Double Ratchet provides the *content* key for each message,
            giving per-message forward secrecy and post-compromise security.

So a sent message now carries three things in its envelope:
  - a fresh stealth one-time address + ephemeral key   (who/where — Phase 1)
  - a Double Ratchet header                            (key schedule — Phase 2)
  - the ratchet-encrypted ciphertext                   (the content)

Ratchet bootstrap — X3DH (audit H3)
-----------------------------------
The ratchet needs a shared root secret and an initial responder ratchet key.
Both peers publish a **prekey bundle** to the relay ahead of time (a signed
prekey + a batch of one-time prekeys — see ``drift.crypto.x3dh``). Whoever sends
first fetches the peer's bundle, runs X3DH, and promotes itself to initiator with
``init_sender`` keyed on the peer's *signed prekey*; the X3DH header rides sealed
inside the opening-chain envelopes so the responder derives the same master
secret and bootstraps with ``init_receiver``. The one-time prekey is consumed and
deleted after a single use, so a later compromise of the recipient's long-term
spend key cannot decrypt a past opening burst — closing the H3 residual.

Every key after the first DH ratchet step is freshly random regardless of how the
session was bootstrapped (see ratchet.py).

Legacy fallback
---------------
If the peer published no bundle (an old client, or it expired), the sender falls
back to the previous **deterministic** bootstrap — ``root = HKDF(ECDH(my_spend,
their_spend))`` with a deterministic responder keypair, plus a fresh discarded
forward-secrecy ephemeral folded in (the earlier, sender-side-only H3 fix). The
UI surfaces a one-time amber warning when this happens. Whoever speaks first is
still the initiator either way; lazy promotion ties the ratchet role to who
actually opens the chat.

Known limitation: if both peers send their very first message before either has
fetched the other's bundle (and the bundles aren't yet published), they may each
promote independently and the two ratchets not line up — the mismatched message
surfaces as ``InvalidTag`` (a clean reject, never silent corruption). The common
one-sided open works correctly.
"""

from __future__ import annotations

import asyncio
import base64
import logging
from collections.abc import AsyncGenerator, Callable, Coroutine
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from drift.crypto import Identity, Keypair, b58encode, derive_message_key, groups
from drift.crypto.burn import generate_burn_token, verify_burn_token
from drift.crypto.fmd import FMDKeypair, fmd_flag
from drift.crypto.groups import ContactInfo, GroupState, MembershipChange
from drift.crypto.ratchet import (
    FS_BOOTSTRAP_INFO,
    Header,
    RatchetError,
    init_receiver,
    init_sender,
    ratchet_decrypt,
    ratchet_encrypt,
)
from drift.crypto.sealed import open_header as open_sender_header
from drift.crypto.sealed import parse as parse_sender
from drift.crypto.sealed import seal as seal_sender
from drift.crypto.stealth import derive_one_time_address, scan_for_message
from drift.crypto.x3dh import (
    ONE_TIME_LOW_WATERMARK,
    PreKeyBundle,
    PreKeyPrivates,
    X3DHError,
    X3DHHeader,
    derive_master_secret_recv,
    replenish_one_time,
    verify_prekey_bundle,
    x3dh_send,
)
from drift.transport.client import BurnFrame, Envelope, RelayClient, RelayError
from drift.transport.tor import TorClient

logger = logging.getLogger("drift.transport.session")

# Shared firehose channel every stealth client subscribes to. The relay
# fans every envelope out to all subscribers; clients scan locally.
STEALTH_CHANNEL = "drift-stealth-v1"

# Callback invoked when a verified burn tombstone arrives from the relay.
# Args: (scope, message_id) — scope is "message" or "conversation";
# message_id is the base64 one-time address for message-scope burns, else None.
BurnHook = Callable[[str, str | None], None]


def _keypair_from_private(private_bytes: bytes) -> Keypair:
    """Reconstruct an X25519 Keypair from raw private key bytes."""
    priv = X25519PrivateKey.from_private_bytes(private_bytes)
    return Keypair(private_key=priv, public_key=priv.public_key())


# Inner sealed-payload framing. The bytes sealed under the per-message stealth
# key are normally just the 40-byte ratchet header. On the initiator's *bootstrap*
# sending chain — every message it sends before the peer's first reply — they are
# prefixed with handshake material so a reordered bootstrap message still carries
# what the responder needs. A one-byte flag distinguishes three layouts:
#
#   0  header only                         (post-bootstrap, the steady state)
#   1  FS ephemeral pub (32) || header     (legacy deterministic bootstrap, H3)
#   2  X3DH header (73) || header          (X3DH bootstrap — the new default)
#
# Flag 1 is the legacy fallback kept for peers that published no prekey bundle;
# flag 2 carries the X3DH handshake header (drift.crypto.x3dh.X3DHHeader) so the
# responder can derive the same master secret without an extra round trip.
_FS_FLAG_ABSENT = 0
_FS_FLAG_PRESENT = 1
_FS_FLAG_X3DH = 2
_FS_PUB_LEN = 32
# len(X3DHHeader.to_bytes()) = ik_a(32) + ek_a(32) + spk_id(4) + flag(1) + otpk_id(4)
_X3DH_HEADER_LEN = 2 * 32 + 4 + 1 + 4


def _pack_inner(
    header_bytes: bytes,
    *,
    fs_pub: bytes | None = None,
    x3dh_header: bytes | None = None,
) -> bytes:
    """Frame the ratchet header (+ optional bootstrap handshake material)."""
    if x3dh_header is not None:
        return bytes([_FS_FLAG_X3DH]) + x3dh_header + header_bytes
    if fs_pub is not None:
        return bytes([_FS_FLAG_PRESENT]) + fs_pub + header_bytes
    return bytes([_FS_FLAG_ABSENT]) + header_bytes


def _unpack_inner(blob: bytes) -> tuple[bytes | None, bytes | None, bytes]:
    """Split a sealed inner payload into ``(x3dh_header, fs_pub, ratchet_header)``.

    Exactly one of ``x3dh_header`` / ``fs_pub`` is non-None on a bootstrap-chain
    message; both are None in the steady state. Raises ``ValueError`` on a
    malformed frame — the caller (which has already unsealed under the stealth
    key) treats that as a non-well-formed message and skips it, so a forged but
    correctly-sealed blob can't crash the receive loop.
    """
    if not blob:
        raise ValueError("empty sealed inner payload")
    flag = blob[0]
    if flag == _FS_FLAG_X3DH:
        if len(blob) < 1 + _X3DH_HEADER_LEN:
            raise ValueError("sealed inner payload too short for X3DH header")
        return blob[1:1 + _X3DH_HEADER_LEN], None, blob[1 + _X3DH_HEADER_LEN:]
    if flag == _FS_FLAG_PRESENT:
        if len(blob) < 1 + _FS_PUB_LEN:
            raise ValueError("sealed inner payload too short for FS ephemeral")
        return None, blob[1:1 + _FS_PUB_LEN], blob[1 + _FS_PUB_LEN:]
    if flag != _FS_FLAG_ABSENT:
        raise ValueError(f"unknown sealed inner-payload flag {flag}")
    return None, None, blob[1:]


def _addr_digest(addr: bytes) -> str:
    """Short, non-secret display digest of a one-time address (already public)."""
    return f"{addr[:2].hex()}···{addr[-2:].hex()}"


# Observable, non-secret transport events for the UI ticker. These report
# operations the session already performs (no crypto behaviour changes); the
# only data exposed is the one-time address — which is public on the wire.
EventHook = Callable[[str, str], None]
# Called with the updated prekey privates after a mid-session replenishment, so
# the owner (CLI/TUI) can persist the new one-time prekey privates to the vault.
# None → keep them in-memory only (sufficient for the live session).
PreKeysHook = Callable[["PreKeyPrivates"], None]


class PairwiseRatchet:
    """
    The per-peer crypto of one conversation, decoupled from the relay socket.

    It owns a single Double Ratchet plus the deterministic bootstrap material
    (root secret + responder keypair, derived from the static spend keys) and
    the peer's public keys. It turns a plaintext into a sealed, stealth-addressed
    envelope body (:meth:`encrypt`) and a ratchet ciphertext back into plaintext
    (:meth:`decrypt_ratchet` / :meth:`attempt_ratchet`).

    :class:`Session` composes exactly one of these (its single peer);
    :class:`GroupSession` composes one per other member. All the subtle
    sealed-sender + forward-secrecy *bootstrap* logic (audit H3) therefore lives
    in exactly one place. Scanning the firehose for messages addressed to *us* is
    identity-level (the same for every peer) and stays with the owner — see
    :func:`_scan_and_unseal`.
    """

    def __init__(
        self,
        identity: Identity,
        contact_code: str,
        prekey_privates: PreKeyPrivates | None = None,
    ) -> None:
        self._identity = identity
        # Our own prekey privates (X3DH, audit H3) — used on the *responder* side
        # to complete an incoming handshake. None for group channels, which never
        # take the X3DH path (group senders publish no bundle).
        self._prekey_privates = prekey_privates
        self._their_scan_pub, self._their_spend_pub = Identity.parse_contact_code(
            contact_code
        )
        # Recipient's FMD detection public sub-keys, if they published any (the
        # optional 3rd contact-code segment). None → we never attach a flag, so
        # FMD-off behaviour is byte-for-byte unchanged (audit M4).
        self._fmd_pub = Identity.parse_fmd_pubs(contact_code)
        static_ecdh = identity.spend_keypair.ecdh(self._their_spend_pub)
        # Legacy deterministic bootstrap material, kept as the *fallback* for a
        # peer who has published no prekey bundle (old client / bundle expired).
        # Both peers reconstruct identical material from the static keys, so
        # whoever speaks first can promote itself to initiator on demand.
        self._root_secret = derive_message_key(static_ecdh, info=b"drift-ratchet-v1-root")
        self._responder_keypair = _keypair_from_private(
            derive_message_key(static_ecdh, info=b"drift-ratchet-v1-responder")
        )
        # Raw ECDH output, base material for burn tokens (domain-separated by the
        # burn module's own HKDF). Kept so the owner can issue burns.
        self._burn_shared = static_ecdh
        # --- X3DH initiator state ----------------------------------------
        # The peer's fetched prekey bundle (set by the session before first send);
        # ``_peer_bundle_fetched`` records that the one-shot fetch has happened, so
        # a 404 (→ legacy fallback) isn't retried every message.
        self._peer_bundle: PreKeyBundle | None = None
        self._peer_bundle_fetched = False
        # The X3DH handshake header to attach to every bootstrap-chain message
        # (set on X3DH promotion); the analogue of ``_fs_send_pub`` for the legacy
        # path. Exactly one of the two is set, depending on which bootstrap ran.
        self._x3dh_send_header: X3DHHeader | None = None
        self._fs_send_pub: bytes | None = None
        # The peer ratchet key our bootstrap chain points at — the responder's
        # signed prekey under X3DH, or the deterministic responder key under
        # legacy. Used to tell whether we're still on the bootstrap chain.
        self._bootstrap_their_pub: bytes | None = None
        self._ratchet = init_receiver(self._root_secret, self._responder_keypair)
        self._last_sent_addr: bytes | None = None
        # Set True by the latest x3dh_bootstrap_decrypt when it burns one of our
        # one-time prekeys, so the owning Session can top up the relay-side pool.
        self._otpk_just_consumed = False

    @property
    def burn_shared(self) -> bytes:
        return self._burn_shared

    @property
    def last_sent_addr(self) -> bytes | None:
        return self._last_sent_addr

    @property
    def send_count(self) -> int:
        return self._ratchet.send_count

    @property
    def recv_count(self) -> int:
        return self._ratchet.recv_count

    @property
    def their_scan_b58(self) -> str:
        """The peer's base58 scan key — the relay's prekey index for this peer."""
        return b58encode(self._their_scan_pub)

    def is_bootstrapped(self) -> bool:
        """True once we have a sending chain (we promoted) — used to gate the
        one-shot peer-bundle fetch."""
        return self._ratchet.sending_chain_key is not None

    def needs_peer_bundle(self) -> bool:
        """True before our first send and before the one-shot bundle fetch — the
        session should fetch the peer's bundle and call :meth:`set_peer_bundle`."""
        return not self._peer_bundle_fetched and not self.is_bootstrapped()

    def set_peer_bundle(self, bundle: PreKeyBundle | None) -> None:
        """Record the peer's prekey bundle (or ``None`` → legacy fallback). The
        session fetches it once before the first send."""
        self._peer_bundle = bundle
        self._peer_bundle_fetched = True

    def used_legacy_bootstrap(self) -> bool:
        """True when we promoted via the legacy deterministic bootstrap (the peer
        had no prekey bundle) — the session surfaces a one-time warning."""
        return self.is_bootstrapped() and self._x3dh_send_header is None

    def _promote_to_initiator(self) -> None:
        """Promote receiver → initiator on first send. Prefers X3DH when the peer
        published a (verified) prekey bundle, closing the H3 recipient-side
        residual; otherwise falls back to the legacy deterministic bootstrap with a
        fresh, immediately-discarded forward-secrecy ephemeral (H3 sender side)."""
        if self._peer_bundle is not None and verify_prekey_bundle(self._peer_bundle):
            result, header = x3dh_send(self._identity, self._peer_bundle)
            # The responder's signed prekey is its initial DH ratchet key.
            self._bootstrap_their_pub = self._peer_bundle.signed_prekey
            self._x3dh_send_header = header
            self._ratchet = init_sender(result.master_secret, self._bootstrap_their_pub)
            # result/EK_A private already discarded inside x3dh_send.
            return
        # Legacy fallback: deterministic root + a discarded FS ephemeral (H3).
        fs_ephemeral = Keypair.generate()
        fs_secret = fs_ephemeral.ecdh(self._their_spend_pub)
        fs_root = derive_message_key(
            fs_secret, salt=self._root_secret, info=FS_BOOTSTRAP_INFO
        )
        self._fs_send_pub = fs_ephemeral.public_bytes()
        self._bootstrap_their_pub = self._responder_keypair.public_bytes()
        self._ratchet = init_sender(fs_root, self._bootstrap_their_pub)
        # fs_ephemeral (private) and fs_secret fall out of scope and are never kept.

    def encrypt(self, plaintext: bytes) -> tuple[bytes, bytes, bytes | None]:
        """Ratchet-encrypt + seal + stealth-address ``plaintext`` for this peer.

        Returns ``(one_time_addr, sealed_blob, fmd_flag)`` ready to drop into an
        Envelope. ``fmd_flag`` is a detection flag bound to ``one_time_addr`` when
        the recipient published an FMD key, else ``None`` (no overhead).
        """
        if self._ratchet.sending_chain_key is None:
            self._promote_to_initiator()
        header, ciphertext = ratchet_encrypt(self._ratchet, plaintext)
        # While our ratchet still points at the bootstrap peer key, carry the
        # handshake material so a reordered opening message still bootstraps the
        # responder: the X3DH header (preferred) or the legacy FS ephemeral.
        on_bootstrap_chain = self._ratchet.their_ratchet_pub == self._bootstrap_their_pub
        x3dh_bytes = (
            self._x3dh_send_header.to_bytes()
            if on_bootstrap_chain and self._x3dh_send_header is not None
            else None
        )
        fs_pub = (
            self._fs_send_pub
            if on_bootstrap_chain and self._x3dh_send_header is None
            else None
        )
        inner = _pack_inner(header.to_bytes(), fs_pub=fs_pub, x3dh_header=x3dh_bytes)
        ephemeral = Keypair.generate()
        one_time_addr, stealth_key = derive_one_time_address(
            ephemeral.private_bytes(), self._their_scan_pub, self._their_spend_pub
        )
        sealed_blob = seal_sender(
            stealth_key, ephemeral.public_bytes(), inner, ciphertext, address=one_time_addr
        )
        self._last_sent_addr = one_time_addr
        # FMD (audit M4): bind the detection flag to the (public) one-time address
        # so the relay can test it with the same message. Only when the recipient
        # advertised a detection key.
        flag = fmd_flag(one_time_addr, self._fmd_pub) if self._fmd_pub else None
        return one_time_addr, sealed_blob, flag

    def x3dh_bootstrap_decrypt(
        self, x3dh_header: X3DHHeader, header: Header, ratchet_ct: bytes
    ) -> bytes:
        """Responder side of the X3DH handshake (audit H3).

        If we are already bootstrapped (a later bootstrap-chain message, or one
        reordered after another already established the session), the X3DH header
        is redundant — decrypt normally.

        Otherwise complete the handshake **transactionally**: derive the master
        secret, build a *trial* receiver keyed on our signed prekey, and only on a
        successful (authenticated) decrypt commit it and consume the one-time
        prekey. A forged bootstrap therefore can neither burn an OTPK nor disturb
        our state — the same H1 guarantee ``ratchet_decrypt`` already provides.
        ``InvalidTag`` (genuine tamper of a message addressed to us) propagates.
        """
        self._otpk_just_consumed = False
        if self._prekey_privates is None:
            raise RatchetError("no prekey privates — cannot complete X3DH handshake")
        if self._ratchet.their_ratchet_pub is not None:
            return ratchet_decrypt(self._ratchet, header, ratchet_ct)
        master = derive_master_secret_recv(
            self._identity, self._prekey_privates, x3dh_header
        )
        signed_prekey = self._prekey_privates.signed_prekey_private(
            x3dh_header.signed_prekey_id
        )
        trial = init_receiver(master, signed_prekey)
        plaintext = ratchet_decrypt(trial, header, ratchet_ct)  # raises on forgery
        # Authenticated → commit the bootstrapped ratchet and burn the OTPK.
        self._ratchet = trial
        if x3dh_header.one_time_prekey_id is not None:
            self._prekey_privates.consume(x3dh_header.one_time_prekey_id)
            self._otpk_just_consumed = True
        return plaintext

    @property
    def otpk_just_consumed(self) -> bool:
        """True if the most recent :meth:`x3dh_bootstrap_decrypt` burned a
        one-time prekey — the signal the Session uses to replenish the relay."""
        return self._otpk_just_consumed

    def decrypt_ratchet(
        self, header: Header, ratchet_ct: bytes, root_mix: bytes | None
    ) -> bytes:
        """Ratchet-decrypt an already-unsealed message. ``InvalidTag`` propagates
        (genuine tamper) — used by the 1:1 path where the peer is unambiguous."""
        return ratchet_decrypt(self._ratchet, header, ratchet_ct, root_mix=root_mix)

    def attempt_ratchet(
        self, header: Header, ratchet_ct: bytes, root_mix: bytes | None
    ) -> bytes | None:
        """Trial ratchet-decrypt for group fan-in: return ``None`` instead of
        raising when this peer's ratchet can't authenticate the message.

        Safe to try against every member: :func:`ratchet_decrypt` runs on a
        snapshot and rolls back on failure, so a wrong-peer attempt leaves this
        ratchet byte-for-byte unchanged. A failure here means "not from this
        member" (expected fan-in disambiguation), **not** tamper — tamper of a
        message genuinely addressed to us is still caught loudly at the
        identity-level unseal in :func:`_scan_and_unseal`.
        """
        try:
            return ratchet_decrypt(self._ratchet, header, ratchet_ct, root_mix=root_mix)
        except (InvalidTag, RatchetError):
            return None


def _scan_and_unseal(
    envelope: Envelope, my_scan_priv: bytes, my_spend_pub: bytes
) -> tuple[X3DHHeader | None, bytes | None, Header, bytes] | None:
    """
    Identity-level receive parsing shared by Session and GroupSession.

    Returns ``(x3dh_header, fs_pub, header, ratchet_ct)`` when ``envelope`` is a
    well-formed stealth message addressed to *us*, else ``None`` (not ours /
    malformed). At most one of ``x3dh_header`` / ``fs_pub`` is set, on a
    bootstrap-chain message (X3DH vs legacy); both are None in the steady state.

    A scan match means the message really is addressed to us (the stealth address
    is bound to our scan + spend keys), so unsealing its header authenticates it:
    a failure there is genuine tamper and ``InvalidTag`` is allowed to propagate
    (project iron rule). Only the per-member *ratchet* trial in
    :meth:`PairwiseRatchet.attempt_ratchet` swallows ``InvalidTag``, and only
    because there a failure means "from a different member".
    """
    if envelope.one_time_addr is None:
        return None
    try:
        ephemeral_pub, sealed_header, ratchet_ct = parse_sender(envelope.ciphertext)
    except ValueError:
        return None
    stealth_key = scan_for_message(
        ephemeral_pub, envelope.one_time_addr, my_scan_priv, my_spend_pub
    )
    if stealth_key is None:
        return None
    inner_bytes = open_sender_header(
        stealth_key, sealed_header, address=envelope.one_time_addr
    )
    try:
        x3dh_bytes, fs_pub, header_bytes = _unpack_inner(inner_bytes)
        x3dh_header = X3DHHeader.from_bytes(x3dh_bytes) if x3dh_bytes is not None else None
        header = Header.from_bytes(header_bytes)
    except (ValueError, X3DHError):
        return None  # malformed inner payload — skip (forged or corrupt)
    return x3dh_header, fs_pub, header, ratchet_ct


class Session:
    """
    An encrypted conversation channel: stealth-addressed delivery (Phase 1)
    with Double Ratchet content encryption (Phase 2).

    Usage::

        async with Session(my_identity, their_contact_code, relay_url) as s:
            await s.send("hello")
            async for msg in s.messages():
                print(msg)

    Either peer may send the first message: whoever speaks first becomes the
    ratchet initiator (see the module docstring's "Who sends first" section).
    """

    def __init__(
        self,
        identity: Identity,
        contact_code: str,
        relay_url: str,
        *,
        ping_interval: float = 30.0,
        on_event: EventHook | None = None,
        on_burn: BurnHook | None = None,
        tor_client: TorClient | None = None,
        fmd_key: FMDKeypair | None = None,
        prekeys: PreKeyPrivates | None = None,
        on_prekeys_changed: PreKeysHook | None = None,
    ) -> None:
        # Optional sink for observable (non-secret) transport events; the UI
        # passes a callback that re-emits them as typed messages. Never carries
        # plaintext or key material.
        self._on_event = on_event
        # Optional callback for verified burn tombstones from the relay.
        self._on_burn = on_burn
        # Optional persistence hook for prekey privates created during a
        # mid-session replenishment (see ``_maybe_replenish_prekeys``).
        self._on_prekeys_changed = on_prekeys_changed
        self._identity = identity
        # Phase 3: when a Tor circuit is supplied the session stays oblivious to
        # it — it only forwards the SOCKS5 endpoint to the transport, which dials
        # through it. The E2E crypto above is unchanged: Tor carries ciphertext
        # only. We keep the handle purely to report the circuit to the UI.
        self._tor_client = tor_client

        # Our own keys — used to scan the firehose for messages addressed *to*
        # us (identity-level: the same regardless of which peer sent them).
        self._my_scan_priv = identity.scan_keypair.private_bytes()
        self._my_spend_pub = identity.spend_keypair.public_bytes()
        # Our spend private key, needed to recover a peer's bootstrap
        # forward-secrecy ephemeral secret on receipt (audit H3).
        self._my_spend_priv = identity.spend_keypair.private_bytes()

        # X3DH prekeys (audit H3): the private halves of our published bundle,
        # used to complete an incoming handshake on the *responder* side. The CLI
        # passes a persisted (vault-sealed) store via ``storage.ensure_prekeys``;
        # if none is supplied we generate a fresh session-scoped bundle and publish
        # it on connect. ``_prekey_bundle_published`` gates the one-shot publish.
        if prekeys is None:
            from drift.crypto.x3dh import generate_prekey_bundle
            _, prekeys = generate_prekey_bundle(identity)
        self._prekeys = prekeys
        self._prekey_bundle_published = False
        # Mid-session relay-side OTPK replenishment: ``_replenishing`` is a
        # single-flight guard (a burst of consumed OTPKs must not fire a storm of
        # overlapping top-ups), and ``_bg_tasks`` keeps the fire-and-forget tasks
        # referenced so the loop can't GC them mid-flight and we can cancel them
        # on close.
        self._replenishing = False
        self._bg_tasks: set[asyncio.Task[None]] = set()

        # All per-peer crypto — the Double Ratchet, its bootstrap material (X3DH
        # plus the legacy deterministic fallback), the peer's public keys and the
        # sealed-sender framing — lives in one PairwiseRatchet (shared, identical
        # code, with GroupSession).
        self._channel = PairwiseRatchet(identity, contact_code, prekeys)
        # Fires once if we fall back to the legacy bootstrap (peer had no bundle).
        self._legacy_warned = False

        # The ratchet state is mutated on every send and receive; serialize
        # access so concurrent send/receive tasks can't interleave a mutation.
        self._lock = asyncio.Lock()

        # One-time addresses of messages we've already accepted. The relay
        # replays recent traffic to late-joining / reconnecting sockets, so the
        # same envelope can arrive twice; each genuine message has a unique
        # one-time address, so a repeat means a duplicate. We drop it before it
        # reaches the ratchet — a replayed, already-consumed message would
        # otherwise advance past its key and surface as a spurious InvalidTag.
        self._seen_addrs: set[bytes] = set()

        # Subscribe to the shared firehose; the relay routes by this key only.
        # When Tor is active, hand the transport the SOCKS5 endpoint so every
        # byte is proxied through the circuit.
        socks_proxy = tor_client.socks_proxy if tor_client is not None else None
        # FMD opt-in (audit M4): hand the relay our detection sub-keys so it
        # pre-filters the firehose to us. None → scan everything (unchanged).
        fmd_secret_keys = fmd_key.secret_keys if fmd_key and fmd_key.secret_keys else None
        self._client = RelayClient(
            relay_url,
            STEALTH_CHANNEL,
            ping_interval=ping_interval,
            socks_proxy=socks_proxy,
            fmd_secret_keys=fmd_secret_keys,
        )

    def _emit(self, kind: str, detail: str = "") -> None:
        """Report a non-secret transport event to the optional hook."""
        if self._on_event is not None:
            self._on_event(kind, detail)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        logger.debug("connect: subscribing to firehose %s", STEALTH_CHANNEL)
        await self._client.connect()
        logger.debug("connect: subscribed")
        if self._tor_client is not None:
            # Circuit is carrying our traffic now — let the UI light up the
            # TOR indicators. Detail is the (public, non-secret) hop count.
            self._emit("tor", str(self._tor_client.num_hops))
        # Phase 4: report the federated reach (relay + discovered peers) and
        # whether we're routed through a Tor onion node, for the UI indicators.
        self._emit("nodes", str(self._client.node_count))
        if self._client.is_onion:
            self._emit("onion", "1")
        # X3DH (audit H3): publish our prekey bundle so peers can open a
        # forward-secret session with us asynchronously. Best-effort — a relay
        # that rejects it just means peers fall back to the legacy bootstrap.
        await self._publish_prekeys()
        # If the relay already shows our pool drained below the watermark (peers
        # consumed OTPKs while we were offline, or our persisted batch was low),
        # top it up now — in the background so connect() stays fast.
        self._spawn_bg(self._maybe_replenish_prekeys())

    async def _publish_prekeys(self) -> None:
        """Publish our public prekey bundle to the relay (best-effort, once)."""
        if self._prekey_bundle_published:
            return
        try:
            await self._client.publish_prekey_bundle(
                self._identity.scan_keypair.public_b58(),
                self._prekeys.publish_payload(self._identity),
            )
            self._prekey_bundle_published = True
            self._emit("prekeys", f"bundle published · {self._prekeys.one_time_count()} OTPKs")
        except RelayError as exc:
            logger.debug("prekey publish failed (non-fatal): %s", exc)

    def _spawn_bg(self, coro: Coroutine[object, object, None]) -> None:
        """Fire-and-forget a coroutine without blocking the caller, keeping a
        reference so the event loop can't GC it mid-flight."""
        task = asyncio.create_task(coro)
        self._bg_tasks.add(task)
        task.add_done_callback(self._bg_tasks.discard)

    async def _maybe_replenish_prekeys(self) -> None:
        """Top up our relay-side one-time prekeys when senders have drained the
        published pool below the low watermark.

        Fired in the background after we burn an OTPK on receipt (a sender opened
        a session with us) and once at startup. Without this, a recipient who
        stays online while many senders consume their OTPKs drains to zero and
        then silently serves weaker, OTPK-less handshakes. Best-effort: any relay
        error is logged and swallowed, exactly like the initial publish.
        """
        if self._replenishing:
            return  # a top-up is already in flight — don't pile on
        self._replenishing = True
        try:
            addr = self._identity.scan_keypair.public_b58()
            try:
                status = await self._client.prekey_status(addr)
            except RelayError as exc:
                logger.debug("prekey status check failed (non-fatal): %s", exc)
                return
            if status is None:
                return  # nothing published yet — _publish_prekeys handles that
            if int(status.get("one_time_count", 0)) >= ONE_TIME_LOW_WATERMARK:
                return  # pool is still healthy
            new_ids = replenish_one_time(self._prekeys)
            payload = [
                {"id": pid, "pub": b58encode(self._prekeys.one_time[pid].public_bytes())}
                for pid in new_ids
            ]
            try:
                await self._client.replenish_prekeys(addr, payload)
            except RelayError as exc:
                logger.debug("prekey replenish failed (non-fatal): %s", exc)
                return
            # Persist the new privates so a later restart can still complete the
            # handshakes the relay will now serve from them (no-op if unwired).
            if self._on_prekeys_changed is not None:
                self._on_prekeys_changed(self._prekeys)
            self._emit("prekeys_replenish", str(len(new_ids)))
        finally:
            self._replenishing = False

    async def _ensure_peer_bundle(self) -> None:
        """Fetch the peer's prekey bundle once before our first send. On a 404 /
        verification failure we fall back to the legacy deterministic bootstrap
        and surface a one-time amber warning."""
        bundle: PreKeyBundle | None = None
        try:
            data = await self._client.fetch_prekey_bundle(self._channel.their_scan_b58)
        except RelayError as exc:
            logger.debug("prekey fetch failed (legacy fallback): %s", exc)
            data = None
        if data is not None:
            try:
                candidate = PreKeyBundle.from_dict(data)
                if verify_prekey_bundle(candidate):
                    bundle = candidate
            except X3DHError as exc:
                logger.debug("peer prekey bundle malformed (legacy fallback): %s", exc)
        self._channel.set_peer_bundle(bundle)
        if bundle is None and not self._legacy_warned:
            self._legacy_warned = True
            self._emit(
                "legacy",
                "⚠ Contact has no prekey bundle — using legacy bootstrap "
                "(reduced forward secrecy for opening messages)",
            )

    @property
    def node_count(self) -> int:
        """Reachable mesh nodes for this session (active relay + failover peers)."""
        return self._client.node_count

    @property
    def relay_nodes(self) -> list[str]:
        """All relay nodes known for failover (the federated path)."""
        return self._client.relays

    @property
    def onion_node(self) -> bool:
        """True when the active relay is a Tor onion service (a Pi-Zero node)."""
        return self._client.is_onion

    async def close(self) -> None:
        for task in list(self._bg_tasks):
            task.cancel()
        await self._client.close()

    async def __aenter__(self) -> Session:
        await self.connect()
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def send(self, plaintext: str) -> None:
        """
        Encrypt and deliver a UTF-8 string to the contact.

        The content is encrypted with a fresh ratchet message key; the message
        is addressed to a fresh stealth one-time address so it is unlinkable on
        the wire. Sealed sender (Phase 3b): the ephemeral key and ratchet header
        are sealed into one opaque blob, so the only metadata the relay sees is
        the recipient's one-time address.
        """
        # Before our first send, fetch the peer's prekey bundle so the channel can
        # promote via X3DH (or fall back to the legacy bootstrap on a 404). Done
        # outside the ratchet lock — it is network I/O that touches no ratchet
        # state; the channel only consults the cached bundle inside encrypt().
        if self._channel.needs_peer_bundle():
            await self._ensure_peer_bundle()
        async with self._lock:
            # The channel promotes to initiator on first send, ratchet-encrypts,
            # seals and stealth-addresses — all the per-peer crypto in one place.
            one_time_addr, sealed_blob, fmd = self._channel.encrypt(plaintext.encode())
            self._emit("ratchet", f"sending chain step · msg #{self._channel.send_count}")
        self._emit("send", _addr_digest(one_time_addr))
        await self._client.send(
            Envelope(
                to=STEALTH_CHANNEL,
                ciphertext=sealed_blob,
                one_time_addr=one_time_addr,
                fmd_flag=fmd,
            )
        )
        self._emit("sealed", "sender identity sealed")
        self._emit("erase", "message key erased")

    async def burn_last_message(self) -> None:
        """Send a burn request for the last message we sent."""
        if self._channel.last_sent_addr is None:
            from drift.transport.client import RelayError
            raise RelayError("no message sent in this session")
        addr_b64 = base64.b64encode(self._channel.last_sent_addr).decode()
        token = generate_burn_token(self._channel.burn_shared, "message", addr_b64)
        await self._client.post_burn(token, "message", addr_b64, STEALTH_CHANNEL)
        self._emit("burn", f"message burn requested · {addr_b64[:8]}···")

    async def burn_conversation(self) -> None:
        """Send a burn request to erase this conversation from the relay and both clients."""
        token = generate_burn_token(self._channel.burn_shared, "conversation")
        await self._client.post_burn(token, "conversation", None, STEALTH_CHANNEL)
        self._emit("burn", "conversation burn requested")

    async def messages(self) -> AsyncGenerator[str, None]:
        """
        Async generator yielding decrypted messages addressed to us.

        Sealed sender (Phase 3b): each envelope carries only the recipient's
        one-time address and an opaque blob. We unpack the blob's ephemeral key
        (the one clear value, needed to derive the stealth secret), scan to see
        if the message is ours, then — only on a match — unseal the ratchet
        header and decrypt. A scan match means the message is genuinely ours, so
        any later authentication failure (unsealing the header or the ratchet
        body) is real tampering and ``InvalidTag`` is allowed to propagate.
        """
        async for item in self._client:
            # Burn tombstone from the relay — verify token, then call hook.
            if isinstance(item, BurnFrame):
                if item.token and verify_burn_token(
                    self._channel.burn_shared, item.token, item.scope, item.message_id
                ):
                    logger.debug("messages: verified burn tombstone scope=%s", item.scope)
                    if self._on_burn is not None:
                        self._on_burn(item.scope, item.message_id)
                else:
                    logger.debug("messages: ignoring burn tombstone — token invalid or missing")
                continue

            # Identity-level scan + unseal (shared with GroupSession). A genuine
            # tamper of a message addressed to us surfaces here as InvalidTag and
            # is allowed to propagate (iron rule).
            parsed = _scan_and_unseal(item, self._my_scan_priv, self._my_spend_pub)
            if parsed is None:
                continue  # not addressed to us, or malformed
            assert item.one_time_addr is not None  # guaranteed by _scan_and_unseal
            if item.one_time_addr in self._seen_addrs:
                continue  # relay replayed a message we've already accepted
            self._seen_addrs.add(item.one_time_addr)
            self._emit("recv", _addr_digest(item.one_time_addr))

            x3dh_header, fs_pub, header, ratchet_ct = parsed
            consumed_otpk = False
            async with self._lock:
                # 1:1: the peer is unambiguous, so an auth failure here is tamper —
                # both decrypt paths let InvalidTag propagate.
                if x3dh_header is not None:
                    # X3DH bootstrap (audit H3): complete the handshake on receipt;
                    # transactional, so a forged bootstrap can't burn an OTPK.
                    plaintext = self._channel.x3dh_bootstrap_decrypt(
                        x3dh_header, header, ratchet_ct
                    )
                    consumed_otpk = self._channel.otpk_just_consumed
                else:
                    # Legacy bootstrap forward-secrecy secret (audit H3): recovered
                    # from the ephemeral's public half. ratchet_decrypt applies it
                    # only before our first DH ratchet, on a trial state that rolls
                    # back on failure. None for steady-state messages.
                    root_mix = (
                        _keypair_from_private(self._my_spend_priv).ecdh(fs_pub)
                        if fs_pub is not None
                        else None
                    )
                    plaintext = self._channel.decrypt_ratchet(header, ratchet_ct, root_mix)
                self._emit("ratchet", f"receiving chain step · msg #{self._channel.recv_count}")
            # A sender just burned one of our OTPKs; top the relay pool back up in
            # the background so we never start serving weaker OTPK-less handshakes.
            if consumed_otpk:
                self._spawn_bg(self._maybe_replenish_prekeys())
            self._emit("erase", "message key erased")
            yield plaintext.decode()
        logger.debug("messages: firehose ended — relay connection closed")


# ===========================================================================
# Group messaging (Phase 8) — pairwise composition, ≤10 members
# ===========================================================================

@dataclass
class GroupMessage:
    """One decrypted group message, tagged with its (authenticated) sender."""

    sender_name: str
    sender_code: str
    text: str


# Callback for an applied membership change, so the UI/CLI can show it as a
# system event ("→ alice added bob"). Mirrors the BurnHook pattern.
MembershipHook = Callable[[MembershipChange], None]


class GroupSession:
    """
    A group conversation as a composition of pairwise channels (Phase 8).

    One firehose subscription; one :class:`PairwiseRatchet` per *other* member.
    A group message is encrypted once per recipient and sent to that recipient's
    own stealth address, so the relay sees N-1 unrelated envelopes — never a
    "group message" (the group id is encrypted *inside* the payload, not the
    envelope). Bandwidth is therefore O(n) per message (DESIGN.md §11); larger
    groups want the deferred Phase 8b sender-keys.

    Receiving fans in over the single firehose: each envelope addressed to us is
    scanned + unsealed once (identity-level), then trial-decrypted against each
    member's ratchet — the member whose ratchet authenticates the message *is*
    the sender. Trial decryption is safe because :func:`ratchet_decrypt` rolls
    back on failure (see :meth:`PairwiseRatchet.attempt_ratchet`).

    Joining a group is out-of-band (the inviter shares the roster, like a contact
    code); in-band :class:`MembershipChange` messages keep already-participating
    members' local views convergent (eventual consistency, DESIGN.md §11).
    """

    def __init__(
        self,
        identity: Identity,
        group: GroupState,
        relay_url: str,
        *,
        ping_interval: float = 30.0,
        on_event: EventHook | None = None,
        on_membership: MembershipHook | None = None,
        tor_client: TorClient | None = None,
        fmd_key: FMDKeypair | None = None,
    ) -> None:
        self._identity = identity
        self._group = group
        self._on_event = on_event
        self._on_membership = on_membership
        self._tor_client = tor_client
        # Identity-level keys for scanning the firehose (same for every peer).
        self._my_scan_priv = identity.scan_keypair.private_bytes()
        self._my_spend_pub = identity.spend_keypair.public_bytes()
        self._my_spend_priv = identity.spend_keypair.private_bytes()
        self._my_code = identity.contact_code()
        # One pairwise channel per other member, keyed by contact code.
        self._channels: dict[str, PairwiseRatchet] = {
            m.code: PairwiseRatchet(identity, m.code) for m in group.members
        }
        self._members: dict[str, ContactInfo] = {m.code: m for m in group.members}
        self._lock = asyncio.Lock()
        self._seen_addrs: set[bytes] = set()
        socks_proxy = tor_client.socks_proxy if tor_client is not None else None
        fmd_secret_keys = fmd_key.secret_keys if fmd_key and fmd_key.secret_keys else None
        self._client = RelayClient(
            relay_url, STEALTH_CHANNEL, ping_interval=ping_interval,
            socks_proxy=socks_proxy, fmd_secret_keys=fmd_secret_keys,
        )

    # ------------------------------------------------------------------ lifecycle
    async def connect(self) -> None:
        await self._client.connect()
        if self._tor_client is not None:
            self._emit("tor", str(self._tor_client.num_hops))
        self._emit("nodes", str(self._client.node_count))
        if self._client.is_onion:
            self._emit("onion", "1")

    async def close(self) -> None:
        await self._client.close()

    async def __aenter__(self) -> GroupSession:
        await self.connect()
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()

    @property
    def group(self) -> GroupState:
        return self._group

    @property
    def members(self) -> list[ContactInfo]:
        return list(self._members.values())

    def _emit(self, kind: str, detail: str = "") -> None:
        if self._on_event is not None:
            self._on_event(kind, detail)

    # ------------------------------------------------------------------ sending
    async def _fanout(self, framed: bytes, codes: list[str] | None = None) -> int:
        """Encrypt ``framed`` once per target member and send N envelopes.

        Returns the number of envelopes sent. Each goes to a distinct stealth
        one-time address with independent ciphertext — unlinkable on the wire.
        """
        targets = list(self._channels) if codes is None else codes
        envelopes: list[Envelope] = []
        async with self._lock:
            for code in targets:
                channel = self._channels.get(code)
                if channel is None:
                    continue
                addr, blob, fmd = channel.encrypt(framed)
                envelopes.append(
                    Envelope(
                        to=STEALTH_CHANNEL, ciphertext=blob,
                        one_time_addr=addr, fmd_flag=fmd,
                    )
                )
        for envelope in envelopes:
            await self._client.send(envelope)
        return len(envelopes)

    async def send_to_group(self, text: str) -> None:
        """Encrypt ``text`` once per member and send N-1 stealth envelopes."""
        framed = groups.pack_group_payload(
            self._group.group_id, groups.KIND_TEXT, text.encode()
        )
        sent = await self._fanout(framed)
        self._emit("send", f"group · {sent} sealed envelopes")
        self._emit("erase", "message key erased")

    async def add_member(self, new_member: ContactInfo) -> MembershipChange:
        """
        Add ``new_member`` and announce it pairwise.

        Existing members get one signed ADD(new). The newcomer gets a signed
        ADD assertion for each existing member, so they can build pairwise
        channels and learn the roster (eventual-consistency roster sync).
        """
        groups.add_member(self._group, new_member)  # validates + enforces ≤10
        self._channels[new_member.code] = PairwiseRatchet(self._identity, new_member.code)
        self._members[new_member.code] = new_member

        change = groups.make_membership_change(
            self._identity, self._group, groups.ACTION_ADD, new_member
        )
        framed = groups.pack_group_payload(
            self._group.group_id, groups.KIND_MEMBERSHIP, change.to_bytes()
        )
        existing = [c for c in self._channels if c != new_member.code]
        await self._fanout(framed, codes=existing)

        # Bootstrap the newcomer's view: assert each existing member to them.
        for code, info in list(self._members.items()):
            if code == new_member.code:
                continue
            assertion = groups.make_membership_change(
                self._identity, self._group, groups.ACTION_ADD, info
            )
            await self._fanout(
                groups.pack_group_payload(
                    self._group.group_id, groups.KIND_MEMBERSHIP, assertion.to_bytes()
                ),
                codes=[new_member.code],
            )
        self._emit("send", f"membership · added {new_member.name}")
        return change

    async def remove_member(self, code: str) -> MembershipChange:
        """
        Remove the member with contact ``code`` and announce it to the rest.

        Forward secrecy after removal is the existing ratchet property, not a new
        mechanism (DESIGN.md §11): the member is dropped from every recipient list
        so they receive no further envelopes, and continued use advances each
        remaining pair's ratchet beyond any state the removed member held.
        """
        target = self._members.get(code)
        if target is None:
            raise groups.GroupError("no such member in the group")
        change = groups.make_membership_change(
            self._identity, self._group, groups.ACTION_REMOVE, target
        )
        framed = groups.pack_group_payload(
            self._group.group_id, groups.KIND_MEMBERSHIP, change.to_bytes()
        )
        remaining = [c for c in self._channels if c != code]
        await self._fanout(framed, codes=remaining)
        groups.remove_member(self._group, code)
        self._channels.pop(code, None)
        self._members.pop(code, None)
        self._emit("send", f"membership · removed {target.name}")
        return change

    def _handle_membership(self, body: bytes, sender_code: str | None) -> None:
        """Authenticate + apply a received membership change; fire the hook on a
        real local change (idempotent re-assertions are silent)."""
        try:
            change = MembershipChange.from_bytes(body)
        except groups.GroupError:
            return
        # Tamper-evidence (signature) + bind to the delivering pairwise channel.
        if not groups.verify_membership_change(change):
            return
        if change.author_code != sender_code:
            return  # author must match the ratchet that actually delivered it

        target_code = change.target.code
        changed = False
        if change.action == groups.ACTION_ADD:
            if target_code != self._my_code and target_code not in self._members:
                try:
                    groups.apply_membership_change(self._group, change)
                except groups.GroupError:
                    return
                self._channels[target_code] = PairwiseRatchet(self._identity, target_code)
                self._members[target_code] = change.target
                changed = True
        elif change.action == groups.ACTION_REMOVE:
            if target_code in self._members or self._group.has_member(target_code):
                groups.apply_membership_change(self._group, change)
                self._channels.pop(target_code, None)
                self._members.pop(target_code, None)
                changed = True

        if changed and self._on_membership is not None:
            self._on_membership(change)

    # ------------------------------------------------------------------ receiving
    async def messages(self) -> AsyncGenerator[GroupMessage, None]:
        """Yield decrypted group :class:`GroupMessage`s; apply membership changes
        in-band (surfaced via the on_membership hook, not yielded)."""
        async for item in self._client:
            if isinstance(item, BurnFrame):
                continue  # group burn is out of scope for Phase 8
            parsed = _scan_and_unseal(item, self._my_scan_priv, self._my_spend_pub)
            if parsed is None:
                continue
            assert item.one_time_addr is not None  # guaranteed by _scan_and_unseal
            if item.one_time_addr in self._seen_addrs:
                continue
            self._seen_addrs.add(item.one_time_addr)
            # Groups stay on the legacy deterministic bootstrap — members publish
            # no prekey bundle — so group traffic never carries an X3DH header
            # (``x3dh_header`` is always None here). Only the legacy FS-ephemeral
            # ``root_mix`` path applies.
            _x3dh_header, fs_pub, header, ratchet_ct = parsed
            root_mix = (
                _keypair_from_private(self._my_spend_priv).ecdh(fs_pub)
                if fs_pub is not None
                else None
            )
            # Fan-in: the member whose ratchet authenticates the message is the
            # sender. Trial decryption is safe (each attempt rolls back on miss).
            async with self._lock:
                sender_code: str | None = None
                plaintext: bytes | None = None
                for code, channel in list(self._channels.items()):
                    attempt = channel.attempt_ratchet(header, ratchet_ct, root_mix)
                    if attempt is not None:
                        sender_code, plaintext = code, attempt
                        break
            if plaintext is None:
                continue  # not from any current member — drop
            unpacked = groups.unpack_group_payload(plaintext)
            if unpacked is None:
                continue  # an ordinary 1:1 message on this ratchet — not ours
            gid, kind, body = unpacked
            if gid.raw != self._group.group_id.raw:
                continue  # a different group we happen to share with this member
            self._emit("recv", _addr_digest(item.one_time_addr))
            if kind == groups.KIND_MEMBERSHIP:
                self._handle_membership(body, sender_code)
                continue
            sender = self._members.get(sender_code) if sender_code else None
            yield GroupMessage(
                sender_name=sender.name if sender else (sender_code or "?"),
                sender_code=sender_code or "",
                text=body.decode(),
            )
