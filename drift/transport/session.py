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

Ratchet bootstrap
-----------------
The ratchet needs a shared root secret and an initial responder ratchet key.
We derive both deterministically so no extra handshake round-trip is needed:

  - root secret      = HKDF(ECDH(my_spend, their_spend))
  - responder's key  = HKDF(same ECDH) → a deterministic X25519 keypair both
                       sides can reconstruct

Who sends first is the initiator
--------------------------------
Both peers bootstrap as *receivers* holding that shared deterministic responder
keypair. Whoever sends the first message lazily promotes itself to initiator at
that moment (``init_sender`` against the deterministic responder key); the peer
turns its DH ratchet on receipt, exactly as in the normal flow. This is the only
deterministic key material; every key after the first DH ratchet step is freshly
random (see ratchet.py).

We previously fixed the initiator role by comparing static spend keys (lower =
initiator). That decoupled "who may speak first" from "who actually opens the
chat", so ~half of real conversations could not start — the first sender, if it
was the key-order responder, hit ``RatchetError: no sending chain yet``. Lazy
promotion ties the role to who actually speaks first instead.

Known limitation: if both peers send their very first message before either has
received the other's, they each promote independently and the two ratchets do
not line up — the mismatched message surfaces as ``InvalidTag`` (a clean reject,
never silent corruption). A production build resolves this with an X3DH prekey
exchange (Phase 3); for now the common one-sided open works correctly.
"""

from __future__ import annotations

import asyncio
import base64
import logging
from collections.abc import AsyncGenerator, Callable
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from drift.crypto import Identity, Keypair, derive_message_key, groups
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
from drift.transport.client import BurnFrame, Envelope, RelayClient
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


# Inner sealed-payload framing (audit H3). The bytes sealed under the per-message
# stealth key are normally just the 40-byte ratchet header. On the initiator's
# *bootstrap* sending chain — every message it sends before the peer's first
# reply — they are prefixed with a fresh forward-secrecy ephemeral public key
# (32 bytes). A one-byte flag distinguishes the two layouts, so even a reordered
# bootstrap message still carries the ephemeral the responder needs.
_FS_FLAG_ABSENT = 0
_FS_FLAG_PRESENT = 1
_FS_PUB_LEN = 32


def _pack_inner(header_bytes: bytes, fs_pub: bytes | None) -> bytes:
    """Frame the ratchet header (+ optional bootstrap FS ephemeral) for sealing."""
    if fs_pub is None:
        return bytes([_FS_FLAG_ABSENT]) + header_bytes
    return bytes([_FS_FLAG_PRESENT]) + fs_pub + header_bytes


def _unpack_inner(blob: bytes) -> tuple[bytes | None, bytes]:
    """Split a sealed inner payload into ``(fs_pub_or_None, ratchet_header)``.

    Raises ``ValueError`` on a malformed frame — the caller (which has already
    unsealed under the stealth key) treats that as a non-well-formed message and
    skips it, so a forged but correctly-sealed blob can't crash the receive loop.
    """
    if not blob:
        raise ValueError("empty sealed inner payload")
    flag = blob[0]
    if flag == _FS_FLAG_PRESENT:
        if len(blob) < 1 + _FS_PUB_LEN:
            raise ValueError("sealed inner payload too short for FS ephemeral")
        return blob[1:1 + _FS_PUB_LEN], blob[1 + _FS_PUB_LEN:]
    if flag != _FS_FLAG_ABSENT:
        raise ValueError(f"unknown sealed inner-payload flag {flag}")
    return None, blob[1:]


def _addr_digest(addr: bytes) -> str:
    """Short, non-secret display digest of a one-time address (already public)."""
    return f"{addr[:2].hex()}···{addr[-2:].hex()}"


# Observable, non-secret transport events for the UI ticker. These report
# operations the session already performs (no crypto behaviour changes); the
# only data exposed is the one-time address — which is public on the wire.
EventHook = Callable[[str, str], None]


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

    def __init__(self, identity: Identity, contact_code: str) -> None:
        self._their_scan_pub, self._their_spend_pub = Identity.parse_contact_code(
            contact_code
        )
        # Recipient's FMD detection public sub-keys, if they published any (the
        # optional 3rd contact-code segment). None → we never attach a flag, so
        # FMD-off behaviour is byte-for-byte unchanged (audit M4).
        self._fmd_pub = Identity.parse_fmd_pubs(contact_code)
        static_ecdh = identity.spend_keypair.ecdh(self._their_spend_pub)
        # Both peers reconstruct identical bootstrap material from the static
        # keys, so whoever speaks first can promote itself to initiator on demand.
        self._root_secret = derive_message_key(static_ecdh, info=b"drift-ratchet-v1-root")
        self._responder_keypair = _keypair_from_private(
            derive_message_key(static_ecdh, info=b"drift-ratchet-v1-responder")
        )
        # Raw ECDH output, base material for burn tokens (domain-separated by the
        # burn module's own HKDF). Kept so the owner can issue burns.
        self._burn_shared = static_ecdh
        # Public half of the bootstrap forward-secrecy ephemeral (audit H3); set
        # on promotion, carried on every opening-chain message. Private half is
        # generated and discarded inside _promote_to_initiator.
        self._fs_send_pub: bytes | None = None
        self._ratchet = init_receiver(self._root_secret, self._responder_keypair)
        self._last_sent_addr: bytes | None = None

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

    def _promote_to_initiator(self) -> None:
        """Promote receiver → initiator on first send (see Session's docstring,
        audit H3). Folds a fresh, immediately-discarded forward-secrecy ephemeral
        into the bootstrap root so the opening burst is forward-secret against our
        own later key theft."""
        fs_ephemeral = Keypair.generate()
        fs_secret = fs_ephemeral.ecdh(self._their_spend_pub)
        fs_root = derive_message_key(
            fs_secret, salt=self._root_secret, info=FS_BOOTSTRAP_INFO
        )
        self._fs_send_pub = fs_ephemeral.public_bytes()
        self._ratchet = init_sender(fs_root, self._responder_keypair.public_bytes())
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
        # Carry the bootstrap FS ephemeral on every opening-chain message — i.e.
        # while our ratchet still points at the deterministic responder key.
        fs_pub = (
            self._fs_send_pub
            if self._ratchet.their_ratchet_pub == self._responder_keypair.public_bytes()
            else None
        )
        inner = _pack_inner(header.to_bytes(), fs_pub)
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
) -> tuple[bytes | None, Header, bytes] | None:
    """
    Identity-level receive parsing shared by Session and GroupSession.

    Returns ``(fs_pub, header, ratchet_ct)`` when ``envelope`` is a well-formed
    stealth message addressed to *us*, else ``None`` (not ours / malformed).

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
        fs_pub, header_bytes = _unpack_inner(inner_bytes)
        header = Header.from_bytes(header_bytes)
    except ValueError:
        return None  # malformed inner payload — skip (forged or corrupt)
    return fs_pub, header, ratchet_ct


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
    ) -> None:
        # Optional sink for observable (non-secret) transport events; the UI
        # passes a callback that re-emits them as typed messages. Never carries
        # plaintext or key material.
        self._on_event = on_event
        # Optional callback for verified burn tombstones from the relay.
        self._on_burn = on_burn
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

        # All per-peer crypto — the Double Ratchet, its deterministic bootstrap
        # material, the peer's public keys and the sealed-sender framing — lives
        # in one PairwiseRatchet (shared, identical code, with GroupSession).
        self._channel = PairwiseRatchet(identity, contact_code)

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

            fs_pub, header, ratchet_ct = parsed
            # Bootstrap forward-secrecy secret (audit H3): recovered from the
            # ephemeral's public half. ratchet_decrypt applies it only before our
            # first DH ratchet, on a trial state that rolls back on failure.
            root_mix = (
                _keypair_from_private(self._my_spend_priv).ecdh(fs_pub)
                if fs_pub is not None
                else None
            )
            async with self._lock:
                # 1:1: the peer is unambiguous, so an auth failure here is tamper —
                # decrypt_ratchet lets InvalidTag propagate.
                plaintext = self._channel.decrypt_ratchet(header, ratchet_ct, root_mix)
                self._emit("ratchet", f"receiving chain step · msg #{self._channel.recv_count}")
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
            fs_pub, header, ratchet_ct = parsed
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
