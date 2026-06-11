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

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from drift.crypto import Identity, Keypair, derive_message_key
from drift.crypto.burn import generate_burn_token, verify_burn_token
from drift.crypto.ratchet import (
    Header,
    RatchetState,
    init_receiver,
    init_sender,
    ratchet_decrypt,
    ratchet_encrypt,
)
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


def _addr_digest(addr: bytes) -> str:
    """Short, non-secret display digest of a one-time address (already public)."""
    return f"{addr[:2].hex()}···{addr[-2:].hex()}"


# Observable, non-secret transport events for the UI ticker. These report
# operations the session already performs (no crypto behaviour changes); the
# only data exposed is the one-time address — which is public on the wire.
EventHook = Callable[[str, str], None]


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

        # Contact's public keys — used to address messages *to* them.
        self._their_scan_pub, self._their_spend_pub = Identity.parse_contact_code(
            contact_code
        )

        # Our own keys — used to scan for messages addressed *to* us.
        self._my_scan_priv = identity.scan_keypair.private_bytes()
        self._my_spend_pub = identity.spend_keypair.public_bytes()

        # Bootstrap the Double Ratchet (see module docstring).
        self._ratchet = self._bootstrap_ratchet(identity)

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

        # One-time address of the most recently sent message — used by burn_last_message().
        self._last_sent_addr: bytes | None = None

        # Subscribe to the shared firehose; the relay routes by this key only.
        # When Tor is active, hand the transport the SOCKS5 endpoint so every
        # byte is proxied through the circuit.
        socks_proxy = tor_client.socks_proxy if tor_client is not None else None
        self._client = RelayClient(
            relay_url,
            STEALTH_CHANNEL,
            ping_interval=ping_interval,
            socks_proxy=socks_proxy,
        )

    def _bootstrap_ratchet(self, identity: Identity) -> RatchetState:
        static_ecdh = identity.spend_keypair.ecdh(self._their_spend_pub)
        # Stash the root secret + deterministic responder keypair so that
        # whichever side speaks first can promote itself to initiator on demand
        # (see _promote_to_initiator). Both peers reconstruct identical values.
        self._root_secret = derive_message_key(static_ecdh, info=b"drift-ratchet-v1-root")
        responder_priv = derive_message_key(
            static_ecdh, info=b"drift-ratchet-v1-responder"
        )
        self._responder_keypair = _keypair_from_private(responder_priv)

        # Raw ECDH output used as the base material for burn tokens.
        # generate_burn_token() runs its own HKDF with info=b"drift-burn-v1",
        # so this is domain-separated from all ratchet key material.
        self._burn_shared = static_ecdh

        # Everyone starts as a receiver; the first sender promotes lazily.
        logger.debug("bootstrap: starting as receiver, awaiting first speaker")
        return init_receiver(self._root_secret, self._responder_keypair)

    def _promote_to_initiator(self) -> None:
        """
        Turn this side into the ratchet initiator on its first send.

        Only valid before any message has been received (no sending chain yet
        and no DH ratchet has turned). Idempotent guard lives in :meth:`send`.
        """
        logger.debug("send: no sending chain — promoting receiver → initiator")
        self._ratchet = init_sender(
            self._root_secret, self._responder_keypair.public_bytes()
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

        The content is encrypted with a fresh ratchet message key; the
        envelope is addressed to a fresh stealth one-time address so it is
        unlinkable on the wire.
        """
        async with self._lock:
            if self._ratchet.sending_chain_key is None:
                # First to speak in this conversation → become the initiator.
                self._promote_to_initiator()
            header, ciphertext = ratchet_encrypt(self._ratchet, plaintext.encode())
            self._emit("ratchet", f"sending chain step · msg #{self._ratchet.send_count}")

        ephemeral = Keypair.generate()
        one_time_addr, _ = derive_one_time_address(
            ephemeral.private_bytes(),
            self._their_scan_pub,
            self._their_spend_pub,
        )
        self._last_sent_addr = one_time_addr  # tracked for burn_last_message()
        self._emit("send", _addr_digest(one_time_addr))
        await self._client.send(
            Envelope(
                to=STEALTH_CHANNEL,
                ciphertext=ciphertext,
                ephemeral_pub=ephemeral.public_bytes(),
                one_time_addr=one_time_addr,
                ratchet_header=header.to_bytes(),
            )
        )
        self._emit("erase", "message key erased")

    async def burn_last_message(self) -> None:
        """Send a burn request for the last message we sent."""
        if self._last_sent_addr is None:
            from drift.transport.client import RelayError
            raise RelayError("no message sent in this session")
        addr_b64 = base64.b64encode(self._last_sent_addr).decode()
        token = generate_burn_token(self._burn_shared, "message", addr_b64)
        await self._client.post_burn(token, "message", addr_b64, STEALTH_CHANNEL)
        self._emit("burn", f"message burn requested · {addr_b64[:8]}···")

    async def burn_conversation(self) -> None:
        """Send a burn request to erase this conversation from the relay and both clients."""
        token = generate_burn_token(self._burn_shared, "conversation")
        await self._client.post_burn(token, "conversation", None, STEALTH_CHANNEL)
        self._emit("burn", "conversation burn requested")

    async def messages(self) -> AsyncGenerator[str, None]:
        """
        Async generator yielding decrypted messages addressed to us.

        Each broadcast envelope is first scanned with our scan key to see if
        it is ours; if so, the ratchet header drives decryption. Envelopes
        that aren't ours scan to ``None`` and are skipped. A scan match means
        the message is genuinely ours, so a decrypt failure is real tampering
        — ``InvalidTag`` is allowed to propagate.
        """
        async for item in self._client:
            # Burn tombstone from the relay — verify token, then call hook.
            if isinstance(item, BurnFrame):
                if item.token and verify_burn_token(
                    self._burn_shared, item.token, item.scope, item.message_id
                ):
                    logger.debug("messages: verified burn tombstone scope=%s", item.scope)
                    if self._on_burn is not None:
                        self._on_burn(item.scope, item.message_id)
                else:
                    logger.debug("messages: ignoring burn tombstone — token invalid or missing")
                continue

            envelope = item
            if envelope.ephemeral_pub is None or envelope.one_time_addr is None:
                continue  # not a stealth envelope
            detected = scan_for_message(
                envelope.ephemeral_pub,
                envelope.one_time_addr,
                self._my_scan_priv,
                self._my_spend_pub,
            )
            if detected is None:
                continue  # not addressed to us (someone else's, or our own echo)
            if envelope.ratchet_header is None:
                continue  # addressed to us but carries no ratchet header
            if envelope.one_time_addr in self._seen_addrs:
                continue  # relay replayed a message we've already accepted
            self._seen_addrs.add(envelope.one_time_addr)

            logger.debug("messages: scan matched — decrypting our envelope")
            self._emit("recv", _addr_digest(envelope.one_time_addr))
            header = Header.from_bytes(envelope.ratchet_header)
            async with self._lock:
                plaintext = ratchet_decrypt(self._ratchet, header, envelope.ciphertext)
                self._emit("ratchet", f"receiving chain step · msg #{self._ratchet.recv_count}")
            self._emit("erase", "message key erased")
            yield plaintext.decode()
        logger.debug("messages: firehose ended — relay connection closed")
