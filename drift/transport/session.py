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

Roles are assigned by comparing the two static spend keys (lower = initiator),
so both peers agree on who bootstraps as sender vs. receiver without talking.
The responder's *initial* ratchet key is the only deterministic key material;
every key after the first DH ratchet step is freshly random (see ratchet.py).
A production build would source these from an X3DH prekey exchange instead.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from drift.crypto import Identity, Keypair, derive_message_key
from drift.crypto.ratchet import (
    Header,
    RatchetState,
    init_receiver,
    init_sender,
    ratchet_decrypt,
    ratchet_encrypt,
)
from drift.crypto.stealth import derive_one_time_address, scan_for_message
from drift.transport.client import Envelope, RelayClient

# Shared firehose channel every stealth client subscribes to. The relay
# fans every envelope out to all subscribers; clients scan locally.
STEALTH_CHANNEL = "drift-stealth-v1"


def _keypair_from_private(private_bytes: bytes) -> Keypair:
    """Reconstruct an X25519 Keypair from raw private key bytes."""
    priv = X25519PrivateKey.from_private_bytes(private_bytes)
    return Keypair(private_key=priv, public_key=priv.public_key())


class Session:
    """
    An encrypted conversation channel: stealth-addressed delivery (Phase 1)
    with Double Ratchet content encryption (Phase 2).

    Usage::

        async with Session(my_identity, their_contact_code, relay_url) as s:
            await s.send("hello")
            async for msg in s.messages():
                print(msg)

    Note: as in Signal/X3DH, only the *initiator* can send the first message.
    The responder must receive that message (turning its DH ratchet) before it
    can reply; calling :meth:`send` earlier raises ``RatchetError``.
    """

    def __init__(
        self,
        identity: Identity,
        contact_code: str,
        relay_url: str,
        *,
        ping_interval: float = 30.0,
    ) -> None:
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

        # Subscribe to the shared firehose; the relay routes by this key only.
        self._client = RelayClient(relay_url, STEALTH_CHANNEL, ping_interval=ping_interval)

    def _bootstrap_ratchet(self, identity: Identity) -> RatchetState:
        static_ecdh = identity.spend_keypair.ecdh(self._their_spend_pub)
        root_secret = derive_message_key(static_ecdh, info=b"drift-ratchet-v1-root")
        responder_priv = derive_message_key(
            static_ecdh, info=b"drift-ratchet-v1-responder"
        )
        responder_keypair = _keypair_from_private(responder_priv)

        # Lower static spend key initiates; both peers compute this identically.
        i_am_initiator = self._my_spend_pub < self._their_spend_pub
        if i_am_initiator:
            return init_sender(root_secret, responder_keypair.public_bytes())
        return init_receiver(root_secret, responder_keypair)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        await self._client.connect()

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
            header, ciphertext = ratchet_encrypt(self._ratchet, plaintext.encode())

        ephemeral = Keypair.generate()
        one_time_addr, _ = derive_one_time_address(
            ephemeral.private_bytes(),
            self._their_scan_pub,
            self._their_spend_pub,
        )
        await self._client.send(
            Envelope(
                to=STEALTH_CHANNEL,
                ciphertext=ciphertext,
                ephemeral_pub=ephemeral.public_bytes(),
                one_time_addr=one_time_addr,
                ratchet_header=header.to_bytes(),
            )
        )

    async def messages(self) -> AsyncGenerator[str, None]:
        """
        Async generator yielding decrypted messages addressed to us.

        Each broadcast envelope is first scanned with our scan key to see if
        it is ours; if so, the ratchet header drives decryption. Envelopes
        that aren't ours scan to ``None`` and are skipped. A scan match means
        the message is genuinely ours, so a decrypt failure is real tampering
        — ``InvalidTag`` is allowed to propagate.
        """
        async for envelope in self._client:
            if envelope.ephemeral_pub is None or envelope.one_time_addr is None:
                continue  # not a stealth envelope
            detected = scan_for_message(
                envelope.ephemeral_pub,
                envelope.one_time_addr,
                self._my_scan_priv,
                self._my_spend_pub,
            )
            if detected is None:
                continue  # not addressed to us
            if envelope.ratchet_header is None:
                continue  # addressed to us but carries no ratchet header

            header = Header.from_bytes(envelope.ratchet_header)
            async with self._lock:
                plaintext = ratchet_decrypt(self._ratchet, header, envelope.ciphertext)
            yield plaintext.decode()
