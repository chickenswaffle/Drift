"""
drift.transport.session — authenticated session layer

Composes crypto + transport. Phase 1 uses rotating stealth addresses:
every message is sent to a fresh, unlinkable one-time address, and the
receiver detects its own messages by scanning with its private scan key.

Phase 0 (historical): a single static ECDH+HKDF shared key per contact.
Phase 1 (current):    per-message ephemeral key → stealth address.
Phase 2 (planned):    swap the per-message key for a Double Ratchet.

Routing model
-------------
One-time addresses are unpredictable, so a receiver cannot subscribe to
them ahead of time. Instead every client subscribes to a shared broadcast
channel and scans the stream locally — exactly like scanning a blockchain
for outputs. The relay therefore learns nothing about who any message is
for; only the holder of the matching scan key can detect it.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from drift.crypto import Identity, Keypair, decrypt, encrypt
from drift.crypto.stealth import derive_one_time_address, scan_for_message
from drift.transport.client import Envelope, RelayClient

# Shared firehose channel every stealth client subscribes to. The relay
# fans every envelope out to all subscribers; clients scan locally.
STEALTH_CHANNEL = "drift-stealth-v1"


class Session:
    """
    An encrypted conversation channel with stealth-addressed delivery.

    Sending derives a fresh one-time address from the contact's scan/spend
    keys; receiving scans the broadcast stream with our own scan key.

    Usage::

        async with Session(my_identity, their_contact_code, relay_url) as s:
            await s.send("hello")
            async for msg in s.messages():
                print(msg)
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

        # Subscribe to the shared firehose; the relay routes by this key only.
        self._client = RelayClient(relay_url, STEALTH_CHANNEL, ping_interval=ping_interval)

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

        Generates a fresh ephemeral keypair so every message lands at a
        distinct, unlinkable one-time address.
        """
        ephemeral = Keypair.generate()
        one_time_addr, message_key = derive_one_time_address(
            ephemeral.private_bytes(),
            self._their_scan_pub,
            self._their_spend_pub,
        )
        ciphertext = encrypt(message_key, plaintext.encode())
        await self._client.send(
            Envelope(
                to=STEALTH_CHANNEL,
                ciphertext=ciphertext,
                ephemeral_pub=ephemeral.public_bytes(),
                one_time_addr=one_time_addr,
            )
        )

    async def messages(self) -> AsyncGenerator[str, None]:
        """
        Async generator yielding decrypted messages addressed to us.

        Each envelope on the broadcast channel is scanned with our scan
        key. Envelopes that aren't ours (other recipients, or our own
        outbound echoes) scan to ``None`` and are skipped. A scan match
        means the message is genuinely ours, so a decrypt failure here is
        real tampering — ``InvalidTag`` is allowed to propagate.
        """
        async for envelope in self._client:
            if envelope.ephemeral_pub is None or envelope.one_time_addr is None:
                continue  # not a stealth envelope
            message_key = scan_for_message(
                envelope.ephemeral_pub,
                envelope.one_time_addr,
                self._my_scan_priv,
                self._my_spend_pub,
            )
            if message_key is None:
                continue  # not addressed to us
            plaintext = decrypt(message_key, envelope.ciphertext)
            yield plaintext.decode()
