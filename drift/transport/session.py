"""
drift.transport.session — authenticated session layer

Composes crypto + transport: derives a shared symmetric key via ECDH + HKDF,
then wraps send/receive in XChaCha20-Poly1305 AEAD.

Phase 0: static shared key derived from spend keypairs.
Phase 2: replace _key with a Double Ratchet state machine.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from drift.crypto import Identity, b58encode, decrypt, derive_message_key, encrypt
from drift.transport.client import Envelope, RelayClient


class Session:
    """
    An encrypted conversation channel between two DRIFT identities.

    Derives a shared key from X25519 ECDH on both parties' spend keypairs,
    stretches it via HKDF-SHA256, and wraps the RelayClient with
    encrypt-on-send / decrypt-on-receive.

    Usage::

        async with Session(my_identity, their_contact_code, relay_url) as session:
            await session.send("hello")
            async for msg in session.messages():
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
        _, contact_spend_pub = Identity.parse_contact_code(contact_code)

        # ECDH: my spend private × their spend public → raw shared secret.
        # X25519 is commutative so both sides produce the same bytes.
        raw_secret = identity.spend_keypair.ecdh(contact_spend_pub)

        # Include both public keys (sorted for symmetry) in the HKDF info so
        # the derived key is bound to exactly this pair of identities.
        my_spend_pub = identity.spend_keypair.public_bytes()
        lo, hi = sorted([my_spend_pub, contact_spend_pub])
        self._key: bytes = derive_message_key(raw_secret, info=b"drift-v0-msg" + lo + hi)

        # Routing addresses: listen on my spend-pub b58, send to theirs.
        my_addr = identity.spend_keypair.public_b58()
        self._their_addr = b58encode(contact_spend_pub)

        self._client = RelayClient(relay_url, my_addr, ping_interval=ping_interval)

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
        """Encrypt and deliver a UTF-8 string to the contact."""
        ct = encrypt(self._key, plaintext.encode())
        await self._client.send(Envelope(to=self._their_addr, ciphertext=ct))

    async def messages(self) -> AsyncGenerator[str, None]:
        """
        Async generator that yields decrypted incoming messages.

        Lets ``InvalidTag`` propagate on authentication failure — a tampered
        or replayed message must be rejected, not silently dropped.
        """
        async for envelope in self._client:
            plaintext = decrypt(self._key, envelope.ciphertext)
            yield plaintext.decode()
