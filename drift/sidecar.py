"""
drift.sidecar — a JSON-RPC-over-stdio bridge for GUI front-ends.

This is the seam the desktop app (``apps/desktop/``, Tauri + React) talks to.
The Tauri shell spawns ``python -m drift.sidecar`` as a child process and
exchanges newline-delimited JSON over its stdin/stdout. The sidecar wraps the
*existing, internally reviewed* Python core (``drift.storage`` +
``drift.transport``) — it adds **no** cryptography of its own. Per AGENTS.md
this keeps a single crypto implementation: the GUI is just another "view" over
``drift.storage``, exactly like the CLI and the TUI.

Wire protocol (one JSON object per line, UTF-8):

  request   {"id": <int>, "method": <str>, "params": {...}}
  response  {"id": <int>, "ok": true,  "result": {...}}
            {"id": <int>, "ok": false, "error": <str>}
  event     {"event": <str>, "data": {...}}        # unsolicited, no id

Events carry only non-secret, observable information (a received message's
plaintext for *this* user, transport status strings) — never key material.

Threading model
---------------
Everything runs on one asyncio loop. stdin is read on a dedicated blocking
thread (so the bridge works identically on Windows, where asyncio can't wrap a
console stdin pipe) and lines are handed to the loop via a thread-safe queue.
**All** stdout writes happen on the loop thread through :func:`_emit`, so frames
never interleave.

This module exposes 1:1 chat, sovereign rooms, broadcast channels and groups,
plus identity/contact/vault management — all as thin wrappers over the
*existing, internally reviewed* core (``drift.crypto.*``, ``drift.storage``,
``drift.transport``). It still adds no cryptography of its own.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import sys
import threading
from collections.abc import Awaitable, Callable
from typing import Any

from drift import storage
from drift.crypto import Identity, b58decode, b58encode, groups
from drift.crypto import rooms as rooms_crypto
from drift.crypto.groups import ContactInfo
from drift.crypto.rooms import Room

logger = logging.getLogger("drift.sidecar")

# Default reference relay (overridable per call or via $DRIFT_RELAY_URL). The
# desktop app surfaces this as a setting; localhost is the dev default that
# matches `python -m relay.server`.
# 127.0.0.1 rather than "localhost" on purpose: on dual-stack hosts "localhost"
# can resolve to IPv6 ::1 first, which a relay bound only to IPv4 won't answer.
DEFAULT_RELAY_URL = os.environ.get("DRIFT_RELAY_URL", "ws://127.0.0.1:8765")


class RpcError(Exception):
    """A handler-level failure returned to the caller as ``{ok: false}``."""


# ---------------------------------------------------------------------------
# Output — every stdout frame goes through here, on the loop thread only.
# ---------------------------------------------------------------------------

_stdout = sys.stdout


def _write_frame(obj: dict[str, Any]) -> None:
    _stdout.write(json.dumps(obj, separators=(",", ":")) + "\n")
    _stdout.flush()


def _emit_event(name: str, data: dict[str, Any]) -> None:
    """Push an unsolicited event to the front-end."""
    _write_frame({"event": name, "data": data})


# ---------------------------------------------------------------------------
# Live 1:1 conversations
# ---------------------------------------------------------------------------

class _Conversation:
    """One open :class:`drift.transport.Session`, with its reader task.

    ``convo`` is the contact's local name — the front-end's handle for the
    thread. The reader task drains ``session.messages()`` and re-emits each
    decrypted line as a ``message`` event; ``send`` pushes plaintext the other
    way. ``on_event`` from the transport becomes a ``chat_event`` event.
    """

    def __init__(self, convo: str, session: Any, loop: asyncio.AbstractEventLoop) -> None:
        self.convo = convo
        self.session = session
        self._loop = loop
        self._reader: asyncio.Task[None] | None = None

    async def start(self) -> None:
        await self.session.__aenter__()
        self._reader = self._loop.create_task(self._read_loop())

    async def _read_loop(self) -> None:
        try:
            async for msg in self.session.messages():
                _emit_event("message", {"convo": self.convo, "dir": "in", "text": msg})
        except asyncio.CancelledError:  # normal on close
            raise
        except Exception as exc:  # surface, don't crash the whole bridge
            # No convo name in the log line: stderr is inherited by the shell
            # process and may land in terminal scrollback or system logs.
            logger.exception("chat reader failed")
            _emit_event("chat_event", {"convo": self.convo, "kind": "error", "detail": str(exc)})

    async def send(self, text: str) -> None:
        await self.session.send(text)
        # Echo our own line back so the UI renders it from a single source.
        _emit_event("message", {"convo": self.convo, "dir": "out", "text": text})

    async def close(self) -> None:
        if self._reader is not None:
            self._reader.cancel()
            try:
                await self._reader
            except asyncio.CancelledError:
                pass
        try:
            await self.session.__aexit__(None, None, None)
        except Exception:
            logger.exception("error closing session")


class _RoomConversation:
    """A live :class:`RoomSession` (a sovereign room or a broadcast channel).

    ``convo`` is the room's local label. Inbound room messages carry a pseudonym
    (``who`` — the signed display name if any, else the 4-char sender tag) and an
    ``authorized`` flag, surfaced so the UI can mark unverified posts. Posting to
    a read-only room raises, which the caller reports as an ``{ok: false}``.
    """

    def __init__(self, convo: str, session: Any, loop: asyncio.AbstractEventLoop) -> None:
        self.convo = convo
        self.session = session
        self._loop = loop
        self._reader: asyncio.Task[None] | None = None

    async def start(self) -> None:
        await self.session.__aenter__()
        self._reader = self._loop.create_task(self._read_loop())

    async def _read_loop(self) -> None:
        try:
            async for rm in self.session.messages():
                who = rm.display_name if rm.display_name else rm.tag_label
                _emit_event("message", {
                    "convo": self.convo, "dir": "in", "text": rm.text,
                    "who": who, "authorized": bool(rm.authorized),
                })
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.exception("room reader failed")
            _emit_event("chat_event", {"convo": self.convo, "kind": "error", "detail": str(exc)})

    async def send(self, text: str) -> None:
        await self.session.send_to_room(text)
        _emit_event("message", {
            "convo": self.convo, "dir": "out", "text": text,
            "who": self.session.session_tag, "authorized": True,
        })

    async def close(self) -> None:
        if self._reader is not None:
            self._reader.cancel()
            try:
                await self._reader
            except asyncio.CancelledError:
                pass
        try:
            await self.session.__aexit__(None, None, None)
        except Exception:
            logger.exception("error closing room")


class _GroupConversation:
    """A live :class:`GroupSession` (pairwise-composed ≤10-member group).

    Inbound messages carry the authenticated sender's local name in ``who``.
    Membership changes surface as ``chat_event`` (kind ``membership``).
    """

    def __init__(self, convo: str, session: Any, loop: asyncio.AbstractEventLoop) -> None:
        self.convo = convo
        self.session = session
        self._loop = loop
        self._reader: asyncio.Task[None] | None = None

    async def start(self) -> None:
        await self.session.__aenter__()
        self._reader = self._loop.create_task(self._read_loop())

    async def _read_loop(self) -> None:
        try:
            async for gm in self.session.messages():
                _emit_event("message", {
                    "convo": self.convo, "dir": "in", "text": gm.text,
                    "who": gm.sender_name,
                })
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.exception("group reader failed")
            _emit_event("chat_event", {"convo": self.convo, "kind": "error", "detail": str(exc)})

    async def send(self, text: str) -> None:
        await self.session.send_to_group(text)
        _emit_event("message", {"convo": self.convo, "dir": "out", "text": text, "who": "you"})

    async def close(self) -> None:
        if self._reader is not None:
            self._reader.cancel()
            try:
                await self._reader
            except asyncio.CancelledError:
                pass
        try:
            await self.session.__aexit__(None, None, None)
        except Exception:
            logger.exception("error closing group")


class Sidecar:
    """Dispatches RPC methods and owns the live-conversation table."""

    def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop
        self._convos: dict[str, _Conversation] = {}
        # One lock per conversation key. Requests are dispatched as independent
        # tasks (see _serve), so without this a close/rotate/leave could pop a
        # conversation out from under an in-flight send on the same key.
        self._convo_locks: dict[str, asyncio.Lock] = {}
        self._handlers: dict[str, Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]] = {
            "ping": self._ping,
            "status": self._status,
            "init": self._init,
            "whoami": self._whoami,
            "contacts_list": self._contacts_list,
            "contacts_add": self._contacts_add,
            "safety_number": self._safety_number,
            "fmd_get": self._fmd_get,
            "fmd_set": self._fmd_set,
            "lock": self._lock,
            "unlock": self._unlock,
            "vault_create": self._vault_create,
            "chat_open": self._chat_open,
            "chat_send": self._chat_send,
            "chat_close": self._chat_close,
            # channels & rooms (sovereign rooms / broadcast channels)
            "channels_list": self._channels_list,
            "channel_create": self._channel_create,
            "channel_join": self._channel_join,
            "room_create": self._room_create,
            "room_join": self._room_join,
            "room_invite": self._room_invite,
            "room_rotate": self._room_rotate,
            "room_leave": self._room_leave,
            # groups (≤10-member pairwise composition)
            "groups_list": self._groups_list,
            "group_create": self._group_create,
            "group_add": self._group_add,
            "group_remove": self._group_remove,
        }

    # -- dispatch ----------------------------------------------------------

    async def dispatch(self, req: dict[str, Any]) -> None:
        req_id = req.get("id")
        method = req.get("method")
        params = req.get("params") or {}
        handler = self._handlers.get(method) if isinstance(method, str) else None
        if handler is None:
            _write_frame({"id": req_id, "ok": False, "error": f"unknown method: {method}"})
            return
        try:
            result = await handler(params)
            _write_frame({"id": req_id, "ok": True, "result": result})
        except RpcError as exc:
            _write_frame({"id": req_id, "ok": False, "error": str(exc)})
        except storage.StorageError as exc:
            _write_frame({"id": req_id, "ok": False, "error": str(exc)})
        except Exception:  # last-resort guard — never kill the bridge
            logger.exception("handler %s failed", method)
            # Deliberately generic: an unexpected exception's repr can carry
            # paths or internal detail that doesn't belong in the UI.
            _write_frame({"id": req_id, "ok": False, "error": "internal error — see sidecar log"})

    def _convo_lock(self, key: str) -> asyncio.Lock:
        return self._convo_locks.setdefault(key, asyncio.Lock())

    # -- identity / model (synchronous core, awaited trivially) ------------

    async def _ping(self, _: dict[str, Any]) -> dict[str, Any]:
        return {"pong": True}

    async def _status(self, _: dict[str, Any]) -> dict[str, Any]:
        return {
            "identity_exists": storage.identity_exists(),
            "vault_exists": storage.vault_exists(),
            "fmd_rate": storage.get_fmd_rate(),
            "relay_url": DEFAULT_RELAY_URL,
        }

    async def _init(self, params: dict[str, Any]) -> dict[str, Any]:
        if storage.identity_exists():
            raise RpcError("identity already exists")
        duress_mode = params.get("duress_mode") or "wipe"
        if duress_mode not in ("wipe", "decoy"):
            raise RpcError("duress_mode must be 'wipe' or 'decoy'")
        identity = Identity.generate()
        passphrase = params.get("passphrase")
        if passphrase:
            storage.create_vault(
                identity,
                passphrase,
                duress_passphrase=params.get("duress_passphrase") or None,
                duress_mode=duress_mode,
                materialize=True,
            )
        else:
            storage.save_identity(identity)
        # Generate + persist the X3DH prekey bundle so async handshakes work.
        storage.ensure_prekeys(identity)
        return {"contact_code": identity.contact_code()}

    async def _whoami(self, _: dict[str, Any]) -> dict[str, Any]:
        identity = storage.load_identity()
        return {"contact_code": identity.contact_code()}

    async def _contacts_list(self, _: dict[str, Any]) -> dict[str, Any]:
        identity = storage.load_identity()
        contacts = storage.load_contacts(identity)
        return {"contacts": {name: c["code"] for name, c in contacts.items()}}

    async def _contacts_add(self, params: dict[str, Any]) -> dict[str, Any]:
        identity = storage.load_identity()
        name = str(params.get("name", ""))
        code = str(params.get("code", ""))
        contacts = storage.add_contact(identity, name, code)
        return {"contacts": {n: c["code"] for n, c in contacts.items()}}

    async def _safety_number(self, params: dict[str, Any]) -> dict[str, Any]:
        identity = storage.load_identity()
        code = str(params.get("code", ""))
        if "name" in params:
            contacts = storage.load_contacts(identity)
            entry = contacts.get(params["name"])
            if entry is None:
                raise RpcError(f"no such contact: {params['name']}")
            code = entry["code"]
        if not storage.is_valid_contact_code(code):
            raise RpcError("invalid contact code")
        return {"safety_number": storage.safety_number(identity, code)}

    async def _fmd_get(self, _: dict[str, Any]) -> dict[str, Any]:
        return {"fmd_rate": storage.get_fmd_rate()}

    async def _fmd_set(self, params: dict[str, Any]) -> dict[str, Any]:
        try:
            rate = float(params.get("rate", 0.0))
        except (TypeError, ValueError):
            raise RpcError("fmd rate must be a number") from None
        if not (0.0 <= rate <= 1.0):  # also rejects NaN
            raise RpcError("fmd rate must be between 0 and 1")
        return {"fmd_rate": storage.set_fmd_rate(rate)}

    async def _lock(self, params: dict[str, Any]) -> dict[str, Any]:
        passphrase = params.get("passphrase")
        if not passphrase:
            raise RpcError("lock requires a passphrase")
        # Close any live conversations first — they hold a loaded identity.
        await self._close_all_convos()
        ok = storage.lock(str(passphrase))
        return {"locked": ok}

    async def _unlock(self, params: dict[str, Any]) -> dict[str, Any]:
        passphrase = params.get("passphrase")
        if not passphrase:
            raise RpcError("unlock requires a passphrase")
        result = storage.unlock(str(passphrase))
        # Indistinguishable by design: real / decoy / wipe all return PROCEED.
        return {"result": result, "ok": result == storage.UNLOCK_PROCEED}

    # -- live chat ---------------------------------------------------------

    async def _chat_open(self, params: dict[str, Any]) -> dict[str, Any]:
        """Open a live conversation. ``kind`` selects the transport:

        - ``contact`` (default) — a 1:1 :class:`Session` keyed by ``contact``.
        - ``room`` / ``channel`` — a :class:`RoomSession` keyed by ``label``.
        - ``group`` — a :class:`GroupSession` keyed by ``label``.

        All three land in the same ``_convos`` map, so ``chat_send``/``chat_close``
        stay type-agnostic.
        """
        kind = str(params.get("kind") or "contact")
        relay_url = str(params.get("relay_url") or DEFAULT_RELAY_URL)
        identity = storage.load_identity()

        if kind == "contact":
            from drift.transport.session import Session

            convo = str(params.get("contact", ""))
            if not convo:
                raise RpcError("chat_open requires a contact name")
            async with self._convo_lock(convo):
                if convo in self._convos:
                    return {"convo": convo, "already_open": True}
                contacts = storage.load_contacts(identity)
                entry = contacts.get(convo)
                if entry is None:
                    raise RpcError(f"no such contact: {convo}")

                def on_event(k: str, d: str) -> None:
                    _emit_event("chat_event", {"convo": convo, "kind": k, "detail": d})

                session: Any = Session(
                    identity, entry["code"], relay_url,
                    on_event=on_event, prekeys=storage.ensure_prekeys(identity),
                )
                conversation: Any = _Conversation(convo, session, self._loop)
                await conversation.start()
                self._convos[convo] = conversation
                return {"convo": convo, "kind": "contact", "relay_url": relay_url}

        label = str(params.get("label", ""))
        if not label:
            raise RpcError("chat_open requires a label")
        async with self._convo_lock(label):
            if label in self._convos:
                return {"convo": label, "already_open": True}

            if kind in ("room", "channel"):
                from drift.transport.room_session import RoomSession

                room = storage.get_room(identity, label)  # channels share the rooms store
                if room is None:
                    raise RpcError(f"no such room or channel: {label}")

                def on_event(k: str, d: str) -> None:
                    _emit_event("chat_event", {"convo": label, "kind": k, "detail": d})

                session = RoomSession(identity, room, relay_url, on_event=on_event)
                conversation = _RoomConversation(label, session, self._loop)
                await conversation.start()
                self._convos[label] = conversation
                return {
                    "convo": label, "kind": room.kind, "tier": room.tier,
                    "can_post": session.can_post(), "session_tag": session.session_tag,
                    "relay_url": relay_url,
                }

            if kind == "group":
                from drift.transport.session import GroupSession

                group = storage.get_group(identity, label)
                if group is None:
                    raise RpcError(f"no such group: {label}")

                def on_event(k: str, d: str) -> None:
                    _emit_event("chat_event", {"convo": label, "kind": k, "detail": d})

                def on_membership(change: Any) -> None:
                    verb = "added" if change.action == "add" else "removed"
                    _emit_event("chat_event", {
                        "convo": label, "kind": "membership",
                        "detail": f"{change.target.name} {verb}",
                    })

                session = GroupSession(
                    identity, group, relay_url,
                    on_event=on_event, on_membership=on_membership,
                )
                conversation = _GroupConversation(label, session, self._loop)
                await conversation.start()
                self._convos[label] = conversation
                return {"convo": label, "kind": "group", "size": group.size, "relay_url": relay_url}

        raise RpcError(f"unknown chat kind: {kind!r}")

    async def _chat_send(self, params: dict[str, Any]) -> dict[str, Any]:
        convo = str(params.get("convo", ""))
        text = str(params.get("text", ""))
        async with self._convo_lock(convo):
            conversation = self._convos.get(convo)
            if conversation is None:
                raise RpcError(f"no open conversation: {convo}")
            await conversation.send(text)
        return {"sent": True}

    async def _chat_close(self, params: dict[str, Any]) -> dict[str, Any]:
        convo = str(params.get("convo", ""))
        async with self._convo_lock(convo):
            conversation = self._convos.pop(convo, None)
            if conversation is not None:
                await conversation.close()
        self._convo_locks.pop(convo, None)
        return {"closed": True}

    # -- vault -------------------------------------------------------------

    async def _vault_create(self, params: dict[str, Any]) -> dict[str, Any]:
        """Seal the current identity behind a passphrase (enables lock/unlock).

        Reuses ``storage.create_vault`` — the same call ``_init`` makes when a
        passphrase is supplied at onboarding. An optional duress passphrase arms
        the panic/duress slot (``duress_mode`` = ``wipe`` | ``decoy``)."""
        if storage.vault_exists():
            raise RpcError("a vault already exists")
        passphrase = params.get("passphrase")
        if not passphrase:
            raise RpcError("vault_create requires a passphrase")
        identity = storage.load_identity()
        storage.create_vault(
            identity,
            str(passphrase),
            duress_passphrase=params.get("duress_passphrase") or None,
            duress_mode=params.get("duress_mode") or "wipe",
            materialize=True,
        )
        return {"vault_exists": True}

    # -- channels & rooms --------------------------------------------------

    @staticmethod
    def _room_token(room: Room) -> str:
        """The base58 invite/posting token for an invite room or channel."""
        if not room.post_secret_b58:
            raise RpcError("not an invite room (no posting secret)")
        return rooms_crypto.encode_invite_token(b58decode(room.post_secret_b58))

    async def _channels_list(self, _: dict[str, Any]) -> dict[str, Any]:
        identity = storage.load_identity()
        all_rooms = storage.load_rooms(identity)

        def describe(label: str, r: Room) -> dict[str, Any]:
            can_post = r.tier != rooms_crypto.TIER_INVITE or r.post_secret_b58 is not None
            return {
                "label": label, "tier": r.tier, "kind": r.kind,
                "is_owner": r.is_owner, "can_post": can_post,
                "message_count": r.message_count,
            }

        return {
            "channels": [describe(lbl, r) for lbl, r in all_rooms.items() if r.is_channel],
            "rooms": [describe(lbl, r) for lbl, r in all_rooms.items() if not r.is_channel],
        }

    async def _channel_create(self, params: dict[str, Any]) -> dict[str, Any]:
        identity = storage.load_identity()
        name = str(params.get("name", "")).strip()
        if not name:
            raise RpcError("channel name required")
        label = str(params.get("label") or name)
        if storage.get_room(identity, label) is not None:
            raise RpcError(f"a room or channel labelled {label!r} already exists")
        channel = rooms_crypto.make_room(
            name, tier=rooms_crypto.TIER_INVITE, label=label, kind="channel")
        storage.add_channel(identity, channel)
        return {"label": channel.label, "kind": "channel", "tier": channel.tier,
                "share_code": name}

    async def _channel_join(self, params: dict[str, Any]) -> dict[str, Any]:
        identity = storage.load_identity()
        name = str(params.get("name", "")).strip()
        if not name:
            raise RpcError("channel name required")
        label = str(params.get("label") or name)
        if storage.get_room(identity, label) is not None:
            raise RpcError(f"already have a room or channel labelled {label!r}")
        # A read-only subscriber holds no posting secret: they read by name.
        channel = Room(label=label, tier=rooms_crypto.TIER_INVITE, name=name, kind="channel")
        storage.add_channel(identity, channel)
        return {"label": label, "kind": "channel", "tier": "invite"}

    async def _room_create(self, params: dict[str, Any]) -> dict[str, Any]:
        identity = storage.load_identity()
        tier = str(params.get("tier") or rooms_crypto.TIER_OPEN)
        if tier not in rooms_crypto.TIERS:
            raise RpcError(f"unknown room tier: {tier}")
        name = str(params.get("name") or "").strip() or None
        if tier != rooms_crypto.TIER_DARK and not name:
            raise RpcError("open and invite rooms need a name")
        label = params.get("label")
        room = rooms_crypto.make_room(name, tier=tier, label=(str(label) if label else None))
        if storage.get_room(identity, room.label) is not None:
            raise RpcError(f"a room labelled {room.label!r} already exists")
        storage.add_room(identity, room)
        result: dict[str, Any] = {"label": room.label, "kind": "room", "tier": room.tier}
        result["share_code"] = room.to_qr() if tier == rooms_crypto.TIER_DARK else room.name
        if tier == rooms_crypto.TIER_INVITE:
            result["token"] = self._room_token(room)
        return result

    async def _room_join(self, params: dict[str, Any]) -> dict[str, Any]:
        identity = storage.load_identity()
        label = params.get("label")
        descriptor = params.get("descriptor")
        if descriptor:
            room = Room.from_qr(str(descriptor), label=(str(label) if label else None))
        else:
            name = str(params.get("name", "")).strip()
            if not name:
                raise RpcError("room name or descriptor required")
            token = params.get("token")
            post_b58 = None
            tier = rooms_crypto.TIER_OPEN
            if token:
                post_b58 = b58encode(rooms_crypto.decode_invite_token(str(token)))
                tier = rooms_crypto.TIER_INVITE
            elif params.get("invite_only"):
                tier = rooms_crypto.TIER_INVITE
            room = Room(label=str(label or name), tier=tier, name=name, post_secret_b58=post_b58)
        if storage.get_room(identity, room.label) is not None:
            raise RpcError(f"already joined {room.label!r}")
        storage.add_room(identity, room)
        can_post = room.tier != rooms_crypto.TIER_INVITE or room.post_secret_b58 is not None
        return {"label": room.label, "kind": room.kind, "tier": room.tier, "can_post": can_post}

    async def _room_invite(self, params: dict[str, Any]) -> dict[str, Any]:
        identity = storage.load_identity()
        label = str(params.get("label", ""))
        room = storage.get_room(identity, label)
        if room is None:
            raise RpcError(f"unknown room: {label}")
        return {"token": self._room_token(room)}

    async def _room_rotate(self, params: dict[str, Any]) -> dict[str, Any]:
        """Roll a room/channel's code. A fresh, unguessable name re-derives all
        key material (the name *is* the key), while the local label stays put so
        it's the same conversation. Old subscribers and tokens are locked out
        until they get the new code — the honest 'revoke' on a blind relay."""
        identity = storage.load_identity()
        label = str(params.get("label", ""))
        async with self._convo_lock(label):
            room = storage.get_room(identity, label)
            if room is None:
                raise RpcError(f"unknown room or channel: {label}")
            if room.tier == rooms_crypto.TIER_DARK:
                raise RpcError("dark rooms can't roll by name — create a new one")
            room.name = f"{room.label}~{secrets.token_urlsafe(6)}"
            if room.tier == rooms_crypto.TIER_INVITE:
                room.post_secret_b58 = b58encode(rooms_crypto.generate_post_secret())
            storage.add_room(identity, room)
            conv = self._convos.pop(label, None)  # drop the live session bound to the old address
            if conv is not None:
                await conv.close()
            result: dict[str, Any] = {"label": label, "share_code": room.name}
            if room.tier == rooms_crypto.TIER_INVITE and not room.is_channel:
                result["token"] = self._room_token(room)
            return result

    async def _room_leave(self, params: dict[str, Any]) -> dict[str, Any]:
        identity = storage.load_identity()
        label = str(params.get("label", ""))
        async with self._convo_lock(label):
            conv = self._convos.pop(label, None)
            if conv is not None:
                await conv.close()
            storage.remove_room(identity, label)
        self._convo_locks.pop(label, None)
        return {"left": True}

    # -- groups ------------------------------------------------------------

    async def _groups_list(self, _: dict[str, Any]) -> dict[str, Any]:
        identity = storage.load_identity()
        saved = storage.load_groups(identity)
        return {"groups": [
            {
                "label": label, "size": g.size,
                "members": [{"name": m.name, "code": m.code} for m in g.members],
            }
            for label, g in saved.items()
        ]}

    async def _group_create(self, params: dict[str, Any]) -> dict[str, Any]:
        identity = storage.load_identity()
        name = str(params.get("name", "")).strip()
        if not name:
            raise RpcError("group name required")
        members = params.get("members") or []
        if not isinstance(members, list) or not all(isinstance(m, str) for m in members):
            raise RpcError("members must be a list of contact names")
        if len(members) > groups.GROUP_MAX_MEMBERS:
            raise RpcError(f"groups hold at most {groups.GROUP_MAX_MEMBERS} members")
        contacts = storage.load_contacts(identity)
        infos: list[ContactInfo] = []
        for member_name in members:
            entry = contacts.get(member_name)
            if entry is None:
                raise RpcError(f"no such contact: {member_name}")
            infos.append(ContactInfo(name=member_name, code=entry["code"]))
        try:
            group = groups.create_group(name, infos)
        except groups.GroupError as exc:
            raise RpcError(str(exc)) from None
        storage.add_group(identity, group)
        return {"label": group.name, "size": group.size}

    async def _group_add(self, params: dict[str, Any]) -> dict[str, Any]:
        identity = storage.load_identity()
        label = str(params.get("group", ""))
        member_name = str(params.get("member_name", ""))
        entry = storage.load_contacts(identity).get(member_name)
        if entry is None:
            raise RpcError(f"no such contact: {member_name}")
        info = ContactInfo(name=member_name, code=entry["code"])
        async with self._convo_lock(label):
            conv = self._convos.get(label)
            try:
                if isinstance(conv, _GroupConversation):
                    await conv.session.add_member(info)  # announces pairwise to live members
                    storage.add_group(identity, conv.session.group)
                else:
                    group = storage.get_group(identity, label)
                    if group is None:
                        raise RpcError(f"no such group: {label}")
                    groups.add_member(group, info)
                    storage.add_group(identity, group)
            except groups.GroupError as exc:
                raise RpcError(str(exc)) from None
        return {"added": member_name}

    async def _group_remove(self, params: dict[str, Any]) -> dict[str, Any]:
        identity = storage.load_identity()
        label = str(params.get("group", ""))
        code = str(params.get("code", ""))
        async with self._convo_lock(label):
            conv = self._convos.get(label)
            try:
                if isinstance(conv, _GroupConversation):
                    await conv.session.remove_member(code)
                    storage.add_group(identity, conv.session.group)
                else:
                    group = storage.get_group(identity, label)
                    if group is None:
                        raise RpcError(f"no such group: {label}")
                    groups.remove_member(group, code)
                    storage.add_group(identity, group)
            except groups.GroupError as exc:
                raise RpcError(str(exc)) from None
        return {"removed": code}

    async def _close_all_convos(self) -> None:
        for convo in list(self._convos):
            async with self._convo_lock(convo):
                conversation = self._convos.pop(convo, None)
                if conversation is not None:
                    await conversation.close()
            self._convo_locks.pop(convo, None)


# ---------------------------------------------------------------------------
# stdin pump + main loop
# ---------------------------------------------------------------------------

def _stdin_reader(loop: asyncio.AbstractEventLoop, queue: asyncio.Queue[str | None]) -> None:
    """Blocking line reader on its own thread (cross-platform, incl. Windows)."""
    for line in sys.stdin:
        loop.call_soon_threadsafe(queue.put_nowait, line)
    loop.call_soon_threadsafe(queue.put_nowait, None)  # EOF sentinel


async def _serve() -> None:
    loop = asyncio.get_running_loop()
    queue: asyncio.Queue[str | None] = asyncio.Queue()
    sidecar = Sidecar(loop)

    reader_thread = threading.Thread(
        target=_stdin_reader, args=(loop, queue), name="drift-sidecar-stdin", daemon=True
    )
    reader_thread.start()

    # Announce readiness so the shell knows the Python side is up.
    _emit_event("ready", {"pid": os.getpid()})

    while True:
        line = await queue.get()
        if line is None:  # stdin closed — shell is gone, shut down.
            break
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            _write_frame({"id": None, "ok": False, "error": "malformed JSON request"})
            continue
        # Each request runs as its own task so a long chat handler can't block
        # the dispatch loop; ordering within a single conversation is preserved
        # by the front-end (one in-flight send at a time).
        loop.create_task(sidecar.dispatch(req))

    await sidecar._close_all_convos()


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("DRIFT_SIDECAR_LOG", "WARNING").upper(),
        stream=sys.stderr,  # stdout is the RPC channel — keep logs off it
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    try:
        asyncio.run(_serve())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
