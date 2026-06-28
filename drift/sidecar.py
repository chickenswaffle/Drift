"""
drift.sidecar — a JSON-RPC-over-stdio bridge for GUI front-ends.

This is the seam the desktop app (``apps/desktop/``, Tauri + React) talks to.
The Tauri shell spawns ``python -m drift.sidecar`` as a child process and
exchanges newline-delimited JSON over its stdin/stdout. The sidecar wraps the
*existing, audited* Python core (``drift.storage`` + ``drift.transport``) — it
adds **no** cryptography of its own. Per AGENTS.md this keeps a single crypto
implementation: the GUI is just another "view" over ``drift.storage``, exactly
like the CLI and the TUI.

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

This module deliberately exposes only 1:1 chat + identity/contact/vault
management — the Phase 13c desktop scope. Groups, rooms and beacon are wired in
later sub-phases.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import threading
from collections.abc import Awaitable, Callable
from typing import Any

from drift import storage
from drift.crypto import Identity

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
            logger.exception("chat reader for %s failed", self.convo)
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
            logger.exception("error closing session for %s", self.convo)


class Sidecar:
    """Dispatches RPC methods and owns the live-conversation table."""

    def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop
        self._convos: dict[str, _Conversation] = {}
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
            "chat_open": self._chat_open,
            "chat_send": self._chat_send,
            "chat_close": self._chat_close,
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
        except Exception as exc:  # last-resort guard — never kill the bridge
            logger.exception("handler %s failed", method)
            _write_frame({"id": req_id, "ok": False, "error": f"{type(exc).__name__}: {exc}"})

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
        identity = Identity.generate()
        passphrase = params.get("passphrase")
        if passphrase:
            storage.create_vault(
                identity,
                passphrase,
                duress_passphrase=params.get("duress_passphrase") or None,
                duress_mode=params.get("duress_mode") or "wipe",
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
        return {"fmd_rate": storage.set_fmd_rate(float(params.get("rate", 0.0)))}

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
        from drift.transport.session import Session

        convo = str(params.get("contact", ""))
        if not convo:
            raise RpcError("chat_open requires a contact name")
        if convo in self._convos:
            return {"convo": convo, "already_open": True}

        identity = storage.load_identity()
        contacts = storage.load_contacts(identity)
        entry = contacts.get(convo)
        if entry is None:
            raise RpcError(f"no such contact: {convo}")
        relay_url = str(params.get("relay_url") or DEFAULT_RELAY_URL)

        def on_event(kind: str, detail: str) -> None:
            _emit_event("chat_event", {"convo": convo, "kind": kind, "detail": detail})

        session = Session(
            identity,
            entry["code"],
            relay_url,
            on_event=on_event,
            prekeys=storage.ensure_prekeys(identity),
        )
        conversation = _Conversation(convo, session, self._loop)
        await conversation.start()
        self._convos[convo] = conversation
        return {"convo": convo, "relay_url": relay_url}

    async def _chat_send(self, params: dict[str, Any]) -> dict[str, Any]:
        convo = str(params.get("convo", ""))
        text = str(params.get("text", ""))
        conversation = self._convos.get(convo)
        if conversation is None:
            raise RpcError(f"no open conversation: {convo}")
        await conversation.send(text)
        return {"sent": True}

    async def _chat_close(self, params: dict[str, Any]) -> dict[str, Any]:
        convo = str(params.get("convo", ""))
        conversation = self._convos.pop(convo, None)
        if conversation is not None:
            await conversation.close()
        return {"closed": True}

    async def _close_all_convos(self) -> None:
        for convo in list(self._convos):
            conversation = self._convos.pop(convo, None)
            if conversation is not None:
                await conversation.close()


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
