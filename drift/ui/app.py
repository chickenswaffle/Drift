"""
drift.ui.app — the DRIFT terminal client (Textual TUI)

This is the face of DRIFT. It is written as a tree of small, single-purpose
widgets — the same component decomposition a React app would use — so the
layout can later be ported to a web UI almost one-to-one:

    DriftApp                     (root / state container — like <App/>)
    ├─ Header
    │  ├─ LogoBox                condensed block wordmark
    │  ├─ LockIndicator          🔓/🔒 boxed channel-security signal
    │  ├─ SecurityBar            🔒 E2E · ⚡ RATCHET · ⬡ STEALTH · 🌐 TOR pills
    │  └─ HeaderBar              active contact · relay · connection
    ├─ CryptoTicker              live (non-secret) crypto-event feed (Ctrl+L)
    ├─ CommandPalette            [I] [A] [V] [C] [/] [Q]  (PillButton ×N)
    ├─ Body
    │  ├─ Sidebar                contact list (ContactItem ×N) + add
    │  ├─ ChatColumn
    │  │  ├─ pane-wrap           layered: LockWatermark (behind) + MessagePane
    │  │  │  ├─ LockWatermark    dim block padlock behind the messages
    │  │  │  └─ MessagePane      scrollable message log (per-line status)
    │  │  └─ InputBar            rule · prompt · input · counter · help bar
    │  └─ InfoPanel              slide-in session info (Ctrl+I)
    └─ Modals (pushed)           AddContactModal · VerifyModal · HelpModal ·
                                 IdentityModal

State lives on DriftApp and flows *down* into widgets via reactive props
(≈ React props); widgets emit *up* via Textual Messages (≈ DOM events that
bubble). No widget reaches sideways into another. The network/crypto work
happens in a background @work worker that talks to drift.transport.Session
and posts plain strings / typed events back — the UI never imports crypto.
Crypto-event messages (CryptoEvent) follow the same worker→UI pattern as
IncomingMessage; they report only non-secret, already-public information.

Colour language:
    #0a0a0a  deep black background
    #00ff41  matrix green — your messages, borders, active state
    #00d4ff  cyan         — contacts, incoming messages
    #888888  dim white    — timestamps, hints, secondary info
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import os
import random
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, ClassVar, TypeVar

import httpx
from rich.console import Group, RenderableType
from rich.rule import Rule as RichRule
from rich.table import Table
from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.events import Key
from textual.message import Message
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.timer import Timer
from textual.widgets import Button, Input, Static

from drift import __version__, storage
from drift.transport.session import Session

if TYPE_CHECKING:
    from textual.await_remove import AwaitRemove

    from drift.crypto import Identity
    from drift.storage import Contacts

__all__ = ["DriftApp"]

# Single source of truth for the version — the package, not a hardcoded string.
VERSION = f"v{__version__}"

# Palette as data — one row per command. (key, label, command-id)
_COMMANDS: list[tuple[str, str, str]] = [
    ("I", "Init", "init"),
    ("A", "Add Contact", "add"),
    ("V", "Verify", "verify"),
    ("C", "Contacts", "contacts"),
    ("/", "Command", "command"),
    ("Q", "Quit", "quit"),
]

# Security indicators. (label, tooltip, active). Tor is honestly inactive
# until Phase 3 lands — it renders dim and struck-through.
_SECURITY: list[tuple[str, str, bool]] = [
    ("🔒 E2E", "End-to-end encrypted — X25519 ECDH → HKDF → XChaCha20-Poly1305. "
               "The relay only ever sees ciphertext.", True),
    ("⚡ RATCHET", "Double Ratchet — every message uses a fresh key; a leaked key "
                   "cannot decrypt past or future messages.", True),
    ("⬡ STEALTH", "Stealth addresses — each message goes to a one-time address only "
                   "you can recognise; the relay can't link your messages.", True),
    ("🌐 TOR", "Tor transport — NOT active yet (Phase 3). Your IP is currently "
               "visible to the relay.", False),
]

# Condensed three-row block wordmark (the full six-row art is too tall for a header).
_LOGO_ROWS: tuple[str, ...] = (
    "█▀▄ █▀▄ █ █▀▀ ▀█▀",
    "█ █ █▀▄ █ █▀   █ ",
    "▀▀  ▀ ▀ ▀ ▀    ▀ ",
)

# Large block padlock rendered as a dim watermark behind the message pane. One
# shape per security state; lines are horizontally symmetric so centre-aligning
# them keeps the lock symmetric regardless of leading whitespace.
#   unsecured — shackle swung open (no secured session)
#   secured   — shackle closed (E2E + ratchet active)
#   max       — closed, with a faint cross in the keyhole (Tor also active; P3)
_LOCK_WATERMARK: dict[str, tuple[str, ...]] = {
    "unsecured": (
        "██████",
        "██    ██",
        "██",
        "████████████",
        "█  ██████  █",
        "█  ██████  █",
        "█  ██████  █",
        "████████████",
    ),
    "secured": (
        "██████",
        "██    ██",
        "██    ██",
        "████████████",
        "█  ██████  █",
        "█  ██████  █",
        "█  ██████  █",
        "████████████",
    ),
    "max": (
        "██████",
        "██    ██",
        "██    ██",
        "████████████",
        "█  ██████  █",
        "█  ██╋╋██  █",
        "█  ██████  █",
        "████████████",
    ),
}


def _now() -> str:
    return datetime.now().strftime("%H:%M:%S")


# ===========================================================================
# Themes — selected at module load via DRIFT_THEME env var.
# ===========================================================================

_THEMES: dict[str, dict[str, str]] = {
    "matrix": {
        "primary":       "#00ff41",
        "secondary":     "#00d4ff",
        "bg":            "#0a0a0a",
        "dim_bg":        "#060606",
        "modal_bg":      "#0c0c0c",
        "border":        "#1a5c1a",
        "hover_bg":      "#06160a",
        "hover_bg_off":  "#160606",  # inactive SecurityPill hover
        "dim":           "#888888",
        "warning":       "#ff4444",
        "scanlines":     "#00ff41 3.5%",
    },
    "amber": {
        "primary":       "#ffaa00",
        "secondary":     "#ff6600",
        "bg":            "#0a0800",
        "dim_bg":        "#060500",
        "modal_bg":      "#0c0900",
        "border":        "#5c4500",
        "hover_bg":      "#160d00",
        "hover_bg_off":  "#160500",
        "dim":           "#887766",
        "warning":       "#ff3300",
        "scanlines":     "#ffaa00 3.5%",
    },
    "frost": {
        "primary":       "#88ccff",
        "secondary":     "#44aaff",
        "bg":            "#080c10",
        "dim_bg":        "#060810",
        "modal_bg":      "#0a0e14",
        "border":        "#1a3a5c",
        "hover_bg":      "#061018",
        "hover_bg_off":  "#060818",
        "dim":           "#8899aa",
        "warning":       "#ff6644",
        "scanlines":     "#88ccff 3%",
    },
    "redacted": {
        "primary":       "#ff3333",
        "secondary":     "#ff8800",
        "bg":            "#0a0a0a",
        "dim_bg":        "#060606",
        "modal_bg":      "#0c0c0c",
        "border":        "#5c1a1a",
        "hover_bg":      "#160808",
        "hover_bg_off":  "#100000",
        "dim":           "#888888",
        "warning":       "#ff0000",
        "scanlines":     "#ff3333 3%",
    },
    "ghost": {
        "primary":       "#bbbbbb",
        "secondary":     "#999999",
        "bg":            "#0a0a0a",
        "dim_bg":        "#060606",
        "modal_bg":      "#0c0c0c",
        "border":        "#3a3a3a",
        "hover_bg":      "#111111",
        "hover_bg_off":  "#0e0e0e",
        "dim":           "#666666",
        "warning":       "#ff4444",
        "scanlines":     "#bbbbbb 2%",
    },
}

_ACTIVE_THEME = _THEMES.get(
    os.environ.get("DRIFT_THEME", "matrix").lower(), _THEMES["matrix"]
)

# Short aliases used in Rich markup and render() methods throughout this module.
_P  = _ACTIVE_THEME["primary"]
_S  = _ACTIVE_THEME["secondary"]
_DM = _ACTIVE_THEME["dim"]
_BG = _ACTIVE_THEME["bg"]
_BD = _ACTIVE_THEME["border"]
_HB = _ACTIVE_THEME["hover_bg"]
_HBI = _ACTIVE_THEME["hover_bg_off"]
_DB = _ACTIVE_THEME["dim_bg"]
_MB = _ACTIVE_THEME["modal_bg"]
_WN = _ACTIVE_THEME["warning"]


def _build_css(t: dict[str, str]) -> str:
    p   = t["primary"]
    bg  = t["bg"]
    db  = t["dim_bg"]
    mb  = t["modal_bg"]
    bd  = t["border"]
    hb  = t["hover_bg"]
    hbi = t["hover_bg_off"]
    dm  = t["dim"]
    sc  = t["scanlines"]
    return f"""
    Screen {{ background: {bg}; }}

    #root {{
        background: {bg};
        hatch: horizontal {sc};
    }}

    /* ── Header ─────────────────────────────────────────────── */
    #header {{ height: 5; padding: 0 1; background: {bg}; }}
    #header-top {{ height: 3; }}
    #logo {{ width: auto; height: 3; content-align: left middle; }}
    #lock {{
        width: auto; height: 3; margin: 0 2 0 2; content-align: center middle;
    }}
    #header-spacer {{ width: 1fr; height: 3; }}
    #security {{ width: auto; height: 3; content-align: right middle; }}
    UptimePill, LatencyPill, RatchetPill {{
        width: auto; height: 3; padding: 0 1; content-align: center middle;
    }}
    SecurityPill {{
        width: auto; height: 3; padding: 0 1; margin: 0 0 0 1;
        background: {bg}; content-align: center middle;
    }}
    SecurityPill:hover {{ background: {hb}; }}
    SecurityPill.inactive:hover {{ background: {hbi}; }}
    #headerinfo {{ height: 1; }}
    #header-rule {{ height: 1; }}

    /* ── Crypto ticker ──────────────────────────────────────── */
    #ticker {{
        height: 1; padding: 0 1; background: {db}; color: {dm};
    }}

    /* ── Command palette ────────────────────────────────────── */
    #palette {{ height: 1; padding: 0 1; background: {bg}; }}
    PillButton {{
        width: auto; height: 1; padding: 0 2; margin: 0 1 0 0;
        color: {dm}; background: {bg};
    }}
    PillButton:hover {{ color: {bg}; background: {p}; text-style: bold; }}
    PillButton:focus {{ color: {p}; background: {hb}; text-style: bold; }}

    /* ── Body: sidebar + chat + info ────────────────────────── */
    #body {{ height: 1fr; }}

    #sidebar {{
        width: 22; background: {db}; border-right: solid {bd}; padding: 0 1;
    }}
    #sidebar-title {{ height: 1; padding: 0 1; }}
    #contact-list {{ height: 1fr; }}
    ContactItem {{ width: 100%; height: 1; padding: 0 1; background: {db}; }}
    ContactItem:hover {{ background: {hb}; }}
    ContactItem.active {{ background: {hb}; }}
    .empty-hint {{ padding: 1; color: #555555; }}

    /* ── Chat column ────────────────────────────────────────── */
    #chat {{ width: 1fr; }}
    #pane-wrap {{ height: 1fr; layers: watermark messages; }}
    #watermark {{
        layer: watermark; width: 100%; height: 100%;
        content-align: center middle; text-align: center;
        color: {p} 8%;
    }}
    #pane {{
        layer: messages; height: 100%; background: transparent; border: solid {bd};
        scrollbar-color: {p}; scrollbar-background: {bg};
        scrollbar-gutter: stable; scrollbar-size-vertical: 1; padding: 0 1;
    }}
    #pane > Static {{ width: 100%; height: auto; }}
    #pane.flash {{ border: solid {p}; background: {hb}; }}
    #netpane {{
        display: none; height: 1fr;
        background: {bg}; border: solid {bd};
        padding: 1 2; overflow-y: auto;
        scrollbar-color: {p}; scrollbar-size-vertical: 1;
    }}

    /* ── Session info panel (slide-in, right) ───────────────── */
    #infopanel {{
        dock: right; width: 48; height: 1fr; display: none; overflow-y: auto;
        background: {db}; border-left: solid {bd}; padding: 1 2;
        scrollbar-color: {p}; scrollbar-size-vertical: 1;
    }}

    /* ── Input bar ──────────────────────────────────────────── */
    #input {{ height: 3; padding: 0 1; background: {bg}; }}
    #input-rule {{ height: 1; }}
    #input-row {{ height: 1; }}
    #prompt {{ width: 2; color: {p}; text-style: bold; }}
    #msg-input {{
        width: 1fr; height: 1; padding: 0; border: none;
        background: {bg}; color: #e0e0e0;
    }}
    #msg-input:focus {{ border: none; }}
    #char-count {{ width: 6; content-align: right middle; color: {dm}; }}
    #input-hint {{ height: 1; color: {dm}; }}

    /* ── Modals ─────────────────────────────────────────────── */
    _FadeModal {{ align: center middle; background: {bg} 75%; }}
    #modal-box {{
        width: 64; height: auto; max-height: 80%; padding: 1 2;
        background: {mb}; border: round {p};
    }}
    .modal-title {{ height: 1; text-align: center; }}
    .field-label {{ height: 1; margin: 1 0 0 0; }}
    .modal-error {{ height: 1; text-align: center; }}
    .modal-hint {{ margin: 1 0; }}
    .modal-actions {{ height: auto; align: center middle; margin: 1 0 0 0; }}
    .modal-actions Button {{ margin: 0 1; }}
    #safety-number, #own-code {{ height: 1; text-align: center; margin: 1 0; text-style: bold; }}
    #help-body {{ height: auto; }}
    AddContactModal Input {{ margin: 0 0 0 0; }}
    """


# ===========================================================================
# Domain events (bubble up from widgets → app). Like custom DOM events.
# ===========================================================================

class CommandSelected(Message):
    """A command palette pill (or its shortcut) was activated."""
    def __init__(self, command: str) -> None:
        super().__init__()
        self.command = command


class ContactSelected(Message):
    """A sidebar contact row was clicked."""
    def __init__(self, name: str) -> None:
        super().__init__()
        self.name = name


class SecurityPillClicked(Message):
    """A security indicator was clicked — show its one-line explanation."""
    def __init__(self, label: str, tooltip: str) -> None:
        super().__init__()
        self.label = label
        self.tooltip = tooltip


class IncomingMessage(Message):
    """Worker → UI: a decrypted message arrived for a contact."""
    def __init__(self, contact: str, text: str) -> None:
        super().__init__()
        self.contact = contact
        self.text = text


class CryptoEvent(Message):
    """
    Worker → UI: a non-secret transport/crypto event for the live ticker.

    Same worker→UI pattern as IncomingMessage. Carries only public info (event
    kind + a short detail such as a one-time address prefix) — never plaintext
    or key material. The UI never imports crypto; it just renders these.
    """
    def __init__(self, kind: str, detail: str) -> None:
        super().__init__()
        self.kind = kind
        self.detail = detail
        self.ts = _now()


class SessionUp(Message):
    """Worker → UI: the session connected to the relay."""
    def __init__(self, contact: str) -> None:
        super().__init__()
        self.contact = contact


class SessionDown(Message):
    """Worker → UI: the session closed or errored."""
    def __init__(self, contact: str, reason: str) -> None:
        super().__init__()
        self.contact = contact
        self.reason = reason


class BurnEvent(Message):
    """Worker → UI: a verified burn tombstone arrived for a conversation."""
    def __init__(self, contact: str, scope: str, message_id: str | None) -> None:
        super().__init__()
        self.contact = contact
        self.scope = scope         # "message" or "conversation"
        self.message_id = message_id  # base64 one-time addr for message scope


@dataclass
class MessageRecord:
    """One rendered line of conversation history (model, not view)."""
    direction: str   # "in" | "out" | "sys"
    sender: str
    text: str
    ts: str


# ===========================================================================
# Presentational components
# ===========================================================================

class LogoBox(Static):
    """The condensed matrix-green DRIFT wordmark, sits left in the header."""

    def render(self) -> RenderableType:
        logo = Text("\n".join(_LOGO_ROWS), style=f"bold {_P}", no_wrap=True)
        return logo


class LockIndicator(Static):
    """
    The single most prominent security signal in the header: a boxed padlock
    whose colour and glyph track the live channel state. Sits just left of the
    security pills so it's the first thing the eye lands on.

        🔓  dim red    — unsecured (no active, connected session)
        🔒  bright green — secured (E2E + Double Ratchet active)
        🔒⁺ green + cyan superscript — maximum security (Tor also active; Phase 3)

    The box-drawing frame makes it read as a status panel rather than a bare
    emoji. ``maximum`` only has meaning when ``secure`` is also set.
    """

    secure: reactive[bool] = reactive(False)
    maximum: reactive[bool] = reactive(False)

    def render(self) -> RenderableType:
        if self.secure and self.maximum:
            colour = _P
            mid = f"[{colour}]│🔒[/][{_S}]⁺[/][{colour}]│[/]"
        elif self.secure:
            colour = _P
            mid = f"[{colour}]│ 🔒│[/]"
        else:
            colour = "#aa3333"  # dim red — channel not secured
            mid = f"[{colour}]│ 🔓│[/]"
        top = f"[{colour}]╭───╮[/]"
        bot = f"[{colour}]╰───╯[/]"
        return f"{top}\n{mid}\n{bot}"


class SecurityPill(Static):
    """A security indicator pill — bright green if active, dim+struck if not."""

    can_focus = True

    def __init__(self, label: str, tooltip_text: str, active: bool) -> None:
        super().__init__()
        self._label = label
        self._tip = tooltip_text
        self._active = active
        self.tooltip = tooltip_text  # native hover tooltip
        if not active:
            self.add_class("inactive")

    def render(self) -> RenderableType:
        if self._active:
            return f"[{_P}]{self._label}[/]"
        return f"[#555555 strike]{self._label}[/]"

    def on_click(self) -> None:
        self.post_message(SecurityPillClicked(self._label, self._tip))

    def on_key(self, event: Key) -> None:
        if event.key == "enter":
            self.post_message(SecurityPillClicked(self._label, self._tip))
            event.stop()


class SecurityBar(Horizontal):
    """The always-visible row of security indicators (right of the header)."""

    def compose(self) -> ComposeResult:
        for label, tooltip_text, active in _SECURITY:
            yield SecurityPill(label, tooltip_text, active)


def _ws_to_http(url: str) -> str:
    """Convert ws:// → http:// and wss:// → https:// for health-check requests."""
    return url.replace("wss://", "https://", 1).replace("ws://", "http://", 1)


class UptimePill(Static):
    """Session uptime counter: ⏱ HH:MM:SS. Ticks every second."""

    elapsed: reactive[int] = reactive(0)
    _start: float | None = None

    def on_mount(self) -> None:
        self.set_interval(1.0, self._tick)

    def _tick(self) -> None:
        if self._start is not None:
            self.elapsed = int(time.monotonic() - self._start)

    def start(self, ts: float) -> None:
        self._start = ts
        self.elapsed = 0

    def render(self) -> RenderableType:
        if self._start is None:
            return "[#444444]⏱ —[/]"
        h, rem = divmod(self.elapsed, 3600)
        m, s = divmod(rem, 60)
        return f"[#888888]⏱ {h:02d}:{m:02d}:{s:02d}[/]"


class LatencyPill(Static):
    """Relay round-trip latency: ⚡ Nms, color-coded green/yellow/red."""

    latency_ms: reactive[int | None] = reactive(None)

    def __init__(self, health_url: str, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._health_url = health_url

    def on_mount(self) -> None:
        self.set_interval(15.0, self._ping)

    async def _ping(self) -> None:
        try:
            t0 = time.monotonic()
            async with httpx.AsyncClient() as c:
                await c.get(self._health_url, timeout=3.0)
            self.latency_ms = int((time.monotonic() - t0) * 1000)
        except Exception:  # noqa: BLE001
            self.latency_ms = None

    def render(self) -> RenderableType:
        if self.latency_ms is None:
            return "[#444444]⚡ —[/]"
        ms = self.latency_ms
        colour = _P if ms < 100 else ("#cccc00" if ms < 300 else _WN)
        return f"[{colour}]⚡ {ms}ms[/]"


class RatchetPill(Static):
    """Ratchet step counter: ↻ N, flashes cyan for 300 ms on each step."""

    count: reactive[int] = reactive(0)
    flashing: reactive[bool] = reactive(False)

    def bump(self) -> None:
        self.count += 1
        self.flashing = True
        self.set_timer(0.3, self._stop_flash)

    def _stop_flash(self) -> None:
        self.flashing = False

    def render(self) -> RenderableType:
        colour = _S if self.flashing else "#555555"
        return f"[{colour}]↻ {self.count}[/]"


class HeaderBar(Static):
    """One line: active contact (left) · relay · version · connection (right)."""

    contact_name: reactive[str] = reactive("")
    relay_url: reactive[str] = reactive("")
    connected: reactive[bool] = reactive(False)
    pulse: reactive[bool] = reactive(True)

    def render(self) -> RenderableType:
        if self.connected:
            dot = f"[{_P}]⣿ secure[/]" if self.pulse else f"[{_BD}]⡇ secure[/]"
        else:
            dot = "[#555555]○ offline[/]"
        who = self.contact_name or "no contact selected"
        grid = Table.grid(expand=True)
        grid.add_column(justify="left", ratio=1)
        grid.add_column(justify="right")
        grid.add_row(
            f"[{_S}]▶ {who}[/]",
            f"[#888888]{self.relay_url}  ·  {VERSION}  ·[/]  {dot}",
        )
        return grid


class CryptoTicker(Static):
    """
    A one-line, dim, live feed of (non-secret) crypto events.

    Makes the cryptography visible without being intrusive. Toggled with Ctrl+L.
    """

    _ICON: ClassVar[dict[str, tuple[str, str]]] = {
        "ratchet": ("⚡", _S),
        "send": ("⬡", _P),
        "recv": ("⬡", _P),
        "erase": ("🔥", "#cc7722"),
        "burn": ("🔥", _WN),
    }

    def on_mount(self) -> None:
        self.update("[#444444]· awaiting crypto activity …[/]")

    def push(self, ts: str, kind: str, detail: str) -> None:
        icon, colour = self._ICON.get(kind, ("·", _DM))
        if kind == "send":
            body = f"stealth addr derived · {detail}"
        elif kind == "recv":
            body = f"inbound matched · {detail}"
        elif kind == "erase":
            body = "message key erased"
        elif kind == "burn":
            body = detail
        else:  # ratchet
            body = detail
        self.update(f"[#555555]\\[{ts}][/]  [{colour}]{icon} {body}[/]")


class PillButton(Static):
    """A clickable command pill: ``[K] Label``. Hover/focus highlights green."""

    can_focus = True

    def __init__(self, key_char: str, label: str, command: str) -> None:
        super().__init__()
        self.key_char = key_char
        self.label = label
        self.command = command

    def render(self) -> RenderableType:
        return f"[bold]{self.key_char}[/] {self.label}"

    def on_click(self) -> None:
        self.post_message(CommandSelected(self.command))

    def on_key(self, event: Key) -> None:
        if event.key == "enter":
            self.post_message(CommandSelected(self.command))
            event.stop()


class CommandPalette(Horizontal):
    """The always-visible row of command pills."""

    def compose(self) -> ComposeResult:
        for key_char, label, command in _COMMANDS:
            yield PillButton(key_char, label, command)


class ContactItem(Static):
    """One contact row in the sidebar: ``▶ name (unread)``."""

    can_focus = True

    def __init__(self, name: str, *, active: bool, unread: int) -> None:
        super().__init__()
        self.contact_name = name
        self.active = active
        self.unread = unread
        if active:
            self.add_class("active")

    def render(self) -> RenderableType:
        prefix = "▶" if self.active else " "
        colour = _P if self.active else _DM
        badge = f"  [{_S}]{self.unread}[/]" if self.unread else ""
        return f"[{colour}]{prefix} {self.contact_name}[/]{badge}"

    def on_click(self) -> None:
        self.post_message(ContactSelected(self.contact_name))

    def on_key(self, event: Key) -> None:
        if event.key == "enter":
            self.post_message(ContactSelected(self.contact_name))
            event.stop()


class Sidebar(Vertical):
    """Contact list with a header and an ``[+] Add`` action at the bottom."""

    def compose(self) -> ComposeResult:
        yield Static(f"[bold {_P}]CONTACTS[/]", id="sidebar-title")
        yield VerticalScroll(id="contact-list")
        yield PillButton("+", "Add Contact", "add")

    async def populate(
        self, contacts: Contacts, active: str | None, unread: dict[str, int]
    ) -> None:
        """Rebuild the contact rows from the current model state."""
        listing = self.query_one("#contact-list", VerticalScroll)
        await listing.remove_children()
        if not contacts:
            await listing.mount(Static("[dim]no contacts yet[/]", classes="empty-hint"))
            return
        await listing.mount(
            *(
                ContactItem(name, active=(name == active), unread=unread.get(name, 0))
                for name in contacts
            )
        )


class _SentLine(Static):
    """An outgoing message line whose delivery-status glyph can update in place."""

    _GLYPH: ClassVar[dict[str, tuple[str, str]]] = {
        "sending": ("◌", "#3a8a4a"),    # dim green
        "sent": ("✓", "#3a8a4a"),       # delivered to relay
        "failed": ("✗", _WN),
    }

    status: reactive[str] = reactive("sending")

    def __init__(self, text: str, ts: str) -> None:
        super().__init__()
        self._text = text
        self._ts = ts

    def render(self) -> RenderableType:
        glyph, colour = self._GLYPH.get(self.status, ("", "#3a8a4a"))
        line = Text(justify="right")
        line.append(f"{self._ts}  ", style=_DM)
        line.append("you:  ", style=f"bold {_P}")
        line.append(self._text, style="#b0ffb0")
        line.append(f"  {glyph}", style=colour)
        return line


class LockWatermark(Static):
    """
    A large, very dim block padlock painted *behind* the message pane (on a
    lower layer). It echoes the channel state — open lock when unsecured,
    closed when secured, closed-with-a-cross at maximum security — as a ghost
    image that never obscures message text (messages render on the layer above).
    """

    state: reactive[str] = reactive("unsecured")

    def render(self) -> RenderableType:
        rows = _LOCK_WATERMARK.get(self.state, _LOCK_WATERMARK["unsecured"])
        return Text("\n".join(rows), no_wrap=True)


class MessagePane(VerticalScroll):
    """Scrollable message log; each line is its own widget (mutable status)."""

    def _add(self, widget: Static) -> None:
        self.mount(widget)
        self.call_after_refresh(self.scroll_end, animate=False)

    def clear(self) -> AwaitRemove:
        return self.remove_children()

    def write_separator(self, label: str) -> None:
        self._add(Static(f"[{_BD}]▓▒░  {label}  ░▒▓[/]"))

    def write_incoming(self, sender: str, text: str, ts: str) -> None:
        self._add(Static(f"[{_DM}]{ts}[/]  [bold {_S}]{sender}:[/]  [white]{text}[/]"))
        self.flash()

    def write_outgoing(self, text: str, ts: str, *, status: str = "sending") -> _SentLine:
        line = _SentLine(text, ts)
        line.status = status
        self._add(line)
        return line

    def write_system(self, text: str) -> None:
        self._add(Static(f"[{_DM} italic]· {text}[/]"))

    def write_warning(self, text: str) -> None:
        self._add(Static(f"[bold red]⚠  {text}[/]"))

    def flash(self) -> None:
        """Briefly tint the border green when a new message lands."""
        self.add_class("flash")
        self.set_timer(0.35, lambda: self.remove_class("flash"))


class InputBar(Vertical):
    """Bottom composer: rule · (prompt + input + counter) · keyboard help bar."""

    HINT = (
        "[#888888]\\[Q]uit  ·  ^G info  ·  ^L log  ·  \\[V]erify  ·  \\[A]dd  ·  "
        "\\[/]command  ·  \\[↑↓]scroll[/]"
    )

    def compose(self) -> ComposeResult:
        yield Static(RichRule(style=_BD, characters="─"), id="input-rule")
        with Horizontal(id="input-row"):
            yield Static("▶", id="prompt")
            yield Input(placeholder="message — or /command", id="msg-input")
            yield Static("0", id="char-count")
        yield Static(self.HINT, id="input-hint")

    @on(Input.Changed, "#msg-input")
    def _on_changed(self, event: Input.Changed) -> None:
        n = len(event.value)
        colour = _WN if n > 1000 else "#ffaa00" if n > 800 else _DM
        self.query_one("#char-count", Static).update(f"[{colour}]{n}[/]")

    def reset_counter(self) -> None:
        self.query_one("#char-count", Static).update(f"[{_DM}]0[/]")

    @property
    def input(self) -> Input:
        return self.query_one("#msg-input", Input)


@dataclass
class NetworkState:
    """Snapshot of the current network topology. Extensible for Phase 3/4."""

    relay_url: str = ""
    relay_connected: bool = False
    relay_latency_ms: int | None = None
    peer_name: str | None = None
    peer_connected: bool = False
    ratchet_steps: int = 0
    stealth_addrs: int = 0
    # Phase 3 extensibility (Tor)
    tor_active: bool = False
    tor_hops: int = 0
    # Phase 4 extensibility (relay federation)
    federation_peers: list[str] = field(default_factory=list)


class NetworkPane(Static):
    """
    ASCII network topology diagram. Hidden by default; toggle with Ctrl+N.

    Call `update_graph(state)` whenever session state changes. The Phase 3/4
    fields in NetworkState are wired up but not yet populated — extend by
    passing a richer state when Tor and federation land.
    """

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._state = NetworkState()

    def on_mount(self) -> None:
        self._redraw()

    def update_graph(self, state: NetworkState) -> None:
        self._state = state
        self._redraw()

    def _redraw(self) -> None:
        self.update(self._build())

    def _build(self) -> RenderableType:
        s = self._state
        rc = _P if s.relay_connected else "#555555"
        pc = _S if s.peer_connected else "#555555"

        relay_host = s.relay_url.replace("ws://", "").replace("wss://", "")
        lat = f"⚡ {s.relay_latency_ms}ms" if s.relay_latency_ms is not None else "⚡ —"
        relay_status = "● connected" if s.relay_connected else "○ offline"
        down_arrow = "│ E2E + ↻ Ratchet" if s.relay_connected else "│"
        peer_arrow = "│ stealth" if s.peer_connected else "│"

        if s.peer_name:
            peer_label = s.peer_name
            peer_status = "● connected" if s.peer_connected else "○ offline"
        else:
            peer_label = "(no contact selected)"
            peer_status = "press C to select"

        # Tor note (Phase 3)
        tor_line = (
            f"\n  [{_S}]⬡ Tor active · {s.tor_hops} hops[/]" if s.tor_active else ""
        )

        # Federation note (Phase 4)
        fed_line = (
            f"\n  [{_DM}]⧉ {len(s.federation_peers)} federation peer(s)[/]"
            if s.federation_peers else ""
        )

        stats = (
            f"  [{_DM}]↻ {s.ratchet_steps} ratchet steps"
            f"  ·  ⬡ {s.stealth_addrs} stealth addrs[/]"
        )

        body = (
            "\n"
            "  ┌──────────┐\n"
            f"  │ [bold {_P}]YOU[/]      │\n"
            f"  │ [{_DM}]local[/]    │\n"
            "  └────┬─────┘\n"
            f"       [{_DM}]{down_arrow}[/]\n"
            "       ▼\n"
            "  ┌────────────────────────────┐\n"
            f"  │ [{rc}]{relay_host}[/]\n"
            f"  │ [{_DM}]{relay_status}  {lat}[/]\n"
            "  └────────────┬───────────────┘\n"
            f"               [{_DM}]{peer_arrow}[/]\n"
            "               ▼\n"
            "  ┌────────────────────────────┐\n"
            f"  │ [{pc}]{peer_label}[/]\n"
            f"  │ [{_DM}]{peer_status}[/]\n"
            "  └────────────────────────────┘\n"
            f"{tor_line}{fed_line}"
        )

        return Group(
            Text.from_markup(
                f"\n  [bold {_DM}]▶ NETWORK TOPOLOGY[/]  [#333333](^N to return to chat)[/]"
            ),
            RichRule(style=_BD, characters="─"),
            Text.from_markup(body),
            RichRule(style=_BD, characters="─"),
            Text.from_markup(f"{stats}\n"),
        )


class InfoPanel(Static):
    """Slide-in session info panel (Ctrl+I). Rendered from app-supplied data."""

    def __init__(self, id: str | None = None) -> None:
        super().__init__(id=id)
        self._active = False
        self._code = ""
        self._contact = ""
        self._safety = ""
        self._sent = 0
        self._recv = 0
        self._stealth = 0
        self._recent: list[str] = []
        self._relay = ""
        self._uptime = "—"

    def clear_data(self) -> None:
        self._active = False
        self.refresh()

    def show_data(
        self,
        *,
        code: str,
        contact: str,
        safety: str,
        sent: int,
        recv: int,
        stealth: int,
        recent: list[str],
        relay: str,
        uptime: str,
    ) -> None:
        self._active = True
        self._code = code
        self._contact = contact
        self._safety = safety
        self._sent = sent
        self._recv = recv
        self._stealth = stealth
        self._recent = recent
        self._relay = relay
        self._uptime = uptime
        self.refresh()

    @staticmethod
    def _field(label: str, value: str, colour: str = "#e0e0e0") -> Table:
        grid = Table.grid(expand=True)
        grid.add_column(justify="left")
        grid.add_row(Text(label, style=_DM))
        grid.add_row(Text(value, style=colour, no_wrap=True))
        return grid

    def render(self) -> RenderableType:
        if not self._active:
            return Text("no active session — select a contact", style="#555555")

        recent_str = "  ".join(self._recent) if self._recent else "—"
        caption = ("scan to add this contact" if _HAS_SEGNO
                   else "decorative · not scannable — share the code below")
        return Group(
            Text("⬡  SESSION", style=f"bold {_P}"),
            Text(""),
            _qr_renderable(self._code),
            Text(caption, style="italic #555555"),
            Text(""),
            self._field("your contact code", self._code, _S),
            Text(""),
            self._field(f"safety number · {self._contact}", self._safety, "#ffff00"),
            Text(""),
            self._field("ratchet messages",
                        f"↑ {self._sent} sent   ↓ {self._recv} received"),
            self._field("stealth addresses used", str(self._stealth)),
            self._field("recent addresses", recent_str, "#3a8a4a"),
            Text(""),
            self._field("relay", self._relay),
            self._field("session uptime", self._uptime),
        )


# A real, scannable QR is rendered with segno when it's installed (the optional
# ``qr`` extra); otherwise we fall back to a decorative block derived from the
# code hash. Resolved once at import.
_HAS_SEGNO = importlib.util.find_spec("segno") is not None


def _real_qr(data: str) -> Text:
    """A scannable QR of ``data`` — half-block cells (2 modules per text row)."""
    import segno

    rows = [list(row) for row in segno.make(data, error="l").matrix_iter(border=2)]
    if len(rows) % 2:
        rows.append([0] * len(rows[0]))
    out = Text(no_wrap=True)
    for r in range(0, len(rows), 2):
        top, bottom = rows[r], rows[r + 1]
        for c in range(len(top)):
            # Dark module → black, light → white (standard orientation). ▀ paints
            # the top module as foreground and the bottom module as background.
            fg = "black" if top[c] else "white"
            bg = "black" if bottom[c] else "white"
            out.append("▀", style=f"{fg} on {bg}")
        out.append("\n")
    return out


def _decorative_qr(data: str, n: int = 8) -> Text:
    """A decorative (NOT scannable) matrix-green block derived from the code."""
    bits: list[int] = []
    src = hashlib.sha256(data.encode()).digest()
    while len(bits) < n * n:
        for byte in src:
            for i in range(8):
                bits.append((byte >> i) & 1)
        src = hashlib.sha256(src).digest()
    rows: list[str] = []
    k = 0
    for _ in range(n):
        cells = []
        for _ in range(n):
            cells.append("██" if bits[k] else "  ")
            k += 1
        rows.append("".join(cells))
    return Text("\n".join(rows), style=_P, no_wrap=True)


def _qr_renderable(data: str) -> Text:
    """Real QR if segno is available, else the decorative fallback."""
    return _real_qr(data) if _HAS_SEGNO else _decorative_qr(data)


# ===========================================================================
# Modals (pushed onto the screen stack)
# ===========================================================================

_ModalResult = TypeVar("_ModalResult")


class _FadeModal(ModalScreen[_ModalResult]):
    """Base modal that fades its box in on mount."""

    _BOX_ID = "modal-box"

    def on_mount(self) -> None:
        box = self.query_one(f"#{self._BOX_ID}")
        box.styles.opacity = 0.0
        box.styles.animate("opacity", value=1.0, duration=0.18)


class AddContactModal(_FadeModal[tuple[str, str]]):
    """Collect a nickname + contact code; returns (name, code) or None."""

    BINDINGS: ClassVar[list[BindingType]] = [Binding("escape", "cancel", "Cancel", show=False)]

    def compose(self) -> ComposeResult:
        with Vertical(id="modal-box"):
            yield Static(f"[bold {_P}]＋  ADD CONTACT[/]", classes="modal-title")
            yield Static("[#888888]nickname[/]", classes="field-label")
            yield Input(placeholder="e.g. alice", id="nick")
            yield Static("[#888888]contact code[/]", classes="field-label")
            yield Input(placeholder="drift:…", id="code")
            yield Static("", id="add-error", classes="modal-error")
            with Horizontal(classes="modal-actions"):
                yield Button("Confirm", variant="success", id="confirm")
                yield Button("Cancel", variant="error", id="cancel")

    @on(Input.Submitted)
    def _submit(self) -> None:
        self._confirm()

    @on(Button.Pressed, "#confirm")
    def _on_confirm(self) -> None:
        self._confirm()

    @on(Button.Pressed, "#cancel")
    def action_cancel(self) -> None:
        self.dismiss(None)

    def _confirm(self) -> None:
        name = self.query_one("#nick", Input).value.strip()
        code = self.query_one("#code", Input).value.strip()
        error = self.query_one("#add-error", Static)
        if not name:
            error.update("[red]enter a nickname[/]")
            return
        if not storage.is_valid_contact_code(code):
            error.update("[red]that doesn't look like a drift: contact code[/]")
            return
        self.dismiss((name, code))


class VerifyModal(_FadeModal[bool]):
    """Show the safety number; returns True (confirmed) or False (abort)."""

    BINDINGS: ClassVar[list[BindingType]] = [Binding("escape", "abort", "Abort", show=False)]

    def __init__(self, contact_name: str, safety_number: str) -> None:
        super().__init__()
        self._contact_name = contact_name
        self._safety_number = safety_number

    def compose(self) -> ComposeResult:
        with Vertical(id="modal-box"):
            yield Static(
                f"[bold #ffff00]⚿  SAFETY NUMBER[/]  ·  with "
                f"[bold {_S}]{self._contact_name}[/]",
                classes="modal-title",
            )
            yield Static(
                f"[bold #ffff00 on #111100]  {self._safety_number}  [/]",
                id="safety-number",
            )
            yield Static(
                f"[{_DM}]Read these digits aloud over a trusted channel.\n"
                "If they match on both sides, the key is verified.[/]",
                classes="modal-hint",
            )
            with Horizontal(classes="modal-actions"):
                yield Button("Confirmed", variant="success", id="confirmed")
                yield Button("Abort", variant="error", id="abort")

    @on(Button.Pressed, "#confirmed")
    def _confirmed(self) -> None:
        self.dismiss(True)

    @on(Button.Pressed, "#abort")
    def action_abort(self) -> None:
        self.dismiss(False)


class IdentityModal(_FadeModal[None]):
    """Show the user's own contact code (the [I] action)."""

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("escape", "close", "Close", show=False),
        Binding("enter", "close", "Close", show=False),
    ]

    def __init__(self, contact_code: str) -> None:
        super().__init__()
        self._contact_code = contact_code

    def compose(self) -> ComposeResult:
        with Vertical(id="modal-box"):
            yield Static(f"[bold {_P}]⬡  YOUR IDENTITY[/]", classes="modal-title")
            yield Static(
                f"[bold {_S} on #001018]  {self._contact_code}  [/]",
                id="own-code",
            )
            yield Static(
                f"[{_DM}]Share this code so others can message you.\n"
                "Your private keys never leave this machine.[/]",
                classes="modal-hint",
            )
            with Horizontal(classes="modal-actions"):
                yield Button("Close", variant="primary", id="close")

    @on(Button.Pressed, "#close")
    def action_close(self) -> None:
        self.dismiss(None)


class HelpModal(_FadeModal[None]):
    """Full command reference overlay."""

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("escape", "close", "Close", show=False),
        Binding("enter", "close", "Close", show=False),
    ]

    _REFERENCE = (
        f"[bold {_P}]Commands[/]\n"
        f"  [{_P}]I[/]  Init / show your identity\n"
        f"  [{_P}]A[/]  Add a contact\n"
        f"  [{_P}]V[/]  Verify the active contact (safety number)\n"
        f"  [{_P}]C[/]  Focus the contact list\n"
        f"  [{_P}]/[/]  Command mode (type a /slash command)\n"
        f"  [{_P}]Q[/]  Quit\n\n"
        f"[bold {_P}]Toggles[/]\n"
        f"  [{_S}]Ctrl+G[/]  session info panel (your code, safety number, counters)\n"
        f"  [{_S}]Ctrl+L[/]  crypto-event ticker on/off\n\n"
        f"[bold {_P}]Slash commands[/]\n"
        f"  [{_S}]/add[/]         add a contact\n"
        f"  [{_S}]/verify[/]      show the safety number\n"
        f"  [{_S}]/clear[/]       clear the current conversation (local only)\n"
        f"  [{_S}]/burn[/]        erase conversation from relay and both clients\n"
        f"  [{_S}]/burn last[/]   burn the last message you sent\n"
        f"  [{_S}]/burn 5m[/]     schedule auto-burn in 5 minutes (or Ns for seconds)\n"
        f"  [{_S}]/burn cancel[/] cancel a scheduled auto-burn\n"
        f"  [{_S}]/help[/]        this screen\n"
        f"  [{_S}]/quit[/]        exit\n\n"
        f"[bold {_P}]Composing[/]\n"
        f"  [{_DM}]Enter[/] send   ·   [{_DM}]Shift+Enter[/] newline\n"
        f"  [{_DM}]Esc[/] unfocus the input so letter shortcuts work\n\n"
        "[#555555]⚠  Burn requests are best-effort — a non-compliant client can ignore them.[/]\n\n"
        f"[{_DM}]Click any pill, contact, or security indicator with the mouse, too.[/]"
    )

    def compose(self) -> ComposeResult:
        with Vertical(id="modal-box"):
            yield Static(f"[bold {_P}]?  HELP[/]", classes="modal-title")
            yield Static(self._REFERENCE, id="help-body")
            with Horizontal(classes="modal-actions"):
                yield Button("Close", variant="primary", id="close")

    @on(Button.Pressed, "#close")
    def action_close(self) -> None:
        self.dismiss(None)


# ===========================================================================
# Root application
# ===========================================================================

class DriftApp(App[None]):
    """The DRIFT client. Owns all state; children render from it."""

    TITLE = "DRIFT"

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("ctrl+c", "do_quit", "Quit", show=False),
        Binding("i", "command('init')", "Init", show=False),
        Binding("a", "command('add')", "Add", show=False),
        Binding("v", "command('verify')", "Verify", show=False),
        Binding("c", "command('contacts')", "Contacts", show=False),
        Binding("q", "command('quit')", "Quit", show=False),
        Binding("question_mark", "command('help')", "Help", show=False),
        Binding("ctrl+g", "toggle_info", "Info", show=False),
        Binding("ctrl+l", "toggle_log", "Log", show=False),
        Binding("ctrl+n", "toggle_network", "Network", show=False),
        Binding("escape", "blur_input", "Unfocus", show=False),
    ]

    CSS = _build_css(_ACTIVE_THEME)

    def __init__(
        self,
        identity: Identity,
        contacts: Contacts,
        relay_url: str,
        *,
        active: str | None = None,
    ) -> None:
        super().__init__()
        self._identity = identity
        self._contacts: Contacts = contacts
        self._relay_url = relay_url
        self._active: str | None = active if active in contacts else None
        self._unread: dict[str, int] = {}
        self._history: dict[str, list[MessageRecord]] = {}
        self._session: Session | None = None
        self._connected = False
        # Per-session crypto telemetry (reset on each conversation open).
        self._sent_count = 0
        self._recv_count = 0
        self._stealth_count = 0
        self._stealth_recent: list[str] = []
        self._session_start: float | None = None
        # Auto-burn timer (set by /burn Nm or /burn Ns).
        self._burn_timer: Timer | None = None

    # ── Layout ────────────────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        with Vertical(id="root"):
            with Vertical(id="header"):
                with Horizontal(id="header-top"):
                    yield LogoBox(id="logo")
                    yield LockIndicator(id="lock")
                    yield Static(id="header-spacer")
                    yield SecurityBar(id="security")
                    yield UptimePill(id="uptime")
                    yield LatencyPill(_ws_to_http(self._relay_url), id="latency")
                    yield RatchetPill(id="ratchet")
                yield HeaderBar(id="headerinfo")
                yield Static(RichRule(style=_BD, characters="─"), id="header-rule")
            yield CryptoTicker(id="ticker")
            yield CommandPalette(id="palette")
            with Horizontal(id="body"):
                yield Sidebar(id="sidebar")
                with Vertical(id="chat"):
                    # The pane sits on a layer above a dim lock watermark.
                    with Container(id="pane-wrap"):
                        yield LockWatermark(id="watermark")
                        yield MessagePane(id="pane")
                    yield NetworkPane(id="netpane")
                    yield InputBar(id="input")
                yield InfoPanel(id="infopanel")

    # ── Lifecycle ─────────────────────────────────────────────────────────

    async def on_mount(self) -> None:
        self._header.relay_url = self._relay_url
        await self._sidebar.populate(self._contacts, self._active, self._unread)
        self.set_interval(0.8, self._tick_pulse)
        self._input.focus()
        if self._active is not None:
            await self._open_conversation(self._active)
        else:
            self._pane.write_system("select a contact (press C) or add one (press A)")

    async def on_unmount(self) -> None:
        if self._session is not None:
            try:
                await self._session.close()
            except OSError:
                pass

    # ── Convenience accessors (typed handles to children) ──────────────────

    @property
    def _header(self) -> HeaderBar:
        return self.query_one("#headerinfo", HeaderBar)

    @property
    def _sidebar(self) -> Sidebar:
        return self.query_one("#sidebar", Sidebar)

    @property
    def _pane(self) -> MessagePane:
        return self.query_one("#pane", MessagePane)

    @property
    def _input(self) -> Input:
        return self.query_one("#input", InputBar).input

    @property
    def _ticker(self) -> CryptoTicker:
        return self.query_one("#ticker", CryptoTicker)

    @property
    def _infopanel(self) -> InfoPanel:
        return self.query_one("#infopanel", InfoPanel)

    @property
    def _lock(self) -> LockIndicator:
        return self.query_one("#lock", LockIndicator)

    @property
    def _watermark(self) -> LockWatermark:
        return self.query_one("#watermark", LockWatermark)

    def _set_secure(self, secure: bool, *, maximum: bool = False) -> None:
        """Drive the header lock and the pane watermark from one place."""
        self._lock.secure = secure
        self._lock.maximum = maximum
        self._watermark.state = (
            "max" if (secure and maximum) else "secured" if secure else "unsecured"
        )

    # ── Background session worker (UI never touches crypto) ────────────────

    @work(exclusive=True, group="session")
    async def _run_session(self, name: str) -> None:
        from cryptography.exceptions import InvalidTag

        code = self._contacts[name]["code"]

        def _burn_cb(scope: str, message_id: str | None) -> None:
            self.post_message(BurnEvent(name, scope, message_id))

        session = Session(
            self._identity,
            code,
            self._relay_url,
            on_event=self._emit_crypto,
            on_burn=_burn_cb,
        )
        self._session = session
        try:
            await session.connect()
            self.post_message(SessionUp(name))
            async for text in session.messages():
                self.post_message(IncomingMessage(name, text))
            self.post_message(SessionDown(name, "relay closed the connection"))
        except InvalidTag:
            self.post_message(
                SessionDown(name, "authentication failure — tampered message rejected")
            )
        except Exception as exc:  # noqa: BLE001 — surface any relay error to the user
            self.post_message(SessionDown(name, str(exc)))
        finally:
            try:
                await session.close()
            except OSError:
                pass

    async def _open_conversation(self, name: str) -> None:
        """Switch the active contact and (re)start its session."""
        self._active = name
        self._unread[name] = 0
        self._connected = False
        self._header.contact_name = name
        self._header.connected = False
        self._set_secure(False)  # not secured until the relay handshake completes
        # Reset per-session telemetry.
        self._sent_count = 0
        self._recv_count = 0
        self._stealth_count = 0
        self._stealth_recent = []
        self._session_start = time.monotonic()
        self.query_one(UptimePill).start(self._session_start)
        self.query_one(RatchetPill).count = 0
        await self._sidebar.populate(self._contacts, self._active, self._unread)

        # Replay this contact's history into a fresh pane.
        await self._pane.clear()
        self._pane.write_separator(f"session opened · {name} · {_now()}")
        for record in self._history.get(name, []):
            self._replay(record)
        if self._infopanel.display:
            self._refresh_info()

        self._run_session(name)

    def _replay(self, record: MessageRecord) -> None:
        if record.direction == "in":
            self._pane.write_incoming(record.sender, record.text, record.ts)
        elif record.direction == "out":
            self._pane.write_outgoing(record.text, record.ts, status="sent")
        else:
            self._pane.write_system(record.text)

    # ── Session + crypto events ────────────────────────────────────────────

    @on(SessionUp)
    def _on_session_up(self, event: SessionUp) -> None:
        if event.contact != self._active:
            return
        self._connected = True
        self._header.connected = True
        self._set_secure(True)  # E2E + ratchet active (Tor is Phase 3 → not maximum)
        self._pane.write_system(f"⣿ secured channel to {self._relay_url}")

    @on(SessionDown)
    def _on_session_down(self, event: SessionDown) -> None:
        if event.contact != self._active:
            return
        self._connected = False
        self._header.connected = False
        self._set_secure(False)
        self._pane.write_warning(event.reason)

    @on(IncomingMessage)
    def _on_incoming(self, event: IncomingMessage) -> None:
        record = MessageRecord("in", event.contact, event.text, _now())
        self._history.setdefault(event.contact, []).append(record)
        if event.contact == self._active:
            self._pane.write_incoming(event.contact, event.text, record.ts)
        else:
            self._unread[event.contact] = self._unread.get(event.contact, 0) + 1
            self.call_later(
                self._sidebar.populate, self._contacts, self._active, self._unread
            )

    @on(CryptoEvent)
    def _on_crypto_event(self, event: CryptoEvent) -> None:
        self._ticker.push(event.ts, event.kind, event.detail)
        if event.kind == "send":
            self._sent_count += 1
            self._note_addr(event.detail)
        elif event.kind == "recv":
            self._recv_count += 1
            self._note_addr(event.detail)
        elif event.kind == "ratchet":
            self.query_one(RatchetPill).bump()
        # "burn" events are ticker-only; no counters needed.
        if self._infopanel.display:
            self._refresh_info()

    def _emit_crypto(self, kind: str, detail: str) -> None:
        """Session worker → UI bridge for non-secret crypto events."""
        self.post_message(CryptoEvent(kind, detail))

    def _note_addr(self, prefix: str) -> None:
        self._stealth_count += 1
        self._stealth_recent.append(prefix)
        self._stealth_recent = self._stealth_recent[-4:]

    @on(SecurityPillClicked)
    def _on_security_pill(self, event: SecurityPillClicked) -> None:
        self._pane.write_system(f"{event.label} — {event.tooltip}")

    @on(BurnEvent)
    async def _on_burn_event(self, event: BurnEvent) -> None:
        if event.contact != self._active:
            return
        ts = _now()
        if event.scope == "conversation":
            await self._pane.clear()
            self._history[event.contact] = []
            self._pane.write_separator(f"🔥 conversation burned · {ts}")
        else:
            self._pane.write_system(f"⛔ message burned · {ts}")

    # ── Contact selection ──────────────────────────────────────────────────

    @on(ContactSelected)
    async def _on_contact_selected(self, event: ContactSelected) -> None:
        if event.name != self._active:
            await self._open_conversation(event.name)
        self._input.focus()

    # ── Command dispatch ───────────────────────────────────────────────────

    @on(CommandSelected)
    def _on_command(self, event: CommandSelected) -> None:
        self._dispatch(event.command)

    def action_command(self, command: str) -> None:
        self._dispatch(command)

    def _dispatch(self, command: str) -> None:
        match command:
            case "init":
                self.push_screen(IdentityModal(self._identity.contact_code()))
            case "add":
                self.push_screen(AddContactModal(), self._on_add_result)
            case "verify":
                self._open_verify()
            case "contacts":
                self._focus_sidebar()
            case "command":
                self._enter_command_mode()
            case "help":
                self.push_screen(HelpModal())
            case "quit":
                self.exit()

    def _on_add_result(self, result: tuple[str, str] | None) -> None:
        if result is None:
            return
        name, code = result
        try:
            self._contacts = storage.add_contact(self._identity, name, code)
        except storage.StorageError as exc:
            self._pane.write_warning(f"could not add {name}: {exc}")
            return
        self._pane.write_system(f"added contact {name}")
        self.call_later(
            self._sidebar.populate, self._contacts, self._active, self._unread
        )

    def _open_verify(self) -> None:
        if self._active is None:
            self._pane.write_system("select a contact before verifying")
            return
        number = storage.safety_number(self._identity, self._contacts[self._active]["code"])
        self.push_screen(VerifyModal(self._active, number), self._on_verify_result)

    def _on_verify_result(self, confirmed: bool | None) -> None:
        if confirmed:
            self._pane.write_system("contact verified ✓")
        elif confirmed is False:
            self._pane.write_warning("verification aborted — do not trust this channel")

    def _focus_sidebar(self) -> None:
        items = self.query(ContactItem)
        if items:
            items.first().focus()

    def _enter_command_mode(self) -> None:
        field = self._input
        field.focus()
        field.value = "/"
        field.cursor_position = len(field.value)

    # ── Input handling ─────────────────────────────────────────────────────

    @on(Input.Submitted, "#msg-input")
    async def _on_submit(self, event: Input.Submitted) -> None:
        text = event.value.strip()
        # Slash commands and empty input clear immediately — no animation.
        if not text or text.startswith("/"):
            event.input.clear()
            self.query_one("#input", InputBar).reset_counter()
            if text.startswith("/"):
                await self._handle_slash(text)
            return
        if self._active is None:
            event.input.clear()
            self.query_one("#input", InputBar).reset_counter()
            self._pane.write_system("select a contact first (press C)")
            return
        # 150 ms encrypt animation before clear + send.
        await self._encrypt_animation(event.input, text)
        event.input.clear()
        self.query_one("#input", InputBar).reset_counter()
        try:
            await self._send(text)
        except Exception as exc:  # noqa: BLE001 — show send failures inline
            self._pane.write_warning(f"send error: {exc}")

    async def _encrypt_animation(self, field: Input, original: str) -> None:
        """Three 50 ms frames of random hex — visual cue that the message is encrypting."""
        _HEX = "0123456789abcdef"
        for _ in range(3):
            field.value = "".join(
                random.choice(_HEX) for _ch in original  # noqa: S311
            )
            await asyncio.sleep(0.05)

    async def _send(self, text: str) -> None:
        assert self._session is not None and self._active is not None
        line = self._pane.write_outgoing(text, _now(), status="sending")
        record = MessageRecord("out", "you", text, line._ts)
        self._history.setdefault(self._active, []).append(record)
        try:
            await self._session.send(text)
        except Exception:
            line.status = "failed"
            raise
        line.status = "sent"

    async def _handle_slash(self, text: str) -> None:
        parts = text[1:].split() if len(text) > 1 else []
        command = parts[0].lower() if parts else ""
        args = parts[1:]
        match command:
            case "help":
                self.push_screen(HelpModal())
            case "add":
                self.push_screen(AddContactModal(), self._on_add_result)
            case "verify":
                self._open_verify()
            case "clear":
                await self._pane.clear()
                if self._active is not None:
                    self._history[self._active] = []
                    self._pane.write_separator(f"cleared · {self._active}")
            case "burn":
                await self._handle_burn_slash(args)
            case "quit" | "exit":
                self.exit()
            case _:
                self._pane.write_system(f"unknown command: /{command}")

    async def _handle_burn_slash(self, args: list[str]) -> None:
        """Handle /burn, /burn last, /burn Nm, /burn cancel."""
        sub = args[0].lower() if args else ""
        if sub == "cancel":
            self._cancel_auto_burn()
            return
        if self._session is None or not self._connected:
            self._pane.write_system("burn: no active session — connect to a contact first")
            return
        if sub == "last":
            try:
                await self._session.burn_last_message()
            except Exception as exc:  # noqa: BLE001
                self._pane.write_warning(f"burn failed: {exc}")
        elif sub == "":
            try:
                await self._session.burn_conversation()
            except Exception as exc:  # noqa: BLE001
                self._pane.write_warning(f"burn failed: {exc}")
        else:
            secs = self._parse_burn_duration(sub)
            if secs is None or secs <= 0:
                self._pane.write_system(
                    "usage: /burn · /burn last · /burn Nm · /burn Ns · /burn cancel"
                )
                return
            self._schedule_auto_burn(secs)

    @staticmethod
    def _parse_burn_duration(arg: str) -> int | None:
        """Parse '5m' or '30s' into seconds. Returns None on failure."""
        arg = arg.strip().lower()
        if arg.endswith("m") and arg[:-1].isdigit():
            return int(arg[:-1]) * 60
        if arg.endswith("s") and arg[:-1].isdigit():
            return int(arg[:-1])
        return None

    def _schedule_auto_burn(self, secs: int) -> None:
        if self._burn_timer is not None:
            self._burn_timer.stop()
        m, s = divmod(secs, 60)
        self._pane.write_system(f"⏱ auto-burn in {m}:{s:02d} — /burn cancel to abort")
        self._burn_timer = self.set_timer(secs, self._fire_auto_burn)

    def _cancel_auto_burn(self) -> None:
        if self._burn_timer is not None:
            self._burn_timer.stop()
            self._burn_timer = None
            self._pane.write_system("auto-burn cancelled")
        else:
            self._pane.write_system("no auto-burn scheduled")

    async def _fire_auto_burn(self) -> None:
        self._burn_timer = None
        if self._session is None or not self._connected:
            self._pane.write_system("auto-burn: no active session — burn skipped")
            return
        try:
            await self._session.burn_conversation()
        except Exception as exc:  # noqa: BLE001
            self._pane.write_warning(f"auto-burn failed: {exc}")

    async def on_key(self, event: Key) -> None:
        """Shift+Enter inserts a newline into the draft instead of sending."""
        if event.key in ("shift+enter", "shift+return"):
            field = self._input
            if field.has_focus:
                field.value = field.value + "\n"
                event.stop()

    # ── Misc actions ───────────────────────────────────────────────────────

    def action_blur_input(self) -> None:
        """Drop focus from the input so single-key shortcuts become active."""
        self.set_focus(None)

    def action_do_quit(self) -> None:
        self.exit()

    def action_toggle_log(self) -> None:
        """Show/hide the crypto-event ticker."""
        self._ticker.display = not self._ticker.display

    def action_toggle_network(self) -> None:
        """Toggle the ASCII network topology panel (replaces message pane)."""
        net = self.query_one("#netpane", NetworkPane)
        pane_wrap = self.query_one("#pane-wrap")
        showing = not net.display
        net.display = showing
        pane_wrap.display = not showing
        if showing:
            self._sync_network_state()

    def _sync_network_state(self) -> None:
        state = NetworkState(
            relay_url=self._relay_url,
            relay_connected=self._connected,
            relay_latency_ms=self.query_one(LatencyPill).latency_ms,
            peer_name=self._active,
            peer_connected=self._connected,
            ratchet_steps=self.query_one(RatchetPill).count,
            stealth_addrs=self._stealth_count,
        )
        self.query_one("#netpane", NetworkPane).update_graph(state)

    def action_toggle_info(self) -> None:
        """Slide the session info panel in/out from the right."""
        panel = self._infopanel
        if panel.display:
            panel.display = False
            return
        self._refresh_info()
        panel.display = True
        panel.styles.opacity = 0.0
        panel.styles.animate("opacity", value=1.0, duration=0.16)

    def _refresh_info(self) -> None:
        if self._active is None:
            self._infopanel.clear_data()
            return
        self._infopanel.show_data(
            code=self._identity.contact_code(),
            contact=self._active,
            safety=storage.safety_number(
                self._identity, self._contacts[self._active]["code"]
            ),
            sent=self._sent_count,
            recv=self._recv_count,
            stealth=self._stealth_count,
            recent=list(self._stealth_recent),
            relay=self._relay_url,
            uptime=self._fmt_uptime(),
        )

    def _fmt_uptime(self) -> str:
        if self._session_start is None:
            return "—"
        secs = int(time.monotonic() - self._session_start)
        return f"{secs // 60:02d}:{secs % 60:02d}"

    def _tick_pulse(self) -> None:
        self._header.pulse = not self._header.pulse
        if self._infopanel.display:
            self._refresh_info()
