"""
drift.ui.app — Textual TUI for DRIFT

Visual design
-------------
Background : #0a0a0a  — deep black
Primary    : #00ff41  — matrix green   (own messages, timestamps, borders)
Secondary  : #00d4ff  — cyan           (incoming messages, contact names)
Accent     : #ffff00  — yellow         (safety-number overlay)

Layout (top → bottom)
---------------------
  HeaderBar   — DRIFT logo · connection status (pulsing ●) · TOR indicator
  MessagesLog — scrollable; timestamps left-guttered; own msgs right-aligned
  InputRow    — ▶ prompt · Input · char counter
  Footer      — relay URL · msg count · [P1] phase badge

Wired to drift.transport.session.Session for real encrypted message flow.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import ClassVar

from rich.align import Align
from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Horizontal, Vertical
from textual.events import Key
from textual.message import Message
from textual.screen import ModalScreen
from textual.widgets import Input, RichLog, Static

from drift.crypto import Identity
from drift.transport.session import Session

# ── One-liner logo ────────────────────────────────────────────────────────────

_LOGO = "░▒▓  D·R·I·F·T  ▓▒░"

# Separator written to the message log when a session opens / closes.
_SEP = "▓▒░" * 8


# ── Internal messages (worker → UI thread) ────────────────────────────────────

class _Incoming(Message):
    """Decrypted plaintext received from the contact."""
    def __init__(self, text: str) -> None:
        super().__init__()
        self.text = text


class _Connected(Message):
    """Session successfully connected to the relay."""


class _Dropped(Message):
    """Session disconnected or encountered an error."""
    def __init__(self, reason: str) -> None:
        super().__init__()
        self.reason = reason


# ── Verify overlay ────────────────────────────────────────────────────────────

class VerifyModal(ModalScreen[None]):
    """
    Safety-number overlay.

    Shows the 4-group hex safety number derived from both parties' scan keys.
    Both sides should see the same digits; a mismatch indicates a MITM.
    """

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("escape", "close_verify", "Close", show=False),
        Binding("enter",  "close_verify", "Close", show=False),
    ]

    def __init__(self, contact_name: str, safety_number: str) -> None:
        super().__init__()
        self._contact_name = contact_name
        self._safety_number = safety_number

    def compose(self) -> ComposeResult:
        with Vertical(id="verify-box"):
            yield Static(
                f"[bold #ffff00] ⚿  SAFETY NUMBER[/bold #ffff00]"
                f"  ·  with [bold #00d4ff]{self._contact_name}[/]",
                id="verify-title",
            )
            yield Static("", id="verify-spacer")
            yield Static(
                f"[bold #ffff00 on #111100]  {self._safety_number}  [/]",
                id="verify-number",
            )
            yield Static(
                "\n[dim]Read these digits aloud over a trusted channel.\n"
                "Digits match on both sides → key verified.\n\n"
                "ESC · Enter to close[/]",
                id="verify-hint",
            )

    def action_close_verify(self) -> None:
        self.dismiss()


# ── Main app ──────────────────────────────────────────────────────────────────

class DriftApp(App[None]):
    """
    DRIFT encrypted-chat TUI.

    Usage::

        DriftApp(identity, contact_name, contact_code, relay_url).run()
    """

    CSS = """
    /* ── Global ────────────────────────────────────────────── */
    Screen {
        background: #0a0a0a;
    }

    /* Scanline overlay on the outermost container.
       hatch: horizontal lays faint ─ chars across the background. */
    #main {
        background: #0a0a0a;
        hatch: horizontal #00ff41 0.035;
    }

    /* ── Header ─────────────────────────────────────────────── */
    #header {
        height: 3;
        background: #0a0a0a;
        border-bottom: solid #00ff41;
        padding: 0 1;
    }

    #logo {
        color: #00ff41;
        text-style: bold;
        width: auto;
        content-align: left middle;
    }

    #status-right {
        color: #00ff41;
        content-align: right middle;
        width: 1fr;
    }

    /* ── Message pane ───────────────────────────────────────── */
    #messages {
        border: solid #00ff41;
        background: #0a0a0a;
        scrollbar-color: #00ff41;
        scrollbar-background: #0a0a0a;
        height: 1fr;
        padding: 0 1;
    }

    /* Brief flash when an incoming message arrives. */
    #messages.flash {
        border: solid #88ffaa;
        background: #001800;
    }

    /* ── Input row ──────────────────────────────────────────── */
    #input-row {
        height: 3;
        background: #0a0a0a;
        border-top: solid #00ff41;
        padding: 0 1;
    }

    #prompt {
        color: #00ff41;
        text-style: bold;
        width: 3;
        content-align: left middle;
    }

    #msg-input {
        background: #0a0a0a;
        color: #e0e0e0;
        border: none;
        height: 1;
        padding: 0;
    }

    #msg-input:focus {
        border: none;
    }

    #char-count {
        color: #1a5c1a;
        width: 6;
        content-align: right middle;
    }

    /* ── Status footer ──────────────────────────────────────── */
    #footer {
        height: 1;
        background: #0a0a0a;
        color: #1a5c1a;
        padding: 0 1;
    }

    /* ── Verify modal ───────────────────────────────────────── */
    VerifyModal {
        align: center middle;
        background: #0a0a0a 80%;
    }

    #verify-box {
        width: 58;
        height: 14;
        background: #0c0c00;
        border: double #ffff00;
        padding: 1 2;
    }

    #verify-title {
        text-align: center;
    }

    #verify-spacer {
        height: 1;
    }

    #verify-number {
        text-align: center;
        text-style: bold;
    }

    #verify-hint {
        text-align: center;
        color: #666600;
    }
    """

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("ctrl+c", "quit", "Quit", show=False),
    ]

    def __init__(
        self,
        identity: Identity,
        contact_name: str,
        contact_code: str,
        relay_url: str,
    ) -> None:
        super().__init__()
        self._identity = identity
        self._contact_name = contact_name
        self._contact_code = contact_code
        self._relay_url = relay_url
        self._session = Session(identity, contact_code, relay_url)
        self._msg_count = 0
        self._pulse_on = True
        self._is_connected = False

    # ── Layout ────────────────────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        with Vertical(id="main"):
            with Horizontal(id="header"):
                yield Static(_LOGO, id="logo")
                yield Static(self._status_text(), id="status-right")
            yield RichLog(id="messages", highlight=False, markup=True)
            with Horizontal(id="input-row"):
                yield Static("▶ ", id="prompt")
                yield Input(
                    placeholder="type a message  ·  /verify",
                    id="msg-input",
                )
                yield Static("0", id="char-count")
            yield Static(self._footer_text(), id="footer")

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def on_mount(self) -> None:
        self.query_one("#msg-input", Input).focus()
        self.set_interval(0.8, self._tick_pulse)
        log = self.query_one("#messages", RichLog)
        log.write(
            f"[dim #00ff41]{_SEP}  "
            f"session opened · {datetime.now().strftime('%Y-%m-%d %H:%M')}  "
            f"{_SEP}[/]",
            scroll_end=True,
        )
        self._start_session()

    async def on_unmount(self) -> None:
        # Best-effort close — the relay connection may already be gone.
        try:
            await self._session.close()
        except OSError:
            pass

    # ── Background worker ─────────────────────────────────────────────────────

    @work(exclusive=True)
    async def _start_session(self) -> None:
        """Connect to the relay and stream decrypted messages indefinitely."""
        try:
            await self._session.connect()
            self.post_message(_Connected())
            async for msg in self._session.messages():
                self.post_message(_Incoming(msg))
            self.post_message(_Dropped("relay closed connection"))
        except Exception as exc:
            self.post_message(_Dropped(str(exc)))

    # ── Session event handlers ────────────────────────────────────────────────

    @on(_Connected)
    def _on_connected(self, _: _Connected) -> None:
        self._is_connected = True
        self._refresh_status()
        self.query_one("#messages", RichLog).write(
            f"[dim #00ff41]⣿  secured channel to {self._relay_url}[/]",
            scroll_end=True,
        )

    @on(_Dropped)
    def _on_dropped(self, event: _Dropped) -> None:
        self._is_connected = False
        self._refresh_status()
        self.query_one("#messages", RichLog).write(
            f"[bold red]✗  {event.reason}[/]",
            scroll_end=True,
        )

    @on(_Incoming)
    def _on_incoming(self, event: _Incoming) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self.query_one("#messages", RichLog).write(
            f"[dim #00ff41]{ts}[/]  "
            f"[bold #00d4ff]{self._contact_name}:[/]  "
            f"[white]{event.text}[/]",
            scroll_end=True,
        )
        self._msg_count += 1
        self.query_one("#footer", Static).update(self._footer_text())

        # Trigger brief green flash on the message-pane border.
        pane = self.query_one("#messages", RichLog)
        pane.add_class("flash")
        self.set_timer(0.35, lambda: pane.remove_class("flash"))

    # ── Input handlers ────────────────────────────────────────────────────────

    @on(Input.Submitted, "#msg-input")
    async def _on_submit(self, event: Input.Submitted) -> None:
        text = event.value.strip()
        if not text:
            return
        event.input.clear()
        self.query_one("#char-count", Static).update("[#1a5c1a]0[/]")

        if text == "/verify":
            self._open_verify()
            return

        try:
            await self._session.send(text)
        except Exception as exc:
            self.query_one("#messages", RichLog).write(
                f"[bold red]⚠  send error: {exc}[/]",
                scroll_end=True,
            )
            return

        ts = datetime.now().strftime("%H:%M:%S")
        out = Text.assemble(
            (f"{ts}  ", "dim #00ff41"),
            ("you:  ", "bold #00ff41"),
            (text, "#b0ffb0"),
        )
        self.query_one("#messages", RichLog).write(
            Align(out, align="right"),
            scroll_end=True,
        )
        self._msg_count += 1
        self.query_one("#footer", Static).update(self._footer_text())

    @on(Input.Changed, "#msg-input")
    def _on_input_changed(self, event: Input.Changed) -> None:
        n = len(event.value)
        color = "#ff4444" if n > 1000 else "#ffaa00" if n > 800 else "#1a5c1a"
        self.query_one("#char-count", Static).update(f"[{color}]{n}[/]")

    async def on_key(self, event: Key) -> None:
        """Shift+Enter appends a newline to the draft rather than sending."""
        if event.key in ("shift+enter", "shift+return"):
            inp = self.query_one("#msg-input", Input)
            if inp.has_focus:
                inp.value = inp.value + "\n"
                event.stop()

    # ── Pulse timer ───────────────────────────────────────────────────────────

    def _tick_pulse(self) -> None:
        self._pulse_on = not self._pulse_on
        self._refresh_status()

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _status_text(self) -> str:
        if self._is_connected:
            dot = "⣿" if self._pulse_on else "⡇"
            return (
                f"{dot}  [bold #00ff41]connected[/]"
                f"  ┊  [dim]TOR: —[/]"
                f"  ┊  [dim]{self._relay_url}[/]"
            )
        return (
            f"⠀  [dim]connecting…[/]"
            f"  ┊  [dim]TOR: —[/]"
            f"  ┊  [dim]{self._relay_url}[/]"
        )

    def _refresh_status(self) -> None:
        from textual.css.query import NoMatches
        try:
            self.query_one("#status-right", Static).update(self._status_text())
        except NoMatches:
            pass  # widget not yet / no longer in the DOM

    def _footer_text(self) -> str:
        return (
            f"[#1a5c1a]relay[/] [dim]{self._relay_url}[/]"
            f"  [#1a5c1a]msgs[/] [dim]{self._msg_count}[/]"
            f"  [[bold #00ff41]P1[/]]"
            f"  [dim]Ctrl+C quit · /verify safety-number[/]"
        )

    def _open_verify(self) -> None:
        their_scan, _ = Identity.parse_contact_code(self._contact_code)
        my_scan = self._identity.scan_keypair.public_bytes()
        combined = b"drift-safety-v0" + b"".join(sorted([my_scan, their_scan]))
        digest = hashlib.sha256(combined).digest()
        safety_number = "-".join(
            f"{digest[i * 4]:02x}{digest[i * 4 + 1]:02x}" for i in range(4)
        )
        self.push_screen(VerifyModal(self._contact_name, safety_number))

    async def action_quit(self) -> None:
        self.exit()
