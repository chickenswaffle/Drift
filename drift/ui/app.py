"""
drift.ui.app — the DRIFT terminal client (Textual TUI)

This is the face of DRIFT. It is written as a tree of small, single-purpose
widgets — the same component decomposition a React app would use — so the
layout can later be ported to a web UI almost one-to-one:

    DriftApp                     (root / state container — like <App/>)
    ├─ HeaderBar                 wordmark · contact · connection
    ├─ CommandPalette            [I] [A] [V] [C] [/] [Q]  (PillButton ×N)
    ├─ Body
    │  ├─ Sidebar                contact list (ContactItem ×N) + add
    │  └─ ChatColumn
    │     ├─ MessagePane         scrollable message log
    │     └─ InputBar            rule · prompt · input · counter · hint
    └─ Modals (pushed)           AddContactModal · VerifyModal · HelpModal ·
                                 IdentityModal

State lives on DriftApp and flows *down* into widgets via reactive props
(≈ React props); widgets emit *up* via Textual Messages (≈ DOM events that
bubble). No widget reaches sideways into another. The network/crypto work
happens in a background @work worker that talks to drift.transport.Session
and posts plain strings back — the UI never imports crypto (see CLAUDE.md).

Colour language:
    #0a0a0a  deep black background
    #00ff41  matrix green — your messages, borders, active state
    #00d4ff  cyan         — contacts, incoming messages
    #888888  dim white    — timestamps, hints, secondary info
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, ClassVar, TypeVar

from rich.console import Group, RenderableType
from rich.rule import Rule as RichRule
from rich.table import Table
from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.events import Key
from textual.message import Message
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import Button, Input, RichLog, Static

from drift import __version__, storage
from drift.transport.session import Session

if TYPE_CHECKING:
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


def _now() -> str:
    return datetime.now().strftime("%H:%M:%S")


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


class IncomingMessage(Message):
    """Worker → UI: a decrypted message arrived for a contact."""
    def __init__(self, contact: str, text: str) -> None:
        super().__init__()
        self.contact = contact
        self.text = text


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

class HeaderBar(Static):
    """Three-line header: wordmark/version/Tor · contact/relay/conn · rule."""

    contact_name: reactive[str] = reactive("")
    relay_url: reactive[str] = reactive("")
    connected: reactive[bool] = reactive(False)
    tor_active: reactive[bool] = reactive(False)
    pulse: reactive[bool] = reactive(True)

    def render(self) -> RenderableType:
        # Line 1 — wordmark left, version + Tor right.
        tor = "[#00ff41]● TOR[/]" if self.tor_active else "[#444444]○ TOR[/]"
        line1 = Table.grid(expand=True)
        line1.add_column(justify="left", ratio=1)
        line1.add_column(justify="right")
        line1.add_row("[bold #00ff41]DRIFT[/]", f"[#888888]{VERSION}[/]   {tor}")

        # Line 2 — active contact left, relay + pulsing connection dot right.
        if self.connected:
            dot = "[#00ff41]⣿[/]" if self.pulse else "[#1a5c1a]⡇[/]"
            state = dot
        else:
            state = "[#444444]⠀ offline[/]"
        who = self.contact_name or "no contact selected"
        line2 = Table.grid(expand=True)
        line2.add_column(justify="left", ratio=1)
        line2.add_column(justify="right")
        line2.add_row(
            f"[#00d4ff]▶ {who}[/]",
            f"[#888888]{self.relay_url}[/]  {state}",
        )

        return Group(line1, line2, RichRule(style="#1a5c1a", characters="─"))


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
        colour = "#00ff41" if self.active else "#888888"
        badge = f"  [#00d4ff]{self.unread}[/]" if self.unread else ""
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
        yield Static("[bold #00ff41]CONTACTS[/]", id="sidebar-title")
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


class MessagePane(RichLog):
    """Scrollable message log with typed write helpers and a flash effect."""

    def write_separator(self, label: str) -> None:
        self.write(
            f"[#1a5c1a]▓▒░  {label}  ░▒▓[/]",
            scroll_end=True,
        )

    def write_incoming(self, sender: str, text: str, ts: str) -> None:
        self.write(
            f"[#888888]{ts}[/]  [bold #00d4ff]{sender}:[/]  [white]{text}[/]",
            scroll_end=True,
        )
        self.flash()

    def write_outgoing(self, text: str, ts: str) -> None:
        # Right-justify via the Text itself (not an Align wrapper, which would
        # report an oversized width and trip RichLog's horizontal scrollbar).
        line = Text(justify="right")
        line.append(f"{ts}  ", style="#888888")
        line.append("you:  ", style="bold #00ff41")
        line.append(text, style="#b0ffb0")
        self.write(line, scroll_end=True)

    def write_system(self, text: str) -> None:
        self.write(f"[#888888 italic]· {text}[/]", scroll_end=True)

    def write_warning(self, text: str) -> None:
        self.write(f"[bold red]⚠  {text}[/]", scroll_end=True)

    def flash(self) -> None:
        """Briefly tint the border green when a new message lands."""
        self.add_class("flash")
        self.set_timer(0.35, lambda: self.remove_class("flash"))


class InputBar(Vertical):
    """Bottom composer: rule · (prompt + input + counter) · hint."""

    HINT = (
        "[#888888]Enter[/] send  ·  [#888888]Shift+Enter[/] newline  ·  "
        "[#888888]/verify[/]  ·  [#888888]/clear[/]  ·  [#888888]/help[/]"
    )

    def compose(self) -> ComposeResult:
        yield Static(RichRule(style="#1a5c1a", characters="─"), id="input-rule")
        with Horizontal(id="input-row"):
            yield Static("▶", id="prompt")
            yield Input(placeholder="message — or /command", id="msg-input")
            yield Static("0", id="char-count")
        yield Static(self.HINT, id="input-hint")

    @on(Input.Changed, "#msg-input")
    def _on_changed(self, event: Input.Changed) -> None:
        n = len(event.value)
        colour = "#ff4444" if n > 1000 else "#ffaa00" if n > 800 else "#888888"
        self.query_one("#char-count", Static).update(f"[{colour}]{n}[/]")

    def reset_counter(self) -> None:
        self.query_one("#char-count", Static).update("[#888888]0[/]")

    @property
    def input(self) -> Input:
        return self.query_one("#msg-input", Input)


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
            yield Static("[bold #00ff41]＋  ADD CONTACT[/]", classes="modal-title")
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
                f"[bold #00d4ff]{self._contact_name}[/]",
                classes="modal-title",
            )
            yield Static(
                f"[bold #ffff00 on #111100]  {self._safety_number}  [/]",
                id="safety-number",
            )
            yield Static(
                "[#888888]Read these digits aloud over a trusted channel.\n"
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
            yield Static("[bold #00ff41]⬡  YOUR IDENTITY[/]", classes="modal-title")
            yield Static(
                f"[bold #00d4ff on #001018]  {self._contact_code}  [/]",
                id="own-code",
            )
            yield Static(
                "[#888888]Share this code so others can message you.\n"
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
        "[bold #00ff41]Commands[/]\n"
        "  [#00ff41]I[/]  Init / show your identity\n"
        "  [#00ff41]A[/]  Add a contact\n"
        "  [#00ff41]V[/]  Verify the active contact (safety number)\n"
        "  [#00ff41]C[/]  Focus the contact list\n"
        "  [#00ff41]/[/]  Command mode (type a /slash command)\n"
        "  [#00ff41]Q[/]  Quit\n\n"
        "[bold #00ff41]Slash commands[/]\n"
        "  [#00d4ff]/add[/]      add a contact\n"
        "  [#00d4ff]/verify[/]   show the safety number\n"
        "  [#00d4ff]/clear[/]    clear the current conversation\n"
        "  [#00d4ff]/help[/]     this screen\n"
        "  [#00d4ff]/quit[/]     exit\n\n"
        "[bold #00ff41]Composing[/]\n"
        "  [#888888]Enter[/] send   ·   [#888888]Shift+Enter[/] newline\n"
        "  [#888888]Esc[/] unfocus the input so letter shortcuts work\n\n"
        "[#888888]Click any pill or contact with the mouse, too.[/]"
    )

    def compose(self) -> ComposeResult:
        with Vertical(id="modal-box"):
            yield Static("[bold #00ff41]?  HELP[/]", classes="modal-title")
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
        Binding("escape", "blur_input", "Unfocus", show=False),
    ]

    CSS = """
    Screen { background: #0a0a0a; }

    #root {
        background: #0a0a0a;
        /* faint horizontal scanlines (≈0.035 opacity) */
        hatch: horizontal #00ff41 3.5%;
    }

    /* ── Header ─────────────────────────────────────────────── */
    #header {
        height: 3;
        padding: 0 1;
        background: #0a0a0a;
    }

    /* ── Command palette ────────────────────────────────────── */
    #palette {
        height: 1;
        padding: 0 1;
        background: #0a0a0a;
    }
    PillButton {
        width: auto;
        height: 1;
        padding: 0 2;
        margin: 0 1 0 0;
        color: #888888;
        background: #0a0a0a;
    }
    PillButton:hover {
        color: #0a0a0a;
        background: #00ff41;
        text-style: bold;
    }
    PillButton:focus {
        color: #00ff41;
        background: #06160a;
        text-style: bold;
    }

    /* ── Body: sidebar + chat ───────────────────────────────── */
    #body { height: 1fr; }

    #sidebar {
        width: 22;
        background: #060606;
        border-right: solid #1a5c1a;
        padding: 0 1;
    }
    #sidebar-title { height: 1; padding: 0 1; }
    #contact-list { height: 1fr; }
    ContactItem {
        width: 100%;
        height: 1;
        padding: 0 1;
        background: #060606;
    }
    ContactItem:hover { background: #06160a; }
    ContactItem.active { background: #06160a; }
    .empty-hint { padding: 1; color: #555555; }

    /* ── Chat column ────────────────────────────────────────── */
    #chat { width: 1fr; }
    #pane {
        height: 1fr;
        background: #0a0a0a;
        border: solid #1a5c1a;
        scrollbar-color: #00ff41;
        scrollbar-background: #0a0a0a;
        scrollbar-gutter: stable;
        scrollbar-size-vertical: 1;
        padding: 0 1;
    }
    #pane.flash { border: solid #88ffaa; background: #001800; }

    /* ── Input bar ──────────────────────────────────────────── */
    #input { height: 3; padding: 0 1; background: #0a0a0a; }
    #input-rule { height: 1; }
    #input-row { height: 1; }
    #prompt { width: 2; color: #00ff41; text-style: bold; }
    #msg-input {
        width: 1fr;
        height: 1;
        padding: 0;
        border: none;
        background: #0a0a0a;
        color: #e0e0e0;
    }
    #msg-input:focus { border: none; }
    #char-count { width: 6; content-align: right middle; color: #888888; }
    #input-hint { height: 1; color: #888888; }

    /* ── Modals ─────────────────────────────────────────────── */
    _FadeModal { align: center middle; background: #0a0a0a 75%; }
    #modal-box {
        width: 64;
        height: auto;
        max-height: 80%;
        padding: 1 2;
        background: #0c0c0c;
        border: round #00ff41;
    }
    .modal-title { height: 1; text-align: center; }
    .field-label { height: 1; margin: 1 0 0 0; }
    .modal-error { height: 1; text-align: center; }
    .modal-hint { margin: 1 0; }
    .modal-actions { height: auto; align: center middle; margin: 1 0 0 0; }
    .modal-actions Button { margin: 0 1; }
    #safety-number, #own-code { height: 1; text-align: center; margin: 1 0; text-style: bold; }
    #help-body { height: auto; }
    AddContactModal Input { margin: 0 0 0 0; }
    """

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

    # ── Layout ────────────────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        with Vertical(id="root"):
            yield HeaderBar(id="header")
            yield CommandPalette(id="palette")
            with Horizontal(id="body"):
                yield Sidebar(id="sidebar")
                with Vertical(id="chat"):
                    yield MessagePane(
                        id="pane", highlight=False, markup=True, wrap=True, min_width=10
                    )
                    yield InputBar(id="input")

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
        return self.query_one("#header", HeaderBar)

    @property
    def _sidebar(self) -> Sidebar:
        return self.query_one("#sidebar", Sidebar)

    @property
    def _pane(self) -> MessagePane:
        return self.query_one("#pane", MessagePane)

    @property
    def _input(self) -> Input:
        return self.query_one("#input", InputBar).input

    # ── Background session worker (UI never touches crypto) ────────────────

    @work(exclusive=True, group="session")
    async def _run_session(self, name: str) -> None:
        from cryptography.exceptions import InvalidTag

        code = self._contacts[name]["code"]
        session = Session(self._identity, code, self._relay_url)
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
        await self._sidebar.populate(self._contacts, self._active, self._unread)

        # Replay this contact's history into a fresh pane.
        self._pane.clear()
        self._pane.write_separator(f"session opened · {name} · {_now()}")
        for record in self._history.get(name, []):
            self._replay(record)

        self._run_session(name)

    def _replay(self, record: MessageRecord) -> None:
        if record.direction == "in":
            self._pane.write_incoming(record.sender, record.text, record.ts)
        elif record.direction == "out":
            self._pane.write_outgoing(record.text, record.ts)
        else:
            self._pane.write_system(record.text)

    # ── Session events ─────────────────────────────────────────────────────

    @on(SessionUp)
    def _on_session_up(self, event: SessionUp) -> None:
        if event.contact != self._active:
            return
        self._connected = True
        self._header.connected = True
        self._pane.write_system(f"⣿ secured channel to {self._relay_url}")

    @on(SessionDown)
    def _on_session_down(self, event: SessionDown) -> None:
        if event.contact != self._active:
            return
        self._connected = False
        self._header.connected = False
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
            self._contacts = storage.add_contact(name, code)
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
        event.input.clear()
        self.query_one("#input", InputBar).reset_counter()
        if not text:
            return
        if text.startswith("/"):
            await self._handle_slash(text)
            return
        if self._active is None:
            self._pane.write_system("select a contact first (press C)")
            return
        try:
            await self._send(text)
        except Exception as exc:  # noqa: BLE001 — show send failures inline
            self._pane.write_warning(f"send error: {exc}")

    async def _send(self, text: str) -> None:
        assert self._session is not None and self._active is not None
        await self._session.send(text)
        record = MessageRecord("out", "you", text, _now())
        self._history.setdefault(self._active, []).append(record)
        self._pane.write_outgoing(text, record.ts)

    async def _handle_slash(self, text: str) -> None:
        command = text[1:].split()[0].lower() if len(text) > 1 else ""
        match command:
            case "help":
                self.push_screen(HelpModal())
            case "add":
                self.push_screen(AddContactModal(), self._on_add_result)
            case "verify":
                self._open_verify()
            case "clear":
                self._pane.clear()
                if self._active is not None:
                    self._history[self._active] = []
                    self._pane.write_separator(f"cleared · {self._active}")
            case "quit" | "exit":
                self.exit()
            case _:
                self._pane.write_system(f"unknown command: /{command}")

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

    def _tick_pulse(self) -> None:
        self._header.pulse = not self._header.pulse
