"""
drift.ui.welcome — the first-run welcome experience for ``drift`` (no args).

Two beats:

1. A boot sequence — the real cryptographic subsystems print one line at a time
   (``time.sleep(0.04)``) like a secure system initialising. Everything it
   claims to load is something DRIFT actually does (ed25519/x25519, XChaCha20,
   Double Ratchet, Tor, relay federation). Skipped when output is not a TTY or
   ``--no-animation`` is set.

2. The main interface — the DRIFT wordmark with the identity dissolving into
   noise beside it (``identity.burn() → 0x00``), the no-accounts manifesto, the
   security pills, and a numbered menu. Then a prompt: type a number (or a full
   command) and go.

The static banner imports **no Textual** — only Rich — so the non-interactive
path (pipes/CI) stays cheap; the interactive arrow-key menu imports Textual
lazily, only when a real terminal is driving (see ``_interactive_choice``). It
reads live state (is there an identity? is Tor available?) so the screen
reflects reality rather than a mock-up. Colours follow the active theme
(``DRIFT_THEME``); ``DRIFT_THEME=redacted`` turns it classified-document red.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import time

from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from drift.ui.theme import active_theme

# The relay clients default to this everywhere in the CLI; mirror it here for the
# status line so the welcome screen and the commands agree.
DEFAULT_RELAY = "ws://localhost:8765"

_BOOT_HEADER = "DRIFT SECURE MESSENGER"
_BOOT_SUBSYSTEMS = [
    ("loading ed25519 identity layer", 14),
    ("loading x25519 stealth addresses", 11),
    ("loading xchacha20-poly1305 cipher", 10),
    ("loading double ratchet protocol", 12),
    ("loading tor transport layer", 16),
    ("scanning relay federation", 18),
]

# The DRIFT wordmark (left) and the identity dissolving into noise (right).
_WORDMARK = [
    "██████╗ ██████╗ ██╗███████╗████████╗",
    "██╔══██╗██╔══██╗██║██╔════╝╚══██╔══╝",
    "██║  ██║██████╔╝██║█████╗     ██║   ",
    "██║  ██║██╔══██╗██║██╔══╝     ██║   ",
    "██████╔╝██║  ██║██║██║        ██║   ",
    "╚═════╝ ╚═╝  ╚═╝╚═╝╚═╝        ╚═╝   ",
]

_MENU = [
    ("1", "✦", "set up my identity"),
    ("2", "◈", "add a contact"),
    ("3", "▶", "start chatting"),
    ("4", "⬡", "join or create a room"),
    ("5", "⊞", "create or open a group"),
    ("6", "◌", "light a beacon"),
    ("7", "🔍", "verify relay blindness"),
    ("8", "≡", "all commands"),
]

# Menu choice → the argv (after the drift launcher) it runs. Entries set to None
# need an inline prompt first (handled in _dispatch).
_COMMAND_FOR_CHOICE: dict[str, list[str] | None] = {
    "1": ["init"],
    "2": None,            # add <nickname> <code>
    "3": ["chat"],
    "4": ["room"],
    "5": ["group"],
    "6": None,            # beacon <handle>
    "7": None,            # witness verify <relay>
    "8": ["--help"],
}


def _short_frag(s: str, head: int = 4, tail: int = 2) -> str:
    """``3f9a···2b`` — a recognisable fragment of a long key/code."""
    s = s.strip()
    if len(s) <= head + tail + 1:
        return s
    return f"{s[:head]}···{s[-tail:]}"


def _identity_state() -> tuple[bool, str | None]:
    """(identity_present, full_contact_code).

    The contact code is None when no plaintext identity is readable (none
    exists, or it is sealed in a locked vault). We never prompt for a passphrase
    just to decorate the banner.
    """
    from drift import storage

    present = storage.identity_exists() or storage.vault_exists()
    if not storage.identity_exists():
        return present, None
    try:
        return present, storage.load_identity().contact_code()
    except Exception:  # noqa: BLE001 — a banner must never crash; just omit it
        return present, None


def _code_parts(code: str | None) -> tuple[str, str]:
    """Split a ``drift:SCAN.SPEND[.FMD]`` contact code into (scan, spend) base58
    bodies (prefix stripped). Falls back to placeholders when absent."""
    if not code:
        return "3f9a4c2b", "a7c18e5d"
    body = code.split(":", 1)[-1]
    segs = body.split(".")
    scan = segs[0] if segs else body
    spend = segs[1] if len(segs) > 1 else scan
    return scan, spend


def _tor_available() -> bool:
    """Whether the Tor transport extra is installed (``stem``).

    We can't know live circuit state without bootstrapping (expensive), so the
    pill reflects capability, not a live connection — Tor is brought up on
    demand when you ``drift chat``.
    """
    return shutil.which("tor") is not None or _module_available("stem")


def _module_available(name: str) -> bool:
    import importlib.util

    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def _frag_line(text: Text, frag: str, frag_style: str, noise_style: str,
               left: str, right: str) -> None:
    """Append a ``▓▒░ <fragment> ░▒▓`` dissolving line to ``text``."""
    text.append(left, style=noise_style)
    text.append(frag, style=frag_style)
    text.append(right, style=noise_style)


def _logo(theme: dict[str, str], code: str | None) -> Table:
    """The wordmark beside the dissolving-identity art."""
    primary, secondary, dim = theme["primary"], theme["secondary"], theme["dim"]

    left = Text("\n".join(_WORDMARK), style=f"bold {primary}")

    scan, spend = _code_parts(code)
    f1 = _short_frag(scan, 4, 2)
    f2 = _short_frag(spend, 4, 2)
    right = Text()
    right.append("░░░▒▒▓▓████▓▓▒▒░░\n", style=dim)
    _frag_line(right, f1, secondary, dim, "▓▒░ ", " ░▒▓\n")
    _frag_line(right, f2, secondary, dim, "░▒▓ ", " ▓▒░\n")
    right.append(" ▒░  identity  ░▒\n", style=dim)
    right.append("  ░   burned    ░\n", style=dim)
    right.append("   // identity.burn() → 0x00", style=f"italic {dim}")

    grid = Table.grid(padding=(0, 3))
    grid.add_column()
    grid.add_column()
    grid.add_row(left, right)
    return grid


def _manifesto(theme: dict[str, str]) -> Panel:
    primary, dim = theme["primary"], theme["dim"]
    body = Text()
    body.append("no accounts", style=primary)
    body.append("  ·  ", style=dim)
    body.append("no phone number", style=primary)
    body.append("  ·  ", style=dim)
    body.append("no server records\n", style=primary)
    body.append("your identity is mathematics. nothing else.", style=f"italic {dim}")
    return Panel(body, box=box.ROUNDED, border_style=theme["border"], padding=(0, 2),
                 expand=False)


def _pills(theme: dict[str, str], tor_on: bool) -> Text:
    primary, dim = theme["primary"], theme["dim"]
    pills = [("🔒", "E2E", True), ("⚡", "RATCHET", True), ("⬡", "STEALTH", True),
             ("✉", "SEALED", True), ("🌐", "TOR", tor_on)]
    out = Text()
    for i, (icon, label, active) in enumerate(pills):
        if i:
            out.append("   ")
        style = primary if active else dim
        out.append(f"{icon} ", style=style)
        out.append(label, style=f"bold {style}" if active else dim)
    return out


def _menu(theme: dict[str, str], has_identity: bool, code: str | None) -> Panel:
    primary, secondary, dim = theme["primary"], theme["secondary"], theme["dim"]
    scan, _ = _code_parts(code)
    body = Text()
    for i, (num, glyph, label) in enumerate(_MENU):
        if i:
            body.append("\n")
        # Item 1 is always live. When an identity exists, items 2-7 are live and
        # item 1 becomes "my identity"; otherwise 2-7 are dimmed "setup required".
        live = (num == "1") or has_identity
        num_style = secondary if live else dim
        text_style = primary if live else dim
        body.append(f"  [{num}]  ", style=f"bold {num_style}")
        body.append(f"{glyph}  ", style=text_style)
        if num == "1" and has_identity:
            body.append("my identity", style=text_style)
            if code:
                body.append("  ·  ", style=dim)
                body.append(f"drift:{scan[:4]}···", style=secondary)
        else:
            body.append(label, style=text_style)
            if not live:
                body.append("   (setup required)", style=dim)
    return Panel(
        body,
        box=box.ROUNDED,
        border_style=theme["border"],
        title=f"[{secondary}]what would you like to do?[/]",
        title_align="left",
        padding=(1, 1),
        expand=False,
    )


def _status(theme: dict[str, str], tor_on: bool) -> Text:
    from drift import __version__

    dim, secondary = theme["dim"], theme["secondary"]
    tor_state = "ready (on-demand)" if tor_on else "not installed · pip install -e '.[tor]'"
    line = Text()
    line.append("relay: ", style=dim)
    line.append(DEFAULT_RELAY, style=secondary)
    line.append("   ·   tor: ", style=dim)
    line.append(tor_state, style=secondary if tor_on else dim)
    line.append(f"\nv{__version__}   ·   pre-alpha   ·   metadata-private by design", style=dim)
    return line


def render(console: Console) -> bool:
    """Render the static welcome interface. Returns whether an identity exists."""
    theme = active_theme()
    has_identity, code = _identity_state()
    tor_on = _tor_available()

    console.print()
    console.print(Align.left(_logo(theme, code)))
    console.print()
    console.print(_manifesto(theme))
    console.print()
    console.print(_pills(theme, tor_on))
    console.print()
    console.print(_menu(theme, has_identity, code))
    console.print()
    console.print(_status(theme, tor_on))
    console.print()
    return has_identity


# ---------------------------------------------------------------------------
# Boot sequence
# ---------------------------------------------------------------------------

def _boot_line(label: str, dots: int, theme: dict[str, str]) -> Text:
    line = Text()
    line.append(label, style=theme["dim"])
    line.append("." * dots, style=theme["dim"])
    line.append(" ok", style=f"bold {theme['primary']}")
    return line


def play_boot_sequence(console: Console, delay: float = 0.04) -> None:
    """Print the subsystem boot sequence one line at a time."""
    theme = active_theme()
    console.print(Text(_BOOT_HEADER, style=f"bold {theme['primary']}"))
    console.print(Text("initializing cryptographic subsystems...", style=theme["dim"]))
    time.sleep(delay)
    for label, dots in _BOOT_SUBSYSTEMS:
        console.print(_boot_line(label, dots, theme))
        time.sleep(delay)
    console.print(Text("all systems nominal.", style=f"bold {theme['primary']}"))
    time.sleep(delay)


# ---------------------------------------------------------------------------
# Interaction / dispatch
# ---------------------------------------------------------------------------

def _drift_argv() -> list[str]:
    """How to re-invoke the CLI for a chosen action.

    Prefer the ``drift`` launcher on PATH; fall back to ``python -m drift`` so
    dispatch works even when only the module entry point is available.
    """
    exe = shutil.which("drift")
    if exe:
        return [exe]
    return [sys.executable, "-m", "drift"]


def _run(argv: list[str]) -> int:
    # The command is our own drift launcher; the trailing tokens are what the
    # user just typed at their own prompt to run against their own CLI. Nothing
    # untrusted or shell-interpreted here (no shell=True).
    return subprocess.call(argv)  # noqa: S603


def _dispatch(choice: str, has_identity: bool, console: Console) -> int:
    """Run the command for a menu choice (or a typed command). Returns exit code."""
    argv = _drift_argv()

    # A full command typed instead of a number → run it verbatim.
    if choice not in _COMMAND_FOR_CHOICE:
        return _run(argv + choice.split())

    if choice != "1" and not has_identity:
        console.print(
            "\n[dim]Set up your identity first — choose [bold]1[/bold].[/dim]"
        )
        return 1

    fixed = _COMMAND_FOR_CHOICE[choice]
    if fixed is not None:
        return _run(argv + fixed)

    # Choices needing inline arguments.
    if choice == "2":
        name = console.input("  contact nickname: ").strip()
        code = console.input("  contact code: ").strip()
        if not name or not code:
            console.print("[dim]Cancelled — need both a nickname and a code.[/dim]")
            return 1
        return _run(argv + ["add", name, code])
    if choice == "6":
        handle = console.input("  beacon handle: ").strip()
        if not handle:
            console.print("[dim]Cancelled.[/dim]")
            return 1
        return _run(argv + ["beacon", handle])
    if choice == "7":
        relay = console.input(f"  relay url [{DEFAULT_RELAY}]: ").strip() or DEFAULT_RELAY
        return _run(argv + ["witness", "verify", relay])
    return 1  # unreachable


def _interactive_choice(has_identity: bool, code: str | None, tor_on: bool) -> str | None:
    """Drive the Textual welcome menu; return the chosen menu key ("1".."8") or
    None to quit.

    Textual is imported **here**, not at module top, so that merely importing
    this module — or rendering the non-interactive banner — never drags Textual
    into process (see ``test_welcome_pulls_in_no_textual``). The menu reuses the
    same Rich renderables as the static banner (``_logo``/``_manifesto``/
    ``_pills``/``_status``); only the numbered list becomes interactive.

    The app fully exits (releasing the terminal) before the caller dispatches
    the chosen command — important because that command may itself be a Textual
    app (``drift chat``) and two cannot share the screen.
    """
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Vertical, VerticalScroll
    from textual.events import Click, Key
    from textual.reactive import reactive
    from textual.widgets import Static

    theme = active_theme()
    primary, secondary, dim = theme["primary"], theme["secondary"], theme["dim"]
    scan, _ = _code_parts(code)

    class _WelcomeMenu(Static):
        """The numbered menu as a single focusable widget: a ``▶`` cursor moves
        with the arrow keys (wrapping), digits 1–8 jump, enter / click fire."""

        can_focus = True
        selected: reactive[int] = reactive(0)

        def __init__(self, *, id: str | None = None) -> None:
            # Default cursor: "set up my identity" when fresh, else "start chatting".
            super().__init__(id=id)
            self.selected = 0 if not has_identity else 2

        def render(self) -> Text:
            body = Text()
            for i, (num, glyph, label) in enumerate(_MENU):
                if i:
                    body.append("\n")
                # Item 1 is always live; 2–7 need an identity first.
                live = (num == "1") or has_identity
                is_sel = i == self.selected
                bright = is_sel and live
                num_style = secondary if bright else dim
                text_style = f"bold {primary}" if bright else dim
                body.append("▶ " if is_sel else "  ",
                            style=f"bold {primary}" if bright else dim)
                body.append(f"[{num}]  ", style=f"bold {num_style}")
                body.append(f"{glyph}  ", style=text_style)
                if num == "1" and has_identity:
                    body.append("my identity", style=text_style)
                    if code:
                        body.append("  ·  ", style=dim)
                        body.append(f"drift:{scan[:4]}···", style=secondary)
                else:
                    body.append(label, style=text_style)
                    if not live:
                        body.append("   (setup required)", style=dim)
            return body

        def _fire(self, choice: str) -> None:
            self.app.exit(choice)

        def on_key(self, event: Key) -> None:
            if event.key == "up":
                self.selected = (self.selected - 1) % len(_MENU)
                event.stop()
            elif event.key == "down":
                self.selected = (self.selected + 1) % len(_MENU)
                event.stop()
            elif event.key == "enter":
                self._fire(_MENU[self.selected][0])
                event.stop()
            elif event.key in {m[0] for m in _MENU}:
                self.selected = int(event.key) - 1
                self._fire(event.key)
                event.stop()

        def on_click(self, event: Click) -> None:
            # The widget has no border/padding of its own (the box around it
            # does), so the click's y-offset is exactly the row index.
            row = event.offset.y
            if 0 <= row < len(_MENU):
                self.selected = row
                self._fire(_MENU[row][0])

    class _WelcomeApp(App[str | None]):
        CSS = f"""
        Screen {{ background: {theme['bg']}; align: center top; }}
        #welcome-body {{ width: auto; height: auto; padding: 1 2; }}
        #w-menu-box {{
            width: auto; height: auto; margin: 1 0; padding: 1 1;
            border: round {theme['border']};
            border-title-color: {secondary}; border-title-align: left;
        }}
        #w-menu {{ width: auto; height: auto; }}
        #w-hint {{ color: {dim}; padding: 1 0 0 0; }}
        """

        BINDINGS = [
            Binding("q", "quit_welcome", "quit", show=False),
            Binding("escape", "quit_welcome", "quit", show=False),
        ]

        def compose(self) -> ComposeResult:
            with VerticalScroll(id="welcome-body"):
                yield Static(_logo(theme, code))
                yield Static("")
                yield Static(_manifesto(theme))
                yield Static("")
                yield Static(_pills(theme, tor_on))
                with Vertical(id="w-menu-box"):
                    yield _WelcomeMenu(id="w-menu")
                yield Static(_status(theme, tor_on))
                yield Static(
                    f"[{dim}]↑/↓ move  ·  1–8 jump  ·  enter select  ·  q quit[/]",
                    id="w-hint",
                )

        def on_mount(self) -> None:
            self.query_one("#w-menu-box", Vertical).border_title = (
                "what would you like to do?"
            )
            self.query_one(_WelcomeMenu).focus()

        def action_quit_welcome(self) -> None:
            self.exit(None)

    return _WelcomeApp().run()


def run(no_animation: bool = False) -> int:
    """Entry point for ``drift`` with no arguments.

    Plays the boot sequence (TTY only), then — when interactive — launches the
    Textual welcome menu and dispatches the chosen action. On non-interactive
    output (pipes, CI) it renders the static banner once and returns without
    prompting, so ``drift | cat`` never hangs.
    """
    console = Console()
    interactive = sys.stdin.isatty() and sys.stdout.isatty()
    animate = interactive and not no_animation

    if animate:
        play_boot_sequence(console)
        console.clear()

    if not interactive:
        render(console)
        return 0

    has_identity, code = _identity_state()
    tor_on = _tor_available()
    choice = _interactive_choice(has_identity, code, tor_on)
    if not choice:
        return 0
    return _dispatch(choice, has_identity, console)
