"""
drift.cli — command-line interface

Commands:
  drift init               generate a new identity
  drift whoami             print your contact code
  drift add <name> <code>  save a contact
  drift contacts           list saved contacts
  drift verify <name>      display safety number for out-of-band verification
  drift chat [name]        open the TUI client (optionally focused on a contact)
  drift version            print the DRIFT version

The CLI is a thin "view" over drift.storage (the model). It owns no on-disk
state of its own and never performs crypto directly.
"""

from __future__ import annotations

import asyncio
import sys
from typing import Any

import typer
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from drift import __version__, storage
from drift.crypto import Identity
from drift.storage import StorageError

app = typer.Typer(
    name="drift",
    help="Terminal-first E2E encrypted messenger with rotating stealth addresses.",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()


def _require_identity() -> Identity:
    try:
        return storage.load_identity()
    except StorageError:
        console.print("[red]No identity found. Run [bold]drift init[/bold] first.[/red]")
        raise typer.Exit(1) from None


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

@app.command()
def init(
    force: bool = typer.Option(False, "--force", help="Overwrite existing identity"),
) -> None:
    """Generate a new DRIFT identity (keypairs stored locally)."""
    identity = Identity.generate()
    try:
        storage.save_identity(identity, overwrite=force)
    except StorageError:
        console.print(
            "[yellow]Identity already exists.[/yellow] "
            "Use --force to regenerate (this is destructive)."
        )
        raise typer.Exit(1) from None

    code = identity.contact_code()
    console.print()
    console.print(Panel(
        Text(code, style="bold cyan"),
        title="[green]✓  Identity generated[/green]",
        subtitle="Share this contact code with people who want to message you",
        border_style="green",
    ))
    console.print()
    console.print("[dim]Keys are stored in:[/dim]", str(storage.IDENTITY_FILE))
    console.print("[dim]They never leave this machine.[/dim]")
    console.print()


@app.command()
def whoami() -> None:
    """Print your contact code."""
    identity = _require_identity()
    # Plain print, not console.print: Rich hard-wraps at the terminal width
    # (80 when piped), and a ~95-char contact code would gain a newline mid-token
    # — corrupting it for copy-paste / capture. The code must come out as one line.
    print(identity.contact_code())


@app.command()
def add(
    name: str = typer.Argument(..., help="Local nickname for this contact"),
    code: str = typer.Argument(..., help="Their drift: contact code"),
) -> None:
    """Save a contact by their contact code."""
    identity = _require_identity()
    try:
        storage.add_contact(identity, name, code)
    except StorageError as e:
        console.print(f"[red]Could not add contact:[/red] {e}")
        raise typer.Exit(1) from None
    console.print(f"[green]✓[/green] Added contact [bold]{name}[/bold]")


@app.command()
def contacts() -> None:
    """List your saved contacts."""
    identity = _require_identity()
    saved = storage.load_contacts(identity)
    if not saved:
        console.print("[dim]No contacts yet. Use [bold]drift add[/bold] to add one.[/dim]")
        return
    for name, data in saved.items():
        console.print(f"  [bold]{name}[/bold]  {data['code'][:40]}···")


@app.command()
def verify(
    name: str = typer.Argument(..., help="Contact name to verify"),
) -> None:
    """
    Display a short safety number for out-of-band key verification.

    Read the words aloud over a phone call or compare them in person.
    They should match on both sides. If they don't, abort — you may be
    talking to the wrong person.
    """
    identity = _require_identity()
    saved = storage.load_contacts(identity)

    if name not in saved:
        console.print(
            f"[red]Unknown contact:[/red] {name}. "
            f"Run [bold]drift add {name} <code>[/bold] first."
        )
        raise typer.Exit(1)

    words = storage.safety_number(identity, saved[name]["code"])

    console.print()
    console.print(Panel(
        Text(words, style="bold yellow"),
        title=f"Safety number with [bold]{name}[/bold]",
        subtitle="Compare out-of-band. Matches on both sides = key verified.",
        border_style="yellow",
    ))
    console.print()


@app.command()
def chat(
    name: str = typer.Argument(None, help="Contact to open (omit for the full client)"),
    relay: str = typer.Option("ws://localhost:8765", "--relay", help="Relay WebSocket URL"),
    no_tui: bool = typer.Option(False, "--no-tui", help="Plain-text mode (no Textual TUI)"),
    no_tor: bool = typer.Option(
        False, "--no-tor", help="Skip Tor and connect to the relay directly (dev/testing)"
    ),
    tor_only: bool = typer.Option(
        False, "--tor-only", help="Refuse to connect at all if Tor fails to bootstrap"
    ),
) -> None:
    """
    Open the DRIFT chat client.

    Phase 1: stealth addresses with rotating one-time addressing.
    Phase 2: Double Ratchet content encryption.
    Phase 3: routes over Tor automatically. Use --no-tor to bypass it, or
             --tor-only to refuse a clearnet fallback.
    """
    identity = _require_identity()
    saved = storage.load_contacts(identity)

    if name is not None and name not in saved:
        console.print(f"[red]Unknown contact:[/red] {name}")
        raise typer.Exit(1)

    if no_tor and tor_only:
        console.print("[red]--no-tor and --tor-only are mutually exclusive.[/red]")
        raise typer.Exit(1)

    use_tor = not no_tor

    if no_tui:
        if name is None:
            console.print("[red]--no-tui requires a contact name.[/red]")
            raise typer.Exit(1)
        ok = asyncio.run(
            _chat_async(
                name, identity, saved[name]["code"], relay,
                use_tor=use_tor, tor_only=tor_only,
            )
        )
        if not ok:
            raise typer.Exit(1)
        return

    from drift.ui.app import DriftApp
    DriftApp(
        identity, dict(saved), relay,
        active=name, use_tor=use_tor, tor_required=tor_only,
    ).run()


@app.command()
def version() -> None:
    """Print the DRIFT version."""
    console.print(f"drift v{__version__}")


# ---------------------------------------------------------------------------
# Headless chat loop (--no-tui) — for CI and environments without a TTY
# ---------------------------------------------------------------------------

async def _chat_async(
    name: str,
    identity: Identity,
    contact_code: str,
    relay_url: str,
    *,
    use_tor: bool = True,
    tor_only: bool = False,
) -> bool:
    """
    Headless chat loop. Returns True on a clean run, False if it could not start
    (e.g. --tor-only and Tor was unavailable).
    """
    from cryptography.exceptions import InvalidTag

    from drift.transport.session import Session

    tor_client = await _bootstrap_tor_cli(use_tor=use_tor, tor_only=tor_only)
    if tor_client is False:
        return False  # --tor-only and bootstrap failed → refuse to connect

    console.print(f"[dim]Connecting to {relay_url} …[/dim]")
    try:
        async with Session(
            identity, contact_code, relay_url, tor_client=tor_client
        ) as session:
            console.print(
                f"[green]Connected.[/green] Chatting with [bold]{name}[/bold]. "
                "Ctrl+C to quit.\n"
            )
            recv_task = asyncio.create_task(_receive_loop(session, name))
            loop = asyncio.get_running_loop()
            try:
                while True:
                    line = await loop.run_in_executor(None, sys.stdin.readline)
                    if not line:
                        break
                    text = line.rstrip("\n")
                    if text:
                        try:
                            await session.send(text)
                        except Exception as exc:  # noqa: BLE001
                            console.print(f"[red]send error:[/red] {exc}")
                            continue
                        console.print(f"[bold green]you:[/bold green] {text}")
            except (KeyboardInterrupt, asyncio.CancelledError):
                pass
            finally:
                recv_task.cancel()
                try:
                    await recv_task
                except (asyncio.CancelledError, InvalidTag):
                    pass
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Connection error:[/red] {exc}")
    finally:
        if tor_client is not None:
            await tor_client.close()
    return True


async def _bootstrap_tor_cli(*, use_tor: bool, tor_only: bool) -> Any:
    """
    Bring up Tor for the headless client.

    Returns the :class:`TorClient` on success, ``None`` to proceed on clearnet
    (Tor disabled or unavailable without --tor-only), or ``False`` to signal
    the caller must abort (--tor-only and bootstrap failed).
    """
    if not use_tor:
        return None

    from drift.transport import tor

    console.print("[dim]⚛ Bootstrapping Tor …[/dim]")

    def _progress(pct: int, _detail: str) -> None:
        console.print(f"[dim]  Bootstrapping Tor... {pct}%[/dim]")

    try:
        client = await tor.bootstrap(on_progress=_progress)
    except tor.TorError as exc:
        if tor_only:
            console.print(
                f"[red]Tor required (--tor-only) but unavailable:[/red] {exc}"
            )
            return False
        console.print(
            f"[yellow]⚠ Tor unavailable — connecting direct:[/yellow] {exc}"
        )
        return None
    console.print(
        f"[green]✓ Tor circuit established[/green] "
        f"[dim]· {client.num_hops} hops[/dim]"
    )
    return client


async def _receive_loop(session: Any, name: str) -> None:
    from cryptography.exceptions import InvalidTag

    try:
        async for msg in session.messages():
            console.print(f"\n[bold cyan]{name}:[/bold cyan] {msg}")
    except InvalidTag:
        console.print(
            "\n[red]Authentication failure — message rejected "
            "(tampered or wrong key).[/red]"
        )


if __name__ == "__main__":
    app()
