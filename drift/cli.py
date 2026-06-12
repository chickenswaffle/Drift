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
    passphrase: str = typer.Option(
        None, "--passphrase",
        help="Unlock passphrase (enables the encrypted vault). Blank = no vault.",
    ),
    duress_passphrase: str = typer.Option(
        None, "--duress-passphrase", help="Optional second passphrase for coercion (panic key)",
    ),
    duress_mode: str = typer.Option(
        "wipe", "--duress-mode",
        help="What the duress passphrase does: 'wipe' (destroy) or 'decoy' (innocuous identity)",
    ),
) -> None:
    """
    Generate a new DRIFT identity (keypairs stored locally).

    Optionally protect it with an unlock passphrase (an encrypted vault) and a
    *duress* passphrase — a second passphrase that, entered under coercion,
    silently wipes your keys or opens a believable decoy. Run interactively to
    be guided through it, or pass --passphrase / --duress-passphrase to script it.
    """
    if storage.identity_exists() and not force:
        console.print(
            "[yellow]Identity already exists.[/yellow] "
            "Use --force to regenerate (this is destructive)."
        )
        raise typer.Exit(1) from None

    identity = Identity.generate()

    # Resolve the unlock passphrase (flag, else interactive prompt, else none).
    interactive = sys.stdin.isatty()
    if passphrase is None and interactive:
        passphrase = typer.prompt(
            "Unlock passphrase (blank to skip and store keys unencrypted)",
            default="", hide_input=True, show_default=False,
        ) or None

    if not passphrase:
        # Legacy path: plain identity.json, no vault, no unlock step.
        storage.save_identity(identity, overwrite=force)
    else:
        # Vault path: optionally set up a duress passphrase.
        if duress_passphrase is None and interactive and typer.confirm(
            "Set up a duress passphrase? (recommended)", default=False
        ):
            duress_mode = typer.prompt(
                "Duress mode — 'wipe' (destroy keys) or 'decoy' (show innocuous identity)",
                default="wipe",
            ).strip().lower()
            if duress_mode not in ("wipe", "decoy"):
                duress_mode = "wipe"
            duress_passphrase = typer.prompt(
                "Duress passphrase (must differ from your unlock passphrase)",
                hide_input=True, confirmation_prompt=True,
            )
        if duress_passphrase is not None and duress_passphrase == passphrase:
            console.print("[red]Duress passphrase must differ from the unlock passphrase.[/red]")
            raise typer.Exit(1)
        if duress_mode not in ("wipe", "decoy"):
            duress_mode = "wipe"
        storage.create_vault(
            identity, passphrase,
            duress_passphrase=duress_passphrase,
            duress_mode=duress_mode,
        )

    code = identity.contact_code()
    console.print()
    console.print(Panel(
        Text(code, style="bold cyan"),
        title="[green]✓  Identity generated[/green]",
        subtitle="Share this contact code with people who want to message you",
        border_style="green",
    ))
    console.print()
    if passphrase:
        console.print("[dim]Keys are sealed in an encrypted vault:[/dim]", str(storage.VAULT_FILE))
        console.print("[dim]Start DRIFT with [bold]drift unlock <passphrase>[/bold].[/dim]")
    else:
        console.print("[dim]Keys are stored in:[/dim]", str(storage.IDENTITY_FILE))
    console.print("[dim]They never leave this machine.[/dim]")
    console.print()


@app.command()
def unlock(
    passphrase: str = typer.Argument(..., help="Your unlock passphrase (or duress passphrase)"),
    relay: str = typer.Option("ws://localhost:8765", "--relay", help="Relay WebSocket URL"),
    no_tor: bool = typer.Option(False, "--no-tor", help="Skip Tor; connect direct (dev/testing)"),
    tor_only: bool = typer.Option(False, "--tor-only", help="Refuse to connect if Tor fails"),
) -> None:
    """
    Unlock DRIFT and open the client — the entry point for vault-protected setups.

    Enter your unlock passphrase to proceed normally. If you set up a duress
    passphrase, entering it does its configured thing (wipe or decoy) and opens
    the client exactly the same way — no error, no difference an onlooker could
    see. Only a passphrase that matches neither is rejected.
    """
    if no_tor and tor_only:
        console.print("[red]--no-tor and --tor-only are mutually exclusive.[/red]")
        raise typer.Exit(1)

    if storage.vault_exists():
        outcome = storage.unlock(passphrase)
        if outcome == storage.UNLOCK_FAILED:
            # Generic, identical-for-any-wrong-passphrase rejection.
            console.print("[red]Could not unlock.[/red]")
            raise typer.Exit(1)
        # PROCEED is returned for real, decoy, AND wipe — indistinguishable here.
    elif not storage.identity_exists():
        console.print("[red]No identity found. Run [bold]drift init[/bold] first.[/red]")
        raise typer.Exit(1)
    # No vault but a plain identity exists → legacy unprotected start (passphrase
    # is not used; nothing to unlock).

    identity = _require_identity()
    saved = storage.load_contacts(identity)
    from drift.ui.app import DriftApp
    DriftApp(
        identity, dict(saved), relay,
        active=None, use_tor=not no_tor, tor_required=tor_only,
    ).run()


@app.command()
def privacy(
    fmd_rate: float = typer.Option(
        None, "--fmd-rate",
        help="Set the FMD false-positive rate (0 = off, pure client-side scanning)",
    ),
) -> None:
    """
    View or set privacy settings.

    The FMD dial trades anonymity for efficiency: 0 scans everything yourself
    (max privacy); higher rates let a relay pre-filter your mail at the cost of a
    larger, noisier match set. Without --fmd-rate this prints the current state.
    """
    if fmd_rate is not None:
        from drift.crypto.fmd import subkeys_for_rate

        stored = storage.set_fmd_rate(fmd_rate)
        n = subkeys_for_rate(stored)
        effective = 2.0 ** -n if n else 0.0
        if n == 0:
            console.print("[green]✓[/green] FMD disabled — pure client-side stealth scanning.")
        else:
            console.print(
                f"[green]✓[/green] FMD rate set to {effective:.4f} "
                f"({n} sub-keys; relay may pre-filter ~{effective * 100:.1f}% of traffic to you)."
            )
        return

    rate = storage.get_fmd_rate()
    console.print()
    console.print("[bold]Privacy settings[/bold]")
    if rate <= 0:
        console.print("  FMD detection:   [cyan]off[/cyan]  (you scan every message yourself)")
    else:
        console.print(f"  FMD detection:   [cyan]{rate:.4f}[/cyan] false-positive rate")
    # Deliberately constant text — identical whether or not a duress passphrase
    # is configured, so this screen never reveals that one exists.
    console.print(
        "  Unlock:          enter your passphrase at [bold]drift unlock[/bold]. "
        "A duress passphrase, if set, unlocks the same way."
    )
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
