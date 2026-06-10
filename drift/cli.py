"""
drift.cli — command-line interface

Commands:
  drift init              generate a new identity
  drift whoami            print your contact code
  drift add <name> <code> save a contact
  drift verify <name>     display safety number for out-of-band verification
  drift chat <name>       open a conversation (Phase 0: basic, Phase 3: Tor)
  drift relay             start a local relay (for dev / self-hosted use)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from drift.crypto import Identity, b58encode
from drift import __version__

app = typer.Typer(
    name="drift",
    help="Terminal-first E2E encrypted messenger with rotating stealth addresses.",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()

# Default config directory: ~/.config/drift/
CONFIG_DIR = Path.home() / ".config" / "drift"
IDENTITY_FILE = CONFIG_DIR / "identity.json"
CONTACTS_FILE = CONFIG_DIR / "contacts.json"


def _load_identity() -> Identity:
    if not IDENTITY_FILE.exists():
        console.print("[red]No identity found. Run [bold]drift init[/bold] first.[/red]")
        raise typer.Exit(1)
    return Identity.load(IDENTITY_FILE)


def _load_contacts() -> dict:
    if not CONTACTS_FILE.exists():
        return {}
    return json.loads(CONTACTS_FILE.read_text())


def _save_contacts(contacts: dict) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONTACTS_FILE.write_text(json.dumps(contacts, indent=2))
    CONTACTS_FILE.chmod(0o600)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

@app.command()
def init(
    force: bool = typer.Option(False, "--force", help="Overwrite existing identity"),
) -> None:
    """Generate a new DRIFT identity (keypairs stored locally)."""
    if IDENTITY_FILE.exists() and not force:
        console.print("[yellow]Identity already exists.[/yellow] Use --force to regenerate (this is destructive).")
        raise typer.Exit(1)

    identity = Identity.generate()
    identity.save(IDENTITY_FILE)

    code = identity.contact_code()
    console.print()
    console.print(Panel(
        Text(code, style="bold cyan"),
        title="[green]✓  Identity generated[/green]",
        subtitle="Share this contact code with people who want to message you",
        border_style="green",
    ))
    console.print()
    console.print("[dim]Keys are stored in:[/dim]", str(IDENTITY_FILE))
    console.print("[dim]They never leave this machine.[/dim]")
    console.print()


@app.command()
def whoami() -> None:
    """Print your contact code."""
    identity = _load_identity()
    console.print(identity.contact_code())


@app.command()
def add(
    name: str = typer.Argument(..., help="Local nickname for this contact"),
    code: str = typer.Argument(..., help="Their drift: contact code"),
) -> None:
    """Save a contact by their contact code."""
    try:
        scan_pub, spend_pub = Identity.parse_contact_code(code)
    except ValueError as e:
        console.print(f"[red]Invalid contact code:[/red] {e}")
        raise typer.Exit(1)

    contacts = _load_contacts()
    contacts[name] = {"code": code}
    _save_contacts(contacts)
    console.print(f"[green]✓[/green] Added contact [bold]{name}[/bold]")


@app.command()
def contacts() -> None:
    """List your saved contacts."""
    c = _load_contacts()
    if not c:
        console.print("[dim]No contacts yet. Use [bold]drift add[/bold] to add one.[/dim]")
        return
    for name, data in c.items():
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
    identity = _load_identity()
    contacts_data = _load_contacts()

    if name not in contacts_data:
        console.print(f"[red]Unknown contact:[/red] {name}. Run [bold]drift add {name} <code>[/bold] first.")
        raise typer.Exit(1)

    their_code = contacts_data[name]["code"]
    their_scan, _ = Identity.parse_contact_code(their_code)
    my_scan = identity.scan_keypair.public_bytes()

    # Safety number: hash of both scan keys (sorted so it's symmetric)
    import hashlib
    combined = b"drift-safety-v0" + bytes(sorted([my_scan, their_scan], key=lambda b: b.hex()))
    digest = hashlib.sha256(combined).digest()

    # Encode as 4 English-ish words from a tiny wordlist (proper BIP39 in Phase 1)
    # For now: 4 groups of 2 decimal digits + one hex nibble, easy to read aloud
    words = "-".join(f"{digest[i*4]:02x}{digest[i*4+1]:02x}" for i in range(4))

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
    name: str = typer.Argument(..., help="Contact name to message"),
    relay: str = typer.Option("ws://localhost:8765", "--relay", help="Relay WebSocket URL"),
) -> None:
    """
    Open a conversation with a contact.

    Phase 0: direct WebSocket, no rotation.
    Phase 1: stealth addresses.
    Phase 3: routes over Tor automatically.
    """
    _load_identity()
    contacts_data = _load_contacts()

    if name not in contacts_data:
        console.print(f"[red]Unknown contact:[/red] {name}")
        raise typer.Exit(1)

    console.print(f"[dim]Connecting to relay at {relay} ...[/dim]")
    console.print("[yellow]Chat UI is Phase 0 — coming soon. Contributions welcome![/yellow]")
    console.print("[dim]See drift/ui/ to start building.[/dim]")


@app.command()
def version() -> None:
    """Print the DRIFT version."""
    console.print(f"drift v{__version__}")


if __name__ == "__main__":
    app()
