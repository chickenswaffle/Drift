"""
drift.cli — command-line interface

Commands:
  drift init               generate a new identity
  drift whoami             print your contact code
  drift add <name> <code>  save a contact
  drift contacts           list saved contacts
  drift verify <name>      display safety number for out-of-band verification
  drift chat [name]        open the TUI client (optionally focused on a contact)
  drift witness verify <relay_url>     verify a relay's proof of blindness
  drift witness subscribe <relay_url>  watch a relay's witness chain live
  drift version            print the DRIFT version

The CLI is a thin "view" over drift.storage (the model). It owns no on-disk
state of its own and never performs crypto directly.
"""

from __future__ import annotations

import asyncio
import sys
from typing import Any

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from drift import __version__, storage
from drift.crypto import Identity, b58decode, b58encode, groups, x3dh
from drift.crypto import rooms as rooms_crypto
from drift.crypto.groups import ContactInfo, GroupError, create_group
from drift.crypto.rooms import Room, RoomError
from drift.storage import StorageError

app = typer.Typer(
    name="drift",
    help="Terminal-first E2E encrypted messenger with rotating stealth addresses.",
    add_completion=False,
    # No no_args_is_help: bare `drift` shows the welcome screen (the callback
    # below) instead of a help dump.
    invoke_without_command=True,
)
console = Console()


@app.callback(invoke_without_command=True)
def _main(
    ctx: typer.Context,
    no_animation: bool = typer.Option(
        False, "--no-animation", help="Skip the boot-sequence animation on the welcome screen."
    ),
) -> None:
    """Terminal-first E2E encrypted messenger with rotating stealth addresses."""
    # Only fire for a bare `drift` (no subcommand). Subcommands run as usual.
    if ctx.invoked_subcommand is not None:
        return
    from drift.ui.welcome import run as run_welcome

    raise typer.Exit(run_welcome(no_animation=no_animation))


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
    relay: str = typer.Option(
        "ws://localhost:8765", "--relay",
        help="Relay to publish your X3DH prekey bundle to (best-effort)",
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
    # X3DH (audit H3): generate a prekey bundle up front so peers can open a
    # forward-secret session with us asynchronously. Sealed in the vault when one
    # is configured, else stored alongside identity.json; published below.
    _, prekeys = x3dh.generate_prekey_bundle(identity)

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
        storage.save_prekey_privates(identity, prekeys)
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
            real_prekeys=prekeys.to_dict(),
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
    next_steps = Text()
    next_steps.append("  1   ", style="bold cyan")
    next_steps.append("share your contact code with someone you trust", style="white")
    next_steps.append("\n\n")
    next_steps.append("  2   ", style="bold cyan")
    next_steps.append("drift add <name> <their-code>", style="bold cyan")
    next_steps.append("\n\n")
    next_steps.append("  3   ", style="bold cyan")
    next_steps.append("drift chat <name>", style="bold cyan")
    console.print(Panel(
        next_steps,
        title="[dim]what to do next[/dim]",
        title_align="left",
        border_style="dim",
        box=box.ROUNDED,
    ))
    # First run is exactly when you need to share your code — show the QR now.
    _render_contact_qr(code)
    console.print()
    if passphrase:
        console.print("[dim]Keys are sealed in an encrypted vault:[/dim]", str(storage.VAULT_FILE))
        console.print("[dim]Start DRIFT with [bold]drift unlock <passphrase>[/bold].[/dim]")
    else:
        console.print("[dim]Keys are stored in:[/dim]", str(storage.IDENTITY_FILE))
    console.print("[dim]They never leave this machine.[/dim]")
    console.print()

    # Publish our prekey bundle (X3DH, audit H3) so peers can open a
    # forward-secret session asynchronously. Best-effort — a failure just means
    # peers fall back to the legacy bootstrap until the bundle is published.
    asyncio.run(_publish_prekeys_async(identity, prekeys, _relay_http(relay)))


async def _publish_prekeys_async(
    identity: Identity, prekeys: Any, http_base: str
) -> None:
    import httpx

    addr = identity.scan_keypair.public_b58()
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{http_base}/prekeys/{addr}",
                json=prekeys.publish_payload(identity),
                timeout=10.0,
            )
            resp.raise_for_status()
    except httpx.HTTPError as exc:
        console.print(
            f"[yellow]⚠ Could not publish prekey bundle:[/yellow] {exc}\n"
            "[dim]Peers will fall back to the legacy bootstrap until you publish. "
            "Re-run [bold]drift prekeys --publish[/bold] against a reachable relay.[/dim]"
        )
        return
    console.print(
        f"[green]✓[/green] [dim]Published your X3DH prekey bundle "
        f"({prekeys.one_time_count()} one-time prekeys) — contacts get full forward "
        "secrecy from the very first message.[/dim]"
    )


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
def lock(
    passphrase: str = typer.Argument(
        None, help="Your unlock passphrase (re-seals identity + contacts; prompted if omitted)",
    ),
) -> None:
    """
    Re-seal the vault: shred the unlocked identity *and contacts* from disk.

    While DRIFT is unlocked, your identity.json (private keys) and your address
    book sit readable on disk. Run this — or just close the app — before handing
    your device to anyone, so only the encrypted vault remains. Your passphrase
    re-seals the current identity and contacts into the vault before shredding
    the plaintext; the keys and contacts come back only with
    [bold]drift unlock <passphrase>[/bold].
    """
    if not storage.vault_exists():
        console.print(
            "[yellow]Nothing to lock:[/yellow] this identity has no vault (no unlock "
            "passphrase was set at init). Shredding it would destroy your only copy of "
            "the keys, so DRIFT refuses. Re-run [bold]drift init[/bold] with a passphrase "
            "to enable locking."
        )
        raise typer.Exit(1)

    if passphrase is None:
        passphrase = typer.prompt("Unlock passphrase", hide_input=True)

    if storage.lock(passphrase):
        console.print(
            "[green]✓[/green] Locked. Your keys and contacts are sealed in the vault — "
            "run [bold]drift unlock <passphrase>[/bold] to use DRIFT again."
        )
    else:
        # Identical generic failure for a wrong passphrase — never confirm or
        # deny that a particular passphrase (e.g. a duress one) is configured.
        console.print("[red]Could not lock.[/red]")
        raise typer.Exit(1)


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
            console.print("[dim]Your contact code is back to the plain 2-segment form.[/dim]")
        else:
            console.print(
                f"[green]✓[/green] FMD rate set to {effective:.4f} "
                f"({n} sub-keys; relay may pre-filter ~{effective * 100:.1f}% of traffic to you)."
            )
            console.print(
                "[dim]Re-share your contact code ([bold]drift whoami[/bold]) — it now carries "
                "your FMD key so senders can flag messages for you.[/dim]"
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


def _local_fmd_key(identity: Identity) -> Any:
    """The local FMD detection key for the configured rate, or None if FMD off.

    Derived deterministically from the identity (no stored secret); the number of
    sub-keys comes from the persisted privacy rate (audit M4).
    """
    from drift.crypto.fmd import subkeys_for_rate

    n = subkeys_for_rate(storage.get_fmd_rate())
    return identity.fmd_keypair(n) if n > 0 else None


def _my_contact_code(identity: Identity) -> str:
    """My contact code, carrying the FMD detection key as a 3rd segment when FMD
    is on so senders can flag messages for me (audit M4)."""
    fmd = _local_fmd_key(identity)
    return identity.contact_code(fmd_pubs=fmd.public_keys if fmd else None)


@app.command()
def whoami(
    qr: bool = typer.Option(
        False, "--qr", help="Render your contact code as a scannable QR in the terminal."
    ),
) -> None:
    """Print your contact code (includes your FMD detection key when FMD is on)."""
    identity = _require_identity()
    code = _my_contact_code(identity)
    # Plain print, not console.print: Rich hard-wraps at the terminal width
    # (80 when piped), and a ~95-char contact code would gain a newline mid-token
    # — corrupting it for copy-paste / capture. The code must come out as one line.
    print(code)
    if qr:
        _render_contact_qr(code)


@app.command()
def prekeys(
    relay: str = typer.Option("ws://localhost:8765", "--relay", help="Relay URL"),
    publish: bool = typer.Option(
        False, "--publish", help="Re-publish your bundle (and replenish if low)"
    ),
) -> None:
    """
    Show your X3DH prekey status, or re-publish your bundle with ``--publish``.

    Prekeys let contacts open a forward-secret session with you asynchronously
    (audit H3). The signed prekey rotates weekly; one-time prekeys are consumed
    one per new session and replenished as they run low.
    """
    import time as _time

    identity = _require_identity()
    # Lazily provision/maintain (generate on first use, rotate, replenish).
    privates = storage.ensure_prekeys(identity)

    if publish:
        asyncio.run(_publish_prekeys_async(identity, privates, _relay_http(relay)))
        return

    now = _time.time()
    remaining = privates.signed_prekey_created + x3dh.SIGNED_PREKEY_LIFETIME - now
    if remaining > 0:
        days, rem = divmod(int(remaining), 86400)
        hours = rem // 3600
        spk = f"valid (rotates in {days}d {hours}h)"
    else:
        spk = "due for rotation — run [bold]drift prekeys --publish[/bold]"

    status = asyncio.run(_prekey_status_async(identity, _relay_http(relay)))
    if status is None:
        otpk = "[yellow]not published[/yellow] (run [bold]drift prekeys --publish[/bold])"
    else:
        otpk = f"{status.get('one_time_count', 0)} remaining on relay"
    last = _time.strftime("%Y-%m-%d %H:%M UTC", _time.gmtime(privates.last_replenished))

    console.print()
    console.print("[bold]X3DH prekeys[/bold]")
    console.print(f"  Signed prekey:     {spk}")
    console.print(f"  One-time prekeys:  {otpk}")
    console.print(f"  Last replenished:  {last}")
    console.print(f"  Local unconsumed:  {privates.one_time_count()}")
    console.print()


async def _prekey_status_async(identity: Identity, http_base: str) -> dict[str, Any] | None:
    import httpx

    addr = identity.scan_keypair.public_b58()
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{http_base}/prekeys/{addr}/status", timeout=10.0)
    except httpx.HTTPError:
        return None
    if resp.status_code != 200:
        return None
    try:
        data: dict[str, Any] = resp.json()
    except ValueError:
        return None
    return data


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
    # Echo a recognisable fragment of the code back — this is the moment to
    # reinforce "you added the right person".
    frag = f"{code[:8]}···{code[-4:]}" if len(code) > 12 else code
    console.print(f"[green]✓[/green] added [bold]{name}[/bold]")
    console.print(f"  [dim]{frag}[/dim]")


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
    console.print(
        "[dim]Note: safety numbers changed in v0.14.1 (they now commit to the "
        "spend key too — audit M5). Any verification done on an older version is "
        "invalidated; re-verify, and make sure your contact is also on v0.14.1+.[/dim]"
    )
    console.print()


# ---------------------------------------------------------------------------
# Beacon — ephemeral discoverable handles (Phase 6)
# ---------------------------------------------------------------------------

def _relay_http(relay: str) -> str:
    """ws(s):// → http(s):// relay base for the beacon HTTP endpoints."""
    return relay.replace("wss://", "https://", 1).replace("ws://", "http://", 1).rstrip("/")


def _parse_ttl(ttl: str) -> int:
    """Parse a human TTL (``1m``/``5m``/``10m`` or raw seconds) → seconds."""
    ttl = ttl.strip().lower()
    try:
        if ttl.endswith("m"):
            return int(ttl[:-1]) * 60
        if ttl.endswith("s"):
            return int(ttl[:-1])
        return int(ttl)
    except ValueError:
        return 300


@app.command()
def beacon(
    handle: str = typer.Argument(..., help="The handle to light, e.g. Diego552"),
    ttl: str = typer.Option("5m", "--ttl", help="Lifetime: 1m, 5m, or 10m (max 10m)"),
    relay: str = typer.Option("ws://localhost:8765", "--relay", help="Relay URL"),
) -> None:
    """
    Light a beacon: make your contact code briefly discoverable by handle.

    Anyone who knows the exact handle while it's lit can `drift find` you. After
    it expires (or you press Ctrl+C) it's gone — no retroactive lookup. The relay
    only ever sees a hash of the handle, never the handle itself.
    """
    from drift.crypto.beacon import MAX_TTL_SECONDS

    identity = _require_identity()
    seconds = min(_parse_ttl(ttl), MAX_TTL_SECONDS)
    asyncio.run(_beacon_async(identity, handle, seconds, _relay_http(relay)))


async def _fetch_relay_pubkey(http_base: str) -> bytes | None:
    """Fetch the relay's long-term Ed25519 pubkey (raw bytes) for the M3
    relay-specific beacon lookup hash. Returns None if the relay can't be reached
    or doesn't expose the endpoint."""
    import httpx

    from drift.crypto import b58decode

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{http_base}/beacon/pubkey", timeout=10.0)
        if resp.status_code != 200:
            return None
        return b58decode(resp.json()["pubkey_b58"])
    except (httpx.HTTPError, KeyError, ValueError):
        return None


async def _beacon_async(identity: Any, handle: str, seconds: int, http_base: str) -> None:
    import base64

    import httpx
    from rich.live import Live

    from drift.crypto.beacon import create_beacon

    relay_pubkey = await _fetch_relay_pubkey(http_base)
    if relay_pubkey is None:
        console.print("[red]Could not light beacon:[/red] relay pubkey unavailable")
        raise typer.Exit(1)
    payload = create_beacon(identity, handle, seconds, relay_pubkey)

    body = {
        "lookup_hash": payload.lookup_hash,
        "payload": base64.b64encode(payload.encrypted).decode(),
        "ttl_seconds": payload.ttl_seconds,
    }
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(f"{http_base}/beacon", json=body, timeout=10.0)
            resp.raise_for_status()
    except httpx.HTTPError as exc:
        console.print(f"[red]Could not light beacon:[/red] {exc}")
        raise typer.Exit(1) from None

    def _render(remaining: int) -> Text:
        m, s = divmod(max(0, remaining), 60)
        return Text.from_markup(
            f"[green]✓ Beacon active[/green] — [bold cyan]{payload.handle}[/bold cyan] "
            f"expires in [bold]{m}:{s:02d}[/bold]   [dim](Ctrl+C to extinguish)[/dim]"
        )

    import time as _time
    try:
        with Live(_render(payload.ttl_seconds), console=console, refresh_per_second=4) as live:
            while True:
                remaining = payload.expires_at - int(_time.time())
                live.update(_render(remaining))
                if remaining <= 0:
                    break
                await asyncio.sleep(0.25)
        console.print(f"[dim]Beacon for {payload.handle} expired.[/dim]")
    except (KeyboardInterrupt, asyncio.CancelledError):
        # Early extinguish — tell the relay to delete it immediately.
        try:
            async with httpx.AsyncClient() as client:
                await client.delete(f"{http_base}/beacon/{payload.lookup_hash}", timeout=5.0)
        except httpx.HTTPError:
            pass
        console.print(f"\n[dim]Beacon for {payload.handle} extinguished.[/dim]")


@app.command()
def find(
    handle: str = typer.Argument(..., help="The handle to look up, e.g. Diego552"),
    relay: str = typer.Option("ws://localhost:8765", "--relay", help="Relay URL"),
) -> None:
    """
    Find a lit beacon by handle and add the person as a contact.

    On success the contact is saved under the handle; verify them out of band
    with `drift verify <handle>` before chatting.
    """
    from drift.crypto.beacon import lookup_hash, resolve_beacon

    identity = _require_identity()
    info = asyncio.run(_find_async(handle, _relay_http(relay), lookup_hash, resolve_beacon))
    if info is None:
        console.print("[yellow]Beacon not found or expired.[/yellow]")
        raise typer.Exit(1)
    try:
        storage.add_contact(identity, handle, info.contact_code)
    except StorageError as exc:
        console.print(f"[red]Found the beacon but could not add contact:[/red] {exc}")
        raise typer.Exit(1) from None
    console.print(f"[green]✓ Found {handle}[/green] → added as a contact.")
    console.print(
        Panel(
            f"[bold yellow]⚠ Verify before trusting.[/bold yellow]\n"
            f"Run [bold]drift verify {handle}[/bold] to confirm you're talking to "
            f"who you think you are.\n\n"
            f"Resolving this beacon proves the message wasn't [i]tampered with[/i] — "
            f"[bold]not who sent it[/bold]. Anyone can light a beacon under any "
            f"handle pointing at any contact code.",
            border_style="yellow",
            title="[yellow]unverified contact[/yellow]",
        )
    )


async def _find_async(handle: str, http_base: str, lookup_hash: Any, resolve_beacon: Any) -> Any:
    import base64

    import httpx

    relay_pubkey = await _fetch_relay_pubkey(http_base)
    if relay_pubkey is None:
        return None
    digest = lookup_hash(handle, relay_pubkey)
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{http_base}/beacon/{digest}", timeout=10.0)
    except httpx.HTTPError:
        return None
    if resp.status_code != 200:
        return None
    try:
        encrypted = base64.b64decode(resp.json()["payload"])
    except (KeyError, ValueError):
        return None
    return resolve_beacon(handle, encrypted)


# ---------------------------------------------------------------------------
# Groups (Phase 8)
# ---------------------------------------------------------------------------

group_app = typer.Typer(
    name="group",
    help="Create and manage group conversations (Phase 8, ≤10 members).",
    no_args_is_help=True,
)
app.add_typer(group_app, name="group")


@group_app.command("create")
def group_create(
    name: str = typer.Argument(..., help="Local label for the group"),
    # Typer's variadic-positional idiom; B008 only exempts immutable-typed defaults.
    members: list[str] = typer.Argument(..., help="Contact names to include"),  # noqa: B008
) -> None:
    """Create a group from saved contacts: drift group create <name> <c1> <c2> …"""
    identity = _require_identity()
    contacts = storage.load_contacts(identity)
    infos: list[ContactInfo] = []
    for m in members:
        if m not in contacts:
            console.print(f"[red]Unknown contact:[/red] {m}")
            raise typer.Exit(1)
        infos.append(ContactInfo(name=m, code=contacts[m]["code"]))
    try:
        g = create_group(name, infos)
    except GroupError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1) from None
    storage.add_group(identity, g)
    console.print(
        f"[green]✓[/green] Created group [bold]{name}[/bold] with "
        f"{len(g.members)} member(s). Open it with [bold]drift chat {name}[/bold]."
    )


@group_app.command("add")
def group_add(
    group_name: str = typer.Argument(..., help="The group to modify"),
    member: str = typer.Argument(..., help="Contact name to add"),
) -> None:
    """Add a saved contact to a group (announced to members when you next chat)."""
    identity = _require_identity()
    g = storage.get_group(identity, group_name)
    if g is None:
        console.print(f"[red]Unknown group:[/red] {group_name}")
        raise typer.Exit(1)
    contacts = storage.load_contacts(identity)
    if member not in contacts:
        console.print(f"[red]Unknown contact:[/red] {member}")
        raise typer.Exit(1)
    try:
        groups.add_member(g, ContactInfo(name=member, code=contacts[member]["code"]))
    except GroupError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1) from None
    storage.add_group(identity, g)
    console.print(f"[green]✓[/green] Added [bold]{member}[/bold] to [bold]{group_name}[/bold]")


@group_app.command("remove")
def group_remove(
    group_name: str = typer.Argument(..., help="The group to modify"),
    member: str = typer.Argument(..., help="Member name to remove"),
) -> None:
    """Remove a member from a group (announced to members when you next chat)."""
    identity = _require_identity()
    g = storage.get_group(identity, group_name)
    if g is None:
        console.print(f"[red]Unknown group:[/red] {group_name}")
        raise typer.Exit(1)
    code = next((m.code for m in g.members if m.name == member), None)
    if code is None:
        console.print(f"[red]{member} is not in {group_name}[/red]")
        raise typer.Exit(1)
    groups.remove_member(g, code)
    storage.add_group(identity, g)
    console.print(
        f"[green]✓[/green] Removed [bold]{member}[/bold] from [bold]{group_name}[/bold]"
    )


@group_app.command("list")
def group_list() -> None:
    """List your groups and their members."""
    identity = _require_identity()
    saved = storage.load_groups(identity)
    if not saved:
        console.print("[dim]No groups yet. Use [bold]drift group create[/bold].[/dim]")
        return
    for name, g in saved.items():
        names = ", ".join(m.name for m in g.members) or "(just you)"
        console.print(f"  [bold]{name}[/bold]  [dim]{g.size} members:[/dim] {names}")


# ---------------------------------------------------------------------------
# Rooms (Phase 11) — sovereign rooms: cryptographic chatrooms, no server-side
# representation. A room is a shared secret derived from its name; the relay
# only ever sees opaque blobs at rotating stealth addresses.
# ---------------------------------------------------------------------------

room_app = typer.Typer(
    name="room",
    help="Sovereign rooms — encrypted chatrooms that exist only as math (Phase 11).",
    no_args_is_help=True,
)
app.add_typer(room_app, name="room")


_TIER_BLURB = {
    rooms_crypto.TIER_OPEN: "open — anyone who knows the name can read and post",
    rooms_crypto.TIER_INVITE: "invite — anyone can read; posting needs an invite token",
    rooms_crypto.TIER_DARK: "dark — no name, joinable only via its QR/secret",
}


def _render_contact_qr(code: str) -> None:
    """Print a scannable QR of a contact code to the terminal, or a graceful
    fallback if segno is not installed."""
    try:
        import segno
        console.print()
        console.print("[dim]scan to add as a contact:[/dim]")
        segno.make(code, error="l").terminal(compact=True)
        console.print()
    except Exception:  # noqa: BLE001 — QR rendering is best-effort, never fatal
        # Escape the literal brackets so Rich doesn't parse [qr] as markup.
        console.print(
            r"[dim](install the 'qr' extra for a scannable QR: pip install -e '.\[qr]')[/dim]"
        )


def _render_room_qr(descriptor: str) -> None:
    """Print a scannable QR of a room descriptor to the terminal (segno), or a
    note if segno is unavailable. The descriptor itself is always printed too."""
    try:
        import segno
        segno.make(descriptor, error="l").terminal(compact=True)
    except Exception:  # noqa: BLE001 — QR rendering is best-effort, never fatal
        console.print("[dim](install the 'qr' extra to render a scannable QR)[/dim]")


def _save_room_qr_png(label: str, descriptor: str) -> str | None:
    """Write a scannable PNG of the descriptor next to the config dir; return its
    path, or None if segno/PNG support is unavailable."""
    try:
        import segno
        path = storage.CONFIG_DIR / f"room-{label.replace('/', '_')}.png"
        storage.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        segno.make(descriptor, error="m").save(str(path), scale=6, border=2)
        return str(path)
    except Exception:  # noqa: BLE001
        return None


async def _discover_relays(relay: str, want: int) -> list[str]:
    """Pick up to ``want`` distinct relays for sharding: this relay plus its
    advertised federation peers. Returns whatever is available (possibly fewer
    than ``want``)."""
    import httpx

    base = _relay_http(relay)
    relays = [relay]
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{base}/federation/peers", timeout=10.0)
            peers = resp.json().get("peers", []) if resp.status_code == 200 else []
    except httpx.HTTPError:
        peers = []
    for p in peers:
        if p not in relays:
            relays.append(p)
    return relays[:want]


@room_app.command("create")
def room_create(
    name: str = typer.Argument(None, help="Room name (omit for --dark)"),
    invite_only: bool = typer.Option(
        False, "--invite-only", help="Posting requires an invite token"),
    dark: bool = typer.Option(False, "--dark", help="No name — joinable only via QR/secret"),
    shards: int = typer.Option(0, "--shards", help="Split the room across N federation relays"),
    relay: str = typer.Option("ws://localhost:8765", "--relay", help="Relay (for shard discovery)"),
    label: str = typer.Option(None, "--label", help="Local label (defaults to the name)"),
) -> None:
    """
    Create a sovereign room.

    The room has no server-side representation — it is purely the shared secret
    derived from its name (or, for --dark, a random secret you share by QR).
    Treat the name as a *password*: a short or common name is a weak room anyone
    can guess into.
    """
    identity = _require_identity()
    if invite_only and dark:
        console.print("[red]--invite-only and --dark cannot be combined.[/red]")
        raise typer.Exit(1)
    tier = (
        rooms_crypto.TIER_DARK if dark
        else rooms_crypto.TIER_INVITE if invite_only
        else rooms_crypto.TIER_OPEN
    )
    if not dark and not name:
        console.print("[red]A room name is required (or use --dark).[/red]")
        raise typer.Exit(1)

    shard_relays: list[str] = []
    if shards and shards > 1:
        shard_relays = asyncio.run(_discover_relays(relay, shards))
        if len(shard_relays) < shards:
            console.print(
                f"[yellow]Only {len(shard_relays)} relay(s) available for "
                f"{shards} shards — sharding across {len(shard_relays)}.[/yellow]"
            )

    try:
        room = rooms_crypto.make_room(name, tier=tier, label=label, shards=shard_relays)
    except RoomError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from None

    if storage.get_room(identity, room.label) is not None:
        console.print(f"[red]A room labelled {room.label!r} already exists.[/red]")
        raise typer.Exit(1)
    storage.add_room(identity, room)

    console.print(
        f"[green]✓[/green] Created [bold]⬡ {room.label}[/bold]  "
        f"[dim]({_TIER_BLURB[tier]})[/dim]"
    )
    if room.shard_count:
        console.print(f"[dim]Sharded across {room.shard_count} relay(s):[/dim] "
                      + ", ".join(room.shards))
    if tier == rooms_crypto.TIER_INVITE:
        token = _room_token(room)
        console.print(Panel(
            f"Posting token (share with members):\n[bold cyan]{token}[/bold cyan]\n\n"
            f"They join with [bold]drift room join {name} --token {token}[/bold].\n"
            f"[dim]The relay can't enforce one-use; everyone with the token can post.[/dim]",
            border_style="cyan", title="[cyan]invite token[/cyan]",
        ))
    if tier == rooms_crypto.TIER_DARK:
        descriptor = room.to_qr()
        console.print(Panel(
            f"This room has no name. Share it [bold]only[/bold] by this code/QR:\n\n"
            f"[bold magenta]{descriptor}[/bold magenta]",
            border_style="red", title="[red]dark room — keep this secret[/red]",
        ))
        _render_room_qr(descriptor)
        png = _save_room_qr_png(room.label, descriptor)
        if png:
            console.print(f"[dim]Scannable QR saved to[/dim] {png}")
        console.print("[dim]Others join with[/dim] "
                      "[bold]drift room join --qr --file <code-or-png>[/bold]")
    console.print(f"\n[dim]Open it with[/dim] [bold]drift chat {room.label!r}[/bold]")


def _room_token(room: Room) -> str:
    """The invite token for an invite room (the posting secret, base58)."""
    if not room.post_secret_b58:
        raise RoomError("not an invite room (no posting secret)")
    return rooms_crypto.encode_invite_token(b58decode(room.post_secret_b58))


@room_app.command("join")
def room_join(
    name: str = typer.Argument(None, help="Room name to join (omit for --qr)"),
    token: str = typer.Option(None, "--token", help="Invite token (for invite-only rooms)"),
    invite_only: bool = typer.Option(
        False, "--invite-only", help="Mark this as an invite room when joining by name"),
    qr: bool = typer.Option(False, "--qr", help="Join a dark room from its QR/descriptor"),
    file: str = typer.Option(
        None, "--file", help="Path to a QR image or a text file holding the driftroom: code"),
    label: str = typer.Option(None, "--label", help="Local label (defaults to the name)"),
) -> None:
    """
    Join a room — derive its keys and save it locally so you can `drift chat` it.

    There is nothing to register with any server: joining is purely deriving the
    same key material everyone else derives from the name (or scanning the dark
    room's QR). You can leave and rejoin at any time.
    """
    identity = _require_identity()

    if qr or (name and name.startswith(rooms_crypto.QR_PREFIX)):
        descriptor = (
            name if (name and name.startswith(rooms_crypto.QR_PREFIX))
            else _read_descriptor(file)
        )
        try:
            room = Room.from_qr(descriptor, label=label)
        except RoomError as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(1) from None
    else:
        if not name:
            console.print("[red]A room name is required (or use --qr).[/red]")
            raise typer.Exit(1)
        tier = rooms_crypto.TIER_INVITE if (token or invite_only) else rooms_crypto.TIER_OPEN
        post_b58 = None
        if token:
            try:
                post_b58 = b58encode(rooms_crypto.decode_invite_token(token))
            except RoomError as exc:
                console.print(f"[red]{exc}[/red]")
                raise typer.Exit(1) from None
            tier = rooms_crypto.TIER_INVITE
        room = Room(label=label or name, tier=tier, name=name, post_secret_b58=post_b58)

    if storage.get_room(identity, room.label) is not None:
        console.print(f"[yellow]Already joined[/yellow] [bold]⬡ {room.label}[/bold].")
        return
    storage.add_room(identity, room)
    blurb = _TIER_BLURB[room.tier]
    console.print(f"[green]✓[/green] Joined [bold]⬡ {room.label}[/bold]  [dim]({blurb})[/dim]")
    if room.tier == rooms_crypto.TIER_INVITE and not room.post_secret_b58:
        console.print("[dim]You joined as a lurker (read-only). Post with an invite token.[/dim]")
    console.print(
        Panel(
            "[bold yellow]⚠ PUBLIC ROOM[/bold yellow] — everyone who knows this room can read "
            "what you post.\nRooms are encrypted but [bold]not forward-secret[/bold]: anyone who "
            "ever learns the\nname/secret can read all past messages.",
            border_style="yellow",
        )
    )
    console.print(f"[dim]Open it with[/dim] [bold]drift chat {room.label!r}[/bold]")


def _read_descriptor(file: str | None) -> str:
    """Resolve a dark-room descriptor from --file: a text file holding the
    ``driftroom:`` code, or (if a QR decoder is installed) a QR image. Camera
    capture is not available in this environment."""
    if not file:
        console.print(
            "[red]--qr needs --file <code-or-image>.[/red] "
            "Live camera capture isn't available here; paste the driftroom: code "
            "into a text file, or pass a QR PNG if you have a decoder installed."
        )
        raise typer.Exit(1)
    from pathlib import Path
    p = Path(file)
    if not p.exists():
        console.print(f"[red]No such file:[/red] {file}")
        raise typer.Exit(1)
    # Text file or pasted descriptor.
    try:
        text = p.read_text().strip()
        if text.startswith(rooms_crypto.QR_PREFIX):
            return text
    except (UnicodeDecodeError, OSError):
        pass
    # Otherwise try to decode an image, if any decoder is available.
    decoded = _decode_qr_image(p)
    if decoded:
        return decoded
    console.print(
        "[red]Could not read a room code from that file.[/red] "
        "No QR image decoder is installed — save the [bold]driftroom:[/bold] text into a "
        "file and pass that instead."
    )
    raise typer.Exit(1)


def _decode_qr_image(path: Any) -> str | None:
    """Best-effort QR-image decode using whatever optional decoder is present."""
    try:
        from PIL import Image
        from pyzbar.pyzbar import decode
        for sym in decode(Image.open(path)):
            data = str(sym.data.decode("utf-8", "ignore"))
            if data.startswith(rooms_crypto.QR_PREFIX):
                return data
    except Exception:  # noqa: BLE001 — decoder is optional
        return None
    return None


@room_app.command("list")
def room_list() -> None:
    """List your joined rooms with their tier and recent activity."""
    identity = _require_identity()
    saved = storage.load_rooms(identity)
    if not saved:
        console.print("[dim]No rooms yet. Use [bold]drift room create[/bold] or "
                      "[bold]drift room join[/bold].[/dim]")
        return
    tier_color = {
        rooms_crypto.TIER_OPEN: "yellow",
        rooms_crypto.TIER_INVITE: "cyan",
        rooms_crypto.TIER_DARK: "red",
    }
    for label, room in saved.items():
        color = tier_color.get(room.tier, "white")
        shard = f" · {room.shard_count} shards" if room.shard_count else ""
        can_post = room.tier != rooms_crypto.TIER_INVITE or bool(room.post_secret_b58)
        post = "" if can_post else " · read-only"
        last = f"window {room.last_window}" if room.last_window else "never"
        console.print(
            f"  [bold]⬡ {label}[/bold]  [{color}]{room.tier}[/{color}]{shard}{post}  "
            f"[dim]{room.message_count} msgs · last {last}[/dim]"
        )


@room_app.command("invite")
def room_invite(
    label: str = typer.Argument(..., help="The invite-only room to mint a token for"),
) -> None:
    """Mint an invite token for an invite-only room (grants posting rights)."""
    identity = _require_identity()
    room = storage.get_room(identity, label)
    if room is None:
        console.print(f"[red]Unknown room:[/red] {label}")
        raise typer.Exit(1)
    if room.tier != rooms_crypto.TIER_INVITE or not room.post_secret_b58:
        console.print(f"[red]{label!r} is not an invite-only room you can invite to.[/red]")
        raise typer.Exit(1)
    token = _room_token(room)
    target = room.name or label
    console.print(Panel(
        f"[bold cyan]{token}[/bold cyan]\n\n"
        f"Share it so someone can post:\n"
        f"[bold]drift room join {target} --token {token}[/bold]\n\n"
        f"[dim]Honest note: the relay is blind, so it can't enforce one-use — every "
        f"holder of this token can post. To revoke, recreate the room.[/dim]",
        border_style="cyan", title="[cyan]invite token[/cyan]",
    ))


@room_app.command("leave")
def room_leave(
    label: str = typer.Argument(..., help="The room to leave (local only)"),
) -> None:
    """Forget a room locally. You can rejoin any time with the name/token/QR."""
    identity = _require_identity()
    if storage.get_room(identity, label) is None:
        console.print(f"[red]Unknown room:[/red] {label}")
        raise typer.Exit(1)
    storage.remove_room(identity, label)
    console.print(f"[green]✓[/green] Left [bold]⬡ {label}[/bold] (local state removed).")


# ---------------------------------------------------------------------------
# Witness — verify a relay's cryptographic proof of blindness (Phase 10)
# ---------------------------------------------------------------------------

witness_app = typer.Typer(
    name="witness",
    help="Verify a relay's live, signed, hash-chained proof of blindness.",
    no_args_is_help=True,
)
app.add_typer(witness_app, name="witness")


def _short_hash(hex_str: str) -> str:
    """``8f3a2b…2b9c`` — first/last 4 bytes of a hex digest for display."""
    return f"{hex_str[:8]}…{hex_str[-4:]}" if len(hex_str) > 12 else hex_str


def _fmt_utc(ts: int) -> str:
    import time as _time
    return _time.strftime("%Y-%m-%d %H:%M:%S", _time.gmtime(ts))


@witness_app.command("verify")
def witness_verify(
    relay_url: str = typer.Argument(..., help="Relay URL, e.g. ws://localhost:8765"),
) -> None:
    """
    Fetch a relay's full 24-hour certificate chain and verify it end to end.

    Checks every Ed25519 signature, the hash-chain continuity (no resets), the
    period coverage (no missing 60-second windows), and that every certificate
    reports zero knowledge. Exits non-zero if anything fails to verify.
    """
    ok = asyncio.run(_witness_verify_async(relay_url))
    if not ok:
        raise typer.Exit(1)


async def _witness_verify_async(relay_url: str) -> bool:
    import httpx

    from drift.crypto import b58decode
    from relay.witness import (
        PERIOD_SECONDS,
        WitnessCertificate,
        verify_chain_report,
    )

    http_base = _relay_http(relay_url)
    console.print(f"Verifying DRIFT relay: [bold]{relay_url}[/bold]")
    try:
        async with httpx.AsyncClient() as client:
            pub_resp = await client.get(f"{http_base}/witness/pubkey", timeout=10.0)
            pub_resp.raise_for_status()
            chain_resp = await client.get(
                f"{http_base}/witness/chain", params={"limit": 1440}, timeout=30.0
            )
            chain_resp.raise_for_status()
    except httpx.HTTPError as exc:
        console.print(f"  [red]✗ Could not reach the relay:[/red] {exc}")
        return False

    expected_id = b58decode(pub_resp.json()["pubkey_b58"])
    raw_certs = chain_resp.json().get("certificates", [])
    try:
        certs = [WitnessCertificate.from_dict(c) for c in raw_certs]
    except (KeyError, ValueError) as exc:
        console.print(f"  [red]✗ Malformed certificate in chain:[/red] {exc}")
        return False

    report = verify_chain_report(certs, expected_relay_id=expected_id)
    n = int(report["count"])  # type: ignore[call-overload]
    hours = (n * PERIOD_SECONDS) / 3600.0
    console.print(f"  [green]✓[/green] Fetched {n} certificates ({hours:.1f} hours)")

    if report["signatures_valid"]:
        console.print(f"  [green]✓[/green] All {n} signatures valid")
    else:
        console.print("  [red]✗ Signature verification failed[/red]")

    if report["chain_intact"]:
        console.print("  [green]✓[/green] Hash chain intact — no gaps or resets")
    else:
        i = report["first_break"]
        nxt = i + 1 if isinstance(i, int) else "?"
        console.print(f"  [red]✗ Hash chain break between certificate {i} and {nxt}[/red]")
        console.print("    The chain was reset or forged — treat this relay as compromised.")

    if report["coverage_complete"]:
        console.print("  [green]✓[/green] Period coverage complete — no missing windows")
    else:
        gap = report["gap"]
        if isinstance(gap, dict):
            console.print(
                f"  [red]✗ Gap detected between certificate {gap['after_index']} "
                f"and {gap['before_index']}[/red]"
            )
            console.print(
                f"    Missing window: {_fmt_utc(int(gap['missing_from']))} — "
                f"{_fmt_utc(int(gap['missing_until']))} UTC"
            )
            console.print("    This may indicate the relay was compelled to modify its behavior.")
            console.print("    Treat this relay as potentially compromised.")

    if report["blindness_held"]:
        console.print("  [green]✓[/green] Relay has provably never held sender identities")
        console.print("  [green]✓[/green] Relay has provably never held recipient identities")
    else:
        console.print("  [red]✗ A certificate reported nonzero knowledge[/red]")

    root = report["current_merkle_root"]
    if isinstance(root, str):
        console.print(f"  [green]✓[/green] Current Merkle root: {_short_hash(root)}")
    console.print(f"  [green]✓[/green] Relay identity fingerprint: {report['fingerprint']}")

    console.print()
    if report["ok"]:
        console.print(
            "[bold green]This relay's blindness is cryptographically verified.[/bold green]"
        )
    else:
        console.print(
            "[bold red]Verification FAILED — do not trust this relay's blindness.[/bold red]"
        )
    return bool(report["ok"])


@witness_app.command("subscribe")
def witness_subscribe(
    relay_url: str = typer.Argument(..., help="Relay URL, e.g. ws://localhost:8765"),
) -> None:
    """
    Watch a relay's witness chain live (the canary watcher).

    Polls for each new certificate, verifies its signature and that it chains
    cleanly onto the previous one, and prints a dot per good period. The instant
    the chain breaks — a reset, a bad signature, or the relay going dark — it
    alerts loudly. Run this in a terminal alongside your chat. Ctrl+C to stop.
    """
    try:
        asyncio.run(_witness_subscribe_async(relay_url))
    except KeyboardInterrupt:
        console.print("\n[dim]Stopped watching.[/dim]")


async def _witness_subscribe_async(relay_url: str) -> None:
    import httpx

    from drift.crypto import b58decode
    from relay.witness import PERIOD_SECONDS, WitnessCertificate

    http_base = _relay_http(relay_url)
    console.print(
        f"[dim]Watching {relay_url} — verifying every new certificate. Ctrl+C to stop.[/dim]"
    )

    expected_id: bytes | None = None
    last: WitnessCertificate | None = None
    while True:
        try:
            async with httpx.AsyncClient() as client:
                if expected_id is None:
                    pk = await client.get(f"{http_base}/witness/pubkey", timeout=10.0)
                    pk.raise_for_status()
                    expected_id = b58decode(pk.json()["pubkey_b58"])
                resp = await client.get(f"{http_base}/witness/current", timeout=10.0)
                resp.raise_for_status()
            cert = WitnessCertificate.from_dict(resp.json())
        except (httpx.HTTPError, KeyError, ValueError) as exc:
            console.print(f"\n[red]⚠ Could not fetch a certificate:[/red] {exc}")
            await asyncio.sleep(PERIOD_SECONDS)
            continue

        if last is None or cert.timestamp != last.timestamp:
            if not cert.verify_signature() or cert.relay_id != expected_id:
                console.print("\n[bold red]⚠ CHAIN BREAK DETECTED — invalid signature. "
                              "Relay may be compromised.[/bold red]")
                return
            if last is not None and cert.previous_cert_hash != last.cert_hash():
                console.print(
                    "\n[bold red]⚠ CHAIN BREAK DETECTED — relay may be compromised.[/bold red]"
                )
                console.print(
                    f"[red]  certificate at {_fmt_utc(cert.timestamp)} UTC does not chain "
                    "onto the previous one.[/red]"
                )
                return
            console.print("·", end="")
            last = cert

        await asyncio.sleep(PERIOD_SECONDS)


@app.command()
def chat(
    name: str = typer.Argument(None, help="Contact or group to open (omit for full client)"),
    relay: str = typer.Option("ws://localhost:8765", "--relay", help="Relay WebSocket URL"),
    no_tui: bool = typer.Option(False, "--no-tui", help="Plain-text mode (no Textual TUI)"),
    no_tor: bool = typer.Option(
        False, "--no-tor", help="Skip Tor and connect to the relay directly (dev/testing)"
    ),
    tor_only: bool = typer.Option(
        False, "--tor-only", help="Refuse to connect at all if Tor fails to bootstrap"
    ),
    lockdown: bool = typer.Option(
        False, "--lockdown", "-L",
        help="Start in Lockdown mode — obfuscated input, no history retained.",
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
    saved_rooms = storage.load_rooms(identity)
    # A name may refer to a group, a room, or a contact; groups take precedence,
    # then rooms, then 1:1 contacts.
    group = storage.get_group(identity, name) if name is not None else None
    room = (
        saved_rooms.get(name) if name is not None and group is None else None
    )

    if name is not None and group is None and room is None and name not in saved:
        console.print(f"[red]Unknown contact, group, or room:[/red] {name}")
        raise typer.Exit(1)

    if no_tor and tor_only:
        console.print("[red]--no-tor and --tor-only are mutually exclusive.[/red]")
        raise typer.Exit(1)

    use_tor = not no_tor
    # FMD (audit M4): if the privacy dial is on, subscribe to the relay with our
    # detection key so it pre-filters our mail. None → classic full scanning.
    fmd_key = _local_fmd_key(identity)
    # X3DH (audit H3): load (and maintain) our persisted prekey privates so 1:1
    # sessions can complete an incoming handshake. Groups/rooms stay on the
    # legacy bootstrap, so they don't need them.
    prekeys = storage.ensure_prekeys(identity)

    if no_tui:
        if name is None:
            console.print("[red]--no-tui requires a contact, group, or room name.[/red]")
            raise typer.Exit(1)
        if group is not None:
            ok = asyncio.run(
                _group_chat_async(
                    identity, group, relay,
                    use_tor=use_tor, tor_only=tor_only, fmd_key=fmd_key,
                )
            )
        elif room is not None:
            ok = asyncio.run(
                _room_chat_async(
                    identity, room, relay, use_tor=use_tor, tor_only=tor_only,
                )
            )
        else:
            ok = asyncio.run(
                _chat_async(
                    name, identity, saved[name]["code"], relay,
                    use_tor=use_tor, tor_only=tor_only, fmd_key=fmd_key,
                    prekeys=prekeys,
                )
            )
        if not ok:
            raise typer.Exit(1)
        return

    from drift.ui.app import DriftApp
    DriftApp(
        identity, dict(saved), relay,
        active=name if (group is None and room is None) else None,
        group=group,
        rooms=dict(saved_rooms),
        room=room,
        use_tor=use_tor, tor_required=tor_only, fmd_key=fmd_key, prekeys=prekeys,
        lockdown=lockdown,
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
    fmd_key: Any = None,
    prekeys: Any = None,
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
            identity, contact_code, relay_url,
            tor_client=tor_client, fmd_key=fmd_key, prekeys=prekeys,
            on_prekeys_changed=lambda p: storage.save_prekey_privates(identity, p),
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


async def _group_chat_async(
    identity: Identity,
    group: Any,
    relay_url: str,
    *,
    use_tor: bool = True,
    tor_only: bool = False,
    fmd_key: Any = None,
) -> bool:
    """Headless group chat loop (--no-tui). Each message is prefixed with its
    sender's name; membership changes print as system lines."""
    from cryptography.exceptions import InvalidTag

    from drift.transport.session import GroupSession

    tor_client = await _bootstrap_tor_cli(use_tor=use_tor, tor_only=tor_only)
    if tor_client is False:
        return False

    def _on_membership(change: Any) -> None:
        verb = "added" if change.action == "add" else "removed"
        console.print(f"[dim]→ {change.target.name} {verb} (membership change)[/dim]")

    console.print(f"[dim]Connecting to {relay_url} …[/dim]")
    try:
        async with GroupSession(
            identity, group, relay_url,
            tor_client=tor_client, on_membership=_on_membership, fmd_key=fmd_key,
        ) as gs:
            console.print(
                f"[green]Connected.[/green] Group [bold]{group.name}[/bold] "
                f"({group.size} members). Ctrl+C to quit.\n"
            )
            recv_task = asyncio.create_task(_group_receive_loop(gs))
            loop = asyncio.get_running_loop()
            try:
                while True:
                    line = await loop.run_in_executor(None, sys.stdin.readline)
                    if not line:
                        break
                    text = line.rstrip("\n")
                    if text:
                        try:
                            await gs.send_to_group(text)
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


async def _group_receive_loop(gs: Any) -> None:
    from cryptography.exceptions import InvalidTag

    try:
        async for gm in gs.messages():
            console.print(f"\n[bold cyan]{gm.sender_name}:[/bold cyan] {gm.text}")
    except InvalidTag:
        console.print("\n[red]Authentication failure — message rejected.[/red]")


async def _room_chat_async(
    identity: Identity,
    room: Room,
    relay_url: str,
    *,
    use_tor: bool = True,
    tor_only: bool = False,
) -> bool:
    """Headless room chat loop (--no-tui). Messages show the anonymous 4-char
    sender tag (or a signed display name); a banner reminds you it's public."""
    from drift.transport.room_session import RoomSession

    tor_client = await _bootstrap_tor_cli(use_tor=use_tor, tor_only=tor_only)
    if tor_client is False:
        return False

    console.print(f"[dim]Connecting to {relay_url} …[/dim]")
    tier_colour = {"open": "yellow", "invite": "cyan", "dark": "red"}.get(room.tier, "yellow")
    try:
        async with RoomSession(
            identity, room, relay_url, tor_client=tor_client,
        ) as rs:
            console.print(
                f"[{tier_colour}]⚠ PUBLIC ROOM[/] [dim]— everyone with this room can "
                f"read what you post. Encrypted, not forward-secret.[/dim]"
            )
            console.print(
                f"[green]Connected.[/green] [bold]⬡ {room.label}[/bold] "
                f"({room.tier}). You are [bold]{rs.session_tag}[/bold]. Ctrl+C to quit.\n"
            )
            if not rs.can_post():
                console.print("[dim]Read-only: you joined without an invite token.[/dim]\n")
            recv_task = asyncio.create_task(_room_receive_loop(rs))
            loop = asyncio.get_running_loop()
            try:
                while True:
                    line = await loop.run_in_executor(None, sys.stdin.readline)
                    if not line:
                        break
                    text = line.rstrip("\n")
                    if text:
                        try:
                            await rs.send_to_room(text)
                        except Exception as exc:  # noqa: BLE001
                            console.print(f"[red]send error:[/red] {exc}")
                            continue
                        console.print(f"[bold green]you ({rs.session_tag}):[/bold green] {text}")
            except (KeyboardInterrupt, asyncio.CancelledError):
                pass
            finally:
                recv_task.cancel()
                try:
                    await recv_task
                except asyncio.CancelledError:
                    pass
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Connection error:[/red] {exc}")
    finally:
        if tor_client is not None:
            await tor_client.close()
    return True


async def _room_receive_loop(rs: Any) -> None:
    async for rm in rs.messages():
        who = rm.display_name if rm.display_name else rm.tag_label
        flag = "" if rm.authorized else " [dim red](unverified)[/]"
        console.print(f"\n[bold cyan][{who}]{flag}:[/bold cyan] {rm.text}")


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
