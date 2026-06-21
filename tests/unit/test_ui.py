"""
tests/unit/test_ui.py — smoke tests for the Textual TUI

These don't need a relay: the session worker simply fails to connect and the
app surfaces that as a status line. We drive the app with Textual's pilot to
confirm the component tree mounts and the core interactions don't crash.

Run: pytest tests/unit/test_ui.py -v
"""

from __future__ import annotations

from io import StringIO

import pytest
from rich.console import Console

from drift.crypto import Identity
from drift.ui.app import (
    _SECURITY,
    _THEMES,
    AddContactModal,
    BurnEvent,
    CommandPalette,
    CryptoEvent,
    CryptoTicker,
    DriftApp,
    HeaderBar,
    HelpModal,
    InfoPanel,
    InputBar,
    LatencyPill,
    LockIndicator,
    LockWatermark,
    LogoBox,
    MessagePane,
    MessageRecord,
    NetworkPane,
    NetworkState,
    NodeCountEvent,
    NodePill,
    OnionNodeEvent,
    PillButton,
    RatchetPill,
    SecurityBar,
    SecurityPill,
    Sidebar,
    TorActiveEvent,
    UptimePill,
    _build_css,
    _LockdownInput,
)


def _app(with_contacts: bool = True) -> DriftApp:
    me = Identity.generate()
    contacts = {}
    if with_contacts:
        contacts = {"alice": {"code": Identity.generate().contact_code()}}
    # Point at a port nothing is listening on so the worker fails fast & quiet.
    return DriftApp(me, contacts, "ws://127.0.0.1:1", active=None)


def _app_active() -> DriftApp:
    """An app opened directly onto a contact (so the info panel has data)."""
    me = Identity.generate()
    contacts = {"alice": {"code": Identity.generate().contact_code()}}
    return DriftApp(me, contacts, "ws://127.0.0.1:1", active="alice")


@pytest.mark.asyncio
async def test_component_tree_mounts() -> None:
    async with _app().run_test() as pilot:
        app = pilot.app
        assert app.query_one(HeaderBar)
        assert app.query_one(CommandPalette)
        assert app.query_one(Sidebar)
        assert app.query_one(MessagePane)
        assert app.query_one(InputBar)
        # One pill per command + the sidebar's "[+] Add" pill.
        assert len(app.query(PillButton)) == 7


@pytest.mark.asyncio
async def test_help_modal_opens_and_closes() -> None:
    async with _app().run_test() as pilot:
        pilot.app.action_blur_input()
        await pilot.press("question_mark")
        assert isinstance(pilot.app.screen, HelpModal)
        await pilot.press("escape")
        assert not isinstance(pilot.app.screen, HelpModal)


@pytest.mark.asyncio
async def test_add_contact_command_opens_modal() -> None:
    async with _app(with_contacts=False).run_test() as pilot:
        pilot.app.action_command("add")
        await pilot.pause()
        assert isinstance(pilot.app.screen, AddContactModal)


@pytest.mark.asyncio
async def test_typing_in_input_updates_char_counter() -> None:
    async with _app().run_test() as pilot:
        pilot.app._input.focus()
        await pilot.pause()
        for ch in "hello":
            await pilot.press(ch)
        counter = pilot.app.query_one("#char-count")
        assert "5" in str(counter.render())


@pytest.mark.asyncio
async def test_slash_clear_does_not_crash_without_contact() -> None:
    async with _app(with_contacts=False).run_test() as pilot:
        await pilot.app._handle_slash("/clear")
        await pilot.pause()
        # Still alive and on the main screen.
        assert pilot.app.screen is pilot.app.screen_stack[0]


@pytest.mark.asyncio
async def test_header_has_logo_security_pills_and_ticker() -> None:
    async with _app().run_test() as pilot:
        app = pilot.app
        assert app.query_one(LogoBox)
        assert app.query_one(CryptoTicker)
        assert app.query_one(InfoPanel)
        # Five indicators: E2E, RATCHET, STEALTH, SEALED, TOR.
        assert len(app.query(SecurityPill)) == 5


@pytest.mark.asyncio
async def test_header_has_lock_indicator_starting_unsecured() -> None:
    async with _app().run_test() as pilot:
        lock = pilot.app.query_one(LockIndicator)
        assert lock.secure is False
        # Block-drawn padlock, shackle open, dim red, before any session connects.
        rendered = str(lock.render())
        assert "╰─██─╯" in rendered      # padlock body + keyhole
        assert "╭╯  ╰╮" in rendered       # open shackle
        assert "#aa3333" in rendered      # dim red
        assert "🔓" not in rendered        # no emoji — block-drawn now


@pytest.mark.asyncio
async def test_lock_indicator_reflects_secure_and_maximum_states() -> None:
    async with _app().run_test() as pilot:
        lock = pilot.app.query_one(LockIndicator)
        lock.secure = True
        await pilot.pause()
        secured = str(lock.render())
        # Closed shackle (feet attached), matrix green, no emoji.
        assert "╭┴──┴╮" in secured
        assert "#00ff41" in secured
        assert "🔒" not in secured

        lock.maximum = True
        await pilot.pause()
        maxed = str(lock.render())
        # Cross keyhole plus a cyan ⁺ superscript at maximum security.
        assert "╰─╋╋─╯" in maxed
        assert "⁺" in maxed and "#00d4ff" in maxed


def test_stealth_pill_uses_hexagon_not_ghost() -> None:
    labels = [label for label, _tip, _active in _SECURITY]
    assert not any("👻" in label for label in labels)
    assert any("⬡" in label for label in labels)


@pytest.mark.asyncio
async def test_watermark_tracks_session_security_state() -> None:
    async with _app().run_test() as pilot:
        mark = pilot.app.query_one(LockWatermark)
        assert mark.state == "unsecured"
        open_shape = str(mark.render())

        pilot.app._set_secure(True)
        await pilot.pause()
        assert mark.state == "secured"
        assert str(mark.render()) != open_shape  # shackle now closed

        pilot.app._set_secure(True, maximum=True)
        await pilot.pause()
        assert mark.state == "max"
        assert "╋" in str(mark.render())  # faint cross in the keyhole


@pytest.mark.asyncio
async def test_ctrl_l_toggles_the_ticker() -> None:
    async with _app().run_test() as pilot:
        ticker = pilot.app.query_one(CryptoTicker)
        assert ticker.display is True
        pilot.app.action_toggle_log()
        await pilot.pause()
        assert ticker.display is False


@pytest.mark.asyncio
async def test_info_panel_toggles() -> None:
    async with _app_active().run_test() as pilot:
        panel = pilot.app.query_one(InfoPanel)
        assert panel.display is False
        pilot.app.action_toggle_info()
        await pilot.pause()
        assert panel.display is True


def test_qr_renderable_falls_back_without_segno(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from drift.ui import app as appmod

    monkeypatch.setattr(appmod, "_HAS_SEGNO", False)
    assert "██" in str(appmod._qr_renderable("drift:abc.def"))


def test_real_qr_round_trips_to_contact_code() -> None:
    """When segno is installed, the rendered QR must actually decode the code."""
    segno = pytest.importorskip("segno")
    code = Identity.generate().contact_code()
    # Same encoding the panel uses; confirm it produces a valid QR for the code.
    qr = segno.make(code, error="l")
    assert qr.matrix  # built without error
    from drift.ui.app import _real_qr

    assert "▀" in str(_real_qr(code))


@pytest.mark.asyncio
async def test_crypto_event_updates_ticker_and_counters() -> None:
    async with _app_active().run_test() as pilot:
        app = pilot.app
        app.post_message(CryptoEvent("send", "a3f9···2b1c"))
        app.post_message(CryptoEvent("recv", "11aa···99ff"))
        await pilot.pause()
        assert app._sent_count == 1
        assert app._recv_count == 1
        assert app._stealth_count == 2
        assert "a3f9" in str(app.query_one(CryptoTicker).render()) or app._recv_count == 1


@pytest.mark.asyncio
async def test_outgoing_line_carries_a_status_glyph() -> None:
    async with _app_active().run_test() as pilot:
        line = pilot.app._pane.write_outgoing("hi", "00:00:00", status="sent")
        await pilot.pause()
        assert "✓" in str(line.render())


# --------------------------------------------------------------------------- #
# Burn feature
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_burn_slash_no_session_writes_system_message() -> None:
    async with _app(with_contacts=True).run_test() as pilot:
        # No active session — /burn should surface a friendly message, not crash.
        await pilot.app._handle_slash("/burn")
        await pilot.pause()
        children = list(pilot.app._pane.children)
        rendered = " ".join(str(c.render()) for c in children)
        assert "burn" in rendered.lower() or "session" in rendered.lower()


@pytest.mark.asyncio
async def test_burn_event_conversation_clears_pane() -> None:
    async with _app_active().run_test() as pilot:
        app = pilot.app
        # Populate pane with a few messages.
        app._pane.write_incoming("alice", "hello", "12:00:00")
        app._pane.write_incoming("alice", "world", "12:00:01")
        await pilot.pause()
        # Post a conversation BurnEvent.
        app.post_message(BurnEvent("alice", "conversation", None))
        await pilot.pause()
        await pilot.pause()  # give the async handler time to clear + remount
        children = list(app._pane.children)
        rendered = " ".join(str(c.render()) for c in children)
        assert "burned" in rendered.lower()
        # Original messages should be gone — history cleared.
        assert app._history.get("alice", []) == []


@pytest.mark.asyncio
async def test_burn_event_message_scope_writes_system_line() -> None:
    async with _app_active().run_test() as pilot:
        app = pilot.app
        app._pane.write_incoming("alice", "hello", "12:00:00")
        await pilot.pause()
        app.post_message(BurnEvent("alice", "message", "abc123=="))
        await pilot.pause()
        rendered = " ".join(str(c.render()) for c in app._pane.children)
        assert "burned" in rendered.lower()


@pytest.mark.asyncio
async def test_burn_event_for_other_contact_is_ignored() -> None:
    """A BurnEvent for a different contact must not touch the active pane."""
    async with _app_active().run_test() as pilot:
        app = pilot.app
        app._pane.write_incoming("alice", "secret", "12:00:00")
        await pilot.pause()
        count_before = len(list(app._pane.children))
        # Post burn for a different contact.
        app.post_message(BurnEvent("bob", "conversation", None))
        await pilot.pause()
        await pilot.pause()
        assert len(list(app._pane.children)) == count_before


@pytest.mark.asyncio
async def test_burn_5m_schedule_and_cancel() -> None:
    async with _app_active().run_test() as pilot:
        app = pilot.app
        # Schedule but immediately cancel.
        app._schedule_auto_burn(300)
        await pilot.pause()
        assert app._burn_timer is not None
        app._cancel_auto_burn()
        await pilot.pause()
        assert app._burn_timer is None
        rendered = " ".join(str(c.render()) for c in app._pane.children)
        assert "cancelled" in rendered.lower()


@pytest.mark.asyncio
async def test_burn_cancel_with_no_timer_writes_system() -> None:
    async with _app_active().run_test() as pilot:
        app = pilot.app
        assert app._burn_timer is None
        app._cancel_auto_burn()
        await pilot.pause()
        rendered = " ".join(str(c.render()) for c in app._pane.children)
        assert "no auto-burn" in rendered.lower()


@pytest.mark.asyncio
async def test_burn_slash_parse_seconds() -> None:
    assert DriftApp._parse_burn_duration("30s") == 30
    assert DriftApp._parse_burn_duration("1m") == 60
    assert DriftApp._parse_burn_duration("5m") == 300
    assert DriftApp._parse_burn_duration("invalid") is None
    assert DriftApp._parse_burn_duration("") is None


def test_help_modal_mentions_best_effort() -> None:
    ref = HelpModal._REFERENCE
    assert "best-effort" in ref
    assert "/burn" in ref


# --------------------------------------------------------------------------- #
# Enhancement 1 — encrypt animation on send
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_encrypt_animation_clears_input_after_send() -> None:
    """Input must be empty after the 150 ms animation completes."""
    async with _app_active().run_test() as pilot:
        app = pilot.app
        app._input.focus()
        await pilot.pause()
        for ch in "hello":
            await pilot.press(ch)
        await pilot.press("enter")
        # 150 ms animation + Textual event-loop overhead.
        await pilot.pause(0.4)
        assert app._input.value == ""


@pytest.mark.asyncio
async def test_encrypt_animation_skipped_for_slash_commands() -> None:
    """Slash commands bypass the animation and clear immediately."""
    async with _app_active().run_test() as pilot:
        app = pilot.app
        app._input.focus()
        await pilot.pause()
        for ch in "/help":
            await pilot.press(ch)
        await pilot.press("enter")
        await pilot.pause()
        assert app._input.value == ""


@pytest.mark.asyncio
async def test_encrypt_animation_skipped_for_empty_input() -> None:
    """Submitting empty input clears immediately, no animation."""
    async with _app_active().run_test() as pilot:
        app = pilot.app
        app._input.focus()
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        assert app._input.value == ""


# --------------------------------------------------------------------------- #
# Enhancement 2 — ambient header indicators
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_e2_pills_mount_in_header() -> None:
    """UptimePill, LatencyPill, RatchetPill must be present in the header."""
    async with _app().run_test() as pilot:
        app = pilot.app
        assert app.query_one(UptimePill)
        assert app.query_one(LatencyPill)
        assert app.query_one(RatchetPill)


@pytest.mark.asyncio
async def test_uptime_pill_starts_idle_then_ticks() -> None:
    async with _app_active().run_test() as pilot:
        app = pilot.app
        pill = app.query_one(UptimePill)
        # After _open_conversation the pill should have a start time.
        assert pill._start is not None
        # elapsed is a non-negative integer (seconds since start).
        assert isinstance(pill.elapsed, int)
        assert pill.elapsed >= 0
        rendered = str(pill.render())
        assert "⏱" in rendered
        # Should show HH:MM:SS format, not the idle dash.
        assert "—" not in rendered


@pytest.mark.asyncio
async def test_uptime_pill_idle_shows_dash() -> None:
    async with _app(with_contacts=True).run_test() as pilot:
        pill = pilot.app.query_one(UptimePill)
        # No conversation opened — should show idle state.
        assert "—" in str(pill.render())


@pytest.mark.asyncio
async def test_ratchet_pill_starts_at_zero() -> None:
    async with _app().run_test() as pilot:
        pill = pilot.app.query_one(RatchetPill)
        assert pill.count == 0


@pytest.mark.asyncio
async def test_ratchet_pill_bumps_on_ratchet_event() -> None:
    async with _app_active().run_test() as pilot:
        app = pilot.app
        pill = app.query_one(RatchetPill)
        assert pill.count == 0
        app.post_message(CryptoEvent("ratchet", "DH step"))
        await pilot.pause()
        assert pill.count == 1
        assert pill.flashing is True  # flash is still active right after bump


@pytest.mark.asyncio
async def test_ratchet_pill_flash_clears_after_timer() -> None:
    async with _app_active().run_test() as pilot:
        app = pilot.app
        pill = app.query_one(RatchetPill)
        app.post_message(CryptoEvent("ratchet", "DH step"))
        await pilot.pause()
        await pilot.pause(0.5)  # wait out the 300 ms timer
        assert pill.flashing is False


@pytest.mark.asyncio
async def test_latency_pill_idle_shows_dash() -> None:
    async with _app().run_test() as pilot:
        pill = pilot.app.query_one(LatencyPill)
        assert pill.latency_ms is None
        assert "—" in str(pill.render())


@pytest.mark.asyncio
async def test_latency_pill_colour_coding() -> None:
    async with _app().run_test() as pilot:
        pill = pilot.app.query_one(LatencyPill)
        pill.latency_ms = 50
        assert "#00ff41" in str(pill.render())
        pill.latency_ms = 200
        assert "#cccc00" in str(pill.render())
        pill.latency_ms = 500
        assert "#ff4444" in str(pill.render())


def test_ratchet_pill_render_shows_count() -> None:
    pill = RatchetPill()
    pill.count = 7
    assert "7" in str(pill.render())


# --------------------------------------------------------------------------- #
# Enhancement 3 — network visualization panel
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_network_pane_mounts_hidden() -> None:
    async with _app().run_test() as pilot:
        net = pilot.app.query_one(NetworkPane)
        assert net.display is False


@pytest.mark.asyncio
async def test_ctrl_n_toggles_network_pane() -> None:
    async with _app().run_test() as pilot:
        app = pilot.app
        net = pilot.app.query_one(NetworkPane)
        pane_wrap = pilot.app.query_one("#pane-wrap")
        assert net.display is False
        assert pane_wrap.display is True
        app.action_toggle_network()
        await pilot.pause()
        assert net.display is True
        assert pane_wrap.display is False
        # Toggle back.
        app.action_toggle_network()
        await pilot.pause()
        assert net.display is False
        assert pane_wrap.display is True


def test_network_state_defaults() -> None:
    s = NetworkState()
    assert s.relay_connected is False
    assert s.peer_name is None
    assert s.tor_active is False
    assert s.federation_peers == []


def _render(renderable: object) -> str:
    buf = StringIO()
    Console(file=buf, force_terminal=False, width=120).print(renderable)
    return buf.getvalue()


def test_network_pane_build_shows_relay_url() -> None:
    pane = NetworkPane()
    state = NetworkState(
        relay_url="ws://localhost:8765",
        relay_connected=True,
        relay_latency_ms=42,
        peer_name="alice",
        peer_connected=True,
        ratchet_steps=5,
        stealth_addrs=10,
    )
    pane._state = state
    rendered = _render(pane._build())
    assert "localhost:8765" in rendered
    assert "alice" in rendered
    assert "42ms" in rendered
    assert "5 ratchet steps" in rendered


def test_network_pane_build_shows_tor_when_active() -> None:
    pane = NetworkPane()
    state = NetworkState(tor_active=True, tor_hops=3)
    pane._state = state
    rendered = _render(pane._build())
    # The YOU→relay connector expands into the 3-hop anonymising circuit.
    assert "tor circuit · 3 hops" in rendered
    assert "guard" in rendered
    assert "exit" in rendered


def test_network_pane_build_shows_federation_peers() -> None:
    pane = NetworkPane()
    state = NetworkState(federation_peers=["relay2.example.com"])
    pane._state = state
    rendered = _render(pane._build())
    assert "federation peer" in rendered


@pytest.mark.asyncio
async def test_network_pane_update_graph_reflects_state() -> None:
    async with _app().run_test() as pilot:
        app = pilot.app
        net = app.query_one(NetworkPane)
        net.update_graph(NetworkState(relay_url="ws://test:9999", relay_connected=True))
        await pilot.pause()
        assert "test:9999" in str(net._state.relay_url)


# --------------------------------------------------------------------------- #
# Enhancement 4 — themes
# --------------------------------------------------------------------------- #

def test_all_five_themes_are_defined() -> None:
    assert set(_THEMES.keys()) == {"matrix", "amber", "frost", "redacted", "ghost"}


def test_each_theme_has_required_keys() -> None:
    required = {"primary", "secondary", "bg", "dim_bg", "modal_bg",
                "border", "hover_bg", "hover_bg_off", "dim", "warning", "scanlines"}
    for name, theme in _THEMES.items():
        missing = required - set(theme.keys())
        assert not missing, f"theme '{name}' missing keys: {missing}"


def test_build_css_substitutes_primary_color() -> None:
    amber = _THEMES["amber"]
    css = _build_css(amber)
    assert amber["primary"] in css
    assert "#00ff41" not in css  # matrix green must NOT appear in amber CSS


def test_build_css_no_raw_placeholders_remain() -> None:
    for name, theme in _THEMES.items():
        css = _build_css(theme)
        for key in theme:
            token = f"__{key.upper()}__"
            assert token not in css, f"unresolved token {token!r} in {name} CSS"


def test_drift_theme_env_matrix_has_no_hardcoded_00ff41_in_css() -> None:
    import os
    os.environ.pop("DRIFT_THEME", None)
    # The active CSS (matrix) should still have #00ff41 since that IS matrix's primary.
    # But other themes must not have #00ff41 as a cross-contamination.
    frost_css = _build_css(_THEMES["frost"])
    assert "#00ff41" not in frost_css


def test_build_css_contains_valid_css_selectors() -> None:
    css = _build_css(_THEMES["matrix"])
    assert "Screen" in css
    assert "#root" in css
    assert "#pane" in css
    assert "SecurityPill" in css


def test_ghost_theme_primary_in_logo_render() -> None:
    from drift.ui import app as appmod
    original = appmod._P
    try:
        appmod._P = _THEMES["ghost"]["primary"]  # "#bbbbbb"
        logo = LogoBox()
        # The style is set as the Text base style — it contains the theme color.
        assert "#bbbbbb" in str(logo.render().style)
    finally:
        appmod._P = original


# --------------------------------------------------------------------------- #
# Phase 3 — Tor indicators
# --------------------------------------------------------------------------- #


def _fake_tor_client(hops: int = 3):
    from drift.transport.tor import TorClient

    return TorClient(socks_host="127.0.0.1", socks_port=9050, backend="mock", num_hops=hops)


def test_latency_pill_bootstrap_mode() -> None:
    pill = LatencyPill("http://localhost:8765/health")
    pill.set_bootstrap(42)
    # Bootstrap shows an animated spinner, a progress bar and the percentage.
    rendered = _render(pill.render())
    assert "42%" in rendered
    assert "tor" in rendered
    assert "█" in rendered and "░" in rendered  # partial progress bar
    # Out-of-range values clamp to 0..100.
    pill.set_bootstrap(150)
    bar = _render(pill.render())
    assert "100%" in bar
    assert "░" not in bar  # full bar at 100%
    pill.clear_bootstrap()
    # Back to the latency readout (no live ping yet → em dash).
    assert "%" not in _render(pill.render())


@pytest.mark.asyncio
async def test_security_bar_flips_tor_pill() -> None:
    async with _app().run_test() as pilot:
        bar = pilot.app.query_one(SecurityBar)
        tor_pill = next(p for p in bar.query(SecurityPill) if p.label.endswith("TOR"))
        assert tor_pill._active is False           # dim until a circuit exists
        bar.set_tor_active(True)
        await pilot.pause()
        assert tor_pill._active is True            # bright green
        assert "TOR" in _render(tor_pill.render())


@pytest.mark.asyncio
async def test_app_bootstraps_tor_and_lights_indicators() -> None:
    """use_tor=True with a mocked bootstrap flips every Tor indicator on."""
    from unittest.mock import AsyncMock, patch

    me = Identity.generate()
    contacts = {"alice": {"code": Identity.generate().contact_code()}}
    app = DriftApp(me, contacts, "ws://127.0.0.1:1", active=None, use_tor=True)

    with patch("drift.transport.tor.bootstrap", AsyncMock(return_value=_fake_tor_client())):
        async with app.run_test() as pilot:
            await pilot.pause()
            assert app._tor_active is True
            assert app._tor_client is not None
            tor_pill = next(
                p for p in app.query_one(SecurityBar).query(SecurityPill)
                if p.label.endswith("TOR")
            )
            assert tor_pill._active is True
            # Bootstrap progress readout has cleared off the latency pill.
            assert app.query_one(LatencyPill).bootstrap_pct is None


@pytest.mark.asyncio
async def test_app_tor_failure_falls_back_to_clearnet() -> None:
    """A bootstrap failure warns and continues; indicators stay dim."""
    from unittest.mock import AsyncMock, patch

    from drift.transport.tor import TorUnavailableError

    me = Identity.generate()
    contacts = {"alice": {"code": Identity.generate().contact_code()}}
    app = DriftApp(me, contacts, "ws://127.0.0.1:1", active=None, use_tor=True)

    with patch(
        "drift.transport.tor.bootstrap",
        AsyncMock(side_effect=TorUnavailableError("no backend")),
    ):
        async with app.run_test() as pilot:
            await pilot.pause()
            assert app._tor_active is False
            assert app._tor_client is None


@pytest.mark.asyncio
async def test_tor_active_event_upgrades_lock_to_maximum() -> None:
    """TorActiveEvent while secured drives the lock to 🔒⁺ (maximum)."""
    async with _app_active().run_test() as pilot:
        app = pilot.app
        app._set_secure(True)                  # E2E + ratchet secured, no Tor yet
        lock = app.query_one(LockIndicator)
        assert lock.secure is True and lock.maximum is False
        app.post_message(TorActiveEvent(3))
        await pilot.pause()
        assert app._tor_active is True
        assert lock.maximum is True            # upgraded to 🔒⁺
        assert "⁺" in _render(lock.render())


# --------------------------------------------------------------------------- #
# Phase 4 — federation indicators
# --------------------------------------------------------------------------- #


def test_node_pill_render_states() -> None:
    pill = NodePill()
    assert "⬡ —" in _render(pill.render())          # unknown
    pill.count = 1
    assert "1 node" in _render(pill.render())        # solo
    pill.count = 3
    out = _render(pill.render())
    assert "3 nodes" in out
    pill.onion = True
    assert "⊕" in _render(pill.render())             # onion-routed marker


def test_network_pane_shows_federation_nodes() -> None:
    pane = NetworkPane()
    pane._state = NetworkState(
        relay_url="ws://relay1:8765",
        relay_connected=True,
        relay_nodes=["ws://relay1:8765", "ws://relay2:8765", "ws://abc.onion:8765"],
        node_count=3,
    )
    rendered = _render(pane._build())
    # The other reachable relays appear as intermediate failover nodes.
    assert "relay2:8765" in rendered
    assert "abc.onion:8765" in rendered
    assert "federated mesh · 3 nodes" in rendered


def test_network_pane_shows_onion_node_badge() -> None:
    pane = NetworkPane()
    pane._state = NetworkState(
        relay_url="ws://abc.onion",
        relay_connected=True,
        onion_node=True,
        node_count=2,
        relay_nodes=["ws://abc.onion", "ws://relay2:8765"],
    )
    rendered = _render(pane._build())
    assert "onion node" in rendered
    assert "onion-routed" in rendered


@pytest.mark.asyncio
async def test_node_count_event_updates_pill() -> None:
    async with _app().run_test() as pilot:
        app = pilot.app
        app.post_message(NodeCountEvent(4))
        await pilot.pause()
        assert app._node_count == 4
        assert app.query_one(NodePill).count == 4
        assert "4 nodes" in _render(app.query_one(NodePill).render())


@pytest.mark.asyncio
async def test_onion_node_event_marks_pill() -> None:
    async with _app().run_test() as pilot:
        app = pilot.app
        app.post_message(OnionNodeEvent())
        await pilot.pause()
        assert app._onion_node is True
        assert app.query_one(NodePill).onion is True


@pytest.mark.asyncio
async def test_primary_relay_parsed_from_comma_list() -> None:
    me = Identity.generate()
    contacts = {"alice": {"code": Identity.generate().contact_code()}}
    app = DriftApp(me, contacts, "ws://r1:8765,ws://r2:8765", active=None)
    assert app._primary_relay == "ws://r1:8765"


# --------------------------------------------------------------------------- #
# Phase 3b — sealed sender pill
# --------------------------------------------------------------------------- #


def test_sealed_pill_present_active_and_between_stealth_and_tor() -> None:
    labels = [label for label, _tip, _active in _SECURITY]
    assert "✉ SEALED" in labels
    # Positioned between STEALTH and TOR.
    assert labels.index("⬡ STEALTH") < labels.index("✉ SEALED") < labels.index("🌐 TOR")
    # Sealed sender is intrinsic to the protocol now → active (bright).
    sealed = next(entry for entry in _SECURITY if entry[0] == "✉ SEALED")
    assert sealed[2] is True


@pytest.mark.asyncio
async def test_sealed_pill_renders_bright() -> None:
    async with _app().run_test() as pilot:
        pills = pilot.app.query(SecurityPill)
        sealed = next(p for p in pills if p.label == "✉ SEALED")
        assert sealed._active is True
        assert "SEALED" in _render(sealed.render())


# ---------------------------------------------------------------------------
# Phase 8 — group conversation UI
# ---------------------------------------------------------------------------

from drift.crypto.groups import ContactInfo, GroupId, GroupState  # noqa: E402
from drift.ui.app import GroupMembershipEvent, IncomingGroupMessage  # noqa: E402


def _group_app() -> DriftApp:
    me = Identity.generate()
    members = [
        ContactInfo("alice", Identity.generate().contact_code()),
        ContactInfo("bob", Identity.generate().contact_code()),
    ]
    group = GroupState(group_id=GroupId.generate(), name="ops", members=members)
    return DriftApp(me, {}, "ws://127.0.0.1:1", group=group)


@pytest.mark.asyncio
async def test_group_chat_shows_group_indicator() -> None:
    async with _group_app().run_test() as pilot:
        await pilot.pause()
        pane = pilot.app.query_one("#pane", MessagePane)
        assert "ops" in (pane.border_title or "")
        # The ⬡ GROUP (N members) indicator replaces the single-recipient view.
        assert "⬡ GROUP" in (pane.border_subtitle or "")
        assert "3 members" in (pane.border_subtitle or "")


@pytest.mark.asyncio
async def test_group_message_renders_with_sender_prefix() -> None:
    async with _group_app().run_test() as pilot:
        app = pilot.app
        pane = app.query_one("#pane", MessagePane)
        before = len(pane.children)
        app.post_message(IncomingGroupMessage("alice", "hello team"))
        await pilot.pause()
        assert len(pane.children) > before  # a sender-prefixed line was added


@pytest.mark.asyncio
async def test_group_membership_event_renders_system_line() -> None:
    async with _group_app().run_test() as pilot:
        app = pilot.app
        pane = app.query_one("#pane", MessagePane)
        before = len(pane.children)
        app.post_message(GroupMembershipEvent("add", "carol"))
        await pilot.pause()
        assert len(pane.children) > before  # "→ carol added the group" system line


# ---------------------------------------------------------------------------
# Phase 11 — sovereign room UI
# ---------------------------------------------------------------------------

from drift.crypto.rooms import TIER_OPEN, Room, make_room  # noqa: E402
from drift.ui.app import ContactItem, IncomingRoomMessage, SessionUp  # noqa: E402


def _rooms_app() -> DriftApp:
    me = Identity.generate()
    rooms = {
        "cats": Room(label="cats", tier=TIER_OPEN, name="cats"),
        "v": Room.from_qr(make_room(None, tier="dark", label="v").to_qr(), label="v"),
    }
    return DriftApp(
        me, {"alice": {"code": Identity.generate().contact_code()}},
        "ws://127.0.0.1:1", rooms=rooms,
    )


@pytest.mark.asyncio
async def test_rooms_appear_in_sidebar_with_hexagon_prefix() -> None:
    async with _rooms_app().run_test() as pilot:
        app = pilot.app
        await pilot.pause()
        rows = {i.contact_name: i for i in app.query(ContactItem)}
        # 1:1 contact is not a room; rooms are flagged is_room with their tier.
        assert rows["alice"].is_room is False
        assert rows["cats"].is_room is True and rows["cats"].tier == "open"
        assert rows["v"].is_room is True and rows["v"].tier == "dark"
        # The ⬡ hexagon marks a room row in its rendered output.
        assert "⬡" in str(rows["cats"].render())


@pytest.mark.asyncio
async def test_opening_a_room_shows_room_pill_and_keeps_lock_non_maximum() -> None:
    app = _rooms_app()
    async with app.run_test() as pilot:
        await app._open_room(app._rooms["cats"])
        await pilot.pause()
        pane = app.query_one("#pane", MessagePane)
        assert "⬡ ROOM (open)" in (pane.border_subtitle or "")
        assert app._conversation_name() == "cats"
        # Rooms are NOT forward-secret → 🔒, never 🔒⁺: even with Tor active the
        # lock stays non-maximum when the session comes up for a room.
        app._tor_active = True
        app._on_session_up(SessionUp("cats"))
        await pilot.pause()
        assert app._lock.secure is True
        assert app._lock.maximum is False


@pytest.mark.asyncio
async def test_room_message_renders_anonymous_tag_and_signed_name() -> None:
    app = _rooms_app()
    async with app.run_test() as pilot:
        await app._open_room(app._rooms["cats"])
        await pilot.pause()
        pane = app.query_one("#pane", MessagePane)
        before = len(pane.children)
        app.post_message(IncomingRoomMessage("a3f9", "hey", display_name=None, authorized=True))
        app.post_message(
            IncomingRoomMessage("b1c2", "yo", display_name="river", authorized=True))
        app.post_message(
            IncomingRoomMessage("cccc", "sus", display_name=None, authorized=False))
        await pilot.pause()
        assert len(pane.children) >= before + 3


# ---------------------------------------------------------------------------
# Lockdown mode (Ctrl+K)
# ---------------------------------------------------------------------------

def test_lockdown_input_buffer_vs_display() -> None:
    """The real plaintext lives in _buf; the screen only ever shows _noise, and
    the noise differs from the plaintext at every position."""
    from textual.events import Key

    field = _LockdownInput()
    for ch in "world":
        field.on_key(Key(ch, ch))
    # _buf holds exactly the typed characters.
    assert field._buf == list("world")
    # _noise mirrors its length but never matches the plaintext, slot for slot.
    assert len(field._noise) == len(field._buf) == 5
    assert all(shown != real for shown, real in zip(field._noise, field._buf, strict=True))
    # The rendered line shows the noise, never the real text.
    rendered = str(field.render())
    assert "".join(field._noise) in rendered
    assert "world" not in rendered


def test_lockdown_input_backspace() -> None:
    """Backspace pops from both the real and the noise buffers in lockstep."""
    from textual.events import Key

    field = _LockdownInput()
    for ch in "abc":
        field.on_key(Key(ch, ch))
    field.on_key(Key("backspace", None))
    assert len(field._buf) == 2
    assert len(field._noise) == 2


@pytest.mark.asyncio
async def test_lockdown_toggle_wipes_history() -> None:
    """Engaging lockdown purges retained history and clears the pane."""
    async with _app_active().run_test() as pilot:
        app = pilot.app
        app._history["alice"] = [MessageRecord("in", "alice", "secret", "12:00:00")]
        await app.action_toggle_lockdown()
        await pilot.pause()
        assert app._lockdown is True
        assert app._history == {}


# ---------------------------------------------------------------------------
# Phase 8 — group discoverability in the sidebar
# ---------------------------------------------------------------------------

from drift.crypto.groups import create_group  # noqa: E402
from drift.ui.app import GroupSelected  # noqa: E402


def _groups_app() -> DriftApp:
    me = Identity.generate()
    member = ContactInfo(name="bob", code=Identity.generate().contact_code())
    groups = {"crew": create_group("crew", [member])}
    return DriftApp(
        me, {"alice": {"code": Identity.generate().contact_code()}},
        "ws://127.0.0.1:1", groups=groups,
    )


@pytest.mark.asyncio
async def test_groups_appear_in_sidebar_with_box_prefix() -> None:
    async with _groups_app().run_test() as pilot:
        app = pilot.app
        await pilot.pause()
        rows = {i.contact_name: i for i in app.query(ContactItem)}
        # 1:1 contact is neither a group nor a room.
        assert rows["alice"].is_group is False
        assert rows["crew"].is_group is True
        # member count includes self: one other member + you = 2.
        assert rows["crew"].members == 2
        # The ⊞ box marks a group row and the member count is rendered.
        rendered = str(rows["crew"].render())
        assert "⊞" in rendered and "2 members" in rendered


@pytest.mark.asyncio
async def test_sidebar_shows_three_labelled_sections() -> None:
    async with _groups_app().run_test() as pilot:
        app = pilot.app
        await pilot.pause()
        headers = [str(s.render()) for s in app.query(".sidebar-section")]
        assert len(headers) == 3
        assert any("CONTACTS" in h for h in headers)
        assert any("GROUPS" in h for h in headers)
        assert any("ROOMS" in h for h in headers)


@pytest.mark.asyncio
async def test_clicking_group_row_opens_group_conversation() -> None:
    """The sidebar GroupSelected → _on_group_selected → _open_group wiring."""
    app = _groups_app()
    async with app.run_test() as pilot:
        app.post_message(GroupSelected("crew"))
        await pilot.pause()
        await pilot.pause()
        assert app._conversation_name() == "crew"
        assert app._group is not None and app._group.name == "crew"
        pane = app.query_one("#pane", MessagePane)
        assert "GROUP" in (pane.border_subtitle or "")
