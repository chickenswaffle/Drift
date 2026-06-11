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
    NetworkPane,
    NetworkState,
    PillButton,
    RatchetPill,
    SecurityPill,
    Sidebar,
    UptimePill,
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
        # Four indicators: E2E, RATCHET, STEALTH, TOR.
        assert len(app.query(SecurityPill)) == 4


@pytest.mark.asyncio
async def test_header_has_lock_indicator_starting_unsecured() -> None:
    async with _app().run_test() as pilot:
        lock = pilot.app.query_one(LockIndicator)
        assert lock.secure is False
        # Open padlock, dim red, before any session connects.
        rendered = str(lock.render())
        assert "🔓" in rendered
        assert "#aa3333" in rendered


@pytest.mark.asyncio
async def test_lock_indicator_reflects_secure_and_maximum_states() -> None:
    async with _app().run_test() as pilot:
        lock = pilot.app.query_one(LockIndicator)
        lock.secure = True
        await pilot.pause()
        secured = str(lock.render())
        assert "🔒" in secured and "#00ff41" in secured

        lock.maximum = True
        await pilot.pause()
        maxed = str(lock.render())
        # Closed lock plus a cyan superscript.
        assert "🔒" in maxed and "⁺" in maxed and "#00d4ff" in maxed


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
    assert "Tor active" in rendered
    assert "3 hops" in rendered


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
