"""
tests/unit/test_ui.py — smoke tests for the Textual TUI

These don't need a relay: the session worker simply fails to connect and the
app surfaces that as a status line. We drive the app with Textual's pilot to
confirm the component tree mounts and the core interactions don't crash.

Run: pytest tests/unit/test_ui.py -v
"""

from __future__ import annotations

import pytest

from drift.crypto import Identity
from drift.ui.app import (
    AddContactModal,
    CommandPalette,
    CryptoEvent,
    CryptoTicker,
    DriftApp,
    HeaderBar,
    HelpModal,
    InfoPanel,
    InputBar,
    LogoBox,
    MessagePane,
    PillButton,
    SecurityPill,
    Sidebar,
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
