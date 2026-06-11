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
    DriftApp,
    HeaderBar,
    HelpModal,
    InputBar,
    MessagePane,
    PillButton,
    Sidebar,
)


def _app(with_contacts: bool = True) -> DriftApp:
    me = Identity.generate()
    contacts = {}
    if with_contacts:
        contacts = {"alice": {"code": Identity.generate().contact_code()}}
    # Point at a port nothing is listening on so the worker fails fast & quiet.
    return DriftApp(me, contacts, "ws://127.0.0.1:1", active=None)


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
