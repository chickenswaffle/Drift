"""
tests/unit/test_welcome.py — the first-run welcome screen (no-args `drift`).

These assert the screen reflects real state and never hangs/crashes, without
depending on this machine's ~/.config/drift: identity/Tor probes are patched.

Run: pytest tests/unit/test_welcome.py -v
"""

from __future__ import annotations

import io
import sys

from rich.console import Console

from drift import __version__
from drift.ui import theme, welcome


def _capture(monkeypatch, *, has_identity: bool, code: str | None, tor: bool = False) -> str:
    monkeypatch.setattr(welcome, "_identity_state", lambda: (has_identity, code))
    monkeypatch.setattr(welcome, "_tor_available", lambda: tor)
    buf = io.StringIO()
    console = Console(file=buf, width=100, no_color=True)
    welcome.render(console)
    return buf.getvalue()


# --- theme -----------------------------------------------------------------

def test_active_theme_respects_env(monkeypatch) -> None:
    monkeypatch.setenv("DRIFT_THEME", "redacted")
    assert theme.active_theme()["primary"] == theme.THEMES["redacted"]["primary"]


def test_active_theme_unknown_falls_back(monkeypatch) -> None:
    monkeypatch.setenv("DRIFT_THEME", "no-such-theme")
    assert theme.active_theme() == theme.THEMES[theme.DEFAULT_THEME]


def test_welcome_pulls_in_no_textual() -> None:
    # The whole point of splitting theme out: the banner must stay cheap. Check
    # in a fresh interpreter — in the shared test process other suites have
    # already imported Textual, so sys.modules here would be meaningless.
    import subprocess

    code = "import drift.ui.welcome, sys; sys.exit(1 if 'textual' in sys.modules else 0)"
    assert subprocess.call([sys.executable, "-c", code]) == 0  # noqa: S603


# --- code parsing ----------------------------------------------------------

def test_code_parts_splits_scan_and_spend() -> None:
    scan, spend = welcome._code_parts("drift:AAAA.BBBB.CCCC")
    assert scan == "AAAA" and spend == "BBBB"


def test_code_parts_placeholder_when_absent() -> None:
    scan, spend = welcome._code_parts(None)
    assert scan and spend  # decorative placeholders, never blank


def test_short_frag() -> None:
    assert welcome._short_frag("8zQjFYabcdef1", 4, 2) == "8zQj···f1"


# --- rendering -------------------------------------------------------------

def test_render_has_core_elements(monkeypatch) -> None:
    out = _capture(monkeypatch, has_identity=True, code="drift:SCANKEY.SPENDKEY")
    assert "██" in out                              # wordmark
    assert "what would you like to do?" in out
    assert "no accounts" in out
    assert "identity.burn()" in out
    assert f"v{__version__}" in out                 # real version, not hardcoded
    for _num, _glyph, label in welcome._MENU[1:]:
        assert label in out


def test_render_no_identity_shows_setup_required(monkeypatch) -> None:
    out = _capture(monkeypatch, has_identity=False, code=None)
    assert "set up my identity" in out
    assert "(setup required)" in out
    assert "my identity  ·" not in out


def test_render_with_identity_shows_my_identity(monkeypatch) -> None:
    out = _capture(monkeypatch, has_identity=True, code="drift:SCANKEY.SPENDKEY")
    assert "my identity" in out
    assert "drift:SCAN···" in out
    assert "(setup required)" not in out


def test_render_tor_pill_reflects_availability(monkeypatch) -> None:
    on = _capture(monkeypatch, has_identity=True, code="drift:A.B", tor=True)
    off = _capture(monkeypatch, has_identity=True, code="drift:A.B", tor=False)
    assert "ready (on-demand)" in on
    assert "not installed" in off


# --- boot sequence ---------------------------------------------------------

def test_boot_sequence_prints_all_subsystems(monkeypatch) -> None:
    monkeypatch.setattr(welcome.time, "sleep", lambda _s: None)
    buf = io.StringIO()
    console = Console(file=buf, width=100, no_color=True)
    welcome.play_boot_sequence(console, delay=0)
    out = buf.getvalue()
    assert welcome._BOOT_HEADER in out
    assert "all systems nominal." in out
    for label, _dots in welcome._BOOT_SUBSYSTEMS:
        assert label in out
    assert out.count(" ok") == len(welcome._BOOT_SUBSYSTEMS)


# --- run() interaction -----------------------------------------------------

def test_run_non_interactive_returns_zero_without_prompt(monkeypatch) -> None:
    # Piped / CI: render once, never block on input.
    monkeypatch.setattr(welcome, "_identity_state", lambda: (False, None))
    monkeypatch.setattr(welcome, "_tor_available", lambda: False)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False)

    def _boom(*a, **k):
        raise AssertionError("must not prompt when non-interactive")

    monkeypatch.setattr(Console, "input", _boom)
    assert welcome.run() == 0


def test_drift_argv_is_runnable() -> None:
    argv = welcome._drift_argv()
    assert argv and isinstance(argv, list)
