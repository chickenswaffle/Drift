"""
drift.ui.theme — colour palettes shared by the TUI and the CLI welcome screen.

Kept deliberately free of any Textual/Rich import so the lightweight CLI
welcome screen (``drift`` with no arguments) can pick up the active palette
without dragging the whole TUI — and Textual — into process just to print a
banner. The Textual app (``drift.ui.app``) imports ``THEMES`` from here; the
welcome screen imports ``active_theme``.

Select a theme with the ``DRIFT_THEME`` environment variable, e.g.
``DRIFT_THEME=redacted``. Unknown names fall back to the default.
"""

from __future__ import annotations

import os

DEFAULT_THEME = "matrix"

THEMES: dict[str, dict[str, str]] = {
    "matrix": {
        "primary":       "#00ff41",
        "secondary":     "#00d4ff",
        "bg":            "#0a0a0a",
        "dim_bg":        "#060606",
        "modal_bg":      "#0c0c0c",
        "border":        "#1a5c1a",
        "hover_bg":      "#06160a",
        "hover_bg_off":  "#160606",  # inactive SecurityPill hover
        "dim":           "#888888",
        "warning":       "#ff4444",
        "scanlines":     "#00ff41 3.5%",
    },
    "amber": {
        "primary":       "#ffaa00",
        "secondary":     "#ff6600",
        "bg":            "#0a0800",
        "dim_bg":        "#060500",
        "modal_bg":      "#0c0900",
        "border":        "#5c4500",
        "hover_bg":      "#160d00",
        "hover_bg_off":  "#160500",
        "dim":           "#887766",
        "warning":       "#ff3300",
        "scanlines":     "#ffaa00 3.5%",
    },
    "frost": {
        "primary":       "#88ccff",
        "secondary":     "#44aaff",
        "bg":            "#080c10",
        "dim_bg":        "#060810",
        "modal_bg":      "#0a0e14",
        "border":        "#1a3a5c",
        "hover_bg":      "#061018",
        "hover_bg_off":  "#060818",
        "dim":           "#8899aa",
        "warning":       "#ff6644",
        "scanlines":     "#88ccff 3%",
    },
    "redacted": {
        "primary":       "#ff3333",
        "secondary":     "#ff8800",
        "bg":            "#0a0a0a",
        "dim_bg":        "#060606",
        "modal_bg":      "#0c0c0c",
        "border":        "#5c1a1a",
        "hover_bg":      "#160808",
        "hover_bg_off":  "#100000",
        "dim":           "#888888",
        "warning":       "#ff0000",
        "scanlines":     "#ff3333 3%",
    },
    "ghost": {
        "primary":       "#bbbbbb",
        "secondary":     "#999999",
        "bg":            "#0a0a0a",
        "dim_bg":        "#060606",
        "modal_bg":      "#0c0c0c",
        "border":        "#3a3a3a",
        "hover_bg":      "#111111",
        "hover_bg_off":  "#0e0e0e",
        "dim":           "#666666",
        "warning":       "#ff4444",
        "scanlines":     "#bbbbbb 2%",
    },
}


def active_theme_name() -> str:
    """The selected theme name (``DRIFT_THEME`` env var, default ``matrix``)."""
    return os.environ.get("DRIFT_THEME", DEFAULT_THEME).lower()


def active_theme() -> dict[str, str]:
    """The active palette, falling back to the default for unknown names."""
    return THEMES.get(active_theme_name(), THEMES[DEFAULT_THEME])
