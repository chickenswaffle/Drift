"""Module entry point so ``python -m drift`` works.

This is deliberately finder-independent: as long as the ``drift`` package is
importable (editable install *or* a ``PYTHONPATH`` that includes the repo root),
``python -m drift`` runs the CLI. The committed ``scripts/drift`` wrapper relies
on this, which is what makes the launcher resilient to a stale or broken
editable install.
"""

from __future__ import annotations

from drift.cli import app

if __name__ == "__main__":
    app()
