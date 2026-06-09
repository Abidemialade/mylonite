"""Allow ``python -m mylonite`` as an alias for the Typer CLI."""

from __future__ import annotations

from mylonite.cli import app

if __name__ == "__main__":
    app()
