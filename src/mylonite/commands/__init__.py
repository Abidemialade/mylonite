"""Typer command implementations extracted out of ``mylonite.cli``.

``cli.py`` is the CLI composition root (Typer app + command registration);
the command bodies that grow large enough to need their own module live
here instead of being inlined in ``cli.py``. See ``tests/test_cli_size.py``.
"""

from __future__ import annotations
