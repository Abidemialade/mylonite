"""Single source of truth for Mylonite's on-disk artefact layout.

Every command writes (and later reads back) artefacts under one root —
``.mylonite/`` by default. Before this module existed, that root was threaded
correctly as a function ARGUMENT on write paths (e.g. ``scan --output-dir``)
but hardcoded as a bare ``.mylonite/...`` string LITERAL on several read paths
(``generate --latest``'s scan search, the gate check-run scratch file). A
custom root then silently failed to propagate: a scan written to
``custom/scans/`` was invisible to ``generate --latest``, which only ever
looked under the hardcoded default.

This module makes that class of bug structurally impossible: :class:`Layout`
is the ONLY place the literal ``.mylonite`` may appear as real filesystem path
construction anywhere under ``src/`` (enforced by
``tests/test_layout.py::test_no_hardcoded_mylonite_paths_outside_layout`` —
an AST guard, not a convention). Every other module gets a :class:`Layout`
(typically via ``ctx.obj`` in ``cli.py``) and reads its properties instead of
constructing ``.mylonite/...`` paths itself.

Full resolution order, top to bottom: an explicit per-command flag
(``scan --output-dir``, ``gate --out``, ``generate --scans-dir``/``--out``)
wins outright; then a ``mylonite.yaml`` ``root:`` field; then the
``MYLONITE_ROOT`` environment variable; then the built-in default
``.mylonite``. Only the BOTTOM three tiers are ``resolve_layout``'s job — see
its docstring for why the top tier can't be, structurally, without
reintroducing double-nested paths.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

#: Env var override for the artefact root — below an explicit CLI flag and a
#: ``mylonite.yaml`` ``root:`` field, above the built-in default.
ROOT_ENV_VAR = "MYLONITE_ROOT"

_DEFAULT_ROOT = Path(".mylonite")


@dataclass(frozen=True)
class Layout:
    """Where Mylonite reads and writes artefacts, rooted at ``root``.

    ``root`` defaults to ``.mylonite`` (the historical hardcoded value) —
    every derived path below is relative to it, so overriding ``root`` once
    (via :func:`resolve_layout`) moves the whole tree consistently.
    """

    root: Path = _DEFAULT_ROOT

    @property
    def scans(self) -> Path:
        """Root the timestamped ``scan`` run dirs are written under / searched from."""
        return self.root / "scans"

    @property
    def generated(self) -> Path:
        """Root the ``generate``-emitted test dirs default under."""
        return self.root / "generated"

    @property
    def gate(self) -> Path:
        """Root the ``gate`` command's artefacts (test, exploit, scratch files) default under."""
        return self.root / "gate"

    def gate_scratch(self, name: str) -> Path:
        """A scratch file under the gate dir (e.g. ``check_run.json``)."""
        return self.gate / name

    def generated_for(self, slug: str) -> Path:
        """Default ``generate --out`` for one emitted test (a per-pattern subdir)."""
        return self.generated / slug


#: The layout in effect when nothing overrides the root — what every command
#: used to hardcode inline.
DEFAULT_LAYOUT = Layout()


def resolve_layout(
    *,
    config_root: Path | None = None,
    env: dict[str, str] | None = None,
) -> Layout:
    """Resolve the effective :class:`Layout` from the BOTTOM three precedence
    tiers: ``config_root`` (``mylonite.yaml``'s ``root:`` field) wins, then the
    ``MYLONITE_ROOT`` env var, then the built-in ``.mylonite`` default.

    ``env`` defaults to ``os.environ`` — overridable so callers (and tests)
    can resolve against an arbitrary mapping instead of the real process
    environment.

    There is deliberately no ``explicit_root`` parameter here for the TOP tier
    (an explicit ``--output-dir``/``--out``/``--scans-dir`` flag). Each of
    those flags names a LEAF directory directly (e.g. ``scan --output-dir``
    IS the scans dir, not a root to nest ``scans/`` under) — routing it
    through this function would set :attr:`Layout.root` instead and
    double-nest the result (``custom/scans/scans``). Every call site instead
    applies its own flag with a direct ``explicit if explicit is not None else
    layout.<leaf>`` check; ``resolve_layout`` only ever supplies the fallback
    ``Layout`` for when that flag is absent.
    """
    if config_root is not None:
        return Layout(root=config_root)
    environ = env if env is not None else os.environ
    env_root = environ.get(ROOT_ENV_VAR)
    if env_root:
        return Layout(root=Path(env_root))
    return DEFAULT_LAYOUT
