"""Offline demo support for ``mylonite demo``.

The LiteLLM record/replay core lives in :mod:`mylonite._replay`, not here. It
was promoted out of this package in 0.8.0 because it was never demo-specific:
:mod:`mylonite.testkit`, the reference validator, and the ``scripts/record_*``
family all depend on it. Restoring a second copy under ``mylonite.demo._replay``
would reintroduce exactly the duplication that promotion removed.

What *is* demo-specific, and therefore lives here:

* :data:`DEMO_RERECORD_HINT` — the re-record instruction appended to a
  cache-miss error. The generic core carries ``GENERIC_RERECORD_HINT``; it has
  no business naming a demo script.
* :func:`packaged_fixture_dir` — the location of the fixtures shipped inside
  the wheel. A path into ``mylonite.demo`` does not belong in a module whose
  docstring requires it to stay dependency-free.

The error types and the recorder are re-exported so ``from mylonite.demo
import ...`` keeps working for the runner, the record script, and the tests.

Recorded fixtures live under ``mylonite/demo/fixtures/<variant>/``, namespaced
per target variant. The namespacing predates cache-key v2 (which folds
``tools`` into the key and would separate the variants on its own) and is kept
because it also makes a partially-recorded fixture set obvious on inspection.
"""

from __future__ import annotations

from importlib.resources import files
from importlib.resources.abc import Traversable

from mylonite._replay import (
    CACHE_KEY_VERSION,
    CACHE_KEY_VERSION_FIELD,
    CorruptFixtureError,
    FixtureConflictError,
    FixtureError,
    LiteLLMRecorder,
    MissingFixtureError,
)

#: Appended to a cache-miss / corrupt-fixture error so the reader is told how
#: to fix it rather than just that it broke. A stale fixture is the demo's
#: most likely failure mode, and it is silent by default -- see
#: ``mylonite.demo.runner`` for why detection needs post-run recorder
#: inspection rather than exception propagation.
DEMO_RERECORD_HINT = (
    "Re-record the demo fixtures with scripts/record_demo_fixtures.py "
    "(requires a live provider key)."
)


def packaged_fixture_dir() -> Traversable:
    """Root of the fixtures shipped inside the wheel (``mylonite/demo/fixtures``).

    Per-variant namespaces live underneath: ``<root>/vulnerable``,
    ``<root>/guarded``. Returns a ``Traversable`` so replay works from a
    zip/wheel install as well as a source checkout.
    """
    return files("mylonite.demo") / "fixtures"


__all__ = [
    "CACHE_KEY_VERSION",
    "CACHE_KEY_VERSION_FIELD",
    "DEMO_RERECORD_HINT",
    "CorruptFixtureError",
    "FixtureConflictError",
    "FixtureError",
    "LiteLLMRecorder",
    "MissingFixtureError",
    "packaged_fixture_dir",
]
