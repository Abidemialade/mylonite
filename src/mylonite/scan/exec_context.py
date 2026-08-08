"""Backward-compat re-export shim for :mod:`mylonite.contracts.exec_context`.

**0.7.10 moved this module's contents.** ``ExecContext`` (plus
``ALLOWED_METADATA_KEYS`` / ``METADATA_PREFIX``) now lives under
``contracts/exec_context.py`` -- ``contracts/test_generator.py`` needs a real
type for its new ``emit(exploit, context=...)`` parameter (see
``CONTRACT_VERSION`` 0.1.0 -> 0.2.0 there), and ``contracts/`` importing FROM
``scan/`` would invert this project's layering (``scan/`` depends on
``contracts/``, never the reverse -- see e.g. ``scan/coverage.py`` and
``scan/predicates.py``, both of which import from
``mylonite.contracts._types``).

This module is kept as a thin re-export so every existing ``from
mylonite.scan.exec_context import ExecContext`` call site (``scan/engine.py``'s
writer, ``testkit/__init__.py``'s runtime resolver, and this project's own
tests) keeps working unchanged. New code should prefer importing from
``mylonite.contracts.exec_context`` directly. See that module's docstring for
the full T12 background (why this rides in ``Payload.metadata`` under the
reserved ``mylonite.exec.*`` prefix at all) and the current one-writer/
several-readers picture.
"""

from __future__ import annotations

from mylonite.contracts.exec_context import (
    ALLOWED_METADATA_KEYS,
    METADATA_PREFIX,
    ExecContext,
)

__all__ = ["ALLOWED_METADATA_KEYS", "METADATA_PREFIX", "ExecContext"]
