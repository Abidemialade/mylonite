"""Single source of truth for Mylonite's process exit codes.

The exit codes are a documented public contract (the ``scan`` epilog and
``docs/cli-reference.md``). They were previously defined three times -- in
``cli.py``, ``gate/orchestrator.py`` and ``scan/coverage.py`` -- the last with a
comment admitting it "mirrors cli.py ... keep this mapping in sync", and nothing
checked that the mirror stayed true. They now live here and every site imports
them, so a change is one edit and drift is impossible.

This module is a dependency-free leaf: ``cli`` (top), ``gate`` and ``scan`` all
import it without inverting any layering.

Contract:

* ``0`` success
* ``1`` ``check --enforce`` found structural findings (``scan`` itself exits ``0``
  even when it finds weaknesses -- reporting is not an error; only ``check``'s
  opt-in enforcement mode turns a finding into a non-zero exit)
* ``2`` config / usage error
* ``3`` budget exceeded
* ``4`` provider unreachable
* ``5`` a generated test was not kept (differential/validation did not hold)
* ``6`` test generation failed
* ``7`` test validation failed
* ``8`` the gate's git/gh step failed (the findings are still on disk)
* ``9`` ``gate`` kept at least one proven finding and wrote its gate test
  (``gate`` exits ``0`` only when the scan ran and found nothing)
* ``10`` ``gate`` kept nothing, but at least one finding reproduced without
  proof (STABLE, NOT PROVEN): it is reported as a candidate, never written as
  a gate test
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Final

EXIT_SUCCESS: Final = 0
EXIT_FINDINGS: Final = 1
EXIT_CONFIG: Final = 2
EXIT_BUDGET: Final = 3
EXIT_PROVIDER: Final = 4
EXIT_NOT_KEPT: Final = 5
EXIT_GENERATE_FAILED: Final = 6
EXIT_VALIDATE_FAILED: Final = 7
EXIT_PR_FAILED: Final = 8
EXIT_GATE_KEPT: Final = 9
EXIT_GATE_CANDIDATES: Final = 10

#: Explicit severity ordering, least to most severe. The codes 0-8 rank more
#: severe as their number increases, so for them this reproduces a plain
#: ``max()``. The gate's result codes are placed by hand: ``9`` (kept) and
#: ``10`` (candidates only) are results, not errors, so they rank above
#: success and below every error code, with a proven finding above an
#: unproven one. Their numbers alone would rank them above ``8``.
SEVERITY_ORDER: Final[tuple[int, ...]] = (
    EXIT_SUCCESS,
    EXIT_GATE_CANDIDATES,
    EXIT_GATE_KEPT,
    EXIT_FINDINGS,
    EXIT_CONFIG,
    EXIT_BUDGET,
    EXIT_PROVIDER,
    EXIT_NOT_KEPT,
    EXIT_GENERATE_FAILED,
    EXIT_VALIDATE_FAILED,
    EXIT_PR_FAILED,
)

_SEVERITY_RANK: Final[dict[int, int]] = {code: rank for rank, code in enumerate(SEVERITY_ORDER)}


def most_severe(codes: Iterable[int]) -> int:
    """Return the most severe of ``codes``, per :data:`SEVERITY_ORDER`.

    This is the explicit replacement for ``max(codes)``: for the codes 0-8 it
    returns exactly what ``max()`` would, because the order was built to
    reproduce that. Later codes (``9``, ``10``) are ranked by where they are
    placed in the list, not by their integer value.

    Raises ``ValueError`` if ``codes`` is empty, or if any code is not in
    :data:`SEVERITY_ORDER` -- an unregistered code is a bug at the call site
    (a new exit code was minted without being added here), so this fails
    loudly instead of silently sorting it first or last.
    """
    codes = list(codes)
    if not codes:
        raise ValueError("most_severe() requires at least one exit code")
    unknown = sorted({code for code in codes if code not in _SEVERITY_RANK})
    if unknown:
        raise ValueError(f"most_severe() received exit code(s) not in SEVERITY_ORDER: {unknown}")
    return max(codes, key=_SEVERITY_RANK.__getitem__)
