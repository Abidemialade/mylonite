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
* ``1`` findings present (a scan found something; not an error)
* ``2`` config / usage error
* ``3`` budget exceeded
* ``4`` provider unreachable
* ``5`` a generated test was not kept (differential/validation did not hold)
* ``6`` test generation failed
* ``7`` test validation failed
* ``8`` the gate's git/gh step failed (the findings are still on disk)
"""

from __future__ import annotations

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
