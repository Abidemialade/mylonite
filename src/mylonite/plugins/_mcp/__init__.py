"""MCP stdio adapter plugin package.

Importing this package triggers eager registration of the per-target
predicate modules (filesystem, fetch, github) against the
``mylonite.scan.predicates`` registry. The ``MCPStdioAdapter``
constructor imports ``mylonite.plugins._mcp`` (this package) before doing
anything else, so any user invoking ``mylonite scan mcp:<family>:<scope>``
gets the predicates resolved by the time engine startup validates seeds.

Registration lives here — not at the bottom of ``mylonite/scan/predicates.py``
— to keep the dependency direction one-way (``plugins → scan``, never
``scan → plugins``). See plan-eng-review finding A4 in
``.claude/plans/so-let-s-pickbackup-from-peaceful-blum.md``.
"""

from __future__ import annotations

from mylonite.plugins._mcp.predicates import fetch as _fetch  # noqa: F401
from mylonite.plugins._mcp.predicates import filesystem as _filesystem  # noqa: F401
from mylonite.plugins._mcp.predicates import github as _github  # noqa: F401
