"""The approved LLM provider registry.

See :mod:`mylonite.providers.registry` for the data table itself. Kept as
its own top-level package (rather than folded into ``mylonite.scan``) so
non-scan consumers -- CI template emission, docs generation, the CLI's
"choose a model" listing -- can import it without pulling in the scan
engine.
"""

from __future__ import annotations
