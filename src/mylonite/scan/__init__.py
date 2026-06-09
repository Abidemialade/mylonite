"""Phase 1 exploit-finding loop.

Modules:

* ``_types`` — shared Pydantic data types (``Verdict``).
* ``seeds`` — declarative attack-seed catalogue (``SeedPattern`` + W1/W2 catalogue).
* ``predicates`` — deterministic success predicate registry.

Higher layers (``customiser``, ``judge``, ``engine``, ``artefacts``, ``_llm``)
land in subsequent PRs.
"""

from __future__ import annotations

from mylonite.scan._types import Verdict
from mylonite.scan.predicates import lookup_predicate, predicate
from mylonite.scan.seeds import SEED_CATALOGUE, SeedPattern

__all__ = [
    "SEED_CATALOGUE",
    "SeedPattern",
    "Verdict",
    "lookup_predicate",
    "predicate",
]
