"""Ratchet: the generated provider table in ``docs/choose-a-model.md`` never
drifts from ``mylonite.providers.registry.PROVIDERS``.

``scripts/gen_provider_table.py`` is the one place that renders the table;
this test re-renders it from the live registry and fails loudly, naming the
script to re-run, whenever the committed page and a fresh render disagree —
the same idempotency contract ``scripts/regenerate_schemas.py`` has for the
JSON schemas (see that script's own docstring).
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import gen_provider_table as gen  # noqa: E402


def _committed_table() -> str:
    text = gen.DOC_PATH.read_text(encoding="utf-8")
    begin = text.index(gen.BEGIN_MARKER) + len(gen.BEGIN_MARKER)
    end = text.index(gen.END_MARKER)
    return text[begin:end].strip()


def test_provider_table_matches_registry() -> None:
    committed = _committed_table()
    fresh = gen.render_table().strip()
    assert committed == fresh, (
        "docs/choose-a-model.md's provider table has drifted from "
        "mylonite.providers.registry.PROVIDERS. Run "
        "`python scripts/gen_provider_table.py` and commit the result."
    )


def test_every_registry_provider_appears_once() -> None:
    """A provider dropped from, or added to, ``PROVIDERS`` without
    regenerating the page would otherwise slip past the previous check only
    if the row counts happened to still line up — this pins every id by
    name instead."""
    committed = _committed_table()
    for provider_id in gen.PROVIDERS:
        assert committed.count(f"| {provider_id} |") == 1, (
            f"provider {provider_id!r} should appear exactly once in the "
            "generated table; run `python scripts/gen_provider_table.py`."
        )


def test_generator_is_idempotent() -> None:
    """Re-running the generator against its own output changes nothing."""
    text = gen.DOC_PATH.read_text(encoding="utf-8")
    assert gen.rendered_page(text) == text
