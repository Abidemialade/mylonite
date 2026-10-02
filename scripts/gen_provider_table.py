"""Regenerate the provider table in ``docs/choose-a-model.md`` from the
approved-provider registry.

Run from the repo root::

    python scripts/gen_provider_table.py

``mylonite.providers.registry.PROVIDERS`` is the one place that answers
"which providers does Mylonite back, and what does each one need". Before
this script, a reader had to trust that the docs page agreed with the
registry by eye; now the table between the two HTML comment markers below is
written straight from ``PROVIDERS``, the same way
``scripts/regenerate_schemas.py`` writes the JSON schemas from the Pydantic
contract models.

The script is idempotent: a clean checkout running this script must produce
no diff. ``tests/test_choose_a_model_docs.py`` enforces that in CI — it fails
loudly, naming this script, whenever the committed table and a fresh render
disagree, rather than letting the page quietly drift from the registry it
claims to describe.
"""

from __future__ import annotations

from pathlib import Path

from mylonite.providers.registry import PROVIDERS, ProviderInfo

ROOT = Path(__file__).resolve().parent.parent
DOC_PATH = ROOT / "docs" / "choose-a-model.md"

BEGIN_MARKER = "<!-- BEGIN GENERATED PROVIDER TABLE -->"
END_MARKER = "<!-- END GENERATED PROVIDER TABLE -->"

_HEADER = (
    "| Provider | Status | LiteLLM prefix | Key env var(s) | Other required vars "
    "| Extra headers | Example model |\n"
    "|---|---|---|---|---|---|---|\n"
)


def _key_env_cell(info: ProviderInfo) -> str:
    if info.key_env:
        return ", ".join(f"`{name}`" for name in info.key_env)
    return "none — local, no key" if info.local else "none — see notes below the table"


def _tuple_cell(values: tuple[str, ...], *, empty: str) -> str:
    return ", ".join(f"`{v}`" for v in values) if values else empty


def _example_cell(info: ProviderInfo) -> str:
    return f"`{info.example_model}`" if info.example_model else "not published yet"


def _row(info: ProviderInfo) -> str:
    return (
        f"| {info.id} | {info.tier} | `{info.model_prefix}` | {_key_env_cell(info)} "
        f"| {_tuple_cell(info.extra_env, empty='—')} "
        f"| {_tuple_cell(info.extra_headers, empty='none yet')} "
        f"| {_example_cell(info)} |"
    )


def render_table() -> str:
    """The generated block's exact text, markers excluded.

    Sorted ``measured`` first (the tiers backed by Mylonite's own
    verification evidence — see the docs page), then alphabetically by id
    within a tier, so a provider's position in the table is a function of
    its data, not insertion order in the registry module.
    """
    ordered = sorted(PROVIDERS.values(), key=lambda info: (info.tier != "measured", info.id))
    rows = "\n".join(_row(info) for info in ordered)
    return _HEADER + rows + "\n"


def rendered_page(current_text: str) -> str:
    """``current_text`` with everything between the two markers replaced."""
    begin = current_text.index(BEGIN_MARKER) + len(BEGIN_MARKER)
    end = current_text.index(END_MARKER)
    return f"{current_text[:begin]}\n\n{render_table()}\n{current_text[end:]}"


def main() -> None:
    text = DOC_PATH.read_text(encoding="utf-8")
    DOC_PATH.write_text(rendered_page(text), encoding="utf-8")
    print(f"wrote {DOC_PATH.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
