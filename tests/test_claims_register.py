"""Tests for ``scripts/check_claims_register.py``, the two-way ratchet
between a `<!-- claim:ID -->` marker in README.md/`docs/journey/*.md` and
its row in `docs/claims.md`.

Hermetic cases build a throwaway repo layout under `tmp_path` so the
mechanism itself is proven without depending on the real docs; the final
test checks the real, committed register is actually in sync.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_claims_register as ccr  # noqa: E402


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_marker_with_a_register_row_is_clean(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "README.md",
        "<!-- claim:widgets-ship -->\n**Mylonite ships widgets.** See the tests.\n",
    )
    _write(
        tmp_path, "docs/claims.md", "| `widgets-ship` | Ships widgets. | tests/test_widgets.py |\n"
    )
    assert ccr.check(tmp_path) == []


def test_marker_with_no_register_row_fails(tmp_path: Path) -> None:
    _write(tmp_path, "README.md", "<!-- claim:undocumented -->\n**A bold claim.**\n")
    _write(tmp_path, "docs/claims.md", "| Id | Claim | Evidence |\n|---|---|---|\n")
    problems = ccr.check(tmp_path)
    assert any("claim:undocumented" in p.message and "no row" in p.message for p in problems)


def test_register_row_with_no_marker_fails(tmp_path: Path) -> None:
    _write(tmp_path, "README.md", "No claims here.\n")
    _write(tmp_path, "docs/claims.md", "| `orphaned` | Nobody says this anymore. | nowhere |\n")
    problems = ccr.check(tmp_path)
    assert any(
        "claim:orphaned" in p.message and "no" in p.message and "marker" in p.message
        for p in problems
    )


def test_journey_page_markers_are_also_checked(tmp_path: Path) -> None:
    _write(
        tmp_path, "docs/journey/1-try.md", "<!-- claim:journey-claim -->\n**Something measured.**\n"
    )
    _write(
        tmp_path,
        "docs/claims.md",
        "| `journey-claim` | Something measured. | verification/results/ |\n",
    )
    assert ccr.check(tmp_path) == []


def test_duplicate_register_row_fails(tmp_path: Path) -> None:
    _write(tmp_path, "README.md", "<!-- claim:dup -->\n**Said once.**\n")
    _write(
        tmp_path,
        "docs/claims.md",
        "| `dup` | Said once. | evidence.json |\n| `dup` | Said once, again. | evidence.json |\n",
    )
    problems = ccr.check(tmp_path)
    assert any("more than one row" in p.message and "claim:dup" in p.message for p in problems)


def test_find_markers_reports_the_source_location(tmp_path: Path) -> None:
    _write(tmp_path, "README.md", "line one\n<!-- claim:located -->\n**claim text**\n")
    markers = ccr.find_markers(tmp_path)
    assert markers["located"] == ["README.md:2"]


def test_real_docs_claims_register_is_in_sync() -> None:
    """The committed README.md / docs/journey/ / docs/claims.md trio, as it
    exists in this checkout right now, must already satisfy the ratchet —
    this is the check CI actually runs."""
    problems = ccr.check(ROOT)
    assert not problems, "\n".join(p.message for p in problems)
