"""Unit tests for scripts/check_no_hardcoded_models.py.

Two kinds of coverage:

1. Unit tests against synthetic files (not the real tree), so the matching/
   allowlist/staleness logic is tested in isolation from whatever
   ``src/mylonite`` currently contains.
2. An integration assertion against the REAL repository tree: this is what
   actually gates a PR locally (CI runs the script directly), and it is
   what keeps ``scripts/hardcoded_models_allowlist.txt`` honest -- a stale
   or missing entry fails here, not just in CI.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_no_hardcoded_models as gate  # noqa: E402

#: The allowlist may only shrink. Lower these whenever an entry is removed
#: or its count drops (a hardcoded model/key got fixed, or a stale entry
#: got deleted); never raise them to make room for a new, unreviewed hit --
#: add a real reason to the allowlist file instead and raise these in the
#: same PR, so the ratchet is a deliberate, reviewable act rather than a
#: silent widening.
#: REG-1b (2026-10-02): drained to 0 -- every row became either a fix or an
#: inline `# allow-literal: example` marker on its own source line (see
#: check_no_hardcoded_models.py's module docstring). A future PR may add a
#: row back for a genuine case the marker/path exemptions don't cover; it
#: should raise these ceilings explicitly, in the same PR, with a reason.
ALLOWLIST_ROW_COUNT_CEILING = 0
ALLOWLIST_TOTAL_OCCURRENCE_CEILING = 0


def _write(tmp_path: Path, rel: str, text: str) -> Path:
    path = tmp_path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


# --- matching -----------------------------------------------------------------


def test_model_literal_is_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "a.py", 'MODEL = "claude-haiku-4-5-20251001"\n')
    hits = gate.scan(tmp_path)
    assert any(h.matched == "claude-" for h in hits)


@pytest.mark.parametrize(
    "literal", ["gpt-4o", "gemini-2.5-pro", "ollama/llama3", "openai/gpt-4o", "bedrock/claude"]
)
def test_every_documented_model_pattern_is_flagged(tmp_path: Path, literal: str) -> None:
    _write(tmp_path, "a.py", f'MODEL = "{literal}"\n')
    hits = gate.scan(tmp_path)
    assert hits, f"{literal!r} was not flagged"


def test_bare_provider_name_without_slash_is_not_flagged(tmp_path: Path) -> None:
    """'the anthropic provider' in prose must not be treated as a literal --
    only the ``anthropic/<model>`` prefix shape is a hardcoded model."""
    _write(tmp_path, "a.py", '# uses the anthropic provider via litellm\nPROVIDER = "anthropic"\n')
    hits = gate.scan(tmp_path)
    assert hits == []


def test_provider_env_var_read_is_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "a.py", 'import os\nos.environ["ANTHROPIC_API_KEY"]\n')
    hits = gate.scan(tmp_path)
    assert any(h.matched == "ANTHROPIC_API_KEY" for h in hits)


def test_unrelated_caps_token_is_not_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "a.py", "MAX_RETRIES = 3\nEXIT_SUCCESS = 0\n")
    hits = gate.scan(tmp_path)
    assert hits == []


def test_non_python_files_are_not_scanned(tmp_path: Path) -> None:
    _write(tmp_path, "a.txt", "claude-haiku-4-5\nANTHROPIC_API_KEY\n")  # pragma: allowlist secret
    hits = gate.scan(tmp_path)
    assert hits == []


def test_a_line_carrying_the_allow_literal_marker_is_skipped(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "a.py",
        'MODEL = "claude-haiku-4-5-20251001"  # allow-literal: example\n',
    )
    assert gate.scan(tmp_path) == []


def test_the_marker_only_exempts_the_line_it_is_on(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "a.py",
        'EXAMPLE = "claude-haiku-4-5"  # allow-literal: example\nDEFAULT = "claude-sonnet-4-6"\n',
    )
    hits = gate.scan(tmp_path)
    assert len(hits) == 1
    assert hits[0].text.startswith("DEFAULT")


def test_redaction_module_is_exempt_by_path_like_the_registry() -> None:
    """``mylonite._redaction`` quotes provider credential vars in its secret-
    shape patterns and comments without ever choosing one for a user -- see
    ``_REDACTION_PATH`` next to the existing ``_REGISTRY_PATH`` exemption."""
    hits = gate.scan()
    assert all(h.path != "src/mylonite/_redaction.py" for h in hits)


# --- allowlist parsing ----------------------------------------------------


def test_parse_allowlist_reads_a_valid_entry() -> None:
    entries = gate.parse_allowlist("a.py | claude- | 2 | an example in a docstring\n")
    assert entries == [
        gate.AllowlistEntry(
            "a.py",
            "claude-",
            2,
            "an example in a docstring",
            "a.py | claude- | 2 | an example in a docstring",
        )
    ]


def test_parse_allowlist_ignores_blank_and_comment_lines() -> None:
    assert gate.parse_allowlist("\n# a comment\n   \n") == []


@pytest.mark.parametrize(
    "bad_line",
    [
        "a.py | claude- | 2",  # missing reason field
        "a.py | claude- | 2 | ",  # empty reason
        "a.py | | 2 | reason",  # empty pattern
        " | claude- | 2 | reason",  # empty path
        "a.py | claude- | zero | reason",  # non-integer count
        "a.py | claude- | 0 | reason",  # count must be >= 1
        "a.py | [ | 1 | reason",  # invalid regex
        "a.py | claude- | 2 | reason | extra",  # too many fields
    ],
)
def test_parse_allowlist_rejects_malformed_entries(bad_line: str) -> None:
    with pytest.raises(gate.AllowlistError):
        gate.parse_allowlist(bad_line)


def test_parse_allowlist_accepts_a_regex_pattern() -> None:
    entries = gate.parse_allowlist(r"a.py | AZURE_API_(BASE|VERSION) | 2 | two related vars\n")
    assert entries[0].pattern == "AZURE_API_(BASE|VERSION)"


# --- unmatched / over-limit / stale ---------------------------------------


def test_an_allowlisted_hit_does_not_fail() -> None:
    hits = [gate.Hit("a.py", 3, "claude-", 'MODEL = "claude-haiku"')]
    entries = [gate.AllowlistEntry("a.py", "claude-", 1, "example", "src")]
    assert gate.unmatched_hits(hits, entries) == []
    assert gate.over_limit_entries(hits, entries) == []
    assert gate.stale_entries(hits, entries) == []


def test_a_hit_not_in_the_allowlist_fails() -> None:
    hits = [gate.Hit("a.py", 3, "claude-", 'MODEL = "claude-haiku"')]
    assert gate.unmatched_hits(hits, []) == hits


def test_an_allowlist_entry_with_no_matching_hit_is_stale() -> None:
    entries = [gate.AllowlistEntry("a.py", "claude-", 1, "example", "src")]
    assert gate.stale_entries([], entries) == entries


def test_an_entry_for_one_path_does_not_cover_the_same_text_in_another_file() -> None:
    hits = [gate.Hit("b.py", 3, "claude-", 'MODEL = "claude-haiku"')]
    entries = [gate.AllowlistEntry("a.py", "claude-", 1, "example", "src")]
    assert gate.unmatched_hits(hits, entries) == hits
    assert gate.stale_entries(hits, entries) == entries


def test_an_edit_that_only_moves_lines_does_not_break_the_entry() -> None:
    """The whole point of the content-keyed format: an unrelated edit that
    shifts every subsequent line number must not make a correct entry look
    stale or unmatched -- there is no line number in the key at all."""
    hits_before = [gate.Hit("a.py", 10, "claude-", 'MODEL = "claude-haiku"')]
    hits_after_insertion_above = [gate.Hit("a.py", 47, "claude-", 'MODEL = "claude-haiku"')]
    entries = [gate.AllowlistEntry("a.py", "claude-", 1, "example", "src")]
    for hits in (hits_before, hits_after_insertion_above):
        assert gate.unmatched_hits(hits, entries) == []
        assert gate.stale_entries(hits, entries) == []


def test_more_occurrences_than_the_count_allows_is_reported() -> None:
    hits = [
        gate.Hit("a.py", 1, "claude-", 'A = "claude-x"'),
        gate.Hit("a.py", 2, "claude-", 'B = "claude-y"'),
    ]
    entries = [gate.AllowlistEntry("a.py", "claude-", 1, "example", "src")]
    assert gate.unmatched_hits(hits, entries) == []  # each hit IS covered by some entry
    over = gate.over_limit_entries(hits, entries)
    assert over == [(entries[0], 2)]


def test_fewer_occurrences_than_the_count_allows_is_not_over_limit_but_not_stale_either() -> None:
    hits = [gate.Hit("a.py", 1, "claude-", 'A = "claude-x"')]
    entries = [gate.AllowlistEntry("a.py", "claude-", 3, "example", "src")]
    assert gate.over_limit_entries(hits, entries) == []
    assert gate.stale_entries(hits, entries) == []  # at least one match remains


def test_a_regex_entry_can_cover_more_than_one_literal_matched_text() -> None:
    hits = [
        gate.Hit("a.py", 1, "AZURE_API_BASE", "..."),
        gate.Hit("a.py", 2, "AZURE_API_VERSION", "..."),
    ]
    entries = [gate.AllowlistEntry("a.py", "AZURE_API_(BASE|VERSION)", 2, "example", "src")]
    assert gate.unmatched_hits(hits, entries) == []
    assert gate.over_limit_entries(hits, entries) == []
    assert gate.stale_entries(hits, entries) == []


# --- the real repository tree ---------------------------------------------


def test_the_real_tree_has_no_unlisted_hits_over_limit_or_stale_entries() -> None:
    hits = gate.scan()
    entries = gate.load_allowlist()
    problems = gate.unmatched_hits(hits, entries)
    assert problems == [], (
        "new hardcoded provider model(s)/credential read(s) found; add them to "
        "scripts/hardcoded_models_allowlist.txt with a reason, or fix them: "
        f"{problems}"
    )
    over = gate.over_limit_entries(hits, entries)
    assert over == [], f"more occurrences than the allowlist's count permits: {over}"
    stale = gate.stale_entries(hits, entries)
    assert stale == [], (
        "stale allowlist entries no longer match anything in the named file; update "
        f"or remove them: {[e.source_line for e in stale]}"
    )


def test_the_allowlist_has_not_grown() -> None:
    entries = gate.load_allowlist()
    assert len(entries) <= ALLOWLIST_ROW_COUNT_CEILING, (
        f"the allowlist grew to {len(entries)} rows (ceiling {ALLOWLIST_ROW_COUNT_CEILING}). "
        "If this is a deliberate, reviewed addition, raise ALLOWLIST_ROW_COUNT_CEILING in "
        "this test in the same PR; otherwise fix the new hardcoded model/key instead of "
        "allowlisting it."
    )
    total = sum(e.count for e in entries)
    assert total <= ALLOWLIST_TOTAL_OCCURRENCE_CEILING, (
        f"the allowlist's total permitted occurrences grew to {total} "
        f"(ceiling {ALLOWLIST_TOTAL_OCCURRENCE_CEILING}). Raise the ceiling in this test "
        "only alongside a deliberate, reviewed addition."
    )


def test_main_exits_zero_against_the_real_tree() -> None:
    assert gate.main([]) == 0
