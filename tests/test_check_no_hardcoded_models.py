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

#: The allowlist may only shrink. Lower this whenever an entry is removed
#: (a hardcoded model/key got fixed, or a stale entry got deleted); never
#: raise it to make room for a new, unreviewed hit -- add a real reason to
#: the allowlist file instead and raise this in the same PR, so the ratchet
#: is a deliberate, reviewable act rather than a silent widening.
ALLOWLIST_COUNT_CEILING = 79


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


# --- allowlist parsing ----------------------------------------------------


def test_parse_allowlist_reads_a_valid_entry() -> None:
    entries = gate.parse_allowlist("a.py:3:claude- | an example in a docstring\n")
    assert entries == [
        gate.AllowlistEntry(
            "a.py",
            3,
            "claude-",
            "an example in a docstring",
            "a.py:3:claude- | an example in a docstring",
        )
    ]


def test_parse_allowlist_ignores_blank_and_comment_lines() -> None:
    assert gate.parse_allowlist("\n# a comment\n   \n") == []


@pytest.mark.parametrize(
    "bad_line",
    [
        "a.py:3:claude-",  # no " | reason"
        "a.py:3:claude- | ",  # empty reason
        "a.py:claude- | reason",  # missing line number field
        "a.py:threeve:claude- | reason",  # non-integer line
        "a.py:3: | reason",  # empty matched text
    ],
)
def test_parse_allowlist_rejects_malformed_entries(bad_line: str) -> None:
    with pytest.raises(gate.AllowlistError):
        gate.parse_allowlist(bad_line)


# --- unmatched / stale ----------------------------------------------------


def test_an_allowlisted_hit_does_not_fail() -> None:
    hits = [gate.Hit("a.py", 3, "claude-", 'MODEL = "claude-haiku"')]
    entries = [gate.AllowlistEntry("a.py", 3, "claude-", "example", "src")]
    assert gate.unmatched_hits(hits, entries) == []
    assert gate.stale_entries(hits, entries) == []


def test_a_hit_not_in_the_allowlist_fails() -> None:
    hits = [gate.Hit("a.py", 3, "claude-", 'MODEL = "claude-haiku"')]
    assert gate.unmatched_hits(hits, []) == hits


def test_an_allowlist_entry_with_no_matching_hit_is_stale() -> None:
    entries = [gate.AllowlistEntry("a.py", 3, "claude-", "example", "src")]
    assert gate.stale_entries([], entries) == entries


def test_an_allowlist_entry_cannot_cover_a_different_matched_text_on_the_same_line() -> None:
    """An entry for one matched substring must not silently also cover a
    DIFFERENT substring that starts appearing on that same line later --
    each hit is keyed on (path, line, matched text), not just location."""
    hits = [gate.Hit("a.py", 3, "gpt-", 'MODEL = "gpt-4o"  # was claude-haiku')]
    entries = [gate.AllowlistEntry("a.py", 3, "claude-", "example", "src")]
    assert gate.unmatched_hits(hits, entries) == hits
    assert gate.stale_entries(hits, entries) == entries


# --- the real repository tree ---------------------------------------------


def test_the_real_tree_has_no_unlisted_hits_and_no_stale_allowlist_entries() -> None:
    hits = gate.scan()
    entries = gate.load_allowlist()
    problems = gate.unmatched_hits(hits, entries)
    assert problems == [], (
        "new hardcoded provider model(s)/credential read(s) found; add them to "
        "scripts/hardcoded_models_allowlist.txt with a reason, or fix them: "
        f"{problems}"
    )
    stale = gate.stale_entries(hits, entries)
    assert stale == [], (
        "stale allowlist entries no longer match the line they name; update or "
        f"remove them: {[e.source_line for e in stale]}"
    )


def test_the_allowlist_count_has_not_grown() -> None:
    entries = gate.load_allowlist()
    assert len(entries) <= ALLOWLIST_COUNT_CEILING, (
        f"the allowlist grew to {len(entries)} entries (ceiling {ALLOWLIST_COUNT_CEILING}). "
        "If this is a deliberate, reviewed addition, raise ALLOWLIST_COUNT_CEILING in this "
        "test in the same PR; otherwise fix the new hardcoded model/key instead of "
        "allowlisting it."
    )


def test_main_exits_zero_against_the_real_tree() -> None:
    assert gate.main([]) == 0
