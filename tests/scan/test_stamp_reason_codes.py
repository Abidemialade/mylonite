"""#319 (follow-up): a NOT_TESTED attempt's own record must carry its reason
code, not just the coverage summary line above it.

``scripts/score_third_party.py``'s ``_unexplained_attempts`` -- the campaign
scorer's definition of "a product defect" -- reads only an attempt's OWN
``verdict_reason``/``not_applicable_reason``/``error_detail`` fields for a
``MYL-*`` code; it never reads the coverage summary. Before this fix,
``skipped_no_seed_arm`` and the ordinary ``skipped_planner_failure``/``error``
runtime outcomes (including the #319 unwrap fix's ``subprocess_crash`` label)
carried no code of their own, so the scorer counted them as unexplained even
though ``coverage.reason_code_for_attempt`` could already name the cause.
"""

from __future__ import annotations

import sys
from pathlib import Path

from mylonite.contracts._types import ScanAttempt
from mylonite.reason_codes import NT_NO_SEED_ARM, NT_PLANNER_FAILURE
from mylonite.scan.coverage import stamp_reason_codes

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "scripts"))

import score_third_party as scorer  # path set up just above


def _unexplained_for(attempt: ScanAttempt) -> list[dict]:
    raw_report = {"attempts": [attempt.model_dump(mode="json")]}
    return scorer._unexplained_attempts(raw_report)


def test_skipped_no_seed_arm_is_stamped_with_its_code() -> None:
    attempt = ScanAttempt(
        seed_id="s1",
        pattern_id="s1",
        outcome="skipped_no_seed_arm",
        verdict_reason="seed_arm tool 'remember' is not among the server's tools",
    )

    (stamped,) = stamp_reason_codes([attempt])

    assert stamped.verdict_reason is not None
    assert NT_NO_SEED_ARM in stamped.verdict_reason
    assert "not among the server's tools" in stamped.verdict_reason
    assert _unexplained_for(stamped) == []


def test_subprocess_crash_skip_is_stamped_with_its_code() -> None:
    """The #319 unwrap fix labels a target/transport crash
    ``skipped_planner_failure`` with a ``subprocess_crash on ...`` reason
    (see ``_session_adapter.py``'s ``_classify_failure``) -- that outcome
    must also be stamped, not just the seed-arm one."""
    attempt = ScanAttempt(
        seed_id="s1",
        pattern_id="s1",
        outcome="skipped_planner_failure",
        verdict_reason="subprocess_crash on s1: BrokenResourceError()",
        error_detail="BrokenResourceError",
    )

    (stamped,) = stamp_reason_codes([attempt])

    assert stamped.verdict_reason is not None
    assert NT_PLANNER_FAILURE in stamped.verdict_reason
    assert "subprocess_crash" in stamped.verdict_reason
    assert _unexplained_for(stamped) == []


def test_unexplained_before_the_fix_is_what_this_fix_removes() -> None:
    """Sanity check on the scorer's OWN rule, unstamped: proves the gap this
    fix closes actually existed, so the two tests above are not vacuous."""
    attempt = ScanAttempt(
        seed_id="s1",
        pattern_id="s1",
        outcome="skipped_no_seed_arm",
        verdict_reason="seed_arm tool 'remember' is not among the server's tools",
    )
    assert len(_unexplained_for(attempt)) == 1


def test_an_already_coded_attempt_is_left_alone() -> None:
    """Idempotent: an engine-synthesized row that already called
    ``reason_codes.tag()`` on itself must not be re-tagged or otherwise
    changed."""
    attempt = ScanAttempt(
        seed_id="no-attack-emitted:W3",
        pattern_id="no-attack-emitted:W3",
        outcome="not_applicable",
        verdict_reason="[MYL-NT-016] no attack module in this run emitted a W3 attack.",
        not_applicable_reason="[MYL-NT-016] no attack module in this run emitted a W3 attack.",
    )

    (stamped,) = stamp_reason_codes([attempt])

    assert stamped == attempt


def test_a_finding_and_a_no_finding_are_never_touched() -> None:
    finding = ScanAttempt(
        seed_id="s1", pattern_id="s1", outcome="finding", verdict_mechanism="predicate"
    )
    no_finding = ScanAttempt(
        seed_id="s2", pattern_id="s2", outcome="no_finding", verdict_mechanism="predicate"
    )

    stamped = stamp_reason_codes([finding, no_finding])

    assert stamped == [finding, no_finding]
