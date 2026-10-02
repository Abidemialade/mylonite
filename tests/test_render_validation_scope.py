"""What the `validate` report says about scope, stand-ins and attacks that never landed.

* The kill matrix shows seeds the run never attacked as "not run", not as misses,
  and the mutation score says it only covers the test's own seed.
* A rejection where the attack never landed on the unguarded side says so,
  instead of blaming the guard or the seed's flakiness.
* When Mylonite's own boundary guard stood in for the guarded side, a passing
  verdict says what that proves and that the user's own guard was not tested.
"""

from __future__ import annotations

import io

from rich.console import Console

from mylonite._twin_fidelity import format_marker
from mylonite.contracts import (
    ReproducibilityEvidence,
    SeedKill,
    ValidationOutcome,
    ValidationReport,
)
from mylonite.report.render import _render_validation_report

_OWN = "indirect-injection-note-body-direct"


def _render(report: ValidationReport) -> str:
    buf = io.StringIO()
    _render_validation_report(report, console=Console(file=buf, width=200))
    return buf.getvalue()


def _outcomes(passed: bool) -> list[ValidationOutcome]:
    return [
        ValidationOutcome(stage="build", passed=True, detail="collected", metric=None),
        ValidationOutcome(stage="differential", passed=passed, detail="d", metric=1.0),
        ValidationOutcome(stage="flakiness", passed=passed, detail="f", metric=1.0),
        ValidationOutcome(stage="metamorphic", passed=passed, detail="m", metric=1.0),
    ]


def _reference_report(
    *, kept: bool = True, vuln_fired: int = 3, notes: str | None = None, other_killed: bool = False
) -> ValidationReport:
    return ValidationReport(
        test_filename=f"test_security_{_OWN.replace('-', '_')}.py",
        outcomes=_outcomes(kept),
        kept=kept,
        notes=notes if notes is not None else format_marker(server_layer=True),
        mutation_score=1 / 3,
        gating_legs=["build", "differential", "flakiness", "metamorphic"],
        reproducibility=ReproducibilityEvidence(
            iterations=3, vuln_fired=vuln_fired, guard_resisted=3, guard_fired=0
        ),
        mutation_matrix=[
            SeedKill(pattern_id="tool-description-smuggle", weakness="W1", killed=other_killed),
            SeedKill(pattern_id=_OWN, weakness="W2", killed=kept),
            SeedKill(pattern_id="excessive-agency-fetch-attacker-url", weakness="W3", killed=False),
        ],
    )


# --- kill matrix and mutation score ------------------------------------------


def test_seeds_the_run_never_attacked_read_not_run() -> None:
    out = _render(_reference_report())

    w1 = next(line for line in out.splitlines() if "W1:tool-description-smuggle" in line)
    w3 = next(line for line in out.splitlines() if "W3:excessive-agency" in line)
    assert "not run" in w1
    assert "not run" in w3
    own = next(line for line in out.splitlines() if f"W2:{_OWN}" in line)
    assert "not run" not in own
    assert "killed" in own


def test_the_matrix_header_says_only_the_own_seed_ran() -> None:
    out = _render(_reference_report())

    header = next(line for line in out.splitlines() if "kill matrix" in line)
    assert "2 not run" in header
    assert "fired-on-vulnerable, resisted-on-guarded" not in header


def test_the_mutation_score_is_labelled_as_scoped_to_the_own_seed() -> None:
    out = _render(_reference_report())

    line = next(line for line in out.splitlines() if line.startswith("mutation score"))
    assert "0.33" in line
    assert "own seed" in line


def test_a_seed_killed_in_an_older_whole_bank_report_still_shows_killed() -> None:
    out = _render(_reference_report(other_killed=True))

    w1 = next(line for line in out.splitlines() if "W1:tool-description-smuggle" in line)
    assert "not run" not in w1


def test_a_report_whose_own_seed_is_unknown_keeps_the_plain_matrix() -> None:
    report = _reference_report().model_copy(update={"test_filename": "test_security_other.py"})
    out = _render(report)

    assert "not run" not in out
    assert "kill matrix" in out


# --- the attack never landed ------------------------------------------------


def test_a_rejection_where_the_attack_never_landed_says_so() -> None:
    out = _render(_reference_report(kept=False, vuln_fired=0))

    remediation = [line for line in out.splitlines() if "remediation" in line]
    assert len(remediation) == 1, out
    assert "never landed" in remediation[0]
    assert "0/3" in remediation[0]
    assert "planner" in remediation[0]
    assert "did not discriminate" not in out
    assert "too flaky" not in out


def test_a_rejection_where_the_attack_landed_keeps_the_leg_remediation() -> None:
    out = _render(_reference_report(kept=False, vuln_fired=2))

    assert "never landed" not in out
    assert "differential fail" in out


def test_a_build_failure_is_still_reported_when_the_attack_never_landed() -> None:
    report = _reference_report(kept=False, vuln_fired=0)
    outcomes = list(report.outcomes)
    outcomes[0] = ValidationOutcome(stage="build", passed=False, detail="broken", metric=None)
    out = _render(report.model_copy(update={"outcomes": outcomes}))

    assert "build fail" in out
    assert "never landed" in out


# --- the stand-in guard ------------------------------------------------------


def test_a_pass_against_the_stand_in_guard_says_your_guard_was_not_tested() -> None:
    out = _render(_reference_report(notes=format_marker(server_layer=False)))

    line = next(line for line in out.splitlines() if line.startswith("guarded side"))
    assert "stand-in" in line
    assert "by design" in out
    assert "control_env" in out
    assert "not your implementation" in out


def test_a_server_layer_pass_has_no_stand_in_line() -> None:
    out = _render(_reference_report())

    assert "stand-in" not in out
