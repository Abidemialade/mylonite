"""AdaptiveAttackDriver: the adaptive injection-refinement loop (Driver 1 / Slice 2)."""

from __future__ import annotations

from mylonite.scan.attack_loop import AdaptiveOutcome, AttackPlan


def test_attack_plan_holds_plant_and_drive_templates() -> None:
    plan = AttackPlan(
        plant_tool="write_note",
        plant_args={"note_id": "{id}", "body": "{payload}"},
        drive_message="Please read note {id} and summarise it.",
    )
    assert plan.plant_tool == "write_note"
    assert plan.plant_args["body"] == "{payload}"
    assert "{id}" in plan.drive_message


def test_adaptive_outcome_records_result() -> None:
    outcome = AdaptiveOutcome(
        success=True, attempts=2, final_body="refined", response=None, verdict=None
    )
    assert outcome.success is True
    assert outcome.attempts == 2
    assert outcome.final_body == "refined"
