import importlib.resources as ir

from mylonite.contracts._types import (
    AdapterResponse,
    ComplianceTags,
    ExploitRecord,
    Payload,
)
from mylonite.gate.mitigation import weakness_class_for
from mylonite.scan.seeds import SEED_CATALOGUE


def test_gate_package_imports():
    import mylonite.gate  # noqa: F401
    from mylonite.gate import GateResult, build_pr_body, run_gate  # noqa: F401


def _exploit_for(pattern_id, *, target_id="reference:vulnerable"):
    seed = next(s for s in SEED_CATALOGUE if s.pattern_id == pattern_id)
    return ExploitRecord(
        target_id=target_id,
        pattern_id=pattern_id,
        payload=Payload(
            pattern_id=pattern_id,
            channel="user-message",
            body="x",
            metadata={},
        ),
        response=AdapterResponse(
            payload_pattern_id=pattern_id,
            raw_response="",
            tool_calls=[],
            metadata={},
        ),
        success_reason="test",
        compliance=seed.compliance,
    )


def test_weakness_class_from_seed_catalogue():
    assert (
        weakness_class_for(_exploit_for("excessive-agency-send-email-direct-unconfirmed")) == "W4"
    )
    assert weakness_class_for(_exploit_for("indirect-injection-note-body-direct")) == "W2"


def test_weakness_class_unknown_pattern_falls_back_to_compliance_then_generic():
    ex = ExploitRecord(
        target_id="mcp:custom",
        pattern_id="totally-unknown-id",
        payload=Payload(
            pattern_id="totally-unknown-id",
            channel="user-message",
            body="x",
            metadata={},
        ),
        response=AdapterResponse(
            payload_pattern_id="totally-unknown-id",
            raw_response="",
            tool_calls=[],
            metadata={},
        ),
        success_reason="test",
        compliance=ComplianceTags(owasp_asi=["ASI02"]),
    )
    assert weakness_class_for(ex) == "W1"  # ASI02 (tool misuse) -> W1/W2 family; see mapping

    ex_blank = ex.model_copy(update={"compliance": ComplianceTags()})
    assert weakness_class_for(ex_blank) == "generic"


def test_all_mitigation_snippets_present():
    base = ir.files("mylonite.gate") / "mitigations"
    for name in ("W1", "W2", "W3", "W4", "generic"):
        text = (base / f"{name}.md").read_text(encoding="utf-8")
        assert text.strip(), f"{name}.md is empty"
