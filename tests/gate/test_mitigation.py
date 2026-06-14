import importlib.resources as ir

from mylonite.contracts._types import (
    AdapterResponse,
    ComplianceTags,
    ExploitRecord,
    Payload,
    ValidationOutcome,
    ValidationReport,
)
from mylonite.gate.mitigation import build_pr_body, weakness_class_for
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
    assert weakness_class_for(ex) == "W1"  # ASI02 (tool-description smuggling) -> W1

    ex_llm = ex.model_copy(update={"compliance": ComplianceTags(owasp_llm=["LLM06"])})
    assert weakness_class_for(ex_llm) == "W4"

    ex_blank = ex.model_copy(update={"compliance": ComplianceTags()})
    assert weakness_class_for(ex_blank) == "generic"


def test_all_mitigation_snippets_present():
    base = ir.files("mylonite.gate") / "mitigations"
    for name in ("W1", "W2", "W3", "W4", "generic"):
        text = (base / f"{name}.md").read_text(encoding="utf-8")
        assert text.strip(), f"{name}.md is empty"


def _report(kept=True):
    return ValidationReport(
        test_filename="test_security_x.py",
        outcomes=[
            ValidationOutcome(stage="stability", passed=True, detail="2/2 runs", metric=1.0),
            ValidationOutcome(stage="effect", passed=True, detail="probe confirmed", metric=1.0),
        ],
        kept=kept,
        mutation_score=0.75,
    )


def test_pr_body_reference_target_has_all_sections_and_diff_link():
    ex = _exploit_for("excessive-agency-send-email-direct-unconfirmed")  # reference:vulnerable
    body = build_pr_body(ex, _report())
    assert "## What Mylonite found" in body
    assert "## Suggested mitigation" in body
    assert "human-applied" in body.lower()
    assert "## How this is gated" in body
    assert "excessive agency (W4)" in body  # the W4 snippet
    assert "LLM06" in body and "ASI02" in body  # compliance tags surfaced
    assert "server_guarded.py" in body  # guarded-twin diff reference
    assert "mutation" in body.lower()  # validation evidence


def test_pr_body_custom_target_has_no_diff_link():
    ex = _exploit_for("excessive-agency-send-email-direct-unconfirmed", target_id="mcp:custom")
    body = build_pr_body(ex, _report())
    assert "server_guarded.py" not in body
    assert "## Suggested mitigation" in body


def test_pr_body_is_deterministic():
    ex = _exploit_for("indirect-injection-note-body-direct")
    assert build_pr_body(ex, _report()) == build_pr_body(ex, _report())


def test_llm_enrichment_is_labelled_and_opt_in():
    ex = _exploit_for("indirect-injection-note-body-direct")

    calls = {"n": 0}

    def fake_completion(*, model, messages, **kwargs):
        calls["n"] += 1

        class _Msg:  # minimal litellm-shaped response
            content = "Wrap retrieved notes in an untrusted envelope and re-test."

        class _Choice:
            message: _Msg = _Msg()  # type: ignore[misc]

        class _Resp:
            def __init__(self) -> None:
                self.choices = [_Choice()]

        return _Resp()

    # default: no enrichment, no call
    body_plain = build_pr_body(ex, _report())
    assert "Unverified LLM suggestion" not in body_plain
    assert calls["n"] == 0

    # opt-in: labelled block, completion called once
    body_rich = build_pr_body(ex, _report(), llm_enrich=True, completion_fn=fake_completion)
    assert "Unverified LLM suggestion" in body_rich
    assert "untrusted envelope" in body_rich
    assert calls["n"] == 1
