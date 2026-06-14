from mylonite.contracts._types import (
    AdapterResponse,
    ComplianceTags,
    ExploitRecord,
    GeneratedTest,
    Payload,
    ValidationOutcome,
    ValidationReport,
)
from mylonite.gate.orchestrator import GateResult, run_gate


def _exploit():
    return ExploitRecord(
        target_id="mcp:custom",
        pattern_id="indirect-injection-note-body-direct",
        payload=Payload(
            pattern_id="indirect-injection-note-body-direct",
            channel="user-message",
            body="injected payload body",
            metadata={},
        ),
        response=AdapterResponse(
            payload_pattern_id="indirect-injection-note-body-direct",
            raw_response="agent did the thing",
            tool_calls=[],
            metadata={},
        ),
        success_reason="r",
        compliance=ComplianceTags(owasp_asi=["ASI01"]),
    )


def test_run_gate_kept_assembles_and_invokes_pr(tmp_path):
    ex = _exploit()
    report = ValidationReport(
        test_filename="test_security_x.py",
        kept=True,
        outcomes=[ValidationOutcome(stage="stability", passed=True, detail="1/1", metric=1.0)],
        mutation_score=None,
    )
    pr_calls = {}

    def fake_scan():
        return [ex]

    def fake_generate(exploit):
        return GeneratedTest(
            framework="pytest",
            filename="test_security_x.py",
            source="# test\n",
            exploit=exploit,
        )

    def fake_validate(test):
        return report

    def fake_open_pr(*, out_dir, exploit, report, body, open_pr):
        pr_calls.update(out_dir=out_dir, body=body, open_pr=open_pr)
        return "printed"

    result = run_gate(
        out_dir=tmp_path / ".mylonite" / "gate",
        scan_fn=fake_scan,
        generate_fn=fake_generate,
        validate_fn=fake_validate,
        open_pr_fn=fake_open_pr,
        open_pr=False,
    )
    assert isinstance(result, GateResult)
    assert result.exit_code == 0
    assert (tmp_path / ".mylonite" / "gate" / "test_security_x.py").exists()
    assert "Suggested mitigation" in pr_calls["body"]
    assert pr_calls["open_pr"] is False


def test_run_gate_no_exploit_exits_zero_no_pr(tmp_path):
    result = run_gate(
        out_dir=tmp_path / ".mylonite" / "gate",
        scan_fn=lambda: [],
        generate_fn=lambda e: None,
        validate_fn=lambda t: None,
        open_pr_fn=lambda **k: None,
        open_pr=False,
    )
    assert result.exit_code == 0
    assert result.opened_pr is False


def test_run_gate_rejected_test_exits_5_no_pr(tmp_path):
    ex = _exploit()
    rejected = ValidationReport(test_filename="t.py", kept=False, outcomes=[], mutation_score=None)
    called = {"pr": False}
    result = run_gate(
        out_dir=tmp_path / ".mylonite" / "gate",
        scan_fn=lambda: [ex],
        generate_fn=lambda e: GeneratedTest(
            framework="pytest", filename="t.py", source="x", exploit=e
        ),
        validate_fn=lambda t: rejected,
        open_pr_fn=lambda **k: called.__setitem__("pr", True),
        open_pr=False,
    )
    assert result.exit_code == 5
    assert called["pr"] is False
