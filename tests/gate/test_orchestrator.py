from mylonite.contracts._types import (
    AdapterResponse,
    ComplianceTags,
    ExploitRecord,
    GeneratedTest,
    Payload,
    ValidationOutcome,
    ValidationReport,
)
from mylonite.gate.orchestrator import GateResult, ScanOutcomeBundle, run_gate
from mylonite.scan.coverage import AbortReason, Coverage, ScanOutcome


def _trustworthy_clean_outcome() -> ScanOutcome:
    """A genuine, meaningful clean scan: ran to completion, nothing found."""
    return ScanOutcome(
        coverage=Coverage.EXERCISED,
        abort=None,
        exercised=3,
        not_tested=0,
        findings=0,
        fallbacks=0,
        exit_code=0,
        operator_message=None,
    )


def _found_outcome(findings: int = 1) -> ScanOutcome:
    """A scan that ran and found something — not "clean" by definition, but a
    trusted result (exploits are real evidence regardless of overall coverage)."""
    return ScanOutcome(
        coverage=Coverage.EXERCISED,
        abort=None,
        exercised=3,
        not_tested=0,
        findings=findings,
        fallbacks=0,
        exit_code=0,
        operator_message=None,
    )


def _aborted_provider_unreachable_outcome() -> ScanOutcome:
    """The scan never meaningfully ran: provider was unreachable. This is the
    fail-open bug's exact shape — empty exploits, but NOT a trustworthy clean
    result — exit_code must be 4 (mirrors cli.py's EXIT_PROVIDER), not 0."""
    return ScanOutcome(
        coverage=Coverage.NOT_EXERCISED,
        abort=AbortReason.PROVIDER_UNREACHABLE,
        exercised=0,
        not_tested=0,
        findings=0,
        fallbacks=0,
        exit_code=4,
        operator_message=None,
    )


def _all_errored_no_formal_abort_outcome() -> ScanOutcome:
    """Built via the REAL ScanOutcome.from_report, not hand-rolled: the
    reviewer-confirmed variant of the fail-open bug where every attempt
    errored (e.g. missing/invalid provider credentials) but the engine never
    tripped the consecutive-failures threshold that sets `aborted` — a target
    with fewer than DEFAULT_PROVIDER_FAILURE_THRESHOLD (3) applicable attempts
    can hit this. `aborted` stays None, so this exercises coverage.py's fix
    (not the abort-mapping path already covered above)."""
    from mylonite.contracts._types import ScanAttempt, ScanReport

    report = ScanReport(
        target_id="t",
        provider="p",
        model="m",
        elapsed_seconds=1.0,
        attempts=[
            ScanAttempt(
                seed_id="s1",
                pattern_id="s1",
                outcome="error",
                verdict_mechanism=None,
                verdict_reason=None,
            ),
            ScanAttempt(
                seed_id="s2",
                pattern_id="s2",
                outcome="error",
                verdict_mechanism=None,
                verdict_reason=None,
            ),
        ],
        findings_count=0,
        aborted=None,
        mylonite_version="0.0.0",
    )
    return ScanOutcome.from_report(report)


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
        return ScanOutcomeBundle(outcome=_found_outcome(), exploits=[ex])

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
    assert (
        tmp_path / ".mylonite" / "gate" / "exploit_indirect-injection-note-body-direct.json"
    ).exists()
    assert "Suggested mitigation" in pr_calls["body"]
    assert pr_calls["open_pr"] is False


def test_run_gate_threads_a_real_configurable_mitigation_model(tmp_path):
    """T14: gate/mitigation.py used to hardcode
    ``litellm.completion(model="claude-haiku-4-5-20251001", ...)`` with no
    model parameter reachable from the caller at all. ``run_gate`` now takes
    ``mitigation_model``/``mitigation_completion_fn`` and threads both into
    ``build_pr_body`` — proving the enrichment call is a real, configurable,
    injectable LiteLLM call (reachable by an offline recorder/cache) instead
    of an unpindownable literal."""
    ex = _exploit()
    report = ValidationReport(
        test_filename="test_security_x.py",
        kept=True,
        outcomes=[ValidationOutcome(stage="stability", passed=True, detail="1/1", metric=1.0)],
        mutation_score=None,
    )
    seen_models: list[str] = []

    def fake_completion(*, model, messages, **kwargs):
        seen_models.append(model)

        class _Msg:
            content = "Wrap it in an untrusted envelope."

        class _Choice:
            message: _Msg = _Msg()  # type: ignore[misc]

        class _Resp:
            def __init__(self) -> None:
                self.choices = [_Choice()]

        return _Resp()

    pr_calls = {}

    result = run_gate(
        out_dir=tmp_path / ".mylonite" / "gate",
        scan_fn=lambda: ScanOutcomeBundle(outcome=_found_outcome(), exploits=[ex]),
        generate_fn=lambda exploit: GeneratedTest(
            framework="pytest",
            filename="test_security_x.py",
            source="# test\n",
            exploit=exploit,
        ),
        validate_fn=lambda test: report,
        open_pr_fn=lambda **k: pr_calls.update(k) or "printed",
        open_pr=False,
        llm_enrich=True,
        mitigation_model="my-custom/enrichment-model",
        mitigation_completion_fn=fake_completion,
    )
    assert result.exit_code == 0
    assert seen_models == ["my-custom/enrichment-model"]
    assert "Unverified LLM suggestion" in pr_calls["body"]
    assert "untrusted envelope" in pr_calls["body"]


def test_run_gate_no_exploit_exits_zero_no_pr(tmp_path):
    result = run_gate(
        out_dir=tmp_path / ".mylonite" / "gate",
        scan_fn=lambda: ScanOutcomeBundle(outcome=_trustworthy_clean_outcome(), exploits=[]),
        generate_fn=lambda e: None,
        validate_fn=lambda t: None,
        open_pr_fn=lambda **k: None,
        open_pr=False,
    )
    assert result.exit_code == 0
    assert result.opened_pr is False
    assert result.kept is None


def test_gate_exits_nonzero_when_scan_aborted(tmp_path):
    """The fail-open regression test (T2): when the scan never meaningfully
    ran — e.g. provider_unreachable, exactly what happens with no API key set
    — an empty exploits list must NOT be treated as a genuine clean pass.
    Before this fix, ``run_gate`` took a bare ``list[ExploitRecord]`` and
    could not tell "aborted" apart from "ran clean"; both produced [] and
    exited 0. This must now exit non-zero, matching ``ScanOutcome.exit_code``
    (4 == EXIT_PROVIDER, mirroring `scan reference:vulnerable`'s own exit code
    under the same condition)."""
    generate_called = {"called": False}
    validate_called = {"called": False}
    pr_called = {"called": False}
    outcome = _aborted_provider_unreachable_outcome()

    result = run_gate(
        out_dir=tmp_path / ".mylonite" / "gate",
        scan_fn=lambda: ScanOutcomeBundle(outcome=outcome, exploits=[]),
        generate_fn=lambda e: generate_called.__setitem__("called", True),
        validate_fn=lambda t: validate_called.__setitem__("called", True),
        open_pr_fn=lambda **k: pr_called.__setitem__("called", True),
        open_pr=False,
    )
    assert result.exit_code == outcome.exit_code
    assert result.exit_code == 4
    assert result.exit_code != 0
    assert result.opened_pr is False
    assert result.kept is None
    # The generate/validate/PR legs must never run for an untrustworthy scan —
    # there is nothing real to gate on.
    assert generate_called["called"] is False
    assert validate_called["called"] is False
    assert pr_called["called"] is False


def test_gate_exits_nonzero_when_every_attempt_errored_without_formal_abort(tmp_path):
    """End-to-end proof (via run_gate, not just coverage.py in isolation) that
    the reviewer-confirmed second fail-open shape is now closed: every attempt
    errored, findings_count is 0, but the engine never tripped the
    consecutive-failures threshold that sets ScanReport.aborted — so
    ScanOutcome.abort is None. Before the coverage.py fix, ScanOutcome.exit_code
    fell through to EXIT_SUCCESS here (abort is None) even though
    trustworthy_clean was correctly False, so run_gate would print its
    untrustworthy-scan message and STILL exit 0."""
    generate_called = {"called": False}
    outcome = _all_errored_no_formal_abort_outcome()
    assert outcome.abort is None  # confirms this is the no-formal-abort shape
    assert outcome.trustworthy_clean is False

    result = run_gate(
        out_dir=tmp_path / ".mylonite" / "gate",
        scan_fn=lambda: ScanOutcomeBundle(outcome=outcome, exploits=[]),
        generate_fn=lambda e: generate_called.__setitem__("called", True),
        validate_fn=lambda t: None,
        open_pr_fn=lambda **k: None,
        open_pr=False,
    )
    assert result.exit_code == outcome.exit_code
    assert result.exit_code != 0
    assert result.opened_pr is False
    assert result.kept is None
    assert generate_called["called"] is False


def test_run_gate_returns_a_typed_result_when_generate_returns_none(tmp_path):
    """DCR-0002: `assert generated is not None` is stripped under python -O, so
    the next line raised a bare AttributeError instead of an exit code."""
    from mylonite.gate.orchestrator import EXIT_GENERATE_FAILED

    ex = _exploit()
    result = run_gate(
        out_dir=tmp_path / ".mylonite" / "gate",
        scan_fn=lambda: ScanOutcomeBundle(outcome=_found_outcome(), exploits=[ex]),
        generate_fn=lambda e: None,
        validate_fn=lambda t: None,
        open_pr_fn=lambda **k: None,
        open_pr=False,
    )
    assert result.exit_code == EXIT_GENERATE_FAILED
    assert result.opened_pr is False
    assert result.kept is None


def test_run_gate_returns_a_typed_result_when_validate_returns_none(tmp_path):
    """The other of the two orchestrator.py asserts: a validator that returns
    None (e.g. an offline collaborator wired wrong) must not crash with a bare
    AttributeError on ``report.kept`` — it must exit with a typed code."""
    from mylonite.gate.orchestrator import EXIT_VALIDATE_FAILED

    ex = _exploit()
    result = run_gate(
        out_dir=tmp_path / ".mylonite" / "gate",
        scan_fn=lambda: ScanOutcomeBundle(outcome=_found_outcome(), exploits=[ex]),
        generate_fn=lambda e: GeneratedTest(
            framework="pytest", filename="t.py", source="x", exploit=e
        ),
        validate_fn=lambda t: None,
        open_pr_fn=lambda **k: None,
        open_pr=False,
    )
    assert result.exit_code == EXIT_VALIDATE_FAILED
    assert result.opened_pr is False
    assert result.kept is None


def test_run_gate_opened_pr_flows_from_prresult(tmp_path):
    from mylonite.gate.pr import PrResult

    ex = _exploit()
    report = ValidationReport(
        test_filename="t.py",
        kept=True,
        outcomes=[ValidationOutcome(stage="stability", passed=True, detail="1/1", metric=1.0)],
        mutation_score=None,
    )

    def fake_open_pr(**k):
        return PrResult(branch="mylonite/gate-x", opened=True, pr_url="http://x/1")

    result = run_gate(
        out_dir=tmp_path / ".mylonite" / "gate",
        scan_fn=lambda: ScanOutcomeBundle(outcome=_found_outcome(), exploits=[ex]),
        generate_fn=lambda e: GeneratedTest(
            framework="pytest", filename="t.py", source="x", exploit=e
        ),
        validate_fn=lambda t: report,
        open_pr_fn=fake_open_pr,
        open_pr=True,
    )
    assert result.opened_pr is True
    assert result.branch == "mylonite/gate-x"


def test_run_gate_rejected_test_exits_5_no_pr(tmp_path):
    ex = _exploit()
    rejected = ValidationReport(test_filename="t.py", kept=False, outcomes=[], mutation_score=None)
    called = {"pr": False}
    result = run_gate(
        out_dir=tmp_path / ".mylonite" / "gate",
        scan_fn=lambda: ScanOutcomeBundle(outcome=_found_outcome(), exploits=[ex]),
        generate_fn=lambda e: GeneratedTest(
            framework="pytest", filename="t.py", source="x", exploit=e
        ),
        validate_fn=lambda t: rejected,
        open_pr_fn=lambda **k: called.__setitem__("pr", True),
        open_pr=False,
    )
    assert result.exit_code == 5
    assert called["pr"] is False
