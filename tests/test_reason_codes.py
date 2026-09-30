"""The reason-code registry: every result that is not a verdict carries a stable,
documented code with a fix.

These tests pin three things:

- coverage: every NOT_TESTED outcome, cause bucket, abort reason and pre-flight
  refusal maps to a registered code, and the operator text carries it;
- shape: every code is well formed, unique, and has a non-empty fix and anchor;
- stability: ``tests/fixtures/reason_codes.snapshot.json`` freezes each shipped
  code's category and summary, so a code can never quietly change meaning.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import typer

from mylonite import reason_codes
from mylonite.contracts import AbortReason, TargetDescriptor, ToolSpec
from mylonite.contracts._types import ScanAttempt, ScanAttemptOutcome, ScanReport
from mylonite.reason_codes import REGISTRY, ReasonCode
from mylonite.scan import coverage
from mylonite.scan.coverage import ATTEMPT_CLASS, NO_ADJUDICATOR, AttemptClass, ScanOutcome

_SNAPSHOT = Path(__file__).parent / "fixtures" / "reason_codes.snapshot.json"
_CODE_RE = re.compile(r"^MYL-(NT|ABT|PRE|INC|SRV)-\d{3}$")


def _attempt(
    outcome: ScanAttemptOutcome,
    *,
    seed_id: str = "s1",
    judge_evidence: dict[str, str] | None = None,
    error_detail: str | None = None,
) -> ScanAttempt:
    return ScanAttempt(
        seed_id=seed_id,
        pattern_id=seed_id,
        outcome=outcome,
        verdict_mechanism=None,
        verdict_reason=None,
        judge_evidence=judge_evidence or {},
        error_detail=error_detail,
    )


def _report(*, attempts: list[ScanAttempt], aborted: str | None = None) -> ScanReport:
    return ScanReport(
        target_id="t",
        provider="p",
        model="m",
        elapsed_seconds=1.0,
        attempts=attempts,
        findings_count=0,
        aborted=aborted,
        mylonite_version="0.0.0",
    )


# --- shape ------------------------------------------------------------------


def test_codes_are_well_formed_and_unique() -> None:
    codes = [rc.code for rc in REGISTRY.values()]
    assert len(codes) == len(set(codes))
    for key, rc in REGISTRY.items():
        assert key == rc.code
        assert _CODE_RE.match(rc.code), rc.code


def test_each_code_prefix_matches_its_category() -> None:
    for rc in REGISTRY.values():
        prefix = rc.code.split("-")[1]
        assert reason_codes.CATEGORY_BY_PREFIX[prefix] == rc.category, rc.code


def test_every_code_has_a_summary_fix_and_anchor() -> None:
    for rc in REGISTRY.values():
        assert rc.summary.strip(), rc.code
        assert rc.fix.strip(), rc.code
        assert rc.anchor == f"reason-codes.md#{rc.code.lower()}", rc.code


def test_reason_code_is_frozen() -> None:
    rc = next(iter(REGISTRY.values()))
    with pytest.raises(AttributeError):
        rc.fix = "changed"  # type: ignore[misc]


def test_lookup_helpers() -> None:
    rc = reason_codes.get("MYL-NT-001")
    assert isinstance(rc, ReasonCode)
    with pytest.raises(KeyError, match="MYL-NT-999"):
        reason_codes.get("MYL-NT-999")


def test_tag_leads_with_the_code_after_the_level_prefix() -> None:
    assert reason_codes.tag("MYL-ABT-001", "error: boom") == "error: [MYL-ABT-001] boom"
    assert reason_codes.tag("MYL-PRE-002", "warning: slow") == "warning: [MYL-PRE-002] slow"
    assert reason_codes.tag("MYL-NT-001", "plain") == "[MYL-NT-001] plain"
    # Idempotent: an already-coded message is left alone.
    once = reason_codes.tag("MYL-ABT-004", "error: x")
    assert reason_codes.tag("MYL-ABT-003", once) == once


def test_tag_refuses_an_unregistered_code() -> None:
    with pytest.raises(KeyError):
        reason_codes.tag("MYL-NT-999", "error: x")


def test_format_code_counts() -> None:
    text = reason_codes.format_code_counts(["MYL-NT-005", "MYL-NT-005", "MYL-NT-001"])
    assert text == "MYL-NT-001 x1, MYL-NT-005 x2"


# --- stability --------------------------------------------------------------


def test_registry_matches_the_frozen_snapshot() -> None:
    """A shipped code never changes meaning. Removing a code, or changing its
    category or summary, fails here. Adding a code means adding it to the
    snapshot in the same change."""
    snapshot = json.loads(_SNAPSHOT.read_text(encoding="utf-8"))
    current = {
        rc.code: {"category": rc.category, "summary": rc.summary} for rc in REGISTRY.values()
    }
    removed = sorted(set(snapshot) - set(current))
    assert not removed, f"shipped reason codes were removed: {removed}"
    changed = sorted(c for c in snapshot if snapshot[c] != current[c])
    assert not changed, f"shipped reason codes changed meaning: {changed}"
    added = sorted(set(current) - set(snapshot))
    assert not added, f"new reason codes must be added to {_SNAPSHOT.name}: {added}"


# --- coverage: NOT_TESTED outcomes and cause buckets --------------------------


def _one_attempt_per_bucket() -> list[ScanAttempt]:
    """One attempt for every NOT_TESTED outcome, plus the evidence splits."""
    attempts = [
        _attempt(outcome)  # type: ignore[arg-type]
        for outcome, cls in ATTEMPT_CLASS.items()
        if cls is AttemptClass.NOT_TESTED
    ]
    attempts += [
        _attempt("error", error_detail="AuthenticationError"),
        _attempt("error", error_detail="RuntimeError"),
        _attempt("undecided", judge_evidence={"fallback_cause": "call_raised"}),
        _attempt("undecided", judge_evidence={"fallback_cause": "unparseable_output"}),
        _attempt("undecided", judge_evidence={"fallback_cause": "effect_probe_errored"}),
        _attempt("undecided", judge_evidence={"no_adjudicator": NO_ADJUDICATOR}),
    ]
    return attempts


def test_every_not_tested_attempt_maps_to_a_registered_code() -> None:
    for attempt in _one_attempt_per_bucket():
        code = coverage.reason_code_for_attempt(attempt)
        assert code is not None, attempt.outcome
        assert code in REGISTRY
        assert REGISTRY[code].category == reason_codes.CATEGORY_NOT_TESTED


def test_every_cause_bucket_has_a_code_and_a_remedy() -> None:
    buckets = {coverage._not_tested_cause_bucket(a) for a in _one_attempt_per_bucket()}
    assert None not in buckets
    assert buckets == set(reason_codes.NT_CODE_BY_BUCKET)
    assert set(coverage._BUCKET_REMEDY) == buckets


def test_bucket_remedy_reads_its_fix_from_the_registry() -> None:
    for bucket, code in reason_codes.NT_CODE_BY_BUCKET.items():
        assert coverage._BUCKET_REMEDY[bucket].endswith(REGISTRY[code].fix), bucket


def test_the_undecided_split_gets_distinct_codes() -> None:
    evidences: list[dict[str, str]] = [
        {"fallback_cause": "call_raised"},
        {"fallback_cause": "unparseable_output"},
        {"fallback_cause": "effect_probe_errored"},
        {"no_adjudicator": NO_ADJUDICATOR},
        {},
    ]
    codes = {
        coverage.reason_code_for_attempt(_attempt("undecided", judge_evidence=e)) for e in evidences
    }
    assert len(codes) == len(evidences)


def test_exercised_attempts_have_no_code() -> None:
    assert coverage.reason_code_for_attempt(_attempt("finding")) is None
    assert coverage.reason_code_for_attempt(_attempt("no_finding")) is None
    assert coverage.reason_code_for_attempt(_attempt("skipped_dry_run")) is None


def test_incomplete_coverage_message_leads_with_the_dominant_code() -> None:
    report = _report(
        attempts=[_attempt("skipped_no_seed_arm"), _attempt("skipped_no_seed_arm", seed_id="s2")]
    )
    outcome = ScanOutcome.from_report(report)
    code = reason_codes.NT_CODE_BY_BUCKET["skipped_no_seed_arm"]
    assert outcome.operator_message is not None
    assert outcome.operator_message.startswith(f"error: [{code}] ")
    assert "This is NOT a clean result" in outcome.operator_message


def test_incomplete_coverage_message_without_a_dominant_cause_names_every_code() -> None:
    report = _report(
        attempts=[_attempt("skipped_no_seed_arm"), _attempt("launch_failure", seed_id="s2")]
    )
    outcome = ScanOutcome.from_report(report)
    assert outcome.operator_message is not None
    for bucket in ("skipped_no_seed_arm", "launch_failure"):
        assert reason_codes.NT_CODE_BY_BUCKET[bucket] in outcome.operator_message


# --- coverage: abort reasons -----------------------------------------------


@pytest.mark.parametrize("reason", list(AbortReason))
def test_every_abort_reason_maps_to_a_code_with_an_operator_message(reason: AbortReason) -> None:
    code = reason_codes.ABT_CODE_BY_ABORT[reason.value]
    assert REGISTRY[code].category == reason_codes.CATEGORY_ABORT
    outcome = ScanOutcome.from_report(_report(attempts=[], aborted=reason.value))
    assert outcome.operator_message is not None, reason
    assert outcome.operator_message.startswith(f"error: [{code}] "), outcome.operator_message


@pytest.mark.parametrize("reason", list(AbortReason))
def test_abort_messages_carry_the_registered_fix(reason: AbortReason) -> None:
    code = reason_codes.ABT_CODE_BY_ABORT[reason.value]
    message = coverage._OPERATOR_MESSAGE_BY_ABORT[reason]
    assert message is not None
    assert REGISTRY[code].fix in message


def test_provider_unreachable_now_says_what_to_do() -> None:
    outcome = ScanOutcome.from_report(
        _report(attempts=[], aborted=AbortReason.PROVIDER_UNREACHABLE.value)
    )
    assert outcome.operator_message is not None
    assert "credentials" in outcome.operator_message
    assert "--model" in outcome.operator_message


def test_an_abort_detail_is_tagged_with_the_abort_code() -> None:
    outcome = ScanOutcome.from_report(
        _report(attempts=[], aborted=AbortReason.DESCRIBE_FAILED.value),
        abort_detail="error: could not reach host example.com (HTTP 401). Check the token.",
    )
    code = reason_codes.ABT_CODE_BY_ABORT[AbortReason.DESCRIBE_FAILED.value]
    assert outcome.operator_message is not None
    assert outcome.operator_message.startswith(f"error: [{code}] could not reach host")


def test_an_abort_detail_that_already_carries_a_code_keeps_it() -> None:
    outcome = ScanOutcome.from_report(
        _report(attempts=[], aborted=AbortReason.NO_PAYLOADS.value),
        abort_detail=f"error: [{reason_codes.ABT_NO_PAYLOADS_FILTER}] filter matched nothing",
    )
    assert outcome.operator_message is not None
    assert reason_codes.ABT_NO_PAYLOADS_FILTER in outcome.operator_message
    assert reason_codes.ABT_CODE_BY_ABORT["no_payloads"] not in outcome.operator_message


def test_each_no_payloads_cause_has_its_own_code() -> None:
    from mylonite.scan.engine import _unseeded_abort_detail, _weakness_filter_abort_detail

    unseeded = _unseeded_abort_detail({"W3": "no fetch tool"})
    filtered = _weakness_filter_abort_detail(["W9"], "acme")
    generic = coverage._OPERATOR_MESSAGE_BY_ABORT[AbortReason.NO_PAYLOADS]
    assert unseeded.startswith(f"error: [{reason_codes.ABT_NO_PAYLOADS_UNSEEDED}] ")
    assert filtered.startswith(f"error: [{reason_codes.ABT_NO_PAYLOADS_FILTER}] ")
    assert "matched no seeds" in filtered
    assert generic is not None
    codes = {
        reason_codes.ABT_NO_PAYLOADS_UNSEEDED,
        reason_codes.ABT_NO_PAYLOADS_FILTER,
        reason_codes.ABT_CODE_BY_ABORT["no_payloads"],
    }
    assert len(codes) == 3


# --- coverage: pre-flight refusals -------------------------------------------


class _FakeAdapter:
    def __init__(self, descriptor: TargetDescriptor) -> None:
        self._descriptor = descriptor

    async def describe(self) -> TargetDescriptor:
        return self._descriptor


class _FailingAdapter:
    async def describe(self) -> TargetDescriptor:
        raise RuntimeError("boom")


class _SlowAdapter:
    async def describe(self) -> TargetDescriptor:
        import asyncio

        await asyncio.sleep(5)
        raise AssertionError("unreachable")


def _refuse(adapter: Any, **kw: Any) -> None:
    from mylonite.plugins.cli_targets import refuse_uncoverable_weakness_classes

    tf = SimpleNamespace(weakness_classes=["W3"])
    with pytest.raises(typer.Exit):
        refuse_uncoverable_weakness_classes(tf, adapter, **kw)


def test_uncoverable_class_refusal_carries_its_code(capsys: pytest.CaptureFixture[str]) -> None:
    adapter = _FakeAdapter(
        TargetDescriptor(
            target_id="mcp:acme",
            kind="mcp",
            weakness_classes=["W3"],
            tools=[ToolSpec(name="x", description="d")],
        )
    )
    _refuse(adapter)
    err = capsys.readouterr().err
    assert f"error: [{reason_codes.PRE_UNCOVERABLE_CLASS}] " in err


def test_describe_failure_refusal_carries_its_code(capsys: pytest.CaptureFixture[str]) -> None:
    _refuse(_FailingAdapter())
    err = capsys.readouterr().err
    assert f"error: [{reason_codes.PRE_DESCRIBE_FAILED}] " in err
    assert REGISTRY[reason_codes.PRE_DESCRIBE_FAILED].fix in err


def test_describe_timeout_refusal_carries_its_code(capsys: pytest.CaptureFixture[str]) -> None:
    _refuse(_SlowAdapter(), timeout_s=0.05)
    err = capsys.readouterr().err
    assert f"error: [{reason_codes.PRE_DESCRIBE_TIMEOUT}] " in err
    assert REGISTRY[reason_codes.PRE_DESCRIBE_TIMEOUT].fix in err


def test_autowire_timeout_carries_its_code(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from mylonite.plugins import cli_targets

    monkeypatch.setattr(cli_targets, "_build_adapter_for_custom", lambda *a, **k: _SlowAdapter())
    with pytest.raises(typer.Exit):
        cli_targets.autowire_seed_arm(SimpleNamespace(), None, "m", budget_s=0.05)
    err = capsys.readouterr().err
    assert f"auto-wire: [{reason_codes.PRE_AUTOWIRE_TIMEOUT}] " in err
    assert REGISTRY[reason_codes.PRE_AUTOWIRE_TIMEOUT].fix in err


def test_autowire_describe_failure_carries_its_code(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from mylonite.plugins import cli_targets
    from mylonite.scan._types import AdapterDescribeFailed

    class _DescribeFails:
        async def describe(self) -> TargetDescriptor:
            raise AdapterDescribeFailed("server exited before listing its tools")

    monkeypatch.setattr(cli_targets, "_build_adapter_for_custom", lambda *a, **k: _DescribeFails())
    with pytest.raises(typer.Exit):
        cli_targets.autowire_seed_arm(SimpleNamespace(), None, "m", budget_s=5)
    err = capsys.readouterr().err
    assert f"auto-wire: [{reason_codes.PRE_AUTOWIRE_DESCRIBE_FAILED}] server exited" in err


def test_every_preflight_code_is_used_by_a_refusal() -> None:
    pre = {c for c, rc in REGISTRY.items() if rc.category == reason_codes.CATEGORY_PREFLIGHT}
    assert pre == {
        reason_codes.PRE_UNCOVERABLE_CLASS,
        reason_codes.PRE_DESCRIBE_TIMEOUT,
        reason_codes.PRE_DESCRIBE_FAILED,
        reason_codes.PRE_AUTOWIRE_TIMEOUT,
        reason_codes.PRE_AUTOWIRE_DESCRIBE_FAILED,
    }


# --- codes reserved for the effect-confirmation path ---------------------------


def test_inconclusive_and_server_reported_codes_are_defined() -> None:
    inc = sorted(
        c for c, rc in REGISTRY.items() if rc.category == reason_codes.CATEGORY_INCONCLUSIVE
    )
    srv = sorted(
        c for c, rc in REGISTRY.items() if rc.category == reason_codes.CATEGORY_SERVER_REPORTED
    )
    assert inc == [f"MYL-INC-{n:03d}" for n in range(1, 9)]
    assert srv == ["MYL-SRV-001", "MYL-SRV-002"]


def test_payload_marker_fix_names_the_replacement() -> None:
    assert "{exfil_email}" in REGISTRY["MYL-INC-008"].fix


def test_calibration_not_authorized_fix_names_every_authorize_taking_command() -> None:
    """SECURITY.md lists scan/gate/ablate/validate plus `check --authorize` as
    the commands that take `--authorize`. The fix for an uncalibrated probe
    (MYL-INC-002) used to name only scan/gate/ablate, leaving `validate` out."""
    fix = REGISTRY["MYL-INC-002"].fix
    assert "scan/gate/ablate/validate" in fix
    assert "check --authorize" in fix


# --- summary lines ------------------------------------------------------------


def test_scan_summary_not_tested_line_includes_the_codes() -> None:
    from mylonite.scan.artefacts import render_summary
    from mylonite.scan.engine import ScanResult

    report = _report(
        attempts=[
            _attempt("skipped_no_seed_arm"),
            _attempt("skipped_no_seed_arm", seed_id="s2"),
            _attempt("launch_failure", seed_id="s3"),
        ]
    )
    summary = render_summary(ScanResult(report=report, exploits=[]), ascii_safe=True)
    arm = reason_codes.NT_CODE_BY_BUCKET["skipped_no_seed_arm"]
    launch = reason_codes.NT_CODE_BY_BUCKET["launch_failure"]
    flat = " ".join(summary.split())
    assert "3 attempt(s) were NOT TESTED" in flat
    assert f"{launch} x1, {arm} x2" in flat


def test_scan_summary_inconclusive_line_includes_the_codes() -> None:
    from mylonite.scan.artefacts import render_summary
    from mylonite.scan.engine import ScanResult

    report = ScanReport(
        target_id="t",
        provider="p",
        model="m",
        elapsed_seconds=1.0,
        attempts=[
            _attempt("undecided", judge_evidence={"fallback_cause": "effect_probe_errored"}),
        ],
        findings_count=0,
        inconclusive_attempts=1,
        fallback_breakdown={"judge_effect_probe_errored": 1},
        mylonite_version="0.0.0",
    )
    summary = render_summary(ScanResult(report=report, exploits=[]), ascii_safe=True)
    code = reason_codes.NT_CODE_BY_BUCKET["undecided_effect_probe_errored"]
    judge_line = next(line for line in summary.splitlines() if line.startswith("judge:"))
    assert code in judge_line


def test_gate_budget_abort_message_carries_the_budget_code() -> None:
    from mylonite.gate.orchestrator import _abort_message

    outcome = ScanOutcome.from_report(
        _report(attempts=[], aborted=AbortReason.BUDGET_EXCEEDED.value)
    )
    message = _abort_message(outcome, "Raise --max-llm-calls.")
    assert message.startswith(f"error: [{reason_codes.ABT_BUDGET_EXCEEDED}] gate's scan phase")
