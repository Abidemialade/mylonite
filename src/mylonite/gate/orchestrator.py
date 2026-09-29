"""Gate orchestration: sequence scan -> generate -> validate -> assemble -> PR.

Owns the SEQUENCE and the exit-code decision only. Collaborators are injected so
the Typer command supplies live ones and tests supply offline fakes.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mylonite._cli_io import echo
from mylonite.contracts import ExploitRecord, GeneratedTest, ValidationReport
from mylonite.exit_codes import (
    EXIT_GENERATE_FAILED,
    EXIT_NOT_KEPT,
    EXIT_SUCCESS,
    EXIT_VALIDATE_FAILED,
)
from mylonite.gate.mitigation import DEFAULT_MITIGATION_MODEL, build_gate_pr_body
from mylonite.generate.wiring import _slugify_pattern
from mylonite.scan.coverage import ScanOutcome
from mylonite.scan.llm_types import CompletionFn


@dataclass
class GateResult:
    exit_code: int
    opened_pr: bool = False
    branch: str | None = None
    kept: bool | None = None
    #: How many of the run's findings were kept / rejected (0/0 when the run
    #: never reached a per-finding verdict at all, e.g. an aborted scan).
    kept_count: int = 0
    rejected_count: int = 0


@dataclass(frozen=True)
class _FindingOutcome:
    """One exploit's path through generate -> write -> validate.

    ``stage`` distinguishes WHY a finding did not end up kept, which is what
    lets #202's all-fail exit-code rule (EXIT_GENERATE_FAILED / EXIT_VALIDATE_FAILED
    only when EVERY finding failed at that stage; EXIT_NOT_KEPT the moment a real
    differential verdict — kept or not — was reached for any finding) survive
    going from one exploit to N without re-deriving it from string matching.
    """

    exploit: ExploitRecord
    stage: str  # "kept" | "rejected" | "generate_failed" | "validate_failed"
    report: ValidationReport | None = None
    reason: str = ""


def _write_validation_report(out_dir: Path, report: ValidationReport) -> None:
    """Persist the oracle verdict to ``out_dir``, redacted for commit.

    Mirrors what ``validate`` writes so the two commands leave the same artefact
    on disk. ``outcome.detail`` and ``notes`` are free text that can carry a live
    exception message (DCR-0003) and this file gets committed to a branch, so the
    same sanitisation applies here.
    """
    from mylonite._redaction import redact

    sanitized = report.model_copy(
        update={
            "outcomes": [
                outcome.model_copy(update={"detail": redact(outcome.detail)})
                for outcome in report.outcomes
            ],
            "notes": redact(report.notes) if report.notes else report.notes,
        }
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "validation_report.json").write_text(
        sanitized.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )


@dataclass(frozen=True)
class ScanOutcomeBundle:
    """What ``scan_fn`` hands ``run_gate``: the typed verdict AND the exploits.

    Replaces a bare ``list[ExploitRecord]`` seam (the A-series false-clean bug:
    a scan that never actually ran — e.g. ``provider_unreachable`` — and a
    scan that ran cleanly both produced an empty list, and ``run_gate``
    couldn't tell them apart). Carrying ``outcome`` alongside the exploits
    makes that distinction structurally reachable at the call site.
    """

    outcome: ScanOutcome
    exploits: list[ExploitRecord]


def _process_one_finding(
    exploit: ExploitRecord,
    this_out: Path,
    *,
    generate_fn: Callable[[ExploitRecord], GeneratedTest | None],
    validate_fn: Callable[[GeneratedTest], ValidationReport | None],
    multi: bool,
) -> _FindingOutcome:
    """Generate, write, and validate ONE finding. Never raises for a per-finding
    failure (generate/validate returning ``None``) — that is recorded as a
    ``_FindingOutcome`` so one bad finding cannot hide the rest (#202)."""
    prefix = f"Mylonite gate: {exploit.pattern_id}: " if multi else "Mylonite gate: "

    generated = generate_fn(exploit)
    if generated is None:
        reason = "the test generator returned nothing"
        echo(f"{prefix}{reason} — skipping." if multi else f"{prefix}{reason} — cannot gate.")
        return _FindingOutcome(exploit=exploit, stage="generate_failed", reason=reason)

    this_out.mkdir(parents=True, exist_ok=True)
    test_path = this_out / generated.filename
    test_path.write_text(generated.source, encoding="utf-8")
    (this_out / f"exploit_{exploit.pattern_id}.json").write_text(
        json.dumps(exploit.model_dump(mode="json"), indent=2, sort_keys=True),
        encoding="utf-8",
    )

    report = validate_fn(generated)
    if report is None:
        reason = "the validator returned nothing"
        echo(f"{prefix}{reason} — skipping." if multi else f"{prefix}{reason} — cannot gate.")
        return _FindingOutcome(exploit=exploit, stage="validate_failed", reason=reason)

    if not report.kept:
        reason = "the generated test was REJECTED (not kept)"
        echo(f"{prefix}{reason}." if multi else f"{prefix}{reason} — no PR opened.")
        return _FindingOutcome(exploit=exploit, stage="rejected", report=report, reason=reason)

    # Persist the oracle verdict BEFORE any git contact. The generated test and
    # the exploit JSON were already on disk above, but the validation report --
    # the most expensive artefact of the run -- was only ever written by
    # `validate`, so a failure in the git/gh step threw it away.
    _write_validation_report(this_out, report)
    return _FindingOutcome(exploit=exploit, stage="kept", report=report)


def run_gate(
    *,
    out_dir: Path,
    scan_fn: Callable[[], ScanOutcomeBundle],
    generate_fn: Callable[[ExploitRecord], GeneratedTest | None],
    validate_fn: Callable[[GeneratedTest], ValidationReport | None],
    open_pr_fn: Callable[..., Any],
    open_pr: bool,
    llm_enrich: bool = False,
    mitigation_model: str = DEFAULT_MITIGATION_MODEL,
    mitigation_completion_fn: CompletionFn | None = None,
    system_prompt: str | None = None,
    target_context: Any | None = None,
) -> GateResult:
    bundle = scan_fn()
    exploits = bundle.exploits
    if not exploits:
        # An empty exploits list is ambiguous on its own: it means either "the
        # scan genuinely ran and found nothing" or "the scan never meaningfully
        # ran" (aborted, e.g. provider_unreachable, or every attempt errored
        # out without an explicit abort). ``trustworthy_clean`` is what
        # disambiguates the two — a real finding (exploits non-empty) is
        # trusted regardless of overall coverage, matching pre-existing
        # behaviour where a partial/aborted scan that still found something
        # before stopping is gated on that finding.
        if not bundle.outcome.trustworthy_clean:
            message = bundle.outcome.operator_message or (
                "Mylonite gate: the scan did not complete a trustworthy run "
                f"(coverage={bundle.outcome.coverage.name}, abort={bundle.outcome.abort}) — "
                "cannot gate."
            )
            echo(message)
            return GateResult(exit_code=bundle.outcome.exit_code, opened_pr=False, kept=None)
        echo("Mylonite gate: no exploit found — nothing to gate.")
        return GateResult(exit_code=EXIT_SUCCESS, opened_pr=False, kept=None)

    # Deterministic order (#202): every finding is gated, in the same order
    # every run, regardless of what order the scan happened to discover them.
    sorted_exploits = sorted(exploits, key=lambda e: e.pattern_id)
    multi = len(sorted_exploits) > 1
    if multi:
        n = len(sorted_exploits)
        echo(f"{n} findings: validating each (about {n}x the single-finding validation cost)")

    outcomes: list[_FindingOutcome] = []
    for exploit in sorted_exploits:
        # With multiple findings, give each its own subdir so tests don't
        # clobber each other; a single finding keeps the exact dir the
        # operator chose — mirrors `generate`'s identical convention
        # (generate/wiring.py's _resolve_exploit_paths + cli.py's `generate`).
        this_out = out_dir / _slugify_pattern(exploit.pattern_id) if multi else out_dir
        outcomes.append(
            _process_one_finding(
                exploit, this_out, generate_fn=generate_fn, validate_fn=validate_fn, multi=multi
            )
        )

    kept = [(o.exploit, o.report) for o in outcomes if o.stage == "kept" and o.report is not None]
    rejected = [(o.exploit, o.reason) for o in outcomes if o.stage != "kept"]

    if multi:
        echo(f"{len(kept)} kept, {len(rejected)} rejected")

    def _finish(result: GateResult) -> GateResult:
        # #206: an aborted scan (budget exhausted or any other abort) always
        # carries the scan's own exit code and operator message, even when
        # proven findings were gated and a PR was opened/printed for them —
        # mirroring ScanOutcome.from_report's own "abort always wins" rule so
        # `gate` cannot silently exit 0 on a budget-exhausted run just because
        # it found something before the budget ran out.
        if bundle.outcome.abort is not None:
            if bundle.outcome.operator_message:
                echo(bundle.outcome.operator_message)
            result.exit_code = bundle.outcome.exit_code
        return result

    if not kept:
        stages = {o.stage for o in outcomes}
        if stages <= {"generate_failed"}:
            return _finish(
                GateResult(
                    exit_code=EXIT_GENERATE_FAILED,
                    opened_pr=False,
                    kept=None,
                    rejected_count=len(rejected),
                )
            )
        if stages <= {"generate_failed", "validate_failed"}:
            return _finish(
                GateResult(
                    exit_code=EXIT_VALIDATE_FAILED,
                    opened_pr=False,
                    kept=None,
                    rejected_count=len(rejected),
                )
            )
        if not multi:
            echo("Mylonite gate: the generated test was REJECTED (not kept) — no PR opened.")
        else:
            echo("Mylonite gate: no generated test was kept — no PR opened.")
        return _finish(
            GateResult(
                exit_code=EXIT_NOT_KEPT, opened_pr=False, kept=False, rejected_count=len(rejected)
            )
        )

    # #202: build_pr_body stays per-finding (mitigation.py); build_gate_pr_body
    # is the thin wrapper that joins the kept findings' sections and lists the
    # rejected ones with their reason.
    body = build_gate_pr_body(
        kept,
        rejected,
        llm_enrich=llm_enrich,
        model=mitigation_model,
        completion_fn=mitigation_completion_fn,
        system_prompt=system_prompt,
        target=target_context,
    )
    pr = open_pr_fn(out_dir=out_dir, findings=kept, body=body, open_pr=open_pr)
    opened = bool(getattr(pr, "opened", False))
    branch = getattr(pr, "branch", None)
    return _finish(
        GateResult(
            exit_code=EXIT_SUCCESS,
            opened_pr=opened,
            branch=branch,
            kept=True,
            kept_count=len(kept),
            rejected_count=len(rejected),
        )
    )
