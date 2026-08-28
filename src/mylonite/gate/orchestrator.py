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
from mylonite.gate.mitigation import DEFAULT_MITIGATION_MODEL, build_pr_body
from mylonite.scan.coverage import ScanOutcome
from mylonite.scan.llm_types import CompletionFn


@dataclass
class GateResult:
    exit_code: int
    opened_pr: bool = False
    branch: str | None = None
    kept: bool | None = None


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

    exploit = exploits[0]
    generated = generate_fn(exploit)
    if generated is None:
        echo("Mylonite gate: the test generator returned nothing — cannot gate.")
        return GateResult(exit_code=EXIT_GENERATE_FAILED, opened_pr=False, kept=None)

    out_dir.mkdir(parents=True, exist_ok=True)
    test_path = out_dir / generated.filename
    test_path.write_text(generated.source, encoding="utf-8")
    (out_dir / f"exploit_{exploit.pattern_id}.json").write_text(
        json.dumps(exploit.model_dump(mode="json"), indent=2, sort_keys=True),
        encoding="utf-8",
    )

    report = validate_fn(generated)
    if report is None:
        echo("Mylonite gate: the validator returned nothing — cannot gate.")
        return GateResult(exit_code=EXIT_VALIDATE_FAILED, opened_pr=False, kept=None)
    if not report.kept:
        echo("Mylonite gate: the generated test was REJECTED (not kept) — no PR opened.")
        return GateResult(exit_code=EXIT_NOT_KEPT, opened_pr=False, kept=False)

    # Persist the oracle verdict BEFORE any git contact. The generated test and
    # the exploit JSON were already on disk above, but the validation report --
    # the most expensive artefact of the run -- was only ever written by
    # `validate`, so a failure in the git/gh step threw it away. Redacted the
    # same way `validate` redacts it (DCR-0003): outcome.detail and notes can
    # carry a live exception message, and this file is committed to a branch.
    _write_validation_report(out_dir, report)

    body = build_pr_body(
        exploit,
        report,
        llm_enrich=llm_enrich,
        model=mitigation_model,
        completion_fn=mitigation_completion_fn,
        system_prompt=system_prompt,
        target=target_context,
    )
    pr = open_pr_fn(out_dir=out_dir, exploit=exploit, report=report, body=body, open_pr=open_pr)
    opened = bool(getattr(pr, "opened", False))
    branch = getattr(pr, "branch", None)
    return GateResult(exit_code=EXIT_SUCCESS, opened_pr=opened, branch=branch, kept=True)
