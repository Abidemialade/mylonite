"""Gate orchestration: sequence scan -> generate -> validate -> assemble -> PR.

Owns the SEQUENCE and the exit-code decision only. Collaborators are injected so
the Typer command supplies live ones and tests supply offline fakes.
"""

from __future__ import annotations

import json
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mylonite import reason_codes
from mylonite._cli_io import echo
from mylonite._redaction import redact_value
from mylonite.contracts import ExploitRecord, GeneratedTest, ValidationReport
from mylonite.exit_codes import (
    EXIT_GENERATE_FAILED,
    EXIT_NOT_KEPT,
    EXIT_SUCCESS,
    EXIT_VALIDATE_FAILED,
)
from mylonite.gate.mitigation import (
    DEFAULT_MITIGATION_MODEL,
    build_gate_pr_body,
    commits_as_pending,
)
from mylonite.generate.wiring import _slugify_pattern
from mylonite.scan.coverage import AbortReason, Coverage, ScanOutcome
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
    lets the all-fail exit-code rule (``EXIT_GENERATE_FAILED`` /
    ``EXIT_VALIDATE_FAILED`` only when EVERY finding failed at that stage;
    ``EXIT_NOT_KEPT`` the moment a real differential verdict — kept or not —
    was reached for any finding) survive going from one exploit to N without
    re-deriving it from string matching.
    """

    exploit: ExploitRecord
    stage: str  # "kept" | "rejected" | "generate_failed" | "validate_failed"
    report: ValidationReport | None = None
    #: For "rejected": the first failed validation stage + its (redacted,
    #: capped) detail — what actually goes in the PR body's rejected-findings
    #: list. For "generate_failed"/"validate_failed": a plain description;
    #: there is no ValidationReport to draw a stage from.
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


def _write_redacted_exploit(path: Path, exploit: ExploitRecord) -> None:
    """Write ``exploit`` to ``path`` with secret-shaped values redacted.

    The exploit record carries the payload, the customised prompt and the
    target's reply, any of which can hold a live credential, and this file is
    committed (#223). Redacted the way ``scan`` and ``generate`` redact their
    copy of the same record: secret-shaped string leaves only, never structure.
    """
    path.write_text(
        json.dumps(redact_value(exploit.model_dump(mode="json")), indent=2, sort_keys=True),
        encoding="utf-8",
    )


def _rejection_reason(report: ValidationReport) -> str:
    """The first validation stage that actually FAILED the verdict, its
    detail redacted and capped — more actionable in the PR body's
    rejected-findings list than a bare "not kept". A ``report_only`` outcome
    (e.g. the custom-target effect leg with no ``effect_probe`` declared)
    never decided ``kept`` by definition, so a failed report-only leg must
    never be named as "the reason" — the real deciding stage may be a later,
    genuinely-gating one.
    """
    from mylonite._redaction import redact

    failed = next((o for o in report.outcomes if not o.passed and not o.report_only), None)
    if failed is None:
        return "the generated test was REJECTED (not kept)"
    detail = redact(failed.detail or "").strip()
    if len(detail) > 200:
        detail = detail[:200].rstrip() + "…"
    return f"failed the {failed.stage} stage" + (f": {detail}" if detail else "")


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


def _slugs_for(exploits: list[ExploitRecord]) -> list[str]:
    """One filesystem slug per exploit, same order, with a deterministic
    numeric suffix when two DIFFERENT pattern_ids collide after slugifying
    (e.g. ``a.b`` and ``a_b`` both -> ``a_b``). Without this the second
    exploit's directory would silently overwrite the first's. Order is the
    caller's (already sorted by pattern_id), so the suffix assignment is
    itself deterministic run to run. Computed for every run, not just a
    multi-finding one, since it also names where a rejected finding's
    evidence is relocated to (see :func:`_finish_unkept`).
    """
    seen: dict[str, int] = {}
    slugs: list[str] = []
    for exploit in exploits:
        base = _slugify_pattern(exploit.pattern_id)
        count = seen.get(base, 0)
        seen[base] = count + 1
        slugs.append(base if count == 0 else f"{base}-{count + 1}")
    return slugs


def _rejected_evidence_dir(out_dir: Path, slug: str) -> Path:
    """Where a REJECTED or validate-failed finding's artefacts are relocated
    to: a directory that is a SIBLING of ``out_dir``, never a descendant of
    it. Two independent things rely on that: (1) the committed `git add`
    path list only ever names files under ``out_dir`` (see
    ``gate/wiring.py``'s ``open_pr_fn``), so nothing here can be swept in by
    it; (2) a later `gate` run reusing the same ``--out`` writes fresh
    content back under ``out_dir`` without ever having to know this
    directory exists, so stale evidence from an earlier run's rejected
    finding can never leak into a later run's own commit.
    """
    return out_dir.parent / f"{out_dir.name}-rejected" / slug


def _finish_unkept(
    this_out: Path, out_dir: Path, slug: str, message: str, written: list[Path]
) -> None:
    """Echo the per-finding verdict, then relocate the files this REJECTED or
    validate-failed finding wrote into :func:`_rejected_evidence_dir`.
    Evidence stays on disk there for local debugging; it is simply outside
    anywhere a commit — automatic or printed for the operator to run by
    hand — ever looks.

    Only ``written`` moves, never a directory. A single finding writes
    straight into ``out_dir``, which can already hold an earlier run's kept
    tests, ``target.yaml`` and workflows; moving the directory took all of
    that with it, and the next rejected run then deleted it. Each file
    replaces only the same-named file of this finding's own earlier
    evidence, so other findings' evidence is never touched. A per-finding
    subdirectory left empty by the move is removed.
    """
    echo(message)
    present = [p for p in written if p.exists()]
    if not present:
        return
    rejected_dir = _rejected_evidence_dir(out_dir, slug)
    rejected_dir.mkdir(parents=True, exist_ok=True)
    for path in present:
        dest = rejected_dir / path.name
        if dest.exists():
            dest.unlink()
        shutil.move(str(path), str(dest))
    if this_out != out_dir and this_out.exists() and not any(this_out.iterdir()):
        this_out.rmdir()
    echo(
        f"Mylonite gate: {slug}: evidence kept at {rejected_dir} for local debugging (not committed)."
    )


def _for_generation(exploit: ExploitRecord) -> ExploitRecord:
    """The copy of ``exploit`` handed to ``generate_fn``.

    A finding that still works on the user's app is tagged so its test is
    emitted as a pending fix (see :func:`commits_as_pending`). Only this copy
    carries the tag: the exploit JSON written next to the test is always the
    untagged record, so a later ``mylonite generate`` run from it (after the
    fix) emits a plain regression test.
    """
    if not commits_as_pending(exploit):
        return exploit
    from mylonite.plugins._reference.reference_pytest_generator import (
        PENDING_FIX_METADATA_KEY,
    )

    meta = {**exploit.payload.metadata, PENDING_FIX_METADATA_KEY: "true"}
    return exploit.model_copy(
        update={"payload": exploit.payload.model_copy(update={"metadata": meta})}
    )


def _process_one_finding(
    exploit: ExploitRecord,
    out_dir: Path,
    slug: str,
    *,
    generate_fn: Callable[[ExploitRecord], GeneratedTest | None],
    validate_fn: Callable[[GeneratedTest], ValidationReport | None],
    multi: bool,
) -> _FindingOutcome:
    """Generate, write, and validate ONE finding. Never raises for a per-finding
    failure (generate/validate returning ``None``) — that is recorded as a
    ``_FindingOutcome`` so one bad finding cannot hide the rest."""
    this_out = out_dir / slug if multi else out_dir
    prefix = f"Mylonite gate: {exploit.pattern_id}: " if multi else "Mylonite gate: "

    generated = generate_fn(_for_generation(exploit))
    if generated is None:
        reason = "the test generator returned nothing"
        echo(f"{prefix}{reason} — skipping." if multi else f"{prefix}{reason} — cannot gate.")
        return _FindingOutcome(exploit=exploit, stage="generate_failed", reason=reason)

    this_out.mkdir(parents=True, exist_ok=True)
    test_path = this_out / generated.filename
    test_path.write_text(generated.source, encoding="utf-8")
    exploit_path = this_out / f"exploit_{exploit.pattern_id}.json"
    written = [test_path, exploit_path]
    _write_redacted_exploit(exploit_path, exploit)

    # The pending tag only shapes the emitted test. Hand the validator the
    # untagged record so it never reaches the payloads it builds.
    generated = generated.model_copy(update={"exploit": exploit})
    try:
        report = validate_fn(generated)
    finally:
        # The validator may write its own copy of the exploit next to the test
        # (the reference route records fixtures there). Write the redacted
        # record again, even if validation raised, so whatever ends up
        # committed or kept for debugging is redacted.
        _write_redacted_exploit(exploit_path, exploit)
    if report is None:
        reason = "the validator returned nothing"
        message = f"{prefix}{reason} — skipping." if multi else f"{prefix}{reason} — cannot gate."
        _finish_unkept(this_out, out_dir, slug, message, written)
        return _FindingOutcome(exploit=exploit, stage="validate_failed", reason=reason)

    if not report.kept:
        # The console line stays the historical wording; the PR-body reason
        # (below) is the one that carries the actual failed-stage detail —
        # keeping the two separate means neither has to compromise.
        console_reason = "the generated test was REJECTED (not kept)"
        message = (
            f"{prefix}{console_reason}." if multi else f"{prefix}{console_reason} — no PR opened."
        )
        _finish_unkept(this_out, out_dir, slug, message, written)
        return _FindingOutcome(
            exploit=exploit, stage="rejected", report=report, reason=_rejection_reason(report)
        )

    # Persist the oracle verdict BEFORE any git contact. The generated test and
    # the exploit JSON were already on disk above, but the validation report --
    # the most expensive artefact of the run -- was only ever written by
    # `validate`, so a failure in the git/gh step threw it away.
    _write_validation_report(this_out, report)
    return _FindingOutcome(exploit=exploit, stage="kept", report=report)


def _coverage_note(outcome: ScanOutcome) -> str:
    """One PR-body line when the scan behind this PR did not exercise every
    attempt, so a reviewer never reads the gated findings as a complete
    result. Empty when coverage was complete.

    An abort can leave ``not_tested == 0``: a seed the scan never reached
    was never added to ``attempts`` at all, so nothing was classified
    NOT_TESTED, even though coverage is still PARTIAL because
    ``abort is not None``. Naming the abort there instead of a zero count
    avoids a note that reads as a contradiction next to a gated finding.
    """
    if outcome.coverage is Coverage.EXERCISED:
        return ""
    if outcome.abort is not None and outcome.not_tested == 0:
        return (
            "\n\n> **Coverage was incomplete.** The scan did not finish "
            f"({outcome.abort.value}), so this PR gates what it proved before "
            "stopping; it does not show the rest of the target is clean.\n"
        )
    return (
        f"\n\n> **Coverage was incomplete.** {outcome.not_tested} attempt(s) were NOT "
        "TESTED, so this PR gates what the scan proved; it does not show the rest of "
        "the target is clean.\n"
    )


def _request_ceiling_tripped() -> bool:
    from mylonite.scan._llm import request_ceiling_hit

    return request_ceiling_hit() is not None


def _echo_nonempty(message: str) -> None:
    if message:
        echo(message)


def _abort_message(outcome: ScanOutcome, budget_hint_text: str | None) -> str:
    """The operator-facing message for an aborted scan. ``scan``'s own budget
    message ends by suggesting ``--weakness-class``, which is `scan`-only —
    `gate` has no such flag, and for a custom target the real lever is the
    target file's own ``weakness_classes:`` key. Rather than tamper with the
    shared ``ScanOutcome`` message text (also used verbatim by ``scan``
    itself, where it IS correct), `gate` prints its own self-contained
    message for a budget abort specifically, using the hint
    ``gate/wiring.budget_hint()`` computed — the same function ``cli.py``'s
    own direct ``BudgetExceededError`` handler calls, so both paths agree.
    Every other abort reason's message doesn't mention a nonexistent flag,
    so it is printed unchanged.
    """
    if outcome.abort is AbortReason.BUDGET_EXCEEDED and _request_ceiling_tripped():
        return ""  # the CLI prints the one line that names the hard ceiling
    if outcome.abort is AbortReason.BUDGET_EXCEEDED and budget_hint_text:
        return reason_codes.tag(
            reason_codes.ABT_BUDGET_EXCEEDED,
            "error: gate's scan phase exhausted its LLM call budget and stopped "
            f"early; coverage is incomplete. {budget_hint_text}",
        )
    return outcome.operator_message or (
        "Mylonite gate: the scan did not complete a trustworthy run "
        f"(coverage={outcome.coverage.name}, abort={outcome.abort}) — cannot gate."
    )


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
    budget_hint_text: str | None = None,
    validation_cost_hint: str | None = None,
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
            _echo_nonempty(_abort_message(bundle.outcome, budget_hint_text))
            return GateResult(exit_code=bundle.outcome.exit_code, opened_pr=False, kept=None)
        echo("Mylonite gate: no exploit found — nothing to gate.")
        return GateResult(exit_code=EXIT_SUCCESS, opened_pr=False, kept=None)

    # Deterministic order: every finding is gated, in the same order every
    # run, regardless of what order the scan happened to discover them.
    sorted_exploits = sorted(exploits, key=lambda e: e.pattern_id)
    multi = len(sorted_exploits) > 1
    slugs = _slugs_for(sorted_exploits)
    if multi:
        n = len(sorted_exploits)
        cost = f" — {validation_cost_hint}" if validation_cost_hint else ""
        echo(f"{n} findings: validating each (about {n}x the single-finding validation cost{cost})")

    # With multiple findings, give each its own subdir so tests don't clobber
    # each other; a single finding keeps the exact dir the operator chose —
    # mirrors `generate`'s identical convention (generate/wiring.py's
    # _resolve_exploit_paths + cli.py's `generate`).
    outcomes = [
        _process_one_finding(
            exploit, out_dir, slug, generate_fn=generate_fn, validate_fn=validate_fn, multi=multi
        )
        for exploit, slug in zip(sorted_exploits, slugs, strict=True)
    ]

    kept = [(o.exploit, o.report) for o in outcomes if o.stage == "kept" and o.report is not None]
    # Parallel to `kept`: the exact directory `open_pr_fn` must treat as
    # committed for that finding — never re-derived independently downstream
    # (a naive re-slugify in wiring.py would disagree with a de-duplicated
    # slug from _slugs_for above).
    kept_dirs = [
        (out_dir / slug if multi else out_dir)
        for outcome, slug in zip(outcomes, slugs, strict=True)
        if outcome.stage == "kept"
    ]
    rejected = [(o.exploit, o.reason) for o in outcomes if o.stage != "kept"]

    if multi:
        echo(f"{len(kept)} kept, {len(rejected)} rejected")

    def _finish(result: GateResult) -> GateResult:
        # An aborted scan (budget exhausted or any other abort) always
        # carries the scan's own exit code and operator message, even when
        # proven findings were gated and a PR was opened/printed for them —
        # mirroring ScanOutcome.from_report's own "abort always wins" rule so
        # `gate` cannot silently exit 0 on a budget-exhausted run just because
        # it found something before the budget ran out.
        # Without an abort, the scan's own caveat (findings alongside NOT
        # TESTED attempts) still prints: `scan` shows it, and a gate run over
        # the same scan must not hide it. The exit code is unchanged.
        if bundle.outcome.abort is not None:
            _echo_nonempty(_abort_message(bundle.outcome, budget_hint_text))
            result.exit_code = bundle.outcome.exit_code
        elif bundle.outcome.operator_message:
            echo(bundle.outcome.operator_message)
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
        # `_process_one_finding` already echoed the per-finding rejected
        # message above; for a single exploit that IS the whole story, so
        # printing another summary line here would just repeat it verbatim.
        # A genuinely multi-finding run still gets an aggregate line, since
        # its per-finding lines differ from it.
        if multi:
            echo("Mylonite gate: no generated test was kept — no PR opened.")
        return _finish(
            GateResult(
                exit_code=EXIT_NOT_KEPT, opened_pr=False, kept=False, rejected_count=len(rejected)
            )
        )

    # build_pr_body stays per-finding (mitigation.py); build_gate_pr_body is
    # the thin wrapper that joins the kept findings' sections and lists the
    # rejected ones with their reason.
    body = build_gate_pr_body(
        kept,
        rejected,
        llm_enrich=llm_enrich,
        model=mitigation_model,
        completion_fn=mitigation_completion_fn,
        system_prompt=system_prompt,
        target=target_context,
        gate_dir=out_dir,
    )
    body += _coverage_note(bundle.outcome)
    pr = open_pr_fn(out_dir=out_dir, findings=kept, kept_dirs=kept_dirs, body=body, open_pr=open_pr)
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
