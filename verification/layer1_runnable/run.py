"""Layer 1 (DVMCP) — emit target files and score recall.

Flow (the live scan is a user step; this module is the hermetic glue):

    # 1. fetch DVMCP at a pinned commit (no LICENSE file -> opt-in)
    python -m verification.runner layer1 fetch --include-unlicensed

    # 2. start the challenge servers (DVMCP's Dockerfile / `python server.py`)

    # 3. emit a Mylonite target.yaml per in-scope challenge (reads each port)
    python -m verification.runner layer1 emit-targets

    # 4. for each emitted target, run a real scan and lift the report out
    #    (`scan` has no --json flag; see `verification.runner`'s printed
    #    instructions for the exact `cp`):
    #    mylonite scan --target-file <t>.yaml --authorize <family> --output-dir <dir>
    #    cp <dir>/*/scan_report.json verification/reports/dvmcp/<family>.json
    #    (Mylonite connects over SSE; runs=5 recommended for the flakiness filter)

    # 5. score recall: did Mylonite flag each challenge's documented weakness?
    python -m verification.runner layer1 score --reports verification/reports/dvmcp

Recall-only: a deliberately-vulnerable target has no clean baseline, so every
in-scope challenge is a positive; precision is a Layer 3 concern.

NOTE (report shape, #136): a copied `scan_report.json` alone tells the scorer
WHETHER a challenge was exercised (its `attempts` list), but not WHICH
weakness class fired (`ScanAttempt` carries no `weakness_class`, only
`findings_count`). `weaknesses_from_bundle` reads a `findings` list instead,
the shape `mylonite report <dir> --json <out>.json` writes. Getting both
"exercised" and "found" right for a real campaign therefore needs BOTH
artefacts folded into (or unioned alongside) the per-challenge report; see
FINDINGS.md's Layer 1 follow-up note for the open question of how best to
wire that up (out of this fix's approved scope).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mylonite.corpus import CaseResult, ConfusionMatrix, confusion_matrix
from mylonite.plugins._mcp.target_file import dump_target_file
from verification.layer1_runnable import dvmcp


def emit_targets(repo_dir: Path, out_dir: Path) -> list[Path]:
    """Write a Mylonite target.yaml per in-scope challenge (port read from server.py)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for ch in dvmcp.in_scope_challenges():
        server_py = repo_dir / ch.sse_server_relpath()
        if not server_py.exists():
            raise FileNotFoundError(f"{server_py} missing — fetch DVMCP first")
        # SSE servers run on 9000+N (server_sse.py's self.port), distinct from server.py.
        port = dvmcp.extract_port(server_py, default=9000 + ch.number)
        tf = dvmcp.build_target_file(ch, port=port)
        dest = out_dir / f"{ch.family}.yaml"
        dest.write_text(dump_target_file(tf), encoding="utf-8")
        written.append(dest)
    return written


def weaknesses_from_bundle(path: Path) -> set[str]:
    """Extract the set of weakness classes flagged in a ``report --json`` bundle."""
    data = json.loads(path.read_text(encoding="utf-8"))
    findings = data.get("findings", data) if isinstance(data, dict) else data
    out: set[str] = set()
    for f in findings if isinstance(findings, list) else []:
        wc = f.get("weakness_class") if isinstance(f, dict) else None
        if wc:
            out.add(str(wc))
    return out


# Attempt outcomes that count as a real, completed probe -- mirrors
# layer3_production/run.py's `_FINDING`/`_NO_FINDING` completed-probe filter.
# Every other outcome (skipped_*, not_applicable, error, undecided, ...) means
# the attempt never actually exercised the target.
_EXERCISED_OUTCOMES = frozenset({"finding", "no_finding"})


def is_exercised(path: Path) -> bool:
    """True if a per-challenge report bundle shows at least one completed probe.

    A report may carry either (or both) of two shapes, unioned across every
    file the caller globs for a challenge:

    * a ``scan_report.json``-shaped bundle, with a top-level ``attempts`` list
      (each an ``outcome``) -- checked directly, mirroring Layer 3's
      completed-probe filter (only ``finding``/``no_finding`` count; every
      ``skipped_*``/``not_applicable``/``error``/``undecided`` does not).
    * a ``report --json`` finding bundle, with a top-level ``findings`` list
      and no attempt-level outcome data at all -- a finding cannot exist
      without an exercised attempt, so a non-empty ``findings`` list counts.

    A bundle with neither a populated ``attempts`` list nor any ``findings``
    is unresolvable from the file alone and is treated as **not exercised** --
    per the "a check that could not run is never a pass" rule, the ambiguous
    case fails toward "don't know", never toward "tested and clean".
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return False
    attempts = data.get("attempts")
    if isinstance(attempts, list) and any(
        isinstance(a, dict) and a.get("outcome") in _EXERCISED_OUTCOMES for a in attempts
    ):
        return True
    return bool(data.get("findings"))


def recall_rows(found_by_challenge: dict[int, set[str]]) -> list[CaseResult]:
    """Build corpus rows: each in-scope challenge is a positive; detected = mapped W found."""
    rows: list[CaseResult] = []
    for ch in dvmcp.in_scope_challenges():
        found = found_by_challenge.get(ch.number, set())
        detected = bool(set(ch.weakness_classes) & found)
        rows.append(
            CaseResult(
                weakness=ch.weakness_classes[0],
                variant=ch.cid,
                expected_exploited=True,  # vulnerable target — every in-scope challenge is a positive
                detected_exploited=detected,
                detail=(
                    f"{ch.title} [{'/'.join(ch.weakness_classes)}]: "
                    + ("flagged " + "/".join(sorted(found)) if detected else "MISSED")
                ),
            )
        )
    return rows


def build_recall_report(
    rows: list[CaseResult],
    matrix: ConfusionMatrix,
    *,
    exercised: set[int],
    untested: set[int],
) -> dict[str, Any]:
    """Build the recall report. ``matrix`` must be computed over EXERCISED rows only.

    ``rows`` still carries all in-scope challenges (for the full ``per_challenge``
    listing, untested ones included); ``matrix`` -- and therefore ``recall``,
    ``found`` and ``missed`` -- reflects only the subset that was genuinely
    exercised, per issue #136.
    """
    per_challenge = []
    for r in rows:
        number = int(r.variant.removeprefix("challenge"))
        row_untested = number in untested
        detail = r.detail
        if row_untested:
            label, _, _ = detail.partition(": ")
            detail = f"{label}: UNTESTED (no exercised attempt -- see issue #136)"
        per_challenge.append(
            {
                "challenge": r.variant,
                "weakness": r.weakness,
                "found": r.detected_exploited,
                "untested": row_untested,
                "detail": detail,
            }
        )

    return {
        # 1.1 (#136): added exercised_challenges/untested_challenges; recall,
        # found and missed are now computed over EXERCISED challenges only --
        # under 1.0 a challenge with no report, or whose report had zero
        # exercised attempts, silently counted as MISSED. recall is null
        # rather than a spurious 1.0/0.0 when nothing has been exercised yet.
        "schema_version": "1.1",
        "layer": "layer1-recall",
        "target": "dvmcp",
        "in_scope_challenges": len(rows),
        "exercised_challenges": len(exercised),
        "untested_challenges": len(untested),
        "recall": round(matrix.recall, 4) if exercised else None,
        "found": matrix.tp,
        "missed": matrix.fn,
        "per_challenge": per_challenge,
        "note": (
            "Recall vs DVMCP's documented per-challenge weaknesses (ground truth: "
            "solutions/challengeN_solution.md), computed over EXERCISED challenges "
            "only -- a challenge with no report, or whose report shows zero attempts "
            "with outcome finding/no_finding, is counted in 'untested_challenges' "
            "rather than folded into 'missed' (issue #136; mirrors "
            "layer3_production/run.py's completed-probe filter). Out-of-scope "
            "challenges (8, 9) are excluded. DVMCP README claims MIT but ships no "
            "LICENSE file: fetched at runtime, never vendored."
        ),
    }


def score_reports(reports_dir: Path) -> tuple[list[CaseResult], ConfusionMatrix, dict[str, Any]]:
    """Map a directory of per-challenge JSON report bundles to a recall report.

    Expects files named ``dvmcp-c<N>*.json`` (the family-named target produces
    matching reports; every matching file for a challenge is unioned). A
    challenge with no matching report, or whose matching report(s) show zero
    exercised attempts (see :func:`is_exercised`), is UNTESTED rather than
    MISSED (issue #136) -- it is excluded from the confusion matrix entirely,
    so recall is computed over exercised challenges only.
    """
    found_by_challenge: dict[int, set[str]] = {}
    exercised: set[int] = set()
    untested: set[int] = set()
    for ch in dvmcp.in_scope_challenges():
        matches = sorted(reports_dir.glob(f"{ch.family}*.json"))
        if matches and any(is_exercised(m) for m in matches):
            exercised.add(ch.number)
            found_by_challenge[ch.number] = set().union(
                *(weaknesses_from_bundle(m) for m in matches)
            )
        else:
            untested.add(ch.number)
    rows = recall_rows(found_by_challenge)
    exercised_cids = {dvmcp.CATALOGUE_BY_NUMBER[n].cid for n in exercised}
    exercised_rows = [r for r in rows if r.variant in exercised_cids]
    matrix = confusion_matrix(exercised_rows)
    report = build_recall_report(rows, matrix, exercised=exercised, untested=untested)
    return rows, matrix, report
