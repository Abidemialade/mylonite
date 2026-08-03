"""Layer 3 — false-positive control on a KNOWN-GOOD target.

Layers 1-2 ask "does Mylonite catch real attacks?" Layer 3 asks the opposite and
equally important question: **does Mylonite stay quiet on an app that is NOT
vulnerable?** A scanner that cries wolf is as useless as one that misses.

The measurement: run a normal scan against a target that *should* resist every
attack, then count findings — every finding is a FALSE POSITIVE (a bug in
Mylonite to fix). The headline is the false-positive rate over the probes that
actually ran.

Clean baselines, easiest first:
* ``reference:guarded`` — the defended kitchen-sink twin. Every W1-W4 attack
  should be blocked, so a correct scanner reports 0 findings. No external
  dependency; the obvious first precision baseline.
* a real, well-built third-party MCP server in a sandbox (see ``candidates.md``)
  — the production-grade extension.

The live scan is a user step (needs a model + the target). This module is the
hermetic scorer:

    mylonite scan reference:guarded --output-dir verification/reports/layer3/guarded
    python -m verification.runner layer3 score --scan verification/reports/layer3/guarded
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from mylonite.corpus import CaseResult, confusion_matrix

logger = logging.getLogger(__name__)

# Scan-attempt outcomes that count as a real, completed probe (a negative case on
# a known-good target). Skips / errors are "not tested" and excluded.
_FINDING = "finding"
_NO_FINDING = "no_finding"


def _load_scan_report(scan_dir_or_file: Path) -> dict[str, Any]:
    path = scan_dir_or_file
    if path.is_dir():
        matches = sorted(path.rglob("scan_report.json"))
        if not matches:
            raise FileNotFoundError(f"no scan_report.json under {path}")
        if len(matches) > 1:
            logger.warning(
                "multiple scan_report.json found under %s (%d); using the "
                "most recent (highest sorted path): %s",
                path,
                len(matches),
                matches[-1],
            )
        # Scan output dirs are ISO-timestamped subdirs, so a lexical sort
        # orders oldest-first — take the LAST (most recent), not the first
        # (#41): scoring a stale report from an earlier run silently reports
        # the wrong precision numbers.
        path = matches[-1]
        logger.info("layer3: scoring scan report %s", path)
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        # DCR-0014: raise HERE, not deep in precision_report — a caller that
        # defensively falls back to `attempts = []` on a bad shape fabricates
        # a clean (0 false positive) report from a malformed file.
        raise ValueError(
            f"{path}: scan_report.json must be a JSON object (mapping), got {type(data).__name__}"
        )
    return data


def precision_report(scan_dir_or_file: Path, *, target_label: str = "") -> dict[str, Any]:
    """Score a scan of a KNOWN-GOOD target for false positives.

    Every completed probe is a negative (the target is not vulnerable), so a
    ``finding`` outcome is a false positive and a ``no_finding`` is a true
    negative. Skips/errors are excluded as "not tested".
    """
    report = _load_scan_report(scan_dir_or_file)
    attempts = report.get("attempts", []) if isinstance(report, dict) else []
    rows: list[CaseResult] = []
    false_positives: list[dict[str, Any]] = []
    for a in attempts:
        outcome = a.get("outcome")
        if outcome not in (_FINDING, _NO_FINDING):
            continue  # skipped / error -> not a completed probe
        detected = outcome == _FINDING
        rows.append(
            CaseResult(
                weakness=str(a.get("pattern_id", "?")),
                variant="clean-baseline",
                expected_exploited=False,  # known-good target — every probe is a negative
                detected_exploited=detected,
                detail=str(a.get("verdict_reason", ""))[:200],
            )
        )
        if detected:
            false_positives.append(
                {
                    "pattern_id": a.get("pattern_id"),
                    # DCR-0015: verdict_reason is schema-legal `null` — `.get(k, "")`
                    # only substitutes the default when the KEY is absent, not when
                    # it's present with value None, so a null reason crashed here.
                    "reason": (a.get("verdict_reason") or "")[:200],
                }
            )
    matrix = confusion_matrix(rows)
    return {
        "schema_version": "1.0",
        "layer": "layer3-precision",
        "target": target_label or report.get("target_id", "known-good"),
        "completed_probes": len(rows),
        "false_positives": matrix.fp,
        "true_negatives": matrix.tn,
        "false_positive_rate": round(matrix.false_positive_rate, 4),
        "false_positive_detail": false_positives,
        "note": (
            "False-positive control on a target that SHOULD resist every attack. "
            "Any false positive is a Mylonite bug to fix. Skipped/errored probes are "
            "excluded (not tested). Start with reference:guarded; add real benign "
            "servers from candidates.md for production-grade precision."
        ),
    }
