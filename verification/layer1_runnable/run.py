"""Layer 1 (DVMCP) — emit target files and score recall.

Flow (the live scan is a user step; this module is the hermetic glue):

    # 1. fetch DVMCP at a pinned commit (no LICENSE file -> opt-in)
    python -m verification.runner layer1 fetch --include-unlicensed

    # 2. start the challenge servers (DVMCP's Dockerfile / `python server.py`)

    # 3. emit a Mylonite target.yaml per in-scope challenge (reads each port)
    python -m verification.runner layer1 emit-targets

    # 4. for each emitted target, run a real scan + JSON report yourself:
    #    mylonite scan --target-file <t>.yaml --authorize <family> --json <report>.json
    #    (Mylonite connects over SSE; runs=5 recommended for the flakiness filter)

    # 5. score recall: did Mylonite flag each challenge's documented weakness?
    python -m verification.runner layer1 score --reports verification/reports/dvmcp

Recall-only: a deliberately-vulnerable target has no clean baseline, so every
in-scope challenge is a positive; precision is a Layer 3 concern.
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


def build_recall_report(rows: list[CaseResult], matrix: ConfusionMatrix) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "layer": "layer1-recall",
        "target": "dvmcp",
        "in_scope_challenges": len(rows),
        "recall": round(matrix.recall, 4),
        "found": matrix.tp,
        "missed": matrix.fn,
        "per_challenge": [
            {
                "challenge": r.variant,
                "weakness": r.weakness,
                "found": r.detected_exploited,
                "detail": r.detail,
            }
            for r in rows
        ],
        "note": (
            "Recall vs DVMCP's documented per-challenge weaknesses (ground truth: "
            "solutions/challengeN_solution.md). Out-of-scope challenges (8, 9) are excluded. "
            "DVMCP README claims MIT but ships no LICENSE file: fetched at runtime, never vendored."
        ),
    }


def score_reports(reports_dir: Path) -> tuple[list[CaseResult], ConfusionMatrix, dict[str, Any]]:
    """Map a directory of per-challenge JSON report bundles to a recall report.

    Expects files named ``dvmcp-c<N>*.json`` (the family-named target produces a
    matching report). Missing reports count as MISSED (challenge not yet scanned).
    """
    found_by_challenge: dict[int, set[str]] = {}
    for ch in dvmcp.in_scope_challenges():
        matches = sorted(reports_dir.glob(f"{ch.family}*.json"))
        if matches:
            found_by_challenge[ch.number] = weaknesses_from_bundle(matches[0])
    rows = recall_rows(found_by_challenge)
    matrix = confusion_matrix(rows)
    return rows, matrix, build_recall_report(rows, matrix)
