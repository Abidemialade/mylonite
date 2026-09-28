"""Layer 1 (DVMCP) — emit target files and score recall.

Flow (the live scan is a user step; this module is the hermetic glue):

    # 1. fetch DVMCP at a pinned commit (no LICENSE file -> opt-in)
    python -m verification.runner layer1 fetch --include-unlicensed

    # 2. start the challenge servers (DVMCP's Dockerfile / `python server.py`)

    # 3. emit a Mylonite target.yaml per in-scope challenge (reads each port)
    python -m verification.runner layer1 emit-targets

    # 4. for each emitted target, run a real scan and copy the WHOLE scan
    #    directory out under the target's family name (`scan` has no --json
    #    flag; it writes scan_report.json + exploit_*.json into a timestamped
    #    subdirectory under --output-dir; see `verification.runner`'s printed
    #    instructions for the exact `cp -r` / `Copy-Item -Recurse`):
    #    mylonite scan --target-file <t>.yaml --authorize <family> --output-dir <dir>
    #    cp -r <dir>/<timestamp>/ verification/reports/dvmcp/<family>/
    #    (Mylonite connects over SSE; runs=5 recommended for the flakiness filter)

    # 5. score recall: did Mylonite flag each challenge's documented weakness?
    python -m verification.runner layer1 score --reports verification/reports/dvmcp

Recall-only: a deliberately-vulnerable target has no clean baseline, so every
in-scope challenge is a positive; precision is a Layer 3 concern.

NOTE (report shape, #136 follow-up, fixed): a bare copy of `scan_report.json`
alone can tell the scorer WHETHER a challenge was exercised (its `attempts`
list), but never WHICH weakness class fired (`ScanAttempt` carries no
`weakness_class`, only `findings_count`). `score_reports` now reads the WHOLE
scan directory `mylonite scan`'s `--output-dir` writes -- `scan_report.json` for
`attempts`, plus the co-located `exploit_*.json` files (resolved through
`mylonite.gate.mitigation.weakness_class_for`, via
`verification._scan_dir.load_scan_dir`) for `found`. A bare `scan_report.json`
copy with no exploit files is refused with a named error rather than silently
scored as `found=0` -- see `verification._scan_dir.ScanDirIntegrityError`. The
older `report --json` finding-bundle shape (a flat `<family>.json` file with a
top-level `findings` list) is still read, for backward compatibility with
existing committed/test data.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mylonite.corpus import CaseResult, ConfusionMatrix, confusion_matrix
from mylonite.plugins._mcp.target_file import dump_target_file
from verification._scan_dir import EXERCISED_OUTCOMES, ScanDirIntegrityError, load_scan_dir
from verification.layer1_runnable import dvmcp

__all__ = [
    "ScanDirIntegrityError",
    "build_recall_report",
    "emit_targets",
    "is_exercised",
    "recall_rows",
    "score_reports",
    "weaknesses_from_bundle",
]


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
    """Extract the set of weakness classes flagged in a ``report --json`` bundle.

    Legacy path (backward compatible): reads the flat finding-bundle shape a
    ``mylonite report <dir> --json <out>.json`` file has -- a top-level
    ``findings`` list, each with a ``weakness_class``. For a real scan
    directory (``scan_report.json`` + ``exploit_*.json``), use
    :func:`verification._scan_dir.load_scan_dir` instead, which resolves the
    class through the same ``weakness_class_for`` the gate and the bundle
    writer use, rather than trusting a pre-computed ``weakness_class`` field.
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    findings = data.get("findings", data) if isinstance(data, dict) else data
    out: set[str] = set()
    for f in findings if isinstance(findings, list) else []:
        wc = f.get("weakness_class") if isinstance(f, dict) else None
        if wc:
            out.add(str(wc))
    return out


def is_exercised(path: Path) -> bool:
    """True if a legacy flat per-challenge report file shows a completed probe.

    Legacy path (backward compatible) for the flat-file shapes ``score_reports``
    has always accepted: a ``scan_report.json``-shaped bundle, with a top-level
    ``attempts`` list (each an ``outcome``) -- checked directly, using the same
    :data:`~verification._scan_dir.EXERCISED_OUTCOMES` Layer 3 and
    :func:`~verification._scan_dir.load_scan_dir` use -- or a ``report --json``
    finding bundle, with a top-level ``findings`` list and no attempt-level
    outcome data at all (a finding cannot exist without an exercised attempt,
    so a non-empty ``findings`` list counts).

    A bundle with neither a populated ``attempts`` list nor any ``findings``
    is unresolvable from the file alone and is treated as **not exercised** --
    per the "a check that could not run is never a pass" rule, the ambiguous
    case fails toward "don't know", never toward "tested and clean".

    For a real scan directory, ``score_reports`` uses
    :func:`~verification._scan_dir.load_scan_dir` instead of this function.
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return False
    attempts = data.get("attempts")
    if isinstance(attempts, list) and any(
        isinstance(a, dict) and a.get("outcome") in EXERCISED_OUTCOMES for a in attempts
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


def _score_challenge_from_scan_dirs(scan_dirs: list[Path]) -> tuple[bool, set[str]]:
    """The primary path: one or more real scan directories for one challenge.

    Unions :func:`~verification._scan_dir.load_scan_dir` across every matching
    directory (multiple runs, e.g. re-scored after a re-run). Lets
    :class:`~verification._scan_dir.ScanDirIntegrityError` propagate --
    a partial copy is a fatal input error, never a silent miss.
    """
    exercised = False
    classes: set[str] = set()
    for scan_dir in scan_dirs:
        result = load_scan_dir(scan_dir)
        exercised = exercised or result.exercised
        classes |= set(result.weakness_classes)
    return exercised, classes


def _score_challenge_from_legacy_files(family: str, files: list[Path]) -> tuple[bool, set[str]]:
    """The legacy path: flat ``<family>*.json`` files (backward compatible).

    A file that has a top-level ``findings`` list (the ``report --json``
    finding-bundle shape) is read as before. A file that instead looks like a
    bare ``scan_report.json`` -- it has ``attempts`` but no ``findings`` key
    at all, and no ``exploit_*.json`` sits beside it -- is exactly the
    historical mistake this fix exists to catch: it can prove the challenge
    was exercised, but never what it found. Refused loudly rather than scored
    as ``found=0``.
    """
    exercised = False
    classes: set[str] = set()
    for f in files:
        data = json.loads(f.read_text(encoding="utf-8"))
        if isinstance(data, dict) and "findings" not in data and "attempts" in data:
            raise ScanDirIntegrityError(
                f"{f}: looks like a bare scan_report.json (has 'attempts' but no "
                "'findings' key), with no co-located exploit_*.json files -- it can "
                "prove challenge "
                f"'{family}' was exercised but never what it found. Copy the WHOLE "
                "scan output directory (scan_report.json AND every exploit_*.json) "
                "under the challenge's family name instead; see "
                "verification/runner.py's printed instructions."
            )
        if is_exercised(f):
            exercised = True
        classes |= weaknesses_from_bundle(f)
    return exercised, classes


def score_reports(reports_dir: Path) -> tuple[list[CaseResult], ConfusionMatrix, dict[str, Any]]:
    """Map a directory of per-challenge scan artefacts to a recall report.

    Two input shapes, tried in order for each in-scope challenge:

    1. **A scan directory** named ``<family>`` (or ``<family>*``) directly
       under ``reports_dir`` -- the exact shape ``mylonite scan``'s
       ``--output-dir`` writes (``scan_report.json`` + ``exploit_*.json``), or a faithful
       ``cp -r`` of it. This is the shape ``verification/runner.py`` now tells
       an operator to produce. ``found`` is resolved from the exploit files
       via :func:`~verification._scan_dir.load_scan_dir`.
    2. **Legacy flat files** matching ``<family>*.json`` directly under
       ``reports_dir`` -- kept for backward compatibility with existing
       committed/test data. A ``report --json`` finding bundle still scores;
       a bare ``scan_report.json`` copy with no exploit files raises
       :class:`~verification._scan_dir.ScanDirIntegrityError` instead of
       silently scoring ``found=0`` (see :func:`_score_challenge_from_legacy_files`).

    A challenge with no matching input at all, or whose input(s) show zero
    exercised attempts, is UNTESTED rather than MISSED (issue #136) -- it is
    excluded from the confusion matrix entirely, so recall is computed over
    exercised challenges only.
    """
    found_by_challenge: dict[int, set[str]] = {}
    exercised: set[int] = set()
    untested: set[int] = set()
    for ch in dvmcp.in_scope_challenges():
        dir_matches = sorted(p for p in reports_dir.glob(f"{ch.family}*") if p.is_dir())
        if dir_matches:
            ch_exercised, classes = _score_challenge_from_scan_dirs(dir_matches)
        else:
            file_matches = sorted(p for p in reports_dir.glob(f"{ch.family}*.json") if p.is_file())
            if not file_matches:
                untested.add(ch.number)
                continue
            ch_exercised, classes = _score_challenge_from_legacy_files(ch.family, file_matches)
        if ch_exercised:
            exercised.add(ch.number)
            found_by_challenge[ch.number] = classes
        else:
            untested.add(ch.number)
    rows = recall_rows(found_by_challenge)
    exercised_cids = {dvmcp.CATALOGUE_BY_NUMBER[n].cid for n in exercised}
    exercised_rows = [r for r in rows if r.variant in exercised_cids]
    matrix = confusion_matrix(exercised_rows)
    report = build_recall_report(rows, matrix, exercised=exercised, untested=untested)
    return rows, matrix, report
