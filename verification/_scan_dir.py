"""Shared loader for a raw scan output directory (what ``mylonite scan``'s
``--output-dir`` writes).

Both Layer 1 (DVMCP recall) and Layer 3 (precision on a known-good target)
score a scan by asking two questions about it: was it genuinely EXERCISED
(did at least one attempt actually run to a verdict, rather than skip or
error), and — for Layer 1 — WHICH weakness class did it find. This module is
the one place that answers both, from the exact directory
:func:`mylonite.scan.artefacts.write_artefacts` writes (``scan_report.json``
plus one ``exploit_<pattern_id>.json`` per kept finding):

* **Exercised** comes from ``scan_report.json``'s ``attempts`` list. Only
  ``outcome in {"finding", "no_finding"}`` counts — every ``skipped_*``,
  ``not_applicable``, ``undecided`` and ``error`` outcome means the attempt
  never actually exercised the target. This mirrors
  ``layer3_production/run.py``'s completed-probe filter exactly: the two
  modules import :data:`FINDING`/:data:`NO_FINDING`/:data:`EXERCISED_OUTCOMES`
  from here rather than each defining their own copy.
* **Found** (which weakness class) comes from the co-located
  ``exploit_*.json`` files, resolved through
  :func:`mylonite.gate.mitigation.weakness_class_for` — the exact function
  the JSON finding bundle (``report/bundle.py``) and the gate PR body
  (``gate/mitigation.py``) already use, so this scorer cannot disagree with
  either about which class a finding belongs to. ``scan_report.json`` alone
  has no per-attempt weakness class (only a ``findings_count`` int), which is
  exactly the historical bug this module exists to fix (issue #136's
  follow-up): a bare copy of ``scan_report.json``, with no exploit files
  beside it, can tell you a challenge was exercised but can never tell you
  what it found.

Two situations mean the INPUT can't be trusted, and both raise
:class:`ScanDirIntegrityError` rather than silently reading as "found
nothing" — a missing or partial artefact is never evidence of a clean
result:

* the directory has no ``scan_report.json`` at all (not a scan directory, or
  an incomplete copy)
* ``scan_report.json`` records at least one ``outcome=finding`` attempt, but
  the directory has no matching ``exploit_*.json`` files (a partial copy —
  the report was copied but the findings it refers to were not)
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

#: Outcomes that count as a real, completed probe. The single definition
#: `layer1_runnable/run.py` and `layer3_production/run.py` both import,
#: rather than each keeping its own copy.
FINDING = "finding"
NO_FINDING = "no_finding"
EXERCISED_OUTCOMES = frozenset({FINDING, NO_FINDING})


class ScanDirIntegrityError(RuntimeError):
    """A scan artefact is present but cannot be trusted as an input.

    Raised instead of silently reading the ambiguous or broken case as "found
    nothing" -- a missing or partial artefact is never evidence of a clean
    result. Every message names the fix: copy the WHOLE scan output
    directory (``scan_report.json`` plus every ``exploit_*.json``), not a
    bare report file.
    """


@dataclass(frozen=True)
class ScanDirResult:
    """What one scan directory shows: was it exercised, and what did it find."""

    exercised: bool
    weakness_classes: frozenset[str]


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_scan_dir(scan_dir: Path) -> ScanDirResult:
    """Read one scan output directory (or a faithful copy of one).

    ``scan_dir`` must contain ``scan_report.json`` directly (the shape
    ``write_artefacts`` writes, and the shape a ``cp -r`` of its timestamped
    subdirectory reproduces exactly). Raises :class:`ScanDirIntegrityError`
    for a directory that cannot be trusted as an input -- see the module
    docstring.
    """
    report_path = scan_dir / "scan_report.json"
    if not report_path.is_file():
        raise ScanDirIntegrityError(
            f"{scan_dir}: no scan_report.json found. Copy the WHOLE scan output "
            "directory (mylonite scan --output-dir ... writes one, timestamped, "
            "per run), not an empty or unrelated directory."
        )
    data = _read_json(report_path)
    attempts = data.get("attempts", []) if isinstance(data, dict) else []
    if not isinstance(attempts, list):
        attempts = []

    exercised = any(
        isinstance(a, dict) and a.get("outcome") in EXERCISED_OUTCOMES for a in attempts
    )
    has_finding_attempt = any(isinstance(a, dict) and a.get("outcome") == FINDING for a in attempts)

    exploit_files = sorted(scan_dir.glob("exploit_*.json"))
    if not exploit_files:
        if has_finding_attempt:
            raise ScanDirIntegrityError(
                f"{scan_dir}: scan_report.json records a 'finding' outcome, but no "
                "exploit_*.json files are present -- an incomplete copy. Copy the "
                "WHOLE scan output directory (scan_report.json AND every "
                "exploit_*.json), not just the report."
            )
        return ScanDirResult(exercised=exercised, weakness_classes=frozenset())

    from mylonite import testkit
    from mylonite.gate.mitigation import weakness_class_for

    classes: set[str] = set()
    for exploit_file in exploit_files:
        exploit = testkit.load_exploit(exploit_file)
        classes.add(weakness_class_for(exploit))
    return ScanDirResult(exercised=exercised, weakness_classes=frozenset(classes))
