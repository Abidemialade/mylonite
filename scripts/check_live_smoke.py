#!/usr/bin/env python3
"""Check a live `mylonite scan` run's output against the #217 calibration
proof the live-smoke workflow (`.github/workflows/live-smoke.yml`) exists to
demonstrate against a real model and a real `npx` MCP server.

Two shapes, selected by `--expect`:

* `inc005` — the docs-following target file (`filesystem.yaml`): calibration
  must have failed with the same schema reason code the offline
  `tests/integration/test_issue217.py` tests assert
  (`MYL-INC-005` — the verify tool's `verify_args_template` fails its own
  `inputSchema`), and the scanned weakness class must not have read
  `RESISTED` / `RESISTED (server-reported)` — the exact false-clean #217
  reported (a broken probe silently clearing a dispatch it never actually
  observed).
* `certified` — the corrected target file (`filesystem.corrected.yaml`):
  calibration must have certified at least one tool.

Reads `verdicts.json` (see `mylonite.scan.artefacts.write_artefacts` /
`mylonite.scan.class_verdict.CalibrationSummary.to_dict` /
`ClassVerdict.to_dict` for the exact shape this script depends on) from the
single timestamped scan directory under the given `--output-dir`. Never
calls a model or opens a network connection itself — it only reads a
directory a `scan` run already wrote.

Usage::

    python scripts/check_live_smoke.py out-docs --expect inc005
    python scripts/check_live_smoke.py out-corrected --expect certified --weakness-class W4
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

#: Class statuses that would make this a false-clean result -- the exact
#: #217 failure mode (an uncalibrated probe's "no change" silently trusted).
_FALSE_CLEAN_STATUSES = frozenset({"RESISTED", "RESISTED (server-reported)"})


class LiveSmokeCheckError(Exception):
    """Raised with every problem found, joined by the caller for one message."""


def find_verdicts_json(output_dir: Path) -> Path:
    """The one `verdicts.json` under a scan `--output-dir`.

    `mylonite.scan.artefacts.write_artefacts` creates exactly one fresh
    ISO-timestamped subdirectory per `write_artefacts` call, so a
    `--output-dir` used for a single `scan` invocation (as the live-smoke
    workflow does -- a fresh directory per fixture) holds exactly one.
    """
    matches = sorted(output_dir.glob("*/verdicts.json"))
    if not matches:
        msg = (
            f"no verdicts.json found under {output_dir} -- scan produced no "
            "per-class summary (see mylonite.scan.artefacts._has_class_summary; "
            "it is only written when an attempt was decided by the trace rule "
            "or the target carries a calibration summary)"
        )
        raise LiveSmokeCheckError(msg)
    if len(matches) > 1:
        msg = (
            f"expected exactly one verdicts.json under {output_dir}, found "
            f"{len(matches)}: {[str(p) for p in matches]} -- use a fresh "
            "--output-dir per scan"
        )
        raise LiveSmokeCheckError(msg)
    return matches[0]


def load_verdicts(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        msg = f"could not read/parse {path}: {exc}"
        raise LiveSmokeCheckError(msg) from exc
    if not isinstance(data, dict):
        msg = f"{path} did not contain a JSON object"
        raise LiveSmokeCheckError(msg)
    return data


def _class(doc: dict[str, Any], weakness: str) -> dict[str, Any]:
    classes = doc.get("classes")
    if not isinstance(classes, list):
        msg = f"verdicts.json has no 'classes' list: {doc!r}"
        raise LiveSmokeCheckError(msg)
    for entry in classes:
        if isinstance(entry, dict) and entry.get("weakness") == weakness:
            return entry
    msg = f"no class {weakness!r} in verdicts.json's 'classes' ({classes!r})"
    raise LiveSmokeCheckError(msg)


def check_inc005(doc: dict[str, Any], *, weakness: str) -> None:
    """The docs-following fixture: calibration failed on MYL-INC-005, and the
    weakness class never silently read as resisted."""
    calibration = doc.get("calibration")
    if not isinstance(calibration, dict):
        msg = f"verdicts.json carries no calibration block: {doc!r}"
        raise LiveSmokeCheckError(msg)
    reason_code = calibration.get("reason_code")
    if reason_code != "MYL-INC-005":
        msg = (
            "expected calibration.reason_code == 'MYL-INC-005' (the verify tool's "
            f"schema-validation failure); got {reason_code!r} -- calibration: {calibration!r}"
        )
        raise LiveSmokeCheckError(msg)
    cls = _class(doc, weakness)
    status = cls.get("status")
    if status in _FALSE_CLEAN_STATUSES:
        msg = (
            f"class {weakness} read {status!r} -- the uncalibrated probe cleared a "
            "dispatch it never actually observed (the exact #217 false-clean failure "
            f"mode); class: {cls!r}"
        )
        raise LiveSmokeCheckError(msg)


def check_certified(doc: dict[str, Any]) -> None:
    """The corrected fixture: calibration certified at least one tool."""
    calibration = doc.get("calibration")
    if not isinstance(calibration, dict):
        msg = f"verdicts.json carries no calibration block: {doc!r}"
        raise LiveSmokeCheckError(msg)
    status = calibration.get("status")
    if status != "certified":
        msg = f"expected calibration.status == 'certified'; got {status!r}: {calibration!r}"
        raise LiveSmokeCheckError(msg)
    certified_tools = calibration.get("certified_tools")
    if not isinstance(certified_tools, list) or not certified_tools:
        msg = f"expected a non-empty certified_tools list; got {certified_tools!r}"
        raise LiveSmokeCheckError(msg)


def run(output_dir: Path, *, expect: str, weakness: str) -> None:
    path = find_verdicts_json(output_dir)
    doc = load_verdicts(path)
    if expect == "inc005":
        check_inc005(doc, weakness=weakness)
    elif expect == "certified":
        check_certified(doc)
    else:  # pragma: no cover -- argparse choices already enforce this
        msg = f"unknown --expect {expect!r}"
        raise LiveSmokeCheckError(msg)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_dir", type=Path, help="the scan's --output-dir")
    parser.add_argument(
        "--expect",
        required=True,
        choices=("inc005", "certified"),
        help="inc005: the docs-following fixture; certified: the corrected fixture",
    )
    parser.add_argument(
        "--weakness-class",
        default="W4",
        dest="weakness",
        help="the class to check for --expect inc005 (default: W4)",
    )
    args = parser.parse_args(argv)
    try:
        run(args.output_dir, expect=args.expect, weakness=args.weakness)
    except LiveSmokeCheckError as exc:
        print(f"check_live_smoke: FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"check_live_smoke: OK ({args.expect}, {args.output_dir})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
