"""A real, committed scan-directory fixture for Layer 1 (issue #136 follow-up).

``tests/verification/fixtures/dvmcp-c4/`` is a genuine
``mylonite.scan.artefacts.write_artefacts`` output (``scan_report.json`` +
``exploit_tool-description-summary-smuggle.json``) for DVMCP challenge 4
("Rug Pull Attack", W1) — generated offline, no LLM, no network, by
constructing a ``ScanResult`` the way ``tests/scan/test_artefacts.py`` does
and writing it with the real writer, then committing the output exactly as a
`cp -r` of a real scan directory would produce it.

Two things this guards:

1. The fixture can't silently drift from the real artefact shape: it is
   validated against ``src/mylonite/schemas/scan_report.schema.json`` and
   ``exploit_record.schema.json`` here, the same way
   ``tests/scan/test_artefacts.py`` validates freshly-written artefacts.
2. ``score_reports`` reads it correctly end-to-end: exercised counted, and
   ``found`` resolved from the exploit file's stamped weakness (W1) via
   ``weakness_class_for`` — not read from ``scan_report.json`` alone, which
   carries no per-attempt weakness class.
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
from verification.layer1_runnable import run as layer1_run

_FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
_SCHEMA_DIR = Path(__file__).resolve().parents[2] / "src" / "mylonite" / "schemas"


def test_fixture_scan_report_validates_against_schema() -> None:
    schema = json.loads((_SCHEMA_DIR / "scan_report.schema.json").read_text(encoding="utf-8"))
    payload = json.loads(
        (_FIXTURES_DIR / "dvmcp-c4" / "scan_report.json").read_text(encoding="utf-8")
    )
    jsonschema.validate(payload, schema)


def test_fixture_exploit_record_validates_against_schema() -> None:
    schema = json.loads((_SCHEMA_DIR / "exploit_record.schema.json").read_text(encoding="utf-8"))
    exploit_files = sorted((_FIXTURES_DIR / "dvmcp-c4").glob("exploit_*.json"))
    assert exploit_files, "fixture has no exploit_*.json -- has it drifted?"
    payload = json.loads(exploit_files[0].read_text(encoding="utf-8"))
    jsonschema.validate(payload, schema)


def test_score_reports_reads_the_committed_fixture_end_to_end() -> None:
    """Challenge 4's real scan directory: exercised, and found=1 as W1 --
    resolved from the exploit file, not from scan_report.json alone."""
    _rows, matrix, report = layer1_run.score_reports(_FIXTURES_DIR)

    assert report["exercised_challenges"] == 1
    assert report["found"] == 1
    assert report["missed"] == 0
    assert matrix.tp == 1

    by_cid = {row["challenge"]: row for row in report["per_challenge"]}
    c4 = by_cid["challenge4"]
    assert c4["untested"] is False
    assert c4["found"] is True
    assert c4["weakness"] == "W1"

    # every other in-scope challenge has no fixture -- untested, not missed.
    others = [row for cid, row in by_cid.items() if cid != "challenge4"]
    assert others and all(row["untested"] is True for row in others)
    assert report["untested_challenges"] == len(others)
