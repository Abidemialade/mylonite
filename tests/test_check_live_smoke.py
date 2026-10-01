"""Unit tests for scripts/check_live_smoke.py.

Synthetic ``verdicts.json`` documents shaped exactly like
``mylonite.scan.class_verdict.CalibrationSummary.to_dict`` /
``ClassVerdict.to_dict`` write them (see ``tests/integration/test_issue217.py``'s
``_verdicts_document``), not a real scan -- this script never needs a live
model to be exercised in CI.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_live_smoke as mod  # noqa: E402


def _calibration(
    *, status: str, reason_code: str | None, certified_tools: tuple[str, ...] = ()
) -> dict[str, Any]:
    return {
        "status": status,
        "reason_code": reason_code,
        "seed_control": {"status": "not_declared", "reason_code": None},
        "certified_tools": list(certified_tools),
    }


def _class(weakness: str, status: str) -> dict[str, Any]:
    return {
        "weakness": weakness,
        "status": status,
        "codes": [],
        "proof_levels": ["dispatched"] if status == "FINDING" else [],
        "counts": {"finding": 0, "resisted": 0, "server_reported": 0, "not_tested": 0},
        "evidence_tiers": {},
        "trace_decided": 1,
    }


def _write_verdicts(tmp_path: Path, doc: dict[str, Any]) -> Path:
    scan_dir = tmp_path / "2026-10-01T00-00-00Z"
    scan_dir.mkdir(parents=True)
    (scan_dir / "verdicts.json").write_text(json.dumps(doc), encoding="utf-8")
    return tmp_path


# ---------------------------------------------------------------------------
# find_verdicts_json
# ---------------------------------------------------------------------------


def test_find_verdicts_json_locates_the_one_timestamped_file(tmp_path: Path) -> None:
    out_dir = _write_verdicts(
        tmp_path, {"classes": [], "calibration": _calibration(status="certified", reason_code=None)}
    )
    found = mod.find_verdicts_json(out_dir)
    assert found == out_dir / "2026-10-01T00-00-00Z" / "verdicts.json"


def test_find_verdicts_json_fails_loudly_when_absent(tmp_path: Path) -> None:
    with pytest.raises(mod.LiveSmokeCheckError, match=r"no verdicts\.json found"):
        mod.find_verdicts_json(tmp_path)


def test_find_verdicts_json_fails_loudly_when_ambiguous(tmp_path: Path) -> None:
    doc = {"classes": [], "calibration": _calibration(status="certified", reason_code=None)}
    _write_verdicts(tmp_path, doc)
    second = tmp_path / "2026-10-01T00-00-01Z"
    second.mkdir()
    (second / "verdicts.json").write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(mod.LiveSmokeCheckError, match="found 2"):
        mod.find_verdicts_json(tmp_path)


# ---------------------------------------------------------------------------
# --expect inc005
# ---------------------------------------------------------------------------


def test_inc005_passes_on_the_docs_following_shape() -> None:
    doc = {
        "classes": [_class("W4", "FINDING")],
        "calibration": _calibration(status="failed", reason_code="MYL-INC-005"),
    }
    mod.check_inc005(doc, weakness="W4")  # does not raise


def test_inc005_fails_when_reason_code_is_not_inc005() -> None:
    doc = {
        "classes": [_class("W4", "FINDING")],
        "calibration": _calibration(status="failed", reason_code="MYL-INC-002"),
    }
    with pytest.raises(mod.LiveSmokeCheckError, match="MYL-INC-005"):
        mod.check_inc005(doc, weakness="W4")


@pytest.mark.parametrize("status", ["RESISTED", "RESISTED (server-reported)"])
def test_inc005_fails_on_the_exact_false_clean_it_guards(status: str) -> None:
    """The whole point of this script: a class that read RESISTED/RESISTED
    (server-reported) against an uncalibrated probe is the false-clean #217
    reported, and must fail the check even though the reason code is right."""
    doc = {
        "classes": [_class("W4", status)],
        "calibration": _calibration(status="failed", reason_code="MYL-INC-005"),
    }
    with pytest.raises(mod.LiveSmokeCheckError, match="false-clean"):
        mod.check_inc005(doc, weakness="W4")


def test_inc005_fails_with_no_calibration_block() -> None:
    doc: dict[str, Any] = {"classes": [_class("W4", "FINDING")], "calibration": None}
    with pytest.raises(mod.LiveSmokeCheckError, match="no calibration block"):
        mod.check_inc005(doc, weakness="W4")


def test_inc005_fails_when_the_class_is_missing() -> None:
    doc = {
        "classes": [_class("W2", "FINDING")],
        "calibration": _calibration(status="failed", reason_code="MYL-INC-005"),
    }
    with pytest.raises(mod.LiveSmokeCheckError, match="no class 'W4'"):
        mod.check_inc005(doc, weakness="W4")


# ---------------------------------------------------------------------------
# --expect certified
# ---------------------------------------------------------------------------


def test_certified_passes_when_calibration_certified_a_tool() -> None:
    doc = {
        "classes": [_class("W4", "RESISTED")],
        "calibration": _calibration(
            status="certified", reason_code=None, certified_tools=("create_directory",)
        ),
    }
    mod.check_certified(doc)  # does not raise


def test_certified_fails_when_status_is_not_certified() -> None:
    doc = {
        "classes": [_class("W4", "FINDING")],
        "calibration": _calibration(status="failed", reason_code="MYL-INC-005"),
    }
    with pytest.raises(mod.LiveSmokeCheckError, match="certified"):
        mod.check_certified(doc)


def test_certified_fails_when_certified_tools_is_empty() -> None:
    doc = {
        "classes": [_class("W4", "RESISTED")],
        "calibration": _calibration(status="certified", reason_code=None, certified_tools=()),
    }
    with pytest.raises(mod.LiveSmokeCheckError, match="certified_tools"):
        mod.check_certified(doc)


# ---------------------------------------------------------------------------
# run() / main() end to end against a real directory.
# ---------------------------------------------------------------------------


def test_run_end_to_end_inc005(tmp_path: Path) -> None:
    doc = {
        "classes": [_class("W4", "FINDING")],
        "calibration": _calibration(status="failed", reason_code="MYL-INC-005"),
    }
    out_dir = _write_verdicts(tmp_path, doc)
    mod.run(out_dir, expect="inc005", weakness="W4")  # does not raise


def test_run_end_to_end_certified(tmp_path: Path) -> None:
    doc = {
        "classes": [_class("W4", "RESISTED")],
        "calibration": _calibration(
            status="certified", reason_code=None, certified_tools=("create_directory",)
        ),
    }
    out_dir = _write_verdicts(tmp_path, doc)
    mod.run(out_dir, expect="certified", weakness="W4")  # does not raise


def test_main_exits_nonzero_on_failure(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    doc = {
        "classes": [_class("W4", "RESISTED")],
        "calibration": _calibration(status="failed", reason_code="MYL-INC-005"),
    }
    out_dir = _write_verdicts(tmp_path, doc)
    code = mod.main([str(out_dir), "--expect", "inc005"])
    assert code == 1
    assert "FAIL" in capsys.readouterr().err


def test_main_exits_zero_on_success(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    doc = {
        "classes": [_class("W4", "FINDING")],
        "calibration": _calibration(status="failed", reason_code="MYL-INC-005"),
    }
    out_dir = _write_verdicts(tmp_path, doc)
    code = mod.main([str(out_dir), "--expect", "inc005"])
    assert code == 0
    assert "OK" in capsys.readouterr().out
