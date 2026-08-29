"""Hermetic tests for the verification-freshness release gate and TRENDS.md.

``scripts/check_verification_freshness.py`` gates minor/major releases on a
committed ``verification/results/X.Y.0/`` (see that script's docstring for
why); ``verification/trends.py`` renders the committed results into a
Markdown history. Both only touch ``tmp_path`` fixtures here -- no real
``verification/results/`` directory is required to exist for these tests to
pass, and none of them write outside ``tmp_path``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_verification_freshness as freshness  # noqa: E402
from verification.trends import render_trends, write_trends  # noqa: E402


def _write_version_file(tmp_path: Path, version: str) -> Path:
    path = tmp_path / "version.py"
    path.write_text(f'__version__ = "{version}"\n', encoding="utf-8")
    return path


def _write_meta(
    results_root: Path,
    version: str,
    *,
    mylonite_version: str | None = None,
    layers: dict[str, str] | None = None,
    model: str = "anthropic/claude-sonnet-4-6",
    recorded_at: str = "2026-08-28T00:00:00Z",
) -> Path:
    version_dir = results_root / version
    version_dir.mkdir(parents=True, exist_ok=True)
    meta = {
        "schema_version": "1.0",
        "mylonite_version": mylonite_version if mylonite_version is not None else version,
        "mylonite_origin": "pypi",
        "harness_sha": "deadbeef",
        "model": model,
        "recorded_at": recorded_at,
        "layers": layers or {"layer1": "ran", "layer2-agentdojo": "ran", "layer3": "ran"},
    }
    meta_path = version_dir / "meta.json"
    meta_path.write_text(json.dumps(meta), encoding="utf-8")
    return meta_path


# --------------------------------------------------------------------------- #
# check_verification_freshness.py
# --------------------------------------------------------------------------- #


def test_patch_version_exempt_with_no_results(tmp_path: Path) -> None:
    version_file = _write_version_file(tmp_path, "0.9.3")
    results_root = tmp_path / "results"  # deliberately does not exist

    version = freshness.read_version(version_file)
    problems = freshness.check(version, results_root=results_root)

    assert problems == []


def test_minor_version_fails_with_no_results(tmp_path: Path) -> None:
    version_file = _write_version_file(tmp_path, "0.9.0")
    results_root = tmp_path / "results"

    version = freshness.read_version(version_file)
    problems = freshness.check(version, results_root=results_root)

    assert len(problems) == 1
    assert "0.9.0" in problems[0]
    assert "verification/results" in problems[0] or "results" in problems[0]


def test_minor_version_passes_with_matching_results(tmp_path: Path) -> None:
    version_file = _write_version_file(tmp_path, "0.9.0")
    results_root = tmp_path / "results"
    _write_meta(results_root, "0.9.0")

    version = freshness.read_version(version_file)
    problems = freshness.check(version, results_root=results_root)

    assert problems == []


def test_minor_version_fails_on_version_mismatch(tmp_path: Path) -> None:
    version_file = _write_version_file(tmp_path, "0.9.0")
    results_root = tmp_path / "results"
    # Directory named 0.9.0, but the recorded campaign was against 0.8.6.
    _write_meta(results_root, "0.9.0", mylonite_version="0.8.6")

    version = freshness.read_version(version_file)
    problems = freshness.check(version, results_root=results_root)

    assert len(problems) == 1
    assert "0.8.6" in problems[0]
    assert "0.9.0" in problems[0]


def test_major_version_also_gated(tmp_path: Path) -> None:
    version_file = _write_version_file(tmp_path, "1.0.0")
    results_root = tmp_path / "results"

    version = freshness.read_version(version_file)
    problems = freshness.check(version, results_root=results_root)

    assert len(problems) == 1


def test_malformed_meta_json_fails_clearly(tmp_path: Path) -> None:
    version_file = _write_version_file(tmp_path, "0.9.0")
    results_root = tmp_path / "results"
    version_dir = results_root / "0.9.0"
    version_dir.mkdir(parents=True)
    (version_dir / "meta.json").write_text("{not valid json", encoding="utf-8")

    version = freshness.read_version(version_file)
    problems = freshness.check(version, results_root=results_root)

    assert len(problems) == 1
    assert "meta.json" in problems[0]


def test_main_exits_1_for_ungated_minor_release(tmp_path: Path, capsys) -> None:
    """End-to-end through ``main()``, matching how CI actually invokes this script."""
    version_file = _write_version_file(tmp_path, "0.9.0")
    results_root = tmp_path / "results"

    exit_code = freshness.main(
        [
            "--check",
            "--version-file",
            str(version_file),
            "--results-root",
            str(results_root),
        ]
    )

    assert exit_code == 1
    captured = capsys.readouterr()
    assert "0.9.0" in captured.err or "0.9.0" in captured.out


def test_main_exits_0_for_patch_release(tmp_path: Path) -> None:
    version_file = _write_version_file(tmp_path, "0.9.3")
    results_root = tmp_path / "results"

    exit_code = freshness.main(
        [
            "--check",
            "--version-file",
            str(version_file),
            "--results-root",
            str(results_root),
        ]
    )

    assert exit_code == 0


def test_check_never_writes_anything(tmp_path: Path) -> None:
    version_file = _write_version_file(tmp_path, "0.9.0")
    results_root = tmp_path / "results"
    _write_meta(results_root, "0.9.0")
    before = {p: p.stat().st_mtime for p in results_root.rglob("*") if p.is_file()}

    freshness.main(
        ["--check", "--version-file", str(version_file), "--results-root", str(results_root)]
    )

    after = {p: p.stat().st_mtime for p in results_root.rglob("*") if p.is_file()}
    assert before == after
    assert not (tmp_path / "results" / "0.9.0" / "extra.json").exists()


# --------------------------------------------------------------------------- #
# verification/trends.py
# --------------------------------------------------------------------------- #


def _write_layer_summaries(
    results_root: Path,
    version: str,
    *,
    recall: float = 0.8,
    judge_agreement_exercised: bool = True,
    f1: float = 0.65,
    fpr: float = 0.0,
) -> None:
    version_dir = results_root / version
    (version_dir / "layer1-recall.json").write_text(
        json.dumps({"schema_version": "1.0", "layer": "layer1-recall", "recall": recall}),
        encoding="utf-8",
    )
    (version_dir / "layer2-agentdojo.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "layer": "layer2-judge-agreement",
                "judge_agreement_exercised": judge_agreement_exercised,
                "judge_agreement": {"precision": 0.5, "recall": 0.9, "f1": f1},
            }
        ),
        encoding="utf-8",
    )
    (version_dir / "layer3-precision.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "layer": "layer3-precision",
                "false_positive_rate": fpr,
            }
        ),
        encoding="utf-8",
    )


def test_render_trends_sorts_versions_by_semver_not_string(tmp_path: Path) -> None:
    """0.10.0 must sort AFTER 0.9.0 -- a string sort gets this backwards
    because '1' < '9' lexicographically."""
    results_root = tmp_path / "results"
    for version in ("0.9.0", "0.10.0", "0.8.6"):
        _write_meta(results_root, version)
        _write_layer_summaries(results_root, version)

    table = render_trends(results_root)
    lines = [line for line in table.splitlines() if line.startswith("| 0.")]

    versions_in_order = [line.split("|")[1].strip() for line in lines]
    assert versions_in_order == ["0.8.6", "0.9.0", "0.10.0"]


def test_render_trends_not_run_layer_renders_literal_not_run(tmp_path: Path) -> None:
    results_root = tmp_path / "results"
    _write_meta(
        results_root,
        "0.9.0",
        layers={"layer1": "ran", "layer2-agentdojo": "not-run", "layer3": "not-run"},
    )
    _write_layer_summaries(results_root, "0.9.0")

    table = render_trends(results_root)

    row = next(line for line in table.splitlines() if line.startswith("| 0.9.0"))
    cells = [c.strip() for c in row.split("|")]
    # | Version | Date | Model | Layer1 | Layer2 | Layer3 | -> indices 1..6
    assert cells[5] == "not run"  # layer2
    assert cells[6] == "not run"  # layer3
    assert "0" not in cells[5]
    assert cells[4] != "0.0%"  # layer1 DID run; sanity it's not accidentally blanked


def test_render_trends_vacuous_f1_never_shown_as_a_number(tmp_path: Path) -> None:
    results_root = tmp_path / "results"
    _write_meta(results_root, "0.9.0")
    _write_layer_summaries(results_root, "0.9.0", judge_agreement_exercised=False, f1=0.99)

    table = render_trends(results_root)

    row = next(line for line in table.splitlines() if line.startswith("| 0.9.0"))
    cells = [c.strip() for c in row.split("|")]
    assert cells[5] == "vacuous"
    assert "0.99" not in row
    assert "99" not in cells[5]


def test_render_trends_skips_malformed_dir_with_a_visible_note(tmp_path: Path) -> None:
    results_root = tmp_path / "results"
    _write_meta(results_root, "0.9.0")
    _write_layer_summaries(results_root, "0.9.0")

    broken_dir = results_root / "0.9.1-broken"
    broken_dir.mkdir(parents=True)
    (broken_dir / "meta.json").write_text("{not json at all", encoding="utf-8")

    table = render_trends(results_root)

    assert "0.9.1-broken" in table
    assert "skipped" in table.lower()
    # The good version still renders despite the sibling being broken.
    assert any(line.startswith("| 0.9.0") for line in table.splitlines())


def test_render_trends_empty_results_root_produces_header_only(tmp_path: Path) -> None:
    results_root = tmp_path / "results"  # does not exist

    table = render_trends(results_root)

    assert "Version" in table
    assert "Layer 1 recall" in table


def test_write_trends_header_names_the_regenerate_command(tmp_path: Path) -> None:
    results_root = tmp_path / "results"
    _write_meta(results_root, "0.9.0")
    _write_layer_summaries(results_root, "0.9.0")
    out = tmp_path / "TRENDS.md"

    write_trends(results_root, out)

    text = out.read_text(encoding="utf-8")
    assert "do not edit by hand" in text.lower() or "generated file" in text.lower()
    assert "python -m verification.trends" in text
    assert "0.9.0" in text


def test_render_trends_reports_numeric_layer1_recall(tmp_path: Path) -> None:
    results_root = tmp_path / "results"
    _write_meta(
        results_root, "0.9.0", layers={"layer1": "ran", "layer2-agentdojo": "ran", "layer3": "ran"}
    )
    _write_layer_summaries(results_root, "0.9.0", recall=0.75)

    table = render_trends(results_root)

    row = next(line for line in table.splitlines() if line.startswith("| 0.9.0"))
    assert "75.0%" in row
