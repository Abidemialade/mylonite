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
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_verification_freshness as freshness  # noqa: E402
from verification.trends import render_trends, write_trends  # noqa: E402

from verification import campaign  # noqa: E402


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
        # A COMPLETE campaign by default. This used to list three of the five
        # layers and write no result files at all, which the freshness gate
        # accepted because it never inspected `layers` or opened anything --
        # so the fixture encoded that hole. The gate now requires every layer
        # to be accounted for and every layer claiming `ran` to have left its
        # file behind, which is what a real campaign produces (compare
        # verification/results/0.9.0/). Tests that want an INCOMPLETE campaign
        # pass `layers=` explicitly.
        "layers": layers or {key: "ran" for key in campaign.LAYER_FILES},
    }
    meta_path = version_dir / "meta.json"
    meta_path.write_text(json.dumps(meta), encoding="utf-8")
    # The evidence the `layers` claim refers to. Only for layers marked `ran`:
    # a layer that did not run must not have a file, or the gate could never
    # catch the claim/evidence mismatch it now checks for.
    for key, state in meta["layers"].items():
        filename = campaign.LAYER_FILES.get(key)
        if state == "ran" and filename is not None:
            (version_dir / filename).write_text("{}" + chr(10), encoding="utf-8")
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
    # A made-up version, not one of the real released versions: those collide
    # with `_KNOWN_DEFECTIVE` (see the AgentDojo-label correction there), which
    # would override the "not-run" status this test is actually exercising.
    results_root = tmp_path / "results"
    _write_meta(
        results_root,
        "0.50.0",
        layers={"layer1": "ran", "layer2-agentdojo": "not-run", "layer3": "not-run"},
    )
    _write_layer_summaries(results_root, "0.50.0")

    table = render_trends(results_root)

    row = next(line for line in table.splitlines() if line.startswith("| 0.50.0"))
    cells = [c.strip() for c in row.split("|")]
    # | Version | Date | Model | Layer1 | Layer2 | Layer3 | -> indices 1..6
    assert cells[5] == "not run"  # layer2
    assert cells[6] == "not run"  # layer3
    assert "0" not in cells[5]
    assert cells[4] != "0.0%"  # layer1 DID run; sanity it's not accidentally blanked


def test_render_trends_vacuous_f1_never_shown_as_a_number(tmp_path: Path) -> None:
    # A made-up version: see the comment in the "not_run" test above.
    results_root = tmp_path / "results"
    _write_meta(results_root, "0.50.0")
    _write_layer_summaries(results_root, "0.50.0", judge_agreement_exercised=False, f1=0.99)

    table = render_trends(results_root)

    row = next(line for line in table.splitlines() if line.startswith("| 0.50.0"))
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
    # A version other than 0.9.0: 0.9.0/layer1 is deliberately special-cased
    # (see _KNOWN_DEFECTIVE) to render an "unmeasured" annotation rather than
    # its number, so a numeric-rendering test needs an unaffected version.
    results_root = tmp_path / "results"
    _write_meta(
        results_root, "0.11.0", layers={"layer1": "ran", "layer2-agentdojo": "ran", "layer3": "ran"}
    )
    _write_layer_summaries(results_root, "0.11.0", recall=0.75)

    table = render_trends(results_root)

    row = next(line for line in table.splitlines() if line.startswith("| 0.11.0"))
    assert "75.0%" in row


def test_render_trends_annotates_the_known_defective_0_9_0_layer1_result(
    tmp_path: Path,
) -> None:
    """0.9.0's committed layer1-recall.json is left as recorded (never edited),
    but the harness that produced it had two defects (issue #136 and its
    follow-up) that could each force a miss regardless of what the scan
    actually found -- so the table must not render its bare number."""
    results_root = tmp_path / "results"
    _write_meta(
        results_root, "0.9.0", layers={"layer1": "ran", "layer2-agentdojo": "ran", "layer3": "ran"}
    )
    _write_layer_summaries(results_root, "0.9.0", recall=0.0)

    table = render_trends(results_root)

    row = next(line for line in table.splitlines() if line.startswith("| 0.9.0"))
    cells = [c.strip() for c in row.split("|")]
    # | Version | Date | Model | Layer1 | Layer2 AgentDojo | dh | ds | Layer3 | -> index 4
    assert cells[4] != "0.0%"
    assert "unmeasured" in cells[4]
    assert "FINDINGS.md" in cells[4]


def test_render_judge_f1_known_defective_pair_renders_the_correction() -> None:
    """Direct unit test for the _KNOWN_DEFECTIVE branch _render_judge_f1 gained
    for the AgentDojo label-polarity fix (the other tests here only exercise
    it indirectly through render_trends + a tmp_path fixture). The check runs
    before anything else in the function, so it must win even with an empty
    meta and a directory that holds no result file at all."""
    from verification.trends import _KNOWN_DEFECTIVE, _render_judge_f1

    rendered = _render_judge_f1(Path("unused"), {}, "layer2-agentdojo", "0.9.0")

    assert rendered == _KNOWN_DEFECTIVE[("0.9.0", "layer2-agentdojo")]
    assert "41.2%" in rendered  # the figure as originally published
    assert "label inverted" in rendered  # why it's annotated, not bare
    assert "81.1%" in rendered  # the corrected figure, recomputed offline


def test_render_judge_f1_non_defective_version_still_renders_plainly(tmp_path: Path) -> None:
    """A version/layer pair absent from _KNOWN_DEFECTIVE must fall through to
    the ordinary numeric rendering -- the registry is an allowlist of known
    bad numbers, not a filter that swallows every call."""
    from verification.trends import _render_judge_f1

    meta = {"layers": {"layer2-agentdojo": "ran"}}
    (tmp_path / "layer2-agentdojo.json").write_text(
        json.dumps({"judge_agreement_exercised": True, "judge_agreement": {"f1": 0.75}}),
        encoding="utf-8",
    )

    # A made-up version: see the comment on the "not_run" test above -- the
    # three real released versions are all in _KNOWN_DEFECTIVE for this layer.
    assert _render_judge_f1(tmp_path, meta, "layer2-agentdojo", "0.50.0") == "75.0%"


# --- TRENDS.md is generated, so pin that it is current ----------------------
#
# `verification/TRENDS.md` says "GENERATED FILE. Do not edit by hand." and
# nothing checked that the committed bytes match what the generator produces
# from the committed results. A stale generated file is worse than no file: it
# is a published number nobody re-derived.
#
# Same idiom `tests/test_schemas.py` uses for the generated JSON schemas.


def test_committed_TRENDS_md_is_current() -> None:
    from verification.trends import write_trends

    results_root = ROOT / "verification" / "results"
    committed = (ROOT / "verification" / "TRENDS.md").read_text(encoding="utf-8")

    regenerated_dir = Path(tempfile.mkdtemp())
    try:
        out = regenerated_dir / "TRENDS.md"
        write_trends(results_root, out)
        regenerated = out.read_text(encoding="utf-8")
    finally:
        shutil.rmtree(regenerated_dir, ignore_errors=True)

    assert committed == regenerated, (
        "verification/TRENDS.md is stale. Regenerate it with "
        "`python -m verification.trends` and commit the result."
    )


# --------------------------------------------------------------------------- #
# The third-party campaign section
# --------------------------------------------------------------------------- #


def _write_third_party_results(
    results_root: Path,
    version: str,
    *,
    rollups: dict[str, dict[str, Any]] | None = None,
    product_issues: list[dict[str, Any]] | None = None,
    spend: dict[str, dict[str, float]] | None = None,
    recorded_at: str = "2026-10-03",
) -> Path:
    version_dir = results_root / version / "third-party"
    version_dir.mkdir(parents=True, exist_ok=True)
    data = {
        "schema_version": "1.0",
        "recorded_at": recorded_at,
        "rollups": rollups
        if rollups is not None
        else {
            "tpv-server-memory/anthropic": {"result": "KEPT", "met_bar": True},
            "tpv-streamablehttp/anthropic": {"result": "PRODUCT_DEFECT", "met_bar": True},
        },
        "product_issues": product_issues if product_issues is not None else [{"state": "open"}],
        "spend_counted_usd": spend
        if spend is not None
        else {"anthropic": {"cost_usd": 0.91}, "openai": {"cost_usd": 0.08}},
    }
    results_path = version_dir / "results.json"
    results_path.write_text(json.dumps(data), encoding="utf-8")
    return results_path


def test_third_party_section_renders_kept_targets_and_spend(tmp_path: Path) -> None:
    results_root = tmp_path / "results"
    _write_third_party_results(results_root, "0.12.0")

    table = render_trends(results_root)

    assert "## Third-party verification campaigns" in table
    row = next(line for line in table.splitlines() if line.startswith("| 0.12.0"))
    assert "`server-memory`" in row  # display name, not the raw `tpv-` id
    assert "`simple-streamablehttp`" not in row  # PRODUCT_DEFECT, not a KEPT bar
    assert "1 (1 open)" in row
    assert "anthropic $0.91" in row
    assert "openai $0.08" in row


def test_third_party_unknown_target_id_falls_back_to_raw_name(tmp_path: Path) -> None:
    """A target id not in ``_THIRD_PARTY_DISPLAY_NAMES`` must still appear in the
    table under its raw id, rather than vanishing -- the mapping is cosmetic,
    never a filter."""
    results_root = tmp_path / "results"
    _write_third_party_results(
        results_root,
        "0.12.0",
        rollups={"tpv-some-future-target/anthropic": {"result": "KEPT", "met_bar": True}},
    )

    table = render_trends(results_root)

    row = next(line for line in table.splitlines() if line.startswith("| 0.12.0"))
    assert "`tpv-some-future-target`" in row


def test_third_party_only_version_is_not_reported_as_skipped(tmp_path: Path) -> None:
    """A version directory holding ONLY third-party evidence (no top-level
    meta.json -- the real 0.12.0 shape) must render its own row, never a
    "skipped: no meta.json" note, which would misread a deliberate shape as a
    broken commit."""
    results_root = tmp_path / "results"
    _write_third_party_results(results_root, "0.12.0")

    table = render_trends(results_root)

    assert "skipped" not in table.lower()


def test_third_party_section_absent_when_no_campaign_committed(tmp_path: Path) -> None:
    results_root = tmp_path / "results"
    _write_meta(results_root, "0.9.0")
    _write_layer_summaries(results_root, "0.9.0")

    table = render_trends(results_root)

    assert "Third-party verification campaigns" not in table


def test_third_party_and_academic_evidence_can_coexist_for_one_version(
    tmp_path: Path,
) -> None:
    results_root = tmp_path / "results"
    _write_meta(results_root, "0.50.0")
    _write_layer_summaries(results_root, "0.50.0")
    _write_third_party_results(results_root, "0.50.0")

    table = render_trends(results_root)

    assert any(line.startswith("| 0.50.0") for line in table.splitlines()[:5])
    assert "## Third-party verification campaigns" in table


def test_third_party_unreadable_results_json_is_noted_not_silent(tmp_path: Path) -> None:
    results_root = tmp_path / "results"
    bad_dir = results_root / "0.12.0" / "third-party"
    bad_dir.mkdir(parents=True)
    (bad_dir / "results.json").write_text("{not json", encoding="utf-8")

    table = render_trends(results_root)

    assert "skipped" in table.lower()
    assert "0.12.0" in table


def test_committed_third_party_section_is_current() -> None:
    """Same idiom as ``test_committed_TRENDS_md_is_current``, for the new
    section: the committed file must match a fresh render of the committed
    ``verification/results/`` tree."""
    from verification.trends import render_trends

    results_root = ROOT / "verification" / "results"
    committed = (ROOT / "verification" / "TRENDS.md").read_text(encoding="utf-8")

    regenerated = render_trends(results_root)

    assert regenerated in committed


def test_the_trend_table_shows_both_injecagent_splits() -> None:
    """The regression this guards. The table published one "Layer 2 judge F1"
    cell reading AgentDojo, while the same 0.9.0 run scored InjecAgent dh F1
    1.000 and ds F1 0.400 at recall 0.25 — both genuinely exercised. The
    `_LAYER_FILES` comment calls that gap "the finding", and it was committed to
    JSON and absent from the only human-readable view of it.

    AgentDojo stays the headline for the documented reason (its positive class
    is released third-party trajectories, not ours). The other two are shown
    beside it rather than instead of it."""
    from verification.trends import _HEADER

    for column in ("AgentDojo", "InjecAgent dh F1", "InjecAgent ds F1"):
        assert column in _HEADER, f"{column!r} missing from the trend table header"

    committed = (ROOT / "verification" / "TRENDS.md").read_text(encoding="utf-8")
    # The 0.9.0 row must carry all three, so the good number and the bad one are
    # published together. AgentDojo's cell is the known-defective annotation,
    # not a bare number: the committed 41.2% was scored against an inverted
    # label (see `_KNOWN_DEFECTIVE` in trends.py and FINDINGS.md).
    assert (
        "| 41.2% (label inverted; corrected 81.1%, see FINDINGS.md) | 100.0% | 40.0% |" in committed
    )
