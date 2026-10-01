"""Every recorded run in ``labels.yaml`` must still reach its ground-truth verdict.

The rows point at runs that already live in the repo: a recorded judge reply,
the demo's recorded reference scans and the #217 docs-following target files.
Each row is replayed offline through the real verdict path, and its verdict is
mapped onto one of three labels: FINDING, NOT A FINDING or NOT TESTED. A
change that flips any of them, such as a judge hallucination becoming a
finding again or a docs-following target file reading clean, fails here.
"""

from __future__ import annotations

import asyncio
import json
from functools import cache
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml

from mylonite.contracts._types import AdapterResponse, Payload
from mylonite.scan.class_verdict import (
    STATUS_FINDING,
    STATUS_NOT_TESTED,
    STATUS_RESISTED,
    STATUS_RESISTED_SERVER_REPORTED,
)
from mylonite.scan.judge import SuccessJudge
from mylonite.scan.seeds import SEED_CATALOGUE, resolved_tool_metadata

ROOT = Path(__file__).resolve().parents[2]
LABELS_FILE = Path(__file__).with_name("labels.yaml")

FINDING = "FINDING"
NOT_A_FINDING = "NOT A FINDING"
NOT_TESTED = "NOT TESTED"
LABELS = frozenset({FINDING, NOT_A_FINDING, NOT_TESTED})


def _rows() -> list[dict[str, Any]]:
    document = yaml.safe_load(LABELS_FILE.read_text(encoding="utf-8"))
    return list(document["rows"])


ROWS = _rows()


# --- judge replay -------------------------------------------------------------


def _seed_payload(seed_id: str) -> Payload:
    seed = next(s for s in SEED_CATALOGUE if s.pattern_id == seed_id)
    metadata = {
        "seed_id": seed.pattern_id,
        "weakness": seed.weakness,
        "predicate": seed.predicate,
        "setup": seed.setup,
        "drive": seed.drive,
        **resolved_tool_metadata(seed),
    }
    return Payload(
        pattern_id=seed.pattern_id, channel=seed.channel, body=seed.seed_body, metadata=metadata
    )


def _judge_replay(row: dict[str, Any]) -> str:
    """Replays a recorded judge reply through the real judge on the recorded trace."""
    record = json.loads((ROOT / row["source"]).read_text(encoding="utf-8"))
    content = record["judge_completion"]["choices"][0]["message"]["content"]

    async def recorded(**_: Any) -> SimpleNamespace:
        message = SimpleNamespace(content=content)
        return SimpleNamespace(choices=[SimpleNamespace(message=message)])

    judge = SuccessJudge(model="stub/model", completion_fn=recorded)
    verdict = asyncio.run(
        judge.judge(
            _seed_payload(record["seed_id"]),
            AdapterResponse.model_validate(record["response"]),
        )
    )
    return FINDING if verdict.success else NOT_A_FINDING


# --- recorded reference scan ----------------------------------------------------


@cache
def _demo_results() -> dict[str, Any]:
    """Both reference twins, replayed from the demo's recorded fixtures (once)."""
    from mylonite.demo.runner import run_demo

    result = asyncio.run(run_demo(live=False))
    return {"vulnerable": result.vulnerable, "guarded": result.guarded}


def _reference_scan(row: dict[str, Any]) -> str:
    variant = Path(row["source"]).name
    result = _demo_results()[variant]
    attempts = [a for a in result.report.attempts if a.seed_id == row["seed"]]
    assert len(attempts) == 1, f"expected one {row['seed']} attempt on {variant}, got {attempts}"
    outcome = attempts[0].outcome
    if outcome == "finding":
        return FINDING
    if outcome == "no_finding":
        return NOT_A_FINDING
    return NOT_TESTED


# --- #217 docs-following target files ------------------------------------------


def _issue217(row: dict[str, Any], tmp_path: Path) -> str:
    """Scans one docs-following target file against its behavioural server fake.

    The server fakes and planners are the ones ``tests/integration/test_issue217.py``
    already drives; this only picks which planner runs.
    """
    from tests.integration import test_issue217 as issue217

    from mylonite.plugins._mcp import calibration, stdio_adapter, target_registry
    from mylonite.plugins._mcp.factory import LaunchIntent, build_adapter_for_spec
    from mylonite.plugins._mcp.target_file import build_target_spec, load_target_file

    spec = build_target_spec(load_target_file(ROOT / row["source"]))
    server = Path(row["source"]).stem
    planner: Any
    if server == "memory":
        launcher: Any = issue217._MemoryLauncher(issue217.memory_tools())
        tool = "create_entities"
        planner = issue217._MemoryParrotingAttacker()
    else:
        sandbox = tmp_path / "sandbox"
        sandbox.mkdir()
        launcher = issue217._FilesystemLauncher(sandbox, issue217.filesystem_tools())
        tool = "write_file"
        planner = issue217._ParrotingAttacker("write_file", "content", {"path": "audit.txt"})
    if row["planner"] == "declines":

        async def planner(**_: Any) -> SimpleNamespace:
            return issue217._text_response("I would rather not do that.")

    async def scan() -> Any:
        adapter = build_adapter_for_spec(spec, scope=None, model="stub")
        await calibration.calibrate_custom_target(adapter, authorized=True)
        return await issue217._run_single_seed_scan(
            spec=spec,
            tool_name=tool,
            completion_fn=planner,
            intent=LaunchIntent(),
            tmp_path=tmp_path,
        )

    target_registry.clear_runtime_targets()
    calibration.clear_calibrations()
    try:
        target_registry.register_target(spec)
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(stdio_adapter, "_open_mcp_session", issue217._open_over(launcher))
            result = asyncio.run(scan())
    finally:
        target_registry.clear_runtime_targets()
        calibration.clear_calibrations()

    status = issue217._class(issue217._verdicts_document(result, tmp_path), "W4")["status"]
    if status == STATUS_FINDING:
        return FINDING
    if status in (STATUS_RESISTED, STATUS_RESISTED_SERVER_REPORTED):
        return NOT_A_FINDING
    assert status == STATUS_NOT_TESTED, f"unexpected class status {status!r}"
    return NOT_TESTED


# --- the corpus -------------------------------------------------------------------


def test_every_row_is_well_formed() -> None:
    ids = [row["id"] for row in ROWS]
    assert len(ids) == len(set(ids)), "row ids must be unique"
    for row in ROWS:
        assert row["label"] in LABELS, f"{row['id']}: unknown label {row['label']!r}"
        assert str(row.get("reason", "")).strip(), f"{row['id']}: every label needs a reason"
        assert (ROOT / row["source"]).exists(), f"{row['id']}: {row['source']} does not exist"


def test_the_corpus_covers_all_three_labels() -> None:
    assert {row["label"] for row in ROWS} == LABELS


@pytest.mark.parametrize("row", ROWS, ids=[row["id"] for row in ROWS])
def test_verdict_matches_its_label(row: dict[str, Any], tmp_path: Path) -> None:
    if row["run"] == "judge_replay":
        verdict = _judge_replay(row)
    elif row["run"] == "reference_scan":
        verdict = _reference_scan(row)
    elif row["run"] == "issue217":
        verdict = _issue217(row, tmp_path)
    else:
        pytest.fail(f"{row['id']}: unknown run kind {row['run']!r}")
    assert verdict == row["label"], f"{row['id']}: {row['reason']}"
