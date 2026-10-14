"""The judge-bench CI template: triggers, inputs, pinning, ceiling, secret handling."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

_TEMPLATE = (
    Path(__file__).resolve().parents[2] / "verification" / "judge_bench" / "ci" / "judge-bench.yml"
)
_PINNED = re.compile(r"^[\w.-]+/[\w.-]+@[0-9a-f]{40}$")


def _workflow() -> dict[str, Any]:
    data = yaml.safe_load(_TEMPLATE.read_text(encoding="utf-8"))
    # PyYAML reads the bare `on` key as boolean True.
    if True in data:
        data["on"] = data.pop(True)
    return dict(data)


def _steps() -> list[dict[str, Any]]:
    return list(_workflow()["jobs"]["judge-bench"]["steps"])


def test_triggers_and_inputs() -> None:
    on = _workflow()["on"]
    assert on["push"]["branches"] == ["judge-bench"]
    inputs = on["workflow_dispatch"]["inputs"]
    assert {"phase", "model", "scans", "max_requests"} <= set(inputs)
    assert inputs["phase"]["options"] == ["pilot", "collect", "measure"]
    assert inputs["model"]["default"] == "openai/gpt-4o-mini"


def test_read_only_permissions_and_pinned_actions() -> None:
    assert _workflow()["permissions"] == {"contents": "read"}
    uses = [s["uses"] for s in _steps() if "uses" in s]
    assert uses, "the template uses actions"
    for ref in uses:
        assert _PINNED.match(ref), f"{ref} is not pinned to a full commit SHA"
    for step in _steps():
        if str(step.get("uses", "")).startswith("actions/checkout@"):
            assert step["with"]["persist-credentials"] is False


def test_secret_reaches_the_job_as_openai_key_only() -> None:
    job = _workflow()["jobs"]["judge-bench"]
    assert job["env"]["OPENAI_API_KEY"] == "${{ secrets.MYLONITE_API_KEY }}"
    text = _TEMPLATE.read_text(encoding="utf-8")
    assert text.count("secrets.") == 1


def test_no_expression_is_spliced_into_a_script() -> None:
    for step in _steps():
        assert "${{" not in str(step.get("run", "")), step.get("name")


def test_every_model_run_has_the_ceiling() -> None:
    runs = [s for s in _steps() if "run" in s]
    collect = [s for s in runs if "judge_bench.collect" in s["run"]]
    measure = [s for s in runs if "measure_judge.py" in s["run"]]
    assert collect and measure
    for step in collect:
        assert '--max-llm-requests "$MAX_REQUESTS"' in step["run"]
    for step in measure:
        assert step["env"]["MYLONITE_MAX_LLM_REQUESTS"] == "${{ env.MAX_REQUESTS }}"
        assert "--mode record" in step["run"]


def test_outputs_are_uploaded_always() -> None:
    [upload] = [
        s for s in _steps() if str(s.get("uses", "")).startswith("actions/upload-artifact@")
    ]
    assert upload["if"] == "always()"
    path = upload["with"]["path"]
    for name in ("captures.jsonl", "spend.json", "cases/", "fixtures/", "measure/"):
        assert name in path


def test_agents_rest_target_starts_the_shim_and_authorizes_its_family() -> None:
    """The REST option starts the campaign's own target and authorizes it by the
    family its target file declares, which is what `scan` requires."""
    inputs = _workflow()["on"]["workflow_dispatch"]["inputs"]
    assert inputs["target"]["options"] == ["reference", "agents-rest"]
    assert inputs["target"]["default"] == "reference"
    steps = {s.get("name"): s for s in _steps()}
    start = steps["Start the REST target"]
    assert "agents-rest" in start["if"]
    assert "openai_agents_ollama_shim:app" in start["run"]
    collect = steps["Collect captures"]["run"]
    target_file = (
        Path(__file__).resolve().parents[2] / "verification" / "third_party" / "agents_rest.yaml"
    )
    family = yaml.safe_load(target_file.read_text(encoding="utf-8"))["family"]
    assert "verification/third_party/agents_rest.yaml" in collect
    assert f"--authorize {family}" in collect
