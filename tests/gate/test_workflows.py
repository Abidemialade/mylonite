import importlib.resources as ir
from pathlib import Path

import yaml

from mylonite.gate.workflows import write_workflows


def test_templates_are_valid_yaml_and_ship_as_package_data():
    base = ir.files("mylonite.gate") / "templates"
    for name in ("mylonite-gate.yml", "mylonite-discovery.yml"):
        text = (base / name).read_text(encoding="utf-8")
        doc = yaml.safe_load(text)
        assert "__RUNS_ON__" in text  # substitution token still present (rendered later)
        assert "__GATE_DIR__" in text  # ditto for the gate-dir token
        assert "jobs" in doc


def test_write_workflows_creates_both_with_runs_on(tmp_path):
    written = write_workflows(tmp_path, runs_on="ubuntu-latest")
    names = {p.name for p in written}
    assert names == {"mylonite-gate.yml", "mylonite-discovery.yml"}
    for p in written:
        assert p.parent == tmp_path / ".github" / "workflows"
        text = p.read_text(encoding="utf-8")
        assert "__RUNS_ON__" not in text  # token substituted
        doc = yaml.safe_load(text)
        job = next(iter(doc["jobs"].values()))
        assert job["runs-on"] == "ubuntu-latest"


def test_write_workflows_self_hosted_runner(tmp_path):
    written = write_workflows(tmp_path, runs_on="[self-hosted, linux]")
    gate = next(p for p in written if p.name == "mylonite-gate.yml")
    doc = yaml.safe_load(gate.read_text(encoding="utf-8"))
    job = next(iter(doc["jobs"].values()))
    assert job["runs-on"] == ["self-hosted", "linux"]


def test_write_workflows_defaults_gate_dir_to_dot_mylonite_gate(tmp_path):
    """No gate_dir passed -> the historical default, rendered via the token."""
    written = write_workflows(tmp_path, runs_on="ubuntu-latest")
    gate = next(p for p in written if p.name == "mylonite-gate.yml")
    text = gate.read_text(encoding="utf-8")
    assert "__GATE_DIR__" not in text
    assert "pytest .mylonite/gate -q" in text


def test_workflow_gate_dir_is_substituted(tmp_path):
    """T7: the token MAP genuinely substitutes __GATE_DIR__ too, not just
    __RUNS_ON__ — a `gate --out custom/dir` run's scaffolded workflows must
    reference that ACTUAL directory, not the hardcoded default baked into the
    template.
    """
    written = write_workflows(tmp_path, runs_on="ubuntu-latest", gate_dir=Path("custom") / "gate")
    names = {p.name: p for p in written}
    gate_text = names["mylonite-gate.yml"].read_text(encoding="utf-8")
    discovery_text = names["mylonite-discovery.yml"].read_text(encoding="utf-8")

    for text in (gate_text, discovery_text):
        assert "__GATE_DIR__" not in text
        assert ".mylonite/gate" not in text

    assert "pytest custom/gate -q" in gate_text
    assert "mylonite gate --target-file custom/gate/target.yaml" in discovery_text

    # Both remain valid, job-bearing YAML after substitution.
    assert "jobs" in yaml.safe_load(gate_text)
    assert "jobs" in yaml.safe_load(discovery_text)
