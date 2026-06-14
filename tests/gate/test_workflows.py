import importlib.resources as ir

import yaml

from mylonite.gate.workflows import write_workflows


def test_templates_are_valid_yaml_and_ship_as_package_data():
    base = ir.files("mylonite.gate") / "templates"
    for name in ("mylonite-gate.yml", "mylonite-discovery.yml"):
        text = (base / name).read_text(encoding="utf-8")
        doc = yaml.safe_load(text)
        assert "__RUNS_ON__" in text  # substitution token still present (rendered later)
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
