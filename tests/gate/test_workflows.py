import importlib.resources as ir

import yaml


def test_templates_are_valid_yaml_and_ship_as_package_data():
    base = ir.files("mylonite.gate") / "templates"
    for name in ("mylonite-gate.yml", "mylonite-discovery.yml"):
        text = (base / name).read_text(encoding="utf-8")
        doc = yaml.safe_load(text)
        assert "__RUNS_ON__" in text  # substitution token still present (rendered later)
        assert "jobs" in doc
