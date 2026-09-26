from pathlib import Path

import yaml

from mylonite.version import __version__


def test_composite_action_is_well_formed():
    doc = yaml.safe_load(Path("gate-action/action.yml").read_text(encoding="utf-8"))
    assert doc["runs"]["using"] == "composite"
    inputs = doc["inputs"]
    for key in ("target-file", "authorize", "model", "open-pr", "runs-on", "mode"):
        assert key in inputs, f"missing input {key}"
    blob = Path("gate-action/action.yml").read_text(encoding="utf-8")
    assert "mylonite gate" in blob


def test_action_pins_package_to_release():
    """The action installs exactly the release its tag names. A bare
    `pip install "mylonite"` runs whatever PyPI serves that day, so an old
    `gate-action@vX.Y.Z` would silently execute a newer release."""
    blob = Path("gate-action/action.yml").read_text(encoding="utf-8")
    assert f'pip install "mylonite=={__version__}"' in blob
    assert 'pip install "mylonite"' not in blob


def test_ci_gating_doc_pins_gate_action_tag():
    """The documented `uses:` line names this release's tag, not `@main`."""
    text = Path("docs/ci-gating.md").read_text(encoding="utf-8")
    assert f"gate-action@v{__version__}" in text
    assert "gate-action@main" not in text
