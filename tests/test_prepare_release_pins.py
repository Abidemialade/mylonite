"""`prepare_release` keeps the gate action's pins in lockstep with the release.

The gate action lives in this repository, so the release tag ``vX.Y.Z`` is also
the action's tag. ``gate-action/action.yml`` installs ``mylonite==X.Y.Z`` and
``docs/ci-gating.md`` tells users to reference ``gate-action@vX.Y.Z``. A release
that bumps ``__version__`` but not these would publish a tag whose action
installs a different package, so the bump rewrites them and ``--check`` (the
release gate) refuses a mismatch.

Every test runs on a throwaway copy of the relevant files under ``tmp_path``
with the script's ``ROOT`` pointed at it; nothing here touches the real tree.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from scripts import prepare_release

_ACTION = """\
runs:
  using: "composite"
  steps:
    - name: Install mylonite
      shell: bash
      run: pip install "mylonite=={v}"
"""

_DOC = """\
# CI gating

```yaml
- uses: Abidemialade/mylonite/gate-action@v{v}
```
"""

_CHANGELOG = """\
# Changelog

## [Unreleased]

### Changed

- **Something.** It changed.

## [1.0.0] - 2026-01-01

- First.

[Unreleased]: https://github.com/Abidemialade/mylonite/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Abidemialade/mylonite/releases/tag/v1.0.0
"""

_PYPROJECT = """\
[project]
name = "{name}"
dynamic = ["version"]

[tool.hatch.version]
path = "{path}"
"""


def _tree(root: Path, version: str = "1.0.0") -> Path:
    """A minimal repo: main package, gate action, CI doc and a kitchen sink."""
    (root / "src" / "mylonite").mkdir(parents=True)
    (root / "src" / "mylonite" / "version.py").write_text(f'__version__ = "{version}"\n')
    (root / "pyproject.toml").write_text(
        _PYPROJECT.format(name="mylonite", path="src/mylonite/version.py")
    )
    (root / "CHANGELOG.md").write_text(_CHANGELOG)
    (root / "gate-action").mkdir()
    (root / "gate-action" / "action.yml").write_text(_ACTION.format(v=version))
    (root / "docs").mkdir()
    (root / "docs" / "ci-gating.md").write_text(_DOC.format(v=version))

    ks = root / "reference_targets" / "mcp_kitchen_sink"
    (ks / "src" / "mcp_kitchen_sink").mkdir(parents=True)
    (ks / "src" / "mcp_kitchen_sink" / "__init__.py").write_text('__version__ = "0.2.0"\n')
    (ks / "pyproject.toml").write_text(
        _PYPROJECT.format(name="mcp-kitchen-sink", path="src/mcp_kitchen_sink/__init__.py")
    )
    return root


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = _tree(tmp_path)
    monkeypatch.setattr(prepare_release, "ROOT", root)
    # No .secrets.baseline in the tree, so the refresh step is a no-op.
    return root


def _read(root: Path, rel: str) -> str:
    return (root / rel).read_text(encoding="utf-8")


def test_bump_rewrites_the_action_pin_and_the_doc_tag(repo: Path) -> None:
    assert prepare_release.main(["1.1.0"]) == 0

    assert 'pip install "mylonite==1.1.0"' in _read(repo, "gate-action/action.yml")
    assert "mylonite==1.0.0" not in _read(repo, "gate-action/action.yml")
    assert "gate-action@v1.1.0" in _read(repo, "docs/ci-gating.md")
    assert "gate-action@v1.0.0" not in _read(repo, "docs/ci-gating.md")
    # And the bumped tree passes its own release gate.
    assert prepare_release.main(["--check", "--tag", "v1.1.0"]) == 0


def test_check_is_clean_when_pins_match(repo: Path) -> None:
    assert prepare_release.main(["--check", "--tag", "v1.0.0", "--no-changelog"]) == 0


def test_check_reports_a_mismatched_action_pin(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    action = repo / "gate-action" / "action.yml"
    action.write_text(_ACTION.format(v="0.9.9"))

    assert prepare_release.main(["--check", "--tag", "v1.0.0", "--no-changelog"]) == 1
    out = capsys.readouterr().out
    assert "gate-action/action.yml" in out
    assert 'pip install "mylonite==1.0.0"' in out


def test_check_reports_an_unpinned_action(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    action = repo / "gate-action" / "action.yml"
    action.write_text(_ACTION.format(v="").replace("==", ""))

    assert prepare_release.main(["--check", "--tag", "v1.0.0", "--no-changelog"]) == 1
    out = capsys.readouterr().out
    assert "gate-action/action.yml" in out
    assert 'pip install "mylonite==1.0.0"' in out


def test_check_reports_a_mismatched_doc_tag(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    doc = repo / "docs" / "ci-gating.md"
    doc.write_text(_DOC.format(v="0.9.9") + "\nOr `gate-action@main`.\n")

    assert prepare_release.main(["--check", "--tag", "v1.0.0", "--no-changelog"]) == 1
    out = capsys.readouterr().out
    assert "docs/ci-gating.md" in out
    assert "gate-action@v1.0.0" in out


def test_kitchen_sink_release_leaves_the_gate_action_alone(repo: Path) -> None:
    """The kitchen sink ships on its own ``ks-vX.Y.Z`` tags. Its release must
    neither rewrite nor check the main package's action pin."""
    before = (_read(repo, "gate-action/action.yml"), _read(repo, "docs/ci-gating.md"))
    ks_args = [
        "--tag-prefix",
        "ks-v",
        "--package",
        "reference_targets/mcp_kitchen_sink",
        "--no-changelog",
    ]

    assert prepare_release.main(["0.3.0", *ks_args]) == 0
    assert prepare_release.main(["--check", "--tag", "ks-v0.3.0", *ks_args]) == 0

    after = (_read(repo, "gate-action/action.yml"), _read(repo, "docs/ci-gating.md"))
    assert after == before
    assert '__version__ = "0.3.0"' in _read(
        repo, "reference_targets/mcp_kitchen_sink/src/mcp_kitchen_sink/__init__.py"
    )
