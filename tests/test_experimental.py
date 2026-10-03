"""`check` and `ablate` are hidden and experimental (see `mylonite._experimental`
and `docs/experimental.md`): neither shows up in `mylonite --help`, neither is
documented as a supported command in README.md or the mkdocs nav, and neither
runs unless `MYLONITE_EXPERIMENTAL=1` is set.

Four guards:

1. Both commands are missing from `mylonite --help`'s listing.
2. Neither is listed as a supported command in README.md's command table.
3. Neither page backing either command (`docs/experimental.md`, which holds
   their moved reference sections) is reachable from the mkdocs nav -- walked
   recursively, since a nav entry can itself be a one-item mapping nested
   under a section.
4. Both refuse with exit code 2 and a one-line message without the env var,
   and actually run (reach their own logic, not the refusal) with it set.
"""

from __future__ import annotations

import sys
from importlib.abc import MetaPathFinder
from pathlib import Path
from typing import Any

import pytest
import yaml
from typer.testing import CliRunner

from mylonite._experimental import ENV_VAR
from mylonite.cli import app
from mylonite.exit_codes import EXIT_CONFIG

_REPO_ROOT = Path(__file__).resolve().parents[1]
_README = _REPO_ROOT / "README.md"
_MKDOCS_YML = _REPO_ROOT / "mkdocs.yml"

runner = CliRunner()


def test_check_and_ablate_absent_from_help() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "check" not in result.output
    assert "ablate" not in result.output


def test_check_and_ablate_absent_from_readme_command_table() -> None:
    readme = _README.read_text(encoding="utf-8")
    start = readme.index("## Commands")
    end = readme.index("\n## ", start + len("## Commands"))
    table = readme[start:end]
    assert "`mylonite check`" not in table
    assert "`mylonite ablate`" not in table


def _flatten_nav_paths(nav: object) -> list[str]:
    """Every page path reachable from a mkdocs ``nav:`` structure.

    A nav entry is a list whose items are either a bare path string, or a
    one-item mapping of ``{title: path_or_nested_list}`` -- recurse into
    whichever shape is present so a page nested under any depth of sections
    is still found.
    """
    paths: list[str] = []
    if isinstance(nav, str):
        paths.append(nav)
    elif isinstance(nav, list):
        for item in nav:
            paths.extend(_flatten_nav_paths(item))
    elif isinstance(nav, dict):
        for value in nav.values():
            paths.extend(_flatten_nav_paths(value))
    return paths


def test_experimental_page_not_in_mkdocs_nav() -> None:
    config = yaml.safe_load(_MKDOCS_YML.read_text(encoding="utf-8"))
    paths = _flatten_nav_paths(config.get("nav", []))
    # Guard against a vacuous pass: the walk must find pages that are in nav.
    assert "quickstart.md" in paths and "cli-reference.md" in paths, paths
    assert "experimental.md" not in paths, (
        "docs/experimental.md (which now holds check's and ablate's reference "
        "sections) must stay out of the published nav -- it belongs in "
        "mkdocs.yml's `not_in_nav` list instead"
    )


def test_check_refuses_without_the_env_var() -> None:
    result = runner.invoke(app, ["check", "reference:vulnerable"], env={ENV_VAR: None})
    assert result.exit_code == EXIT_CONFIG
    assert "mylonite check" in result.output
    assert "experimental" in result.output
    assert f"{ENV_VAR}=1" in result.output


def test_ablate_refuses_without_the_env_var() -> None:
    result = runner.invoke(app, ["ablate", "--target-file", "unused.yaml"], env={ENV_VAR: None})
    assert result.exit_code == EXIT_CONFIG
    assert "mylonite ablate" in result.output
    assert "experimental" in result.output
    assert f"{ENV_VAR}=1" in result.output


def test_check_runs_with_the_env_var_set() -> None:
    """`check reference:vulnerable` needs no LLM call and no key -- just the
    in-process reference app's own `describe()` -- so this proves the gate
    lets a real run through, not only that the refusal message changes."""
    result = runner.invoke(app, ["check", "reference:vulnerable"], env={ENV_VAR: "1"})
    assert result.exit_code == 0, result.output
    assert "is experimental" not in result.output


def test_check_reference_missing_kitchen_sink_maps_to_exit_2(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#195/#210: `check reference:*` without the reference target package
    installed used to surface the raw `ModuleNotFoundError` from describe()
    (via the generic ``echo_exc`` fallback, exception class name and all)
    instead of the same friendly hint `scan`/`validate` already give."""

    class _BlockKitchenSink(MetaPathFinder):
        def find_spec(self, fullname: str, path: Any = None, target: Any = None) -> None:
            if fullname == "mcp_kitchen_sink" or fullname.startswith("mcp_kitchen_sink."):
                raise ModuleNotFoundError(f"No module named '{fullname}'", name="mcp_kitchen_sink")
            return None

    for name in list(sys.modules):
        if name == "mcp_kitchen_sink" or name.startswith("mcp_kitchen_sink."):
            monkeypatch.delitem(sys.modules, name, raising=False)
    monkeypatch.setattr(sys, "meta_path", [_BlockKitchenSink(), *sys.meta_path])

    result = runner.invoke(app, ["check", "reference:vulnerable"], env={ENV_VAR: "1"})
    assert result.exit_code == EXIT_CONFIG, result.output
    out = result.stderr or result.output
    assert "pip install -e ./reference_targets/mcp_kitchen_sink" in out
    assert "ModuleNotFoundError" not in out
    assert "Traceback" not in out


def test_check_describe_failure_shows_the_message_not_the_exception_class_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#195: ``AdapterDescribeFailed`` is raised with an operator-ready message
    already (the same contract ``ScanEngine.run()`` relies on for its own
    abort detail) -- `check` used to lose that and show the bare exception
    class name first (``AdapterDescribeFailed: ...``) via the generic
    ``echo_exc`` fallback."""
    import mylonite.commands.check as check_mod
    from mylonite.scan._types import AdapterDescribeFailed

    class _DescribeFails:
        async def describe(self) -> Any:
            raise AdapterDescribeFailed("the server closed the connection before replying")

    monkeypatch.setattr(check_mod, "_build_adapter_for_reference", lambda *a, **k: _DescribeFails())

    result = runner.invoke(app, ["check", "reference:vulnerable"], env={ENV_VAR: "1"})
    assert result.exit_code == EXIT_CONFIG, result.output
    out = result.stderr or result.output
    assert "the server closed the connection before replying" in out, out
    assert "AdapterDescribeFailed" not in out, out


def test_ablate_runs_with_the_env_var_set() -> None:
    """No target file is passed, so this still exits non-zero -- but on
    ablate's OWN `--target-file` validation, not the experimental refusal,
    which proves the gate let the call reach ablate's real body."""
    result = runner.invoke(app, ["ablate"], env={ENV_VAR: "1"})
    assert result.exit_code == EXIT_CONFIG
    assert "is experimental" not in result.output
    assert "--target-file" in result.output
