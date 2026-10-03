import shutil
import subprocess
from pathlib import Path

import pytest
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


def test_mode_and_runs_on_inputs_are_documented_as_deprecated():
    """#198: both inputs still exist (backward compat), but their
    descriptions say plainly that they do nothing."""
    doc = yaml.safe_load(Path("gate-action/action.yml").read_text(encoding="utf-8"))
    assert "deprecated" in doc["inputs"]["mode"]["description"].lower()
    assert "deprecated" in doc["inputs"]["runs-on"]["description"].lower()


def test_action_never_passes_workflows_flag():
    """#198: don't make the action write workflow files in CI."""
    doc = yaml.safe_load(Path("gate-action/action.yml").read_text(encoding="utf-8"))
    run_script = doc["runs"]["steps"][-1]["run"]
    args_block = run_script[run_script.index("args=(") : run_script.index("mylonite gate")]
    assert "--workflows" not in args_block
    assert "--runs-on" not in args_block


def test_action_warns_on_a_non_default_mode_or_runs_on():
    """#198: a non-default value for either deprecated input logs a GitHub
    ::warning:: rather than being silently accepted and silently ignored."""
    blob = Path("gate-action/action.yml").read_text(encoding="utf-8")
    assert "::warning::" in blob
    assert '$MODE" != "discovery"' in blob
    assert '$RUNS_ON" != "ubuntu-latest"' in blob


def _rendered_args(**env: str) -> list[str]:
    """Execute the action's own run script (swapping the final `mylonite
    gate "${args[@]}"` line for one that just prints the built array) under
    the given env, and return the resulting argv list.

    Proves what the composite action's ACTUAL bash does, not a re-
    implementation of it -- the same shape of check
    test_target_secrets_are_checked_non_empty_before_the_gate_runs in
    test_workflows.py already runs.
    """
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash not available to execute the rendered run script")
    doc = yaml.safe_load(Path("gate-action/action.yml").read_text(encoding="utf-8"))
    run_script = doc["runs"]["steps"][-1]["run"]
    script = run_script.replace('mylonite gate "${args[@]}"', 'printf "%s\\n" "${args[@]}"')
    base_env = {"PATH": __import__("os").environ.get("PATH", "")}
    result = subprocess.run(
        [bash, "-c", script],
        env={**base_env, "MODE": "discovery", "RUNS_ON": "ubuntu-latest", **env},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout.splitlines()


def test_model_flag_is_appended_when_the_input_is_non_empty() -> None:
    """GitHub does not enforce `required: true` on a composite action's
    input -- a caller can still wire an empty string. When MODEL IS set,
    --model must still reach mylonite gate."""
    args = _rendered_args(
        TARGET_FILE="target.yaml",
        AUTHORIZE="my-app",
        MODEL="anthropic/claude-haiku-4-5",
        OPEN_PR="",
    )
    assert "--model" in args
    assert "anthropic/claude-haiku-4-5" in args


def test_model_flag_is_omitted_when_the_input_is_empty() -> None:
    """An empty MODEL (an unset secret/variable, a blank matrix cell) must
    NOT become `--model ""` -- that exits 2 ("invalid --model") instead of
    the clearer exit 4 + approved-provider-list message a genuinely missing
    model gets from mylonite gate itself."""
    args = _rendered_args(TARGET_FILE="target.yaml", AUTHORIZE="my-app", MODEL="", OPEN_PR="")
    assert "--model" not in args


# ---------------------------------------------------------------------------
# An api-key input, a provider-driven key mapping, and a git-identity step.
# ---------------------------------------------------------------------------


def test_action_has_a_required_api_key_input():
    doc = yaml.safe_load(Path("gate-action/action.yml").read_text(encoding="utf-8"))
    assert doc["inputs"]["api-key"]["required"] is True


def test_action_maps_the_api_key_through_the_registry_not_a_hardcoded_var():
    """The key-mapping step reads the provider registry at run time -- it
    must never spell out one provider's credential variable itself (that's
    the same bug the scaffolded workflows used to have, just moved into the
    action)."""
    blob = Path("gate-action/action.yml").read_text(encoding="utf-8")
    assert "provider_from_model" in blob
    assert "env_vars_for" in blob
    assert "ANTHROPIC_API_KEY" not in blob


def test_action_configures_git_identity_before_running_gate():
    doc = yaml.safe_load(Path("gate-action/action.yml").read_text(encoding="utf-8"))
    steps = doc["runs"]["steps"]
    names = [s.get("name") for s in steps]
    assert "Configure git identity for the gating PR" in names
    git_idx = names.index("Configure git identity for the gating PR")
    assert git_idx < len(steps) - 1, "must run before the step that runs mylonite gate"
    git_step = steps[git_idx]
    assert "git config user.email" in git_step["run"]
    assert "git config user.name" in git_step["run"]


def test_action_decides_node_or_uv_setup_from_the_target_files_command():
    doc = yaml.safe_load(Path("gate-action/action.yml").read_text(encoding="utf-8"))
    names = [s.get("name") for s in doc["runs"]["steps"]]
    assert "Decide whether the target needs Node or uv" in names
    assert any(n and n.startswith("Set up Node") for n in names)
    assert any(n and n.startswith("Install uv") for n in names)


def test_action_passes_through_optional_llm_headers():
    """An optional llm-headers input, mapped through env: only (never
    interpolated into run:), named exactly as mylonite itself reads it so
    the mylonite gate subprocess picks it up directly."""
    doc = yaml.safe_load(Path("gate-action/action.yml").read_text(encoding="utf-8"))
    assert doc["inputs"]["llm-headers"]["required"] is False
    run_step = doc["runs"]["steps"][-1]
    assert run_step["env"]["MYLONITE_LLM_HEADERS"] == "${{ inputs.llm-headers }}"
    assert "MYLONITE_LLM_HEADERS" not in run_step["run"]


def test_action_pins_its_own_litellm_install_to_the_constraints_file():
    """The same exact-pin constraints file the scaffolded workflows use,
    vendored next to this action rather than fetched."""
    blob = Path("gate-action/action.yml").read_text(encoding="utf-8")
    assert "constraints.txt" in blob
    assert Path("gate-action/constraints.txt").is_file()
    assert "litellm==" in Path("gate-action/constraints.txt").read_text(encoding="utf-8")
