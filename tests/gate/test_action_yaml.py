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
    for key in ("target-file", "authorize", "model", "open-pr", "runs-on", "mode", "fail-on"):
        assert key in inputs, f"missing input {key}"
    blob = Path("gate-action/action.yml").read_text(encoding="utf-8")
    assert "mylonite gate" in blob


def test_action_declares_exit_code_and_result_outputs():
    """A caller that wants a red signal on a specific result reads these
    instead of (or alongside) `fail-on` -- e.g.
    `steps.<id>.outputs.result == 'kept'`."""
    doc = yaml.safe_load(Path("gate-action/action.yml").read_text(encoding="utf-8"))
    outputs = doc["outputs"]
    assert outputs["exit-code"]["value"] == "${{ steps.gate.outputs.exit-code }}"
    assert outputs["result"]["value"] == "${{ steps.gate.outputs.result }}"
    steps = doc["runs"]["steps"]
    gate_step = next(s for s in steps if s.get("id") == "gate")
    assert gate_step["name"] == "Run mylonite gate"


def test_fail_on_input_defaults_to_none():
    doc = yaml.safe_load(Path("gate-action/action.yml").read_text(encoding="utf-8"))
    assert doc["inputs"]["fail-on"]["required"] is False
    assert doc["inputs"]["fail-on"]["default"] == "none"


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
    # The real step writes exit-code/result to $GITHUB_OUTPUT after calling
    # `mylonite gate` -- this helper's stand-in (the printf above) always
    # exits 0, so that always lands on the "clean" branch, which appends a
    # single `::notice::` line to stdout. Membership checks below ("--model"
    # in args) tolerate the extra element; exact-length/equality checks
    # would not.
    base_env = {"PATH": __import__("os").environ.get("PATH", ""), "GITHUB_OUTPUT": "/dev/null"}
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


def test_action_s_own_install_step_passes_its_constraints_path_through_env():
    """`${{ github.action_path }}` travels through `env:` (ACTION_PATH),
    never interpolated directly into `run:` -- the same rule this file's
    other inputs already follow, and what zizmor flags otherwise."""
    doc = yaml.safe_load(Path("gate-action/action.yml").read_text(encoding="utf-8"))
    install_step = next(s for s in doc["runs"]["steps"] if s.get("name") == "Install mylonite")
    assert install_step["env"]["ACTION_PATH"] == "${{ github.action_path }}"
    assert "github.action_path" not in install_step["run"]


def test_action_never_writes_the_api_key_to_github_env():
    """The key is never persisted to $GITHUB_ENV (which would expose it
    to every later step of the CALLER's job) or to any file -- only the
    credential variable's NAME (never secret-shaped) goes to
    $GITHUB_OUTPUT. The key itself travels as a plain env var (API_KEY),
    scoped to the one step that exports it into its own process right
    before calling mylonite."""
    doc = yaml.safe_load(Path("gate-action/action.yml").read_text(encoding="utf-8"))
    keymap_step = next(s for s in doc["runs"]["steps"] if s.get("id") == "keymap")
    assert "GITHUB_ENV" not in keymap_step["run"]
    assert "GITHUB_OUTPUT" in keymap_step["run"]

    run_step = doc["runs"]["steps"][-1]
    assert run_step["env"]["API_KEY"] == "${{ inputs.api-key }}"
    assert run_step["env"]["KEY_VAR"] == "${{ steps.keymap.outputs.var }}"
    assert 'export "$KEY_VAR=$API_KEY"' in run_step["run"]


def _run_final_step_script(**env: str) -> subprocess.CompletedProcess:
    """Execute the action's final ("Run mylonite gate") step's own script
    up to (not including) the `mylonite gate` call, replacing it with a
    probe that prints what the export logic actually left behind --
    whether $KEY_VAR's target got the key, and whether $API_KEY itself is
    still set afterward."""
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash not available to execute the rendered run script")
    doc = yaml.safe_load(Path("gate-action/action.yml").read_text(encoding="utf-8"))
    run_script = doc["runs"]["steps"][-1]["run"]
    probe = (
        'printf "KEY_VAR_TARGET=%s\\n" "${!KEY_VAR}"\n'
        'printf "API_KEY_STILL_SET=%s\\n" "${API_KEY+yes}"\n'
    )
    script = run_script.replace('mylonite gate "${args[@]}"', probe)
    base_env = {"PATH": __import__("os").environ.get("PATH", ""), "GITHUB_OUTPUT": "/dev/null"}
    return subprocess.run(
        [bash, "-c", script],
        env={
            **base_env,
            "MODE": "discovery",
            "RUNS_ON": "ubuntu-latest",
            "TARGET_FILE": "target.yaml",
            "AUTHORIZE": "my-app",
            "MODEL": "anthropic/claude-haiku-4-5",
            "OPEN_PR": "",
            **env,
        },
        capture_output=True,
        text=True,
    )


def test_action_does_not_export_an_empty_api_key_over_a_real_one():
    """A caller who already exports the real credential at job
    level, but wires `api-key` to an unset secret (empty string), must not
    have that real key overwritten with an empty one -- the export only
    fires when BOTH the variable name and the key are non-empty."""
    result = _run_final_step_script(KEY_VAR="ANTHROPIC_API_KEY", API_KEY="")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "KEY_VAR_TARGET=\n" in result.stdout


def test_action_exports_a_real_key_to_its_mapped_variable():
    result = _run_final_step_script(KEY_VAR="ANTHROPIC_API_KEY", API_KEY="sk-ant-test")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "KEY_VAR_TARGET=sk-ant-test\n" in result.stdout


def test_action_unsets_api_key_after_exporting_it():
    """The key doesn't travel under a second name (API_KEY) into
    the `mylonite gate` subprocess tree once it's been exported to the
    provider's own variable."""
    result = _run_final_step_script(KEY_VAR="ANTHROPIC_API_KEY", API_KEY="sk-ant-test")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "API_KEY_STILL_SET=\n" in result.stdout


# ---------------------------------------------------------------------------
# mylonite gate's own exit code: outputs, annotations, and `fail-on`.
# ---------------------------------------------------------------------------


def _run_gate_mapping(tmp_path: Path, code: int, **env: str) -> subprocess.CompletedProcess:
    """Execute the final step's own script with `mylonite gate "${args[@]}"`
    swapped for a bare `(exit <code>)`, against a real $GITHUB_OUTPUT file,
    proving the mapping the step itself applies -- not a re-implementation
    of it."""
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash not available to execute the rendered run script")
    doc = yaml.safe_load(Path("gate-action/action.yml").read_text(encoding="utf-8"))
    run_script = doc["runs"]["steps"][-1]["run"]
    script = run_script.replace('mylonite gate "${args[@]}"', f"(exit {code})")
    github_output = tmp_path / "github_output"
    github_output.write_text("", encoding="utf-8")
    base_env = {
        "PATH": __import__("os").environ.get("PATH", ""),
        "GITHUB_OUTPUT": str(github_output),
        "MODE": "discovery",
        "RUNS_ON": "ubuntu-latest",
        "TARGET_FILE": "target.yaml",
        "AUTHORIZE": "my-app",
        "MODEL": "anthropic/claude-haiku-4-5",
        "OPEN_PR": "",
        "FAIL_ON": "none",
    }
    result = subprocess.run(
        [bash, "-c", script],
        env={**base_env, **env},
        capture_output=True,
        text=True,
    )
    result.github_output = github_output.read_text(encoding="utf-8")  # type: ignore[attr-defined]
    return result


def test_exit_0_maps_to_clean_and_never_fails_the_step(tmp_path: Path) -> None:
    result = _run_gate_mapping(tmp_path, 0)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "exit-code=0" in result.github_output
    assert "result=clean" in result.github_output
    assert "::notice::" in result.stdout


def test_exit_9_maps_to_kept_and_does_not_fail_by_default(tmp_path: Path) -> None:
    """Covers a freshly-opened PR and a repeat night where the finding was
    already proposed -- both are `gate`'s exit 9."""
    result = _run_gate_mapping(tmp_path, 9)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "exit-code=9" in result.github_output
    assert "result=kept" in result.github_output
    assert "::notice::" in result.stdout


def test_exit_10_maps_to_candidates_and_warns_without_failing(tmp_path: Path) -> None:
    result = _run_gate_mapping(tmp_path, 10)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "exit-code=10" in result.github_output
    assert "result=candidates" in result.github_output
    assert "::warning::" in result.stdout


def test_an_infrastructure_exit_code_still_fails_the_step(tmp_path: Path) -> None:
    """1-8 (config, budget, provider, the PR step itself) is a real
    failure, never mapped to a result or softened by `fail-on`."""
    result = _run_gate_mapping(tmp_path, 4)
    assert result.returncode == 4
    assert "exit-code=4" in result.github_output
    assert "result=" not in result.github_output


def test_fail_on_kept_fails_the_step_on_a_kept_finding(tmp_path: Path) -> None:
    result = _run_gate_mapping(tmp_path, 9, FAIL_ON="kept")
    assert result.returncode == 9
    assert "result=kept" in result.github_output


def test_fail_on_kept_leaves_a_candidates_only_run_green(tmp_path: Path) -> None:
    result = _run_gate_mapping(tmp_path, 10, FAIL_ON="kept")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "result=candidates" in result.github_output


def test_fail_on_candidates_fails_the_step_on_candidates_only(tmp_path: Path) -> None:
    result = _run_gate_mapping(tmp_path, 10, FAIL_ON="candidates")
    assert result.returncode == 10
    assert "result=candidates" in result.github_output


def test_fail_on_none_is_the_default_and_never_fails_on_a_result(tmp_path: Path) -> None:
    for code in (0, 9, 10):
        result = _run_gate_mapping(tmp_path, code, FAIL_ON="none")
        assert result.returncode == 0, result.stdout + result.stderr


def _run_bash_step(step: dict, env: dict[str, str], tmp_path: Path) -> subprocess.CompletedProcess:
    """Execute one composite-action step's own `run:` script, exactly as
    GitHub Actions does (`bash --noprofile --norc -eo pipefail`), with a
    real $GITHUB_OUTPUT file so the step's own `>> "$GITHUB_OUTPUT"` writes
    land somewhere real. Used to prove the runtime-detection step
    survives the flags GitHub actually runs it under, not a re-
    implementation of what it does.
    """
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash not available to execute the rendered step")
    github_output = tmp_path / "github_output"
    github_output.write_text("", encoding="utf-8")
    base_env = {
        "PATH": __import__("os").environ.get("PATH", ""),
        "PYTHONPATH": __import__("os").environ.get("PYTHONPATH", ""),
        "GITHUB_OUTPUT": str(github_output),
    }
    result = subprocess.run(
        [bash, "--noprofile", "--norc", "-eo", "pipefail", "-c", step["run"]],
        env={**base_env, **env},
        capture_output=True,
        text=True,
    )
    result.github_output = github_output.read_text(encoding="utf-8")  # type: ignore[attr-defined]
    return result


def _runtime_step() -> dict:
    doc = yaml.safe_load(Path("gate-action/action.yml").read_text(encoding="utf-8"))
    return next(s for s in doc["runs"]["steps"] if s.get("id") == "runtime")


@pytest.mark.parametrize("transport", ["sse", "http"])
def test_runtime_detection_step_survives_a_remote_target_with_no_command(
    tmp_path: Path, transport: str
) -> None:
    """GitHub runs `shell: bash` as `bash --noprofile --norc -eo
    pipefail {0}`. A remote target (transport: sse|http) declares no
    `command:` line at all -- the previous grep-based step exited 1 (and
    `-e` aborted the whole step) here; this must not."""
    target_file = tmp_path / "target.yaml"
    target_file.write_text(
        f"family: demo\ntransport: {transport}\nurl: https://example.invalid/mcp\n",
        encoding="utf-8",
    )
    result = _run_bash_step(_runtime_step(), {"TARGET_FILE": str(target_file)}, tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "needs=\n" in result.github_output


def test_runtime_detection_step_finds_a_bare_npx_command(tmp_path: Path) -> None:
    target_file = tmp_path / "target.yaml"
    target_file.write_text('family: demo\ncommand: npx\nargs: ["-y", "x"]\n', encoding="utf-8")
    result = _run_bash_step(_runtime_step(), {"TARGET_FILE": str(target_file)}, tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "needs=node\n" in result.github_output


def test_runtime_detection_step_unquotes_a_quoted_command(tmp_path: Path) -> None:
    """`command: "npx"` -- a quoted value a line-oriented grep would
    not match. The real YAML parser unquotes it before this step ever
    compares it."""
    target_file = tmp_path / "target.yaml"
    target_file.write_text('family: demo\ncommand: "npx"\nargs: []\n', encoding="utf-8")
    result = _run_bash_step(_runtime_step(), {"TARGET_FILE": str(target_file)}, tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "needs=node\n" in result.github_output


def test_runtime_detection_step_reduces_an_absolute_path_to_its_basename(tmp_path: Path) -> None:
    """An absolute-path command (e.g. `/usr/bin/npx`) still needs Node --
    a bare string-equality/membership test would miss it."""
    target_file = tmp_path / "target.yaml"
    target_file.write_text(
        'family: demo\ncommand: /usr/local/bin/uvx\nargs: ["x"]\n', encoding="utf-8"
    )
    result = _run_bash_step(_runtime_step(), {"TARGET_FILE": str(target_file)}, tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "needs=uv\n" in result.github_output


def test_runtime_detection_step_survives_a_missing_target_file(tmp_path: Path) -> None:
    """Never the job's problem to fail on -- a missing/unreadable target
    file is caught properly, with a real error, by the step that actually
    runs `mylonite gate`. It still leaves a visible trail -- a
    ::notice:: naming the exception type, not swallowed silently (never
    the exception's own message, which could echo back an unredacted
    field value)."""
    missing = tmp_path / "does-not-exist.yaml"
    result = _run_bash_step(_runtime_step(), {"TARGET_FILE": str(missing)}, tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "needs=\n" in result.github_output
    assert "::notice::" in result.stdout
    assert "FileNotFoundError" in result.stdout
