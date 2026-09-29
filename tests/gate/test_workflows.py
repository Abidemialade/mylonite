import importlib.resources as ir
import subprocess
from pathlib import Path

import pytest
import yaml

from mylonite.gate.workflows import _TEMPLATES, write_workflows
from mylonite.version import __version__

#: Vendored, pre-substituted renders of the templates from before the
#: target-secrets ``env:`` token existed — committed fixture files, not a
#: live ``git show``, so the check below can't break on a shallow checkout,
#: a squashed history, or a non-git tree, and can't mojibake on a Windows
#: console without PYTHONUTF8 set.
_NO_SECRETS_RENDER_DIR = Path(__file__).resolve().parent / "fixtures" / "no_secrets_render"


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


def test_gate_workflow_requires_the_gate_to_run(tmp_path):
    """The per-PR gate job sets MYLONITE_REQUIRE_GATE_RUN and prints skip reasons."""
    written = write_workflows(tmp_path, runs_on="ubuntu-latest")
    gate = next(p for p in written if p.name == "mylonite-gate.yml")
    doc = yaml.safe_load(gate.read_text(encoding="utf-8"))
    job = doc["jobs"]["gate"]
    assert job["env"]["MYLONITE_REQUIRE_GATE_RUN"] == "1"
    assert job["env"]["MYLONITE_LIVE_TARGET"] == "1"
    assert job["steps"][-1]["run"] == "pytest .mylonite/gate -q -ra"


@pytest.mark.parametrize("name", ["mylonite-gate.yml", "mylonite-discovery.yml"])
def test_emitted_workflows_pin_the_package(tmp_path, name):
    """Emitted workflows install the release that wrote them, not whatever
    PyPI serves on the day the job runs."""
    written = write_workflows(tmp_path, runs_on="ubuntu-latest")
    text = next(p for p in written if p.name == name).read_text(encoding="utf-8")
    assert f'"mylonite=={__version__}"' in text
    assert '"mylonite" ' not in text
    assert "__MYLONITE_VERSION__" not in text


def test_discovery_passes_authorize_through_env(tmp_path):
    """No `${{ }}` inside `run:`: GitHub substitutes it textually before bash
    parses the script. The value travels through env, as in gate-action."""
    written = write_workflows(tmp_path, runs_on="ubuntu-latest")
    discovery = next(p for p in written if p.name == "mylonite-discovery.yml")
    job = yaml.safe_load(discovery.read_text(encoding="utf-8"))["jobs"]["discover"]
    step = job["steps"][-1]
    assert "${{" not in step["run"]
    assert step["env"]["MYLONITE_AUTHORIZE"] == "${{ vars.MYLONITE_AUTHORIZE }}"
    assert '--authorize "$MYLONITE_AUTHORIZE" --open-pr' in step["run"]


def test_write_workflows_no_target_secrets_renders_no_extra_env_lines(tmp_path):
    """#185: a target with no secrets renders nothing extra — the gate job
    step keeps no ``env:`` key at all, matching pre-#185 output."""
    written = write_workflows(tmp_path, runs_on="ubuntu-latest")
    gate = next(p for p in written if p.name == "mylonite-gate.yml")
    doc = yaml.safe_load(gate.read_text(encoding="utf-8"))
    step = doc["jobs"]["gate"]["steps"][-1]
    assert "env" not in step

    discovery = next(p for p in written if p.name == "mylonite-discovery.yml")
    ddoc = yaml.safe_load(discovery.read_text(encoding="utf-8"))
    dstep = ddoc["jobs"]["discover"]["steps"][-1]
    assert set(dstep["env"]) == {"MYLONITE_AUTHORIZE"}


def test_write_workflows_no_secrets_is_byte_identical_to_the_vendored_render(tmp_path):
    """A no-secrets render must be identical to what this template produced
    before the target-secrets ``env:`` token existed — checked against a
    committed fixture (vendored from that pre-existing render, tokens
    already substituted), not a live ``git show``, so this can't break on a
    shallow checkout, a squashed history, a non-git tree, or Windows console
    mojibake from a missing explicit encoding. The original bug left a stray
    blank line where the (empty) token used to be.

    The fixture's ``__MYLONITE_VERSION__`` token was substituted with the
    version current when it was vendored, so this compares against a
    re-rendered copy of the fixture text with today's version substituted
    in, not the live package version directly.
    """
    for name in _TEMPLATES:
        base_text = (_NO_SECRETS_RENDER_DIR / name).read_text(encoding="utf-8")
        base_text = base_text.replace('"mylonite==0.10.4"', f'"mylonite=={__version__}"')

        written = write_workflows(tmp_path, runs_on="ubuntu-latest")
        actual_text = next(p for p in written if p.name == name).read_text(encoding="utf-8")

        assert actual_text == base_text, name


def test_write_workflows_target_secrets_render_an_env_line(tmp_path):
    """#185: a target with a header secret renders an env: entry mapped to a
    repository secret of the same name, in the step that runs pytest."""
    written = write_workflows(
        tmp_path,
        runs_on="ubuntu-latest",
        target_env_vars=["MYLONITE_TARGET_HEADERS_X_API_KEY"],
    )
    gate = next(p for p in written if p.name == "mylonite-gate.yml")
    doc = yaml.safe_load(gate.read_text(encoding="utf-8"))
    step = doc["jobs"]["gate"]["steps"][-1]
    assert step["env"] == {
        "MYLONITE_TARGET_HEADERS_X_API_KEY": "${{ secrets.MYLONITE_TARGET_HEADERS_X_API_KEY }}"
    }

    discovery = next(p for p in written if p.name == "mylonite-discovery.yml")
    ddoc = yaml.safe_load(discovery.read_text(encoding="utf-8"))
    dstep = ddoc["jobs"]["discover"]["steps"][-1]
    assert dstep["env"]["MYLONITE_TARGET_HEADERS_X_API_KEY"] == (
        "${{ secrets.MYLONITE_TARGET_HEADERS_X_API_KEY }}"
    )
    assert dstep["env"]["MYLONITE_AUTHORIZE"] == "${{ vars.MYLONITE_AUTHORIZE }}"


# ---------------------------------------------------------------------------
# gate_dir must render relative to repo_root, never a machine-local absolute
# path — a workflow file checked into someone else's repo must not leak this
# machine's directory layout.
# ---------------------------------------------------------------------------


def test_write_workflows_relativizes_an_absolute_gate_dir(tmp_path):
    """An absolute gate_dir under repo_root (exactly what
    resolve_gate_out_dir produces) is rendered relative in the workflow —
    never the machine-local absolute path."""
    repo_root = tmp_path
    absolute_gate_dir = repo_root / ".mylonite" / "gate"
    written = write_workflows(repo_root, runs_on="ubuntu-latest", gate_dir=absolute_gate_dir)

    gate = next(p for p in written if p.name == "mylonite-gate.yml")
    text = gate.read_text(encoding="utf-8")
    assert str(absolute_gate_dir) not in text
    assert "pytest .mylonite/gate -q -ra" in text

    discovery = next(p for p in written if p.name == "mylonite-discovery.yml")
    dtext = discovery.read_text(encoding="utf-8")
    assert str(absolute_gate_dir) not in dtext
    assert "--target-file .mylonite/gate/target.yaml" in dtext


def test_write_workflows_relativizes_from_a_nested_absolute_gate_dir(tmp_path):
    """Same as above but with an extra path segment, to catch an
    accidentally-hardcoded '.mylonite/gate' rather than a genuine relativize."""
    repo_root = tmp_path
    absolute_gate_dir = repo_root / "custom" / "out" / "gate"
    written = write_workflows(repo_root, runs_on="ubuntu-latest", gate_dir=absolute_gate_dir)
    gate = next(p for p in written if p.name == "mylonite-gate.yml")
    text = gate.read_text(encoding="utf-8")
    assert str(absolute_gate_dir) not in text
    assert "pytest custom/out/gate -q -ra" in text


def test_write_workflows_raises_when_gate_dir_is_outside_the_repo_root(tmp_path):
    from mylonite.gate.pr import GatePrError

    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    outside_gate_dir = tmp_path / "elsewhere" / "gate"

    with pytest.raises(GatePrError, match="not inside the repository root"):
        write_workflows(repo_root, runs_on="ubuntu-latest", gate_dir=outside_gate_dir)


def test_write_workflows_end_to_end_from_a_subdirectory_stays_relative(tmp_path, monkeypatch):
    """The full chain a real `gate --workflows` run from a subdirectory goes
    through: resolve_gate_out_dir anchors --out as an ABSOLUTE path at the
    repo root, and write_workflows must still render it relative."""
    from mylonite.gate import pr as pr_mod
    from mylonite.gate.wiring import resolve_gate_out_dir

    subprocess.run(["git", "init", str(tmp_path)], check=True, capture_output=True)
    subdir = tmp_path / "sub" / "dir"
    subdir.mkdir(parents=True)
    monkeypatch.chdir(subdir)

    out = resolve_gate_out_dir(
        Path(".mylonite") / "gate", open_pr=False, workflows=True, pr_mod=pr_mod
    )
    assert out.is_absolute()
    root = pr_mod.resolve_repo_root()

    written = write_workflows(root, gate_dir=out)
    gate = next(p for p in written if p.name == "mylonite-gate.yml")
    text = gate.read_text(encoding="utf-8")
    assert str(tmp_path) not in text
    assert "pytest .mylonite/gate -q -ra" in text


@pytest.mark.parametrize(
    ("name", "job"), [("mylonite-gate.yml", "gate"), ("mylonite-discovery.yml", "discover")]
)
def test_target_secrets_are_checked_non_empty_before_the_gate_runs(tmp_path, name, job):
    """GitHub renders a missing ``${{ secrets.X }}`` as an empty string, and an
    empty value counts as set when the target file is expanded, so the target
    would launch with an empty credential. Each workflow checks every target
    secret is non-empty in its own step, before the step that runs the gate."""
    import shutil

    names = ["MYLONITE_TARGET_HEADERS_X_API_KEY", "MYLONITE_TARGET_ENV_DB_TOKEN"]
    written = write_workflows(tmp_path, runs_on="ubuntu-latest", target_env_vars=names)
    doc = yaml.safe_load(next(p for p in written if p.name == name).read_text(encoding="utf-8"))
    steps = doc["jobs"][job]["steps"]
    check = steps[-2]
    assert check["env"] == {n: f"${{{{ secrets.{n} }}}}" for n in names}
    for n in names:
        assert f'[ -n "${n}" ]' in check["run"]
    # A self-hosted Windows runner (a documented `runs-on` option) defaults
    # to pwsh, where `[ -n ... ]` is a syntax error. Pin bash explicitly.
    assert check["shell"] == "bash"

    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash not available to execute the rendered check")
    base_env = {"PATH": __import__("os").environ.get("PATH", "")}
    empty = subprocess.run(
        [bash, "-c", check["run"]],
        env={**base_env, names[0]: "set", names[1]: ""},
        capture_output=True,
        text=True,
    )
    assert empty.returncode == 1
    assert f"::error::secret {names[1]} is empty" in empty.stdout
    full = subprocess.run(
        [bash, "-c", check["run"]],
        env={**base_env, names[0]: "set", names[1]: "set"},
        capture_output=True,
        text=True,
    )
    assert full.returncode == 0, full.stdout + full.stderr
