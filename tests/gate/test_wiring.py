"""Tests for ``mylonite.gate.wiring``'s ``open_pr_fn`` factory.

Covers what the CLI-facing collaborator does that ``run_gate`` itself is
Typer-agnostic about: computing the gate branch name from the kept findings
(#202), and writing the redacted target file / secrets notice before the
workflows are scaffolded so the workflow's own ``env:`` has something to
substitute (#185).
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from mylonite.gate import pr as pr_mod
from mylonite.gate.wiring import _gate_branch, make_open_pr_fn, resolve_gate_out_dir


def _exploit(pattern_id: str) -> Any:
    return SimpleNamespace(pattern_id=pattern_id)


class _FakePrMod:
    """Stands in for ``mylonite.gate.pr``: records the call, never touches git."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def GatePaths(self, **kwargs: Any) -> Any:
        return SimpleNamespace(**kwargs)

    def resolve_repo_root(self) -> Path:
        return Path.cwd()

    def resolve_default_base(self, repo_root: Path) -> str:
        return "detected-default"

    def open_or_print_pr(self, paths: Any, **kwargs: Any) -> Any:
        self.calls.append({"paths": paths, **kwargs})
        return SimpleNamespace(opened=False, branch=kwargs.get("branch"))


def test_gate_branch_single_kept_finding_keeps_the_exact_pattern_id_name() -> None:
    assert _gate_branch([(_exploit("indirect-injection-x"), None)]) == (
        "mylonite/gate-indirect-injection-x"
    )


def test_gate_branch_several_kept_findings_uses_a_stable_hash_with_the_prefix() -> None:
    findings = [(_exploit("b-pattern"), None), (_exploit("a-pattern"), None)]
    branch = _gate_branch(findings)
    assert branch.startswith("mylonite/gate-")
    assert branch != "mylonite/gate-b-pattern"
    assert branch != "mylonite/gate-a-pattern"
    # Deterministic: order of the input list must not change the hash.
    assert _gate_branch(list(reversed(findings))) == branch


def test_open_pr_fn_writes_target_before_workflows_and_threads_secret_vars(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.chdir(tmp_path)
    target_file = tmp_path / "target.yaml"
    target_file.write_text(
        "family: demo\ncommand: python\nargs: []\n"
        "headers:\n  X-Api-Key: sk-live-abcdefghijklmnopqrstuvwx\n",  # pragma: allowlist secret
        encoding="utf-8",
    )
    pr_mod = _FakePrMod()
    open_pr_fn = make_open_pr_fn(
        runs_on="ubuntu-latest",
        workflows=True,
        target_file=target_file,
        pr_mod=pr_mod,
        model="anthropic/claude-haiku-4-5-20251001",
    )
    out_dir = tmp_path / ".mylonite" / "gate"
    out_dir.mkdir(parents=True)

    open_pr_fn(
        out_dir=out_dir,
        findings=[(_exploit("p1"), SimpleNamespace(test_filename="test_p1.py"))],
        body="## What Mylonite found\n",
        open_pr=False,
    )

    written_target = (out_dir / "target.yaml").read_text(encoding="utf-8")
    assert "sk-live-abcdefghijklmnopqrstuvwx" not in written_target  # pragma: allowlist secret
    assert "MYLONITE_TARGET_HEADERS_X_API_KEY" in written_target

    gate_workflow = (tmp_path / ".github" / "workflows" / "mylonite-gate.yml").read_text(
        encoding="utf-8"
    )
    assert "MYLONITE_TARGET_HEADERS_X_API_KEY" in gate_workflow
    assert "${{ secrets.MYLONITE_TARGET_HEADERS_X_API_KEY }}" in gate_workflow

    # The PR body pr_mod actually received names the repository secret to add.
    assert pr_mod.calls, "expected open_or_print_pr to be called"
    body_sent = pr_mod.calls[0]["pr_body"]
    assert "MYLONITE_TARGET_HEADERS_X_API_KEY" in body_sent
    assert "repository secret" in body_sent.lower()


def test_open_pr_fn_no_target_file_no_secrets_notice(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.chdir(tmp_path)
    pr_mod = _FakePrMod()
    open_pr_fn = make_open_pr_fn(
        runs_on="ubuntu-latest",
        workflows=False,
        target_file=None,
        pr_mod=pr_mod,
        model="anthropic/claude-haiku-4-5-20251001",
    )
    out_dir = tmp_path / ".mylonite" / "gate"
    out_dir.mkdir(parents=True)

    open_pr_fn(
        out_dir=out_dir,
        findings=[(_exploit("p1"), SimpleNamespace(test_filename="test_p1.py"))],
        body="## What Mylonite found\n",
        open_pr=False,
    )

    body_sent = pr_mod.calls[0]["pr_body"]
    assert "repository secret" not in body_sent.lower()


# ---------------------------------------------------------------------------
# #203: resolve_gate_out_dir
# ---------------------------------------------------------------------------


def test_resolve_gate_out_dir_is_a_no_op_without_open_pr_or_workflows(tmp_path, monkeypatch):
    """A plain `gate` (neither flag) needs no git repository at all."""
    monkeypatch.chdir(tmp_path)
    out = Path(".mylonite") / "gate"
    resolved = resolve_gate_out_dir(out, open_pr=False, workflows=False, pr_mod=pr_mod)
    assert resolved == out


def test_resolve_gate_out_dir_is_a_no_op_for_an_absolute_out_inside_the_repo(tmp_path, monkeypatch):
    """An explicit --out (already absolute) is returned unchanged when it's
    inside the repository root — only the default relative layout is
    anchored there; an absolute one is merely checked, not rewritten."""
    subprocess.run(["git", "init", str(tmp_path)], check=True, capture_output=True)
    monkeypatch.chdir(tmp_path)
    out = tmp_path / "custom" / "gate"
    resolved = resolve_gate_out_dir(out, open_pr=True, workflows=False, pr_mod=pr_mod)
    assert resolved == out


def test_resolve_gate_out_dir_raises_for_an_absolute_out_outside_the_repo(tmp_path, monkeypatch):
    """The other half of the same check: an explicit absolute --out that
    sits OUTSIDE the repository root must raise, not silently accept a path
    later steps (the committed `git add` list, the workflow's __GATE_DIR__)
    could never express relative to the repo."""
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", str(repo)], check=True, capture_output=True)
    monkeypatch.chdir(repo)
    outside = tmp_path / "elsewhere" / "gate"
    with pytest.raises(pr_mod.GatePrError, match="not inside the repository root"):
        resolve_gate_out_dir(outside, open_pr=True, workflows=False, pr_mod=pr_mod)


def test_resolve_gate_out_dir_anchors_a_relative_out_at_the_repo_root(tmp_path, monkeypatch):
    subprocess.run(["git", "init", str(tmp_path)], check=True, capture_output=True)
    subdir = tmp_path / "sub" / "dir"
    subdir.mkdir(parents=True)
    monkeypatch.chdir(subdir)

    resolved = resolve_gate_out_dir(
        Path(".mylonite") / "gate", open_pr=True, workflows=False, pr_mod=pr_mod
    )

    assert resolved.resolve() == (tmp_path / ".mylonite" / "gate").resolve()


def test_resolve_gate_out_dir_anchors_when_only_workflows_is_set(tmp_path, monkeypatch):
    subprocess.run(["git", "init", str(tmp_path)], check=True, capture_output=True)
    subdir = tmp_path / "sub"
    subdir.mkdir()
    monkeypatch.chdir(subdir)

    resolved = resolve_gate_out_dir(
        Path(".mylonite") / "gate", open_pr=False, workflows=True, pr_mod=pr_mod
    )

    assert resolved.resolve() == (tmp_path / ".mylonite" / "gate").resolve()


def test_resolve_gate_out_dir_outside_a_repo_raises(tmp_path, monkeypatch):
    outside = tmp_path / "not-a-repo"
    outside.mkdir()
    monkeypatch.chdir(outside)

    with pytest.raises(pr_mod.GatePrError, match="not inside a git repository"):
        resolve_gate_out_dir(
            Path(".mylonite") / "gate", open_pr=True, workflows=False, pr_mod=pr_mod
        )


# ---------------------------------------------------------------------------
# budget_hint's per-routing wording, and resolve_gate_out_dir_or_exit's
# repo-root containment check.
# ---------------------------------------------------------------------------


def test_budget_hint_custom_target_points_at_weakness_classes_key(tmp_path):
    from mylonite.gate.wiring import budget_hint

    target_file = tmp_path / "app.yaml"
    hint = budget_hint("custom", target_file)
    assert "--weakness-classes" not in hint
    assert "--weakness-class" not in hint
    assert "weakness_classes:" in hint
    assert str(target_file) in hint


def test_budget_hint_reference_target_says_no_per_class_filter():
    from mylonite.gate.wiring import budget_hint

    hint = budget_hint("reference", None)
    assert "--weakness-class" not in hint
    assert "weakness_classes:" not in hint
    assert "no per-class filter" in hint


def test_budget_hint_mcp_bundled_target_says_no_per_class_filter():
    from mylonite.gate.wiring import budget_hint

    hint = budget_hint("mcp", None)
    assert "no per-class filter" in hint


def test_resolve_gate_out_dir_or_exit_returns_the_resolved_path(tmp_path, monkeypatch):
    import subprocess

    from mylonite.gate.wiring import resolve_gate_out_dir_or_exit

    subprocess.run(["git", "init", str(tmp_path)], check=True, capture_output=True)
    monkeypatch.chdir(tmp_path)
    resolved = resolve_gate_out_dir_or_exit(
        Path(".mylonite") / "gate", open_pr=True, workflows=False, pr_mod=pr_mod
    )
    assert resolved.resolve() == (tmp_path / ".mylonite" / "gate").resolve()


def test_resolve_gate_out_dir_or_exit_outside_a_repo_exits_8(tmp_path, monkeypatch):
    import typer

    from mylonite.gate.wiring import resolve_gate_out_dir_or_exit

    monkeypatch.chdir(tmp_path)  # not a git repo
    with pytest.raises(typer.Exit) as excinfo:
        resolve_gate_out_dir_or_exit(
            Path(".mylonite") / "gate", open_pr=True, workflows=False, pr_mod=pr_mod
        )
    assert excinfo.value.exit_code == 8


# ---------------------------------------------------------------------------
# target.yaml co-located with each kept multi-finding test, not just the
# gate root.
# ---------------------------------------------------------------------------


def _real_exploit(pattern_id: str, metadata: dict[str, str] | None = None):
    """A real ExploitRecord whose pattern_id is a bundled seed, so
    ReferencePytestGenerator can actually emit source for it."""
    from mylonite.contracts import AdapterResponse, ComplianceTags, ExploitRecord, Payload

    return ExploitRecord(
        target_id="mcp:custom",
        pattern_id=pattern_id,
        payload=Payload(
            pattern_id=pattern_id, channel="tool-result", body="poison", metadata=metadata or {}
        ),
        response=AdapterResponse(
            payload_pattern_id=pattern_id, raw_response="did it", tool_calls=["remember"]
        ),
        success_reason="the agent stored and later acted on the planted content",
        compliance=ComplianceTags(owasp_asi=["ASI01"]),
    )


def test_multi_finding_kept_dirs_each_get_a_redacted_target_yaml(tmp_path, monkeypatch):
    """Every KEPT finding's own directory gets a target.yaml — proven by
    actually loading it (not just checking it exists) — because the emitted
    test's `here = Path(__file__).parent` looks there, not at the gate root.
    The root copy stays too, for the discovery workflow."""
    import subprocess

    from mylonite.contracts import ValidationReport
    from mylonite.gate import pr as real_pr_mod
    from mylonite.gate.orchestrator import ScanOutcomeBundle, run_gate
    from mylonite.gate.wiring import make_open_pr_fn
    from mylonite.plugins._mcp.target_file import load_target_file
    from mylonite.plugins._reference.reference_pytest_generator import ReferencePytestGenerator

    subprocess.run(["git", "init", str(tmp_path)], check=True, capture_output=True)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MYLONITE_TARGET_HEADERS_X_API_KEY", "test-value-not-a-real-secret")

    target_file = tmp_path / "app.yaml"
    target_file.write_text(
        "family: myapp\ncommand: python\nargs: [-m, srv]\n"
        "weakness_classes: [W2]\n"
        "seed_arm:\n  tool: remember\n  args_template: {content: '{payload}'}\n"
        "headers:\n  X-Api-Key: sk-live-abcdefghijklmnopqrstuvwxyz\n",  # pragma: allowlist secret
        encoding="utf-8",
    )

    exploits = [
        _real_exploit("indirect-injection-note-body-direct"),
        _real_exploit("indirect-injection-note-body-roleplay"),
    ]
    kept_report = ValidationReport(test_filename="x.py", kept=True)

    open_pr_fn = make_open_pr_fn(
        runs_on="ubuntu-latest",
        workflows=False,
        target_file=target_file,
        pr_mod=real_pr_mod,
        model="anthropic/claude-haiku-4-5-20251001",
    )
    out_dir = Path(".mylonite") / "gate"

    run_gate(
        out_dir=out_dir,
        scan_fn=lambda: ScanOutcomeBundle(outcome=_found_outcome_2(), exploits=exploits),
        generate_fn=ReferencePytestGenerator().emit,
        validate_fn=lambda generated, _finding_dir: kept_report.model_copy(
            update={"test_filename": generated.filename}
        ),
        open_pr_fn=open_pr_fn,
        open_pr=False,
    )

    from mylonite.gate.orchestrator import _finding_id

    slug_a, slug_b = (_finding_id(e) for e in exploits)

    # Each kept finding's own directory has BOTH the emitted test AND its own
    # target.yaml — the emitted source's `here / "target.yaml"` proves this
    # is exactly where the test looks.
    for slug in (slug_a, slug_b):
        finding_dir = out_dir / slug
        emitted = next(finding_dir.glob("test_*.py"))
        assert 'here / "target.yaml"' in emitted.read_text(encoding="utf-8")
        finding_target = finding_dir / "target.yaml"
        assert finding_target.is_file()
        # Redaction applies to every copy, not just the root's.
        secret = "sk-live-abcdefghijklmnopqrstuvwxyz"  # pragma: allowlist secret
        assert secret not in finding_target.read_text(encoding="utf-8")
        loaded = load_target_file(finding_target)
        assert loaded.family == "myapp"

    # The root copy still exists too (the discovery workflow reads it).
    assert (out_dir / "target.yaml").is_file()

    # Proof, not inference: the emitted directory actually collects cleanly
    # under pytest (no import/syntax error in either emitted test file).
    collect = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", str(out_dir)],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    assert collect.returncode == 0, collect.stdout + collect.stderr


def test_multi_finding_live_run_resolves_the_per_finding_target_yaml(tmp_path, monkeypatch):
    """--collect-only never enters the emitted test's body, so it can't prove
    the target-loading path actually works. This runs the REAL emitted test
    with MYLONITE_LIVE_TARGET=1 (a genuine `pytest` subprocess, offline: the
    target command names a module that doesn't exist, so the run fails fast
    at launch, before any LLM call): it must fail with evidence it actually
    tried to launch the target (found target.yaml, went further), then --
    once that finding's target.yaml is deleted -- fail specifically with
    FileNotFoundError naming target.yaml.
    """
    import subprocess

    from mylonite.contracts import ValidationReport
    from mylonite.contracts.exec_context import ExecContext
    from mylonite.gate import pr as real_pr_mod
    from mylonite.gate.orchestrator import ScanOutcomeBundle, _finding_id, run_gate
    from mylonite.gate.wiring import make_open_pr_fn
    from mylonite.plugins._reference.reference_pytest_generator import ReferencePytestGenerator

    subprocess.run(["git", "init", str(tmp_path)], check=True, capture_output=True)
    monkeypatch.chdir(tmp_path)

    target_file = tmp_path / "app.yaml"
    target_file.write_text(
        "family: myapp\ncommand: python\nargs: [-m, no_such_srv_mod_xyz]\n"
        "weakness_classes: [W2]\n"
        "seed_arm:\n  tool: remember\n  args_template: {content: '{payload}'}\n",
        encoding="utf-8",
    )
    # A model/provider that needs no live key, so _resolve_exec_context
    # resolves without a config file or an API key -- the launch failure
    # below is fully offline.
    metadata = ExecContext(provider="ollama", model="ollama/none").to_metadata()
    # Two findings (multi=True) so the target.yaml under test is the
    # PER-FINDING subdirectory copy, not the flat single-finding layout.
    exploits = [
        _real_exploit("indirect-injection-note-body-direct", metadata=metadata),
        _real_exploit("indirect-injection-note-body-roleplay", metadata=metadata),
    ]
    kept_report = ValidationReport(test_filename="x.py", kept=True)

    open_pr_fn = make_open_pr_fn(
        runs_on="ubuntu-latest",
        workflows=False,
        target_file=target_file,
        pr_mod=real_pr_mod,
        model="anthropic/claude-haiku-4-5-20251001",
    )
    out_dir = Path(".mylonite") / "gate"

    run_gate(
        out_dir=out_dir,
        scan_fn=lambda: ScanOutcomeBundle(outcome=_found_outcome_2(), exploits=exploits),
        generate_fn=ReferencePytestGenerator().emit,
        validate_fn=lambda generated, _finding_dir: kept_report.model_copy(
            update={"test_filename": generated.filename}
        ),
        open_pr_fn=open_pr_fn,
        open_pr=False,
    )

    finding_dir = out_dir / _finding_id(exploits[0])
    assert (finding_dir / "target.yaml").is_file()

    repo_src = str(Path(__file__).resolve().parents[2] / "src")
    # PYTHONUTF8=1 forces the CHILD process's own stdio to UTF-8 regardless of
    # the parent console's codepage. Without it, on a Windows console running
    # under cp1252, the child's em-dash output round-trips as a byte this
    # parent's encoding="utf-8" read cannot decode -- the exact class of bug
    # this test is guarding the emitted test's target-loading path against.
    env = {**os.environ, "MYLONITE_LIVE_TARGET": "1", "PYTHONPATH": repo_src, "PYTHONUTF8": "1"}

    def _run_emitted_test() -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "--no-header", str(finding_dir)],
            cwd=str(tmp_path),
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=120,
        )

    with_target = _run_emitted_test()
    assert with_target.returncode != 0
    combined = with_target.stdout + with_target.stderr
    # It got PAST the file-existence check and tried to actually launch the
    # target -- proof the per-finding target.yaml was found and loaded.
    assert "FileNotFoundError" not in combined
    assert "target.yaml" not in combined or "not found" not in combined

    (finding_dir / "target.yaml").unlink()
    without_target = _run_emitted_test()
    assert without_target.returncode != 0
    combined_without = without_target.stdout + without_target.stderr
    assert "FileNotFoundError" in combined_without
    assert "target.yaml" in combined_without


def _found_outcome_2():
    from mylonite.scan.coverage import Coverage, ScanOutcome

    return ScanOutcome(
        coverage=Coverage.EXERCISED,
        abort=None,
        exercised=2,
        not_tested=0,
        findings=2,
        fallbacks=0,
        exit_code=0,
        operator_message=None,
    )


# ---------------------------------------------------------------------------
# --open-pr pre-flight: a dirty or staged tree, and --base.
# ---------------------------------------------------------------------------


def _committed_repo(repo: Path) -> Path:
    def git(*args: str) -> None:
        subprocess.run(["git", *args], cwd=str(repo), check=True, capture_output=True)

    repo.mkdir(parents=True, exist_ok=True)
    git("init")
    git("config", "user.email", "test@example.com")
    git("config", "user.name", "Test")
    git("config", "commit.gpgsign", "false")
    (repo / "README.md").write_text("init\n", encoding="utf-8")
    git("add", "README.md")
    git("commit", "-m", "init")
    return repo


def test_resolve_gate_out_dir_refuses_a_dirty_tree_with_open_pr(tmp_path, monkeypatch):
    repo = _committed_repo(tmp_path / "repo")
    (repo / "README.md").write_text("edited\n", encoding="utf-8")
    monkeypatch.chdir(repo)
    with pytest.raises(pr_mod.GatePrError, match="uncommitted changes"):
        resolve_gate_out_dir(
            Path(".mylonite") / "gate", open_pr=True, workflows=False, pr_mod=pr_mod
        )


def test_resolve_gate_out_dir_allows_a_dirty_tree_without_open_pr(tmp_path, monkeypatch):
    """`--workflows` alone never commits, so a dirty tree is fine there."""
    repo = _committed_repo(tmp_path / "repo")
    (repo / "README.md").write_text("edited\n", encoding="utf-8")
    monkeypatch.chdir(repo)
    resolved = resolve_gate_out_dir(
        Path(".mylonite") / "gate", open_pr=False, workflows=True, pr_mod=pr_mod
    )
    assert resolved.resolve() == (repo / ".mylonite" / "gate").resolve()


@pytest.mark.parametrize("bad", ["", "-x", "--force", "two words"])
def test_resolve_gate_out_dir_rejects_a_malformed_base(tmp_path, monkeypatch, bad):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(pr_mod.GatePrError, match="--base"):
        resolve_gate_out_dir(
            Path(".mylonite") / "gate", open_pr=False, workflows=False, pr_mod=pr_mod, base=bad
        )


def _run_open_pr_fn(tmp_path: Path, monkeypatch: Any, *, base: str | None) -> _FakePrMod:
    monkeypatch.chdir(tmp_path)
    fake = _FakePrMod()
    open_pr_fn = make_open_pr_fn(
        model="anthropic/claude-haiku-4-5-20251001",
        runs_on="ubuntu-latest",
        workflows=False,
        target_file=None,
        pr_mod=fake,
        base=base,
    )
    out_dir = tmp_path / ".mylonite" / "gate"
    out_dir.mkdir(parents=True)
    open_pr_fn(
        out_dir=out_dir,
        findings=[(_exploit("p1"), SimpleNamespace(test_filename="test_p1.py"))],
        body="body\n",
        open_pr=False,
    )
    return fake


def test_open_pr_fn_passes_an_explicit_base(tmp_path: Path, monkeypatch: Any) -> None:
    fake = _run_open_pr_fn(tmp_path, monkeypatch, base="release/2.x")
    assert fake.calls[0]["base"] == "release/2.x"


def test_open_pr_fn_defaults_to_the_detected_base(tmp_path: Path, monkeypatch: Any) -> None:
    fake = _run_open_pr_fn(tmp_path, monkeypatch, base=None)
    assert fake.calls[0]["base"] == "detected-default"


def test_open_pr_commits_each_findings_own_fixtures_not_a_stale_root_dir(tmp_path):
    """Each kept finding's `fixtures/` is committed with it. A `fixtures/` left
    at the gate root by an earlier run belongs to no kept test and stays out."""
    from mylonite.contracts import ValidationReport

    out_dir = tmp_path / "gate"
    dirs = [out_dir / "a", out_dir / "b"]
    for d in [*dirs, out_dir]:
        (d / "fixtures").mkdir(parents=True)
    captured: list[Any] = []
    fake_pr = SimpleNamespace(
        GatePaths=pr_mod.GatePaths,
        open_or_print_pr=lambda paths, **_k: captured.append(paths),
        resolve_repo_root=lambda: tmp_path,
        resolve_default_base=lambda _root: "main",
    )
    open_pr_fn = make_open_pr_fn(
        runs_on="ubuntu-latest",
        workflows=False,
        target_file=None,
        pr_mod=fake_pr,
        model="anthropic/claude-haiku-4-5-20251001",
    )
    findings = [
        (
            _real_exploit("indirect-injection-note-body-direct"),
            ValidationReport(test_filename="a.py", kept=True),
        ),
        (
            _real_exploit("indirect-injection-note-body-roleplay"),
            ValidationReport(test_filename="b.py", kept=True),
        ),
    ]

    open_pr_fn(out_dir=out_dir, findings=findings, body="b", open_pr=False, kept_dirs=dirs)

    add_paths = captured[0].add_paths
    assert dirs[0] / "fixtures" in add_paths
    assert dirs[1] / "fixtures" in add_paths
    assert out_dir / "fixtures" not in add_paths
