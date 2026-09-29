"""Tests for ``mylonite.gate.wiring``'s ``open_pr_fn`` factory.

Covers what the CLI-facing collaborator does that ``run_gate`` itself is
Typer-agnostic about: computing the gate branch name from the kept findings
(#202), and writing the redacted target file / secrets notice before the
workflows are scaffolded so the workflow's own ``env:`` has something to
substitute (#185).
"""

from __future__ import annotations

import subprocess
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
        runs_on="ubuntu-latest", workflows=True, target_file=target_file, pr_mod=pr_mod
    )
    out_dir = tmp_path / ".mylonite" / "gate"
    out_dir.mkdir(parents=True)

    open_pr_fn(
        out_dir=out_dir,
        findings=[(_exploit("p1"), None)],
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
        runs_on="ubuntu-latest", workflows=False, target_file=None, pr_mod=pr_mod
    )
    out_dir = tmp_path / ".mylonite" / "gate"
    out_dir.mkdir(parents=True)

    open_pr_fn(
        out_dir=out_dir,
        findings=[(_exploit("p1"), None)],
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


def test_resolve_gate_out_dir_is_a_no_op_for_an_absolute_out(tmp_path):
    """An explicit --out (already absolute) is left alone — only the default
    relative layout is anchored at the repo root."""
    subprocess.run(["git", "init", str(tmp_path)], check=True, capture_output=True)
    out = tmp_path / "custom" / "gate"
    resolved = resolve_gate_out_dir(out, open_pr=True, workflows=False, pr_mod=pr_mod)
    assert resolved == out


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
