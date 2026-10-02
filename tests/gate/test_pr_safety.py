"""`gate --open-pr` must never lose a user's work.

Every test here drives a real temporary git repository (no network, no
remote): a re-run must not delete a branch it didn't create, a dirty or
staged tree is refused before any spend, and the PR base is the repo's own
default branch unless `--base` says otherwise.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from mylonite.gate import pr as pr_mod
from mylonite.gate.pr import (
    GatePaths,
    GatePrError,
    ensure_clean_tree,
    open_or_print_pr,
    resolve_default_base,
)


def _git(repo: Path, *args: str) -> str:
    cp = subprocess.run(["git", *args], cwd=str(repo), check=True, capture_output=True, text=True)
    return cp.stdout.strip()


def _init_repo(repo: Path, *, branch: str = "main") -> Path:
    repo.mkdir(parents=True, exist_ok=True)
    _git(repo, "init", "-b", branch)
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test")
    _git(repo, "config", "commit.gpgsign", "false")
    (repo / "README.md").write_text("init\n", encoding="utf-8")
    _git(repo, "add", "README.md")
    _git(repo, "commit", "-m", "init")
    return repo


def _gate_paths(repo: Path) -> GatePaths:
    gate_dir = repo / ".mylonite" / "gate"
    gate_dir.mkdir(parents=True, exist_ok=True)
    test_file = gate_dir / "test_security_x.py"
    test_file.write_text("# test\n", encoding="utf-8")
    return GatePaths(
        repo_root=repo,
        gate_dir=gate_dir,
        add_paths=[test_file, gate_dir / "PR_BODY.md"],
    )


# ---------------------------------------------------------------------------
# Rollback deletes only a branch this run created.
# ---------------------------------------------------------------------------


def test_failed_run_keeps_a_branch_that_already_existed(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path / "repo")
    # A previous run's branch, carrying a commit that exists nowhere else.
    _git(repo, "checkout", "-b", "mylonite/gate-x")
    (repo / "work.txt").write_text("unpushed work\n", encoding="utf-8")
    _git(repo, "add", "work.txt")
    _git(repo, "commit", "-m", "unpushed work")
    unpushed_sha = _git(repo, "rev-parse", "HEAD")
    _git(repo, "checkout", "main")

    with pytest.raises(GatePrError, match="already exists"):
        open_or_print_pr(
            _gate_paths(repo),
            branch="mylonite/gate-x",
            pr_title="t",
            pr_body="x",
            open_pr=True,
            base="main",
        )

    # The branch and its commit survive the failed run.
    assert _git(repo, "rev-parse", "mylonite/gate-x") == unpushed_sha
    assert _git(repo, "rev-parse", "--abbrev-ref", "HEAD") == "main"


def test_failed_commit_still_deletes_the_branch_this_run_created(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path / "repo")
    paths = _gate_paths(repo)
    # Make `git commit` fail after `checkout -b` succeeded: a pre-commit hook
    # that always rejects.
    hook = repo / ".git" / "hooks" / "pre-commit"
    hook.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    hook.chmod(0o755)

    with pytest.raises(GatePrError):
        open_or_print_pr(
            paths,
            branch="mylonite/gate-new",
            pr_title="t",
            pr_body="x",
            open_pr=True,
            base="main",
        )

    branches = _git(repo, "branch", "--list", "mylonite/gate-new")
    assert branches == ""
    assert _git(repo, "rev-parse", "--abbrev-ref", "HEAD") == "main"


# ---------------------------------------------------------------------------
# A dirty or staged tree is refused.
# ---------------------------------------------------------------------------


def test_clean_tree_passes(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path / "repo")
    ensure_clean_tree(repo)


def test_untracked_files_are_allowed(tmp_path: Path) -> None:
    """`git add` takes explicit paths, so an untracked file never rides along."""
    repo = _init_repo(tmp_path / "repo")
    (repo / "scratch.txt").write_text("not tracked\n", encoding="utf-8")
    ensure_clean_tree(repo)


def test_modified_tracked_file_is_refused(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path / "repo")
    (repo / "README.md").write_text("edited\n", encoding="utf-8")
    with pytest.raises(GatePrError, match="uncommitted changes") as excinfo:
        ensure_clean_tree(repo)
    assert "\n" not in str(excinfo.value)


def test_staged_file_is_refused(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path / "repo")
    (repo / "new.txt").write_text("staged\n", encoding="utf-8")
    _git(repo, "add", "new.txt")
    with pytest.raises(GatePrError, match="staged") as excinfo:
        ensure_clean_tree(repo)
    assert "\n" not in str(excinfo.value)


def test_open_pr_refuses_to_commit_something_staged_mid_run(tmp_path: Path) -> None:
    """Defence in depth: a file staged after the pre-flight must never be
    swept into the gate commit."""
    repo = _init_repo(tmp_path / "repo")
    (repo / "secret-notes.txt").write_text("private\n", encoding="utf-8")
    _git(repo, "add", "secret-notes.txt")

    with pytest.raises(GatePrError, match="staged"):
        open_or_print_pr(
            _gate_paths(repo),
            branch="mylonite/gate-x",
            pr_title="t",
            pr_body="x",
            open_pr=True,
            base="main",
        )

    assert _git(repo, "branch", "--list", "mylonite/gate-x") == ""
    assert _git(repo, "rev-parse", "--abbrev-ref", "HEAD") == "main"


# ---------------------------------------------------------------------------
# Default-branch detection.
# ---------------------------------------------------------------------------


def test_default_base_comes_from_origin_head(tmp_path: Path) -> None:
    upstream = _init_repo(tmp_path / "upstream", branch="trunk")
    clone = tmp_path / "clone"
    subprocess.run(
        ["git", "clone", "-q", str(upstream), str(clone)], check=True, capture_output=True
    )
    _git(clone, "checkout", "-b", "feature")
    assert resolve_default_base(clone) == "trunk"


def test_default_base_falls_back_to_the_current_branch_upstream(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path / "repo", branch="develop")
    _git(repo, "checkout", "-b", "feature")
    _git(repo, "branch", "--set-upstream-to=develop")
    assert resolve_default_base(repo) == "develop"


def test_default_base_falls_back_to_main(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path / "repo", branch="work")
    assert resolve_default_base(repo) == "main"


def test_default_base_outside_a_repo_is_main(tmp_path: Path) -> None:
    assert resolve_default_base(tmp_path) == "main"


def test_base_reaches_the_printed_command(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path / "repo")
    result = open_or_print_pr(
        _gate_paths(repo),
        branch="mylonite/gate-x",
        pr_title="t",
        pr_body="x",
        open_pr=False,
        base="release/2.x",
    )
    assert result.printed_command is not None
    assert "--base release/2.x" in result.printed_command


def test_base_reaches_gh_pr_create(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def run(cmd, **kwargs):
        calls.append(list(cmd))

        class _CP:
            returncode = 0
            stdout = "main\n" if cmd[:3] == ["git", "rev-parse", "--abbrev-ref"] else ""
            stderr = ""

        return _CP()

    monkeypatch.setattr(pr_mod.shutil, "which", lambda _: "/usr/bin/gh")
    open_or_print_pr(
        _gate_paths(tmp_path),
        branch="mylonite/gate-x",
        pr_title="t",
        pr_body="x",
        open_pr=True,
        base="trunk",
        _run=run,
    )
    gh = next(c for c in calls if c[:3] == ["gh", "pr", "create"])
    assert gh[gh.index("--base") + 1] == "trunk"
