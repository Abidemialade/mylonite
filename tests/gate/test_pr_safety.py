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


def test_rerun_over_an_existing_branch_reports_already_proposed(tmp_path: Path) -> None:
    """A re-run that re-finds the same gated pattern hits the same
    deterministic branch name. That's not a PR-flow failure: it's this
    run's own earlier output, already proposed, so `gate` reports it and
    exits cleanly instead of failing on exit 8."""
    repo = _init_repo(tmp_path / "repo")
    # A previous run's branch, carrying a commit that exists nowhere else.
    _git(repo, "checkout", "-b", "mylonite/gate-x")
    (repo / "work.txt").write_text("unpushed work\n", encoding="utf-8")
    _git(repo, "add", "work.txt")
    _git(repo, "commit", "-m", "unpushed work")
    unpushed_sha = _git(repo, "rev-parse", "HEAD")
    _git(repo, "checkout", "main")

    result = open_or_print_pr(
        _gate_paths(repo),
        branch="mylonite/gate-x",
        pr_title="t",
        pr_body="x",
        open_pr=True,
        base="main",
    )

    assert result.opened is False
    assert result.already_proposed is True
    # Neither the pre-existing branch nor its commit are touched.
    assert _git(repo, "rev-parse", "mylonite/gate-x") == unpushed_sha
    assert _git(repo, "rev-parse", "--abbrev-ref", "HEAD") == "main"


def test_branch_only_on_origin_reports_already_proposed(tmp_path: Path) -> None:
    """A nightly discovery job is almost always a FRESH clone: a re-found
    finding then has no LOCAL branch to collide with at all -- only
    `origin` has it, from an earlier run's push. `gate` must recognize that
    BEFORE creating a new local branch, committing, or pushing -- not only
    the local-branch-collision shape the test above covers.
    """
    repo = _init_repo(tmp_path / "repo")
    _with_local_origin(tmp_path, repo)
    # An earlier run: proposed, pushed, and the local branch is gone --
    # exactly what a fresh clone on a later night sees.
    _git(repo, "checkout", "-b", "mylonite/gate-x")
    (repo / "work.txt").write_text("proposed earlier\n", encoding="utf-8")
    _git(repo, "add", "work.txt")
    _git(repo, "commit", "-m", "proposed earlier")
    origin_sha = _git(repo, "rev-parse", "mylonite/gate-x")
    _git(repo, "push", "origin", "mylonite/gate-x")
    _git(repo, "checkout", "main")
    _git(repo, "branch", "-D", "mylonite/gate-x")

    calls: list[list[str]] = []

    def run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(list(cmd))
        return subprocess.run(cmd, text=True, capture_output=True, check=False, **kwargs)

    result = open_or_print_pr(
        _gate_paths(repo),
        branch="mylonite/gate-x",
        pr_title="t",
        pr_body="x",
        open_pr=True,
        base="main",
        _run=run,
    )

    assert result.opened is False
    assert result.already_proposed is True
    # Nothing destructive ran at all -- not even a local checkout -b, let
    # alone an add, commit or push.
    assert not any(c[:3] == ["git", "checkout", "-b"] for c in calls)
    assert not any(c[:2] == ["git", "add"] for c in calls)
    assert not any(c[:2] == ["git", "commit"] for c in calls)
    assert not any(c[:2] == ["git", "push"] for c in calls)
    # The repo stays exactly where it started: on `main`, with no local
    # branch of this name ever created.
    assert _git(repo, "rev-parse", "--abbrev-ref", "HEAD") == "main"
    absent = subprocess.run(
        ["git", "rev-parse", "--verify", "--quiet", "refs/heads/mylonite/gate-x"],
        cwd=str(repo),
        capture_output=True,
        text=True,
    )
    assert absent.returncode != 0
    # origin's branch is untouched.
    assert _git(tmp_path / "origin.git", "rev-parse", "mylonite/gate-x") == origin_sha


def test_missing_origin_falls_through_honestly_instead_of_claiming_proposed(
    tmp_path: Path,
) -> None:
    """No `origin` remote at all (the shape a network failure or a
    never-configured remote also produces for `ls-remote`) must never be
    read as "already proposed" -- that's a guess this check has no
    business making. `gate` falls through to the normal flow, which here
    means `checkout -b` succeeds (no local collision either) and the run
    fails later, honestly, when `git push` has nothing to push to."""
    repo = _init_repo(tmp_path / "repo")  # no `origin` remote configured

    calls: list[list[str]] = []

    def run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(list(cmd))
        return subprocess.run(cmd, text=True, capture_output=True, check=False, **kwargs)

    with pytest.raises(GatePrError, match="git push"):
        open_or_print_pr(
            _gate_paths(repo),
            branch="mylonite/gate-x",
            pr_title="t",
            pr_body="x",
            open_pr=True,
            base="main",
            _run=run,
        )

    # It did NOT stop at the remote check with a false "already proposed" --
    # it proceeded exactly as if there were no remote to ask at all.
    assert ["git", "checkout", "-b", "mylonite/gate-x"] in calls
    assert ["git", "commit", "-m", "t"] in calls
    assert _git(repo, "rev-parse", "--abbrev-ref", "HEAD") == "main"
    # The gate branch and its commit are still kept (DCR-0017's rule),
    # exactly as a push failure for any other reason already behaves.
    assert _git(repo, "log", "-1", "--format=%s", "mylonite/gate-x") == "t"


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


# ---------------------------------------------------------------------------
# After the gate commit exists, the run returns to where it started and keeps
# the gate branch: on success, and when push or `gh pr create` fails.
# ---------------------------------------------------------------------------


def _real_git_fake_gh(*, gh_rc: int = 0):
    """Runs git for real; answers `gh` (auth status, pr create) without a network."""

    def run(cmd, **kwargs):
        if cmd[0] == "gh":
            create = cmd[:3] == ["gh", "pr", "create"]

            class _CP:
                returncode = gh_rc if create else 0
                stdout = "https://github.com/o/r/pull/1\n" if create and gh_rc == 0 else ""
                stderr = "gh: could not create the pull request" if create and gh_rc else ""

            return _CP()
        return subprocess.run(cmd, text=True, capture_output=True, check=False, **kwargs)

    return run


def _with_local_origin(tmp_path: Path, repo: Path) -> None:
    bare = tmp_path / "origin.git"
    subprocess.run(["git", "init", "--bare", "-q", str(bare)], check=True, capture_output=True)
    _git(repo, "remote", "add", "origin", str(bare))


def _open(repo: Path, run) -> object:
    return open_or_print_pr(
        _gate_paths(repo),
        branch="mylonite/gate-x",
        pr_title="t",
        pr_body="x",
        open_pr=True,
        base="main",
        _run=run,
    )


def test_success_returns_to_the_original_branch_and_keeps_the_gate_branch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(pr_mod.shutil, "which", lambda _: "/usr/bin/gh")
    repo = _init_repo(tmp_path / "repo")
    _with_local_origin(tmp_path, repo)

    result = _open(repo, _real_git_fake_gh())

    assert getattr(result, "opened", False) is True
    assert _git(repo, "rev-parse", "--abbrev-ref", "HEAD") == "main"
    gate_sha = _git(repo, "rev-parse", "mylonite/gate-x")
    assert getattr(result, "commit_sha", None) == gate_sha
    out = capsys.readouterr().out
    assert "'mylonite/gate-x' is kept" in out
    assert "back on 'main'" in out


def test_push_failure_returns_to_the_original_branch_and_keeps_the_gate_branch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pr_mod.shutil, "which", lambda _: "/usr/bin/gh")
    repo = _init_repo(tmp_path / "repo")  # no `origin` remote: the push fails

    with pytest.raises(GatePrError, match="git push") as excinfo:
        _open(repo, _real_git_fake_gh())

    assert "'mylonite/gate-x' is kept" in str(excinfo.value)
    assert "back on 'main'" in str(excinfo.value)
    assert _git(repo, "rev-parse", "--abbrev-ref", "HEAD") == "main"
    assert _git(repo, "log", "-1", "--format=%s", "mylonite/gate-x") == "t"


def test_gh_failure_returns_to_the_original_branch_and_keeps_the_gate_branch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pr_mod.shutil, "which", lambda _: "/usr/bin/gh")
    repo = _init_repo(tmp_path / "repo")
    _with_local_origin(tmp_path, repo)

    with pytest.raises(GatePrError, match="gh pr create failed") as excinfo:
        _open(repo, _real_git_fake_gh(gh_rc=1))

    assert "'mylonite/gate-x' is kept" in str(excinfo.value)
    assert _git(repo, "rev-parse", "--abbrev-ref", "HEAD") == "main"
    assert _git(repo, "log", "-1", "--format=%s", "mylonite/gate-x") == "t"


def test_gh_missing_returns_to_the_original_branch_and_keeps_the_gate_branch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pr_mod.shutil, "which", lambda _: None)
    repo = _init_repo(tmp_path / "repo")

    result = _open(repo, _real_git_fake_gh())

    assert getattr(result, "opened", True) is False
    assert _git(repo, "rev-parse", "--abbrev-ref", "HEAD") == "main"
    assert _git(repo, "log", "-1", "--format=%s", "mylonite/gate-x") == "t"


# ---------------------------------------------------------------------------
# A detached HEAD (common in CI) is restored to the same commit.
# ---------------------------------------------------------------------------


def test_detached_head_is_restored_after_a_failed_commit(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path / "repo")
    start = _git(repo, "rev-parse", "HEAD")
    _git(repo, "checkout", "-q", "--detach")
    hook = repo / ".git" / "hooks" / "pre-commit"
    hook.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    hook.chmod(0o755)

    with pytest.raises(GatePrError):
        _open(repo, _real_git_fake_gh())

    assert _git(repo, "rev-parse", "--abbrev-ref", "HEAD") == "HEAD"  # still detached
    assert _git(repo, "rev-parse", "HEAD") == start
    assert _git(repo, "branch", "--list", "mylonite/gate-x") == ""


def test_detached_head_is_restored_after_a_successful_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(pr_mod.shutil, "which", lambda _: "/usr/bin/gh")
    repo = _init_repo(tmp_path / "repo")
    _with_local_origin(tmp_path, repo)
    start = _git(repo, "rev-parse", "HEAD")
    _git(repo, "checkout", "-q", "--detach")

    _open(repo, _real_git_fake_gh())

    assert _git(repo, "rev-parse", "--abbrev-ref", "HEAD") == "HEAD"
    assert _git(repo, "rev-parse", "HEAD") == start
    assert _git(repo, "log", "-1", "--format=%s", "mylonite/gate-x") == "t"
    assert f"detached commit {start[:12]}" in capsys.readouterr().out


def test_a_git_error_checking_the_index_is_not_reported_as_staged_files(tmp_path: Path) -> None:
    def run(cmd, **kwargs):
        class _CP:
            returncode = 128 if cmd[:3] == ["git", "diff", "--cached"] else 0
            stdout = "main\n" if cmd[:3] == ["git", "rev-parse", "--abbrev-ref"] else ""
            stderr = "fatal: index file corrupt" if cmd[:3] == ["git", "diff", "--cached"] else ""

        return _CP()

    with pytest.raises(GatePrError, match="rc=128") as excinfo:
        _open(_init_repo(tmp_path / "repo"), run)
    assert "staged" not in str(excinfo.value)


# ---------------------------------------------------------------------------
# Git errors on the guard paths are reported as git errors.
# ---------------------------------------------------------------------------


def _failing_git(fail_cmd: list[str], *, rc: int = 128, stderr: str = "fatal: boom"):
    """Runs git for real, except ``fail_cmd``, which returns ``rc``."""

    def run(cmd, **kwargs):
        if list(cmd) == fail_cmd:

            class _CP:
                returncode = rc
                stdout = ""

            _CP.stderr = stderr
            return _CP()
        if cmd[0] == "gh":
            return _real_git_fake_gh()(cmd, **kwargs)
        return subprocess.run(cmd, text=True, capture_output=True, check=False, **kwargs)

    return run


def test_a_failing_git_status_is_a_git_error_not_a_clean_tree(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path / "repo")
    run = _failing_git(["git", "status", "--porcelain", "--untracked-files=no"])
    with pytest.raises(GatePrError, match=r"git status failed \(rc=128\): fatal: boom"):
        ensure_clean_tree(repo, _run=run)


def test_a_failing_git_status_exits_8_at_preflight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import typer

    from mylonite.gate.wiring import resolve_gate_out_dir_or_exit

    repo = _init_repo(tmp_path / "repo")
    monkeypatch.chdir(repo)
    run = _failing_git(["git", "status", "--porcelain", "--untracked-files=no"])
    real = pr_mod.ensure_clean_tree
    monkeypatch.setattr(pr_mod, "ensure_clean_tree", lambda root: real(root, _run=run))

    with pytest.raises(typer.Exit) as excinfo:
        resolve_gate_out_dir_or_exit(
            Path(".mylonite") / "gate", open_pr=True, workflows=False, pr_mod=pr_mod
        )
    assert excinfo.value.exit_code == 8


def test_a_failing_rev_parse_after_the_commit_still_returns_to_the_original_branch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pr_mod.shutil, "which", lambda _: "/usr/bin/gh")
    repo = _init_repo(tmp_path / "repo")
    _with_local_origin(tmp_path, repo)

    with pytest.raises(GatePrError, match="git rev-parse HEAD failed") as excinfo:
        _open(repo, _failing_git(["git", "rev-parse", "HEAD"]))

    assert "'mylonite/gate-x' is kept" in str(excinfo.value)
    assert _git(repo, "rev-parse", "--abbrev-ref", "HEAD") == "main"
    assert _git(repo, "log", "-1", "--format=%s", "mylonite/gate-x") == "t"
