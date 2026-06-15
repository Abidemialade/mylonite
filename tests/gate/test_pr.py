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
    monkeypatch.chdir(tmp_path)
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
        open_pr=False,
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
        open_or_print_pr(paths, branch="b", pr_title="t", pr_body="x", open_pr=False, _run=run)
