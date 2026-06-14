from pathlib import Path

from mylonite.gate.pr import GatePaths, PrResult, open_or_print_pr


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
        calls.append(cmd)

        class _CP:  # completed-process-ish
            returncode = 0
            stdout = ""
            stderr = ""

        return _CP()

    run.calls = calls  # type: ignore[attr-defined]
    return run


def test_print_path_when_open_pr_false(tmp_path, capsys):
    paths = _make_artifacts(tmp_path)
    result = open_or_print_pr(
        paths,
        branch="mylonite/gate-x",
        pr_title="Gate: x",
        pr_body="body",
        open_pr=False,
        _run=_fake_runner_recording(),
    )
    assert isinstance(result, PrResult)
    assert result.opened is False
    out = capsys.readouterr().out
    assert "mylonite/gate-x" in out
    assert "gh pr create" in out  # prints the exact command to run by hand
