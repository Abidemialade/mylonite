"""``testkit.pending_fix``: a committed gate for a finding that is not fixed yet.

Each case runs a real pytest session in a subprocess, so the ``pytest11``
plugin loads exactly as it does in a consumer's environment.

The lifecycle has three states:

1. the finding is still open: the test is an expected failure and the run is
   green;
2. the fix lands: the test passes, and because the marker is strict the run
   fails with a message that says to remove the marker;
3. the marker is removed: the test is a plain gate that passes, and fails
   again if the fix regresses.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from mylonite import testkit
from mylonite.contracts._types import AdapterResponse, ComplianceTags, ExploitRecord, Payload
from mylonite.plugins._reference.reference_pytest_generator import (
    PENDING_FIX_METADATA_KEY,
    ReferencePytestGenerator,
)


def _run(
    tmp_path: Path, *, extra: tuple[str, ...] = (), env_extra: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    env = {
        k: v
        for k, v in os.environ.items()
        if k not in {"MYLONITE_REQUIRE_GATE_RUN", "MYLONITE_LIVE_TARGET", "PYTEST_ADDOPTS"}
    }
    env.update(env_extra or {})
    env["PYTHONUTF8"] = "1"
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-rA",
            "-p",
            "no:cacheprovider",
            "--strict-markers",
            "-o",
            "addopts=",
            "--rootdir",
            str(tmp_path),
            *extra,
            str(tmp_path),
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )


def _write(tmp_path: Path, body: str) -> None:
    source = (
        "import pytest\n"
        "from mylonite import testkit\n\n"
        "@pytest.mark.mylonite_security\n"
        '@testkit.pending_fix("the attack still worked when this test was committed")\n'
        "def test_gate():\n"
        f"    {body}\n"
    )
    (tmp_path / "test_pending_sample.py").write_text(source, encoding="utf-8")


def test_still_open_is_an_expected_failure_and_the_run_is_green(tmp_path: Path) -> None:
    _write(tmp_path, 'raise AssertionError("the attack worked")')
    proc = _run(tmp_path)
    assert proc.returncode == pytest.ExitCode.OK, proc.stdout + proc.stderr
    assert "1 xfailed" in proc.stdout
    assert "pending fix" in proc.stdout.lower()


def test_fixed_fails_and_says_to_remove_the_marker(tmp_path: Path) -> None:
    _write(tmp_path, "pass")
    proc = _run(tmp_path)
    assert proc.returncode == pytest.ExitCode.TESTS_FAILED, proc.stdout + proc.stderr
    assert "1 failed" in proc.stdout
    assert "remove the `@testkit.pending_fix(...)` line" in proc.stdout


@pytest.mark.parametrize(
    "body",
    [
        'raise testkit.TestkitFixtureError("the fixture is missing")',
        'raise testkit.TestkitConfigError("no model to re-drive with")',
        'raise RuntimeError("the target did not start")',
    ],
)
def test_an_inconclusive_run_is_never_green(tmp_path: Path, body: str) -> None:
    """Only the attack working counts as "still open". Anything else that stops
    the check from reaching a verdict is a real failure, as it is without the
    marker."""
    _write(tmp_path, body)
    proc = _run(tmp_path)
    assert proc.returncode == pytest.ExitCode.TESTS_FAILED, proc.stdout + proc.stderr
    assert "xfailed" not in proc.stdout


def test_marker_is_registered_and_selects_pending_tests(tmp_path: Path) -> None:
    _write(tmp_path, 'raise AssertionError("the attack worked")')
    (tmp_path / "test_other.py").write_text("def test_other():\n    pass\n", encoding="utf-8")
    proc = _run(tmp_path, extra=("-m", "mylonite_pending_fix"))
    assert proc.returncode == pytest.ExitCode.OK, proc.stdout + proc.stderr
    assert "1 xfailed" in proc.stdout
    assert "1 deselected" in proc.stdout


def test_a_pending_test_counts_as_a_gate_run_in_ci(tmp_path: Path) -> None:
    """The CI job that requires the gate to run must not read an expected
    failure as "skipped, checked nothing"."""
    _write(tmp_path, 'raise AssertionError("the attack worked")')
    proc = _run(tmp_path, env_extra={"MYLONITE_REQUIRE_GATE_RUN": "1"})
    assert proc.returncode == pytest.ExitCode.OK, proc.stdout + proc.stderr


def test_a_hand_added_xfail_still_counts_as_a_skipped_gate(tmp_path: Path) -> None:
    """Only a pending-fix expected failure counts as a run. A plain
    ``@pytest.mark.xfail`` on a gate test can hide a check that never reached a
    verdict, so the required-run check still fails it."""
    source = "\n".join(
        [
            "import pytest",
            "",
            "@pytest.mark.mylonite_security",
            "@pytest.mark.xfail",
            "def test_gate():",
            "    raise RuntimeError('the target did not start')",
            "",
        ]
    )
    (tmp_path / "test_plain_xfail.py").write_text(source, encoding="utf-8")
    proc = _run(tmp_path, env_extra={"MYLONITE_REQUIRE_GATE_RUN": "1"})
    assert "1 xfailed" in proc.stdout
    assert proc.returncode == pytest.ExitCode.TESTS_FAILED, proc.stdout + proc.stderr


def test_runxfail_reports_the_still_open_text_not_a_fix(tmp_path: Path) -> None:
    """Under ``--runxfail`` a still-open finding fails with the "still fails"
    text. It must never claim the attack stopped landing."""
    _write(tmp_path, 'raise AssertionError("the attack worked")')
    proc = _run(tmp_path, extra=("--runxfail",))
    assert proc.returncode == pytest.ExitCode.TESTS_FAILED, proc.stdout + proc.stderr
    assert "The check still fails (the attack worked)" in proc.stdout
    assert "Failed: The attack did not land" not in proc.stdout


def test_pending_fix_rejects_an_empty_reason() -> None:
    with pytest.raises(ValueError, match="reason"):
        testkit.pending_fix("  ")


# --- The three states on the file `gate` actually commits --------------------

_PATTERN = "indirect-injection-note-body-direct"

# Stands in for the live re-drive: the attack works while ATTACK_WORKS exists.
_CONFTEST = """
from pathlib import Path

from mylonite import testkit


def _stub(exploit, *, target_file, model=None, provider=None):
    if (Path(target_file).parent / "ATTACK_WORKS").exists():
        raise AssertionError("the attack worked on your target")


testkit.assert_target_resists = _stub
"""


def _committed_exploit() -> ExploitRecord:
    return ExploitRecord(
        target_id="mcp:acme",
        pattern_id=_PATTERN,
        payload=Payload(pattern_id=_PATTERN, channel="tool-result", body="x", metadata={}),
        response=AdapterResponse(payload_pattern_id=_PATTERN, raw_response="ok", tool_calls=[]),
        success_reason="test fixture",
        compliance=ComplianceTags(owasp_llm=["LLM01"], owasp_asi=["ASI01"]),
    )


def test_three_state_lifecycle_on_the_emitted_gate_test(tmp_path: Path) -> None:
    exploit = _committed_exploit()
    tagged = exploit.model_copy(
        update={
            "payload": exploit.payload.model_copy(
                update={"metadata": {PENDING_FIX_METADATA_KEY: "still open"}}
            )
        }
    )
    generated = ReferencePytestGenerator().emit(tagged)
    test_file = tmp_path / generated.filename
    test_file.write_text(generated.source, encoding="utf-8")
    (tmp_path / f"exploit_{_PATTERN}.json").write_text(exploit.model_dump_json(), encoding="utf-8")
    (tmp_path / "target.yaml").write_text("family: acme\n", encoding="utf-8")
    (tmp_path / "conftest.py").write_text(_CONFTEST, encoding="utf-8")
    attack_works = tmp_path / "ATTACK_WORKS"
    live = {"MYLONITE_LIVE_TARGET": "1", "MYLONITE_REQUIRE_GATE_RUN": "1"}

    # State 1: not fixed yet. Expected failure; the run is green.
    attack_works.touch()
    proc = _run(tmp_path, env_extra=live)
    assert proc.returncode == pytest.ExitCode.OK, proc.stdout + proc.stderr
    assert "1 xfailed" in proc.stdout

    # State 2: the fix lands. The test passes, and the run fails with the
    # instruction to remove the marker.
    attack_works.unlink()
    proc = _run(tmp_path, env_extra=live)
    assert proc.returncode == pytest.ExitCode.TESTS_FAILED, proc.stdout + proc.stderr
    assert "remove the `@testkit.pending_fix(...)` line" in proc.stdout

    # State 3: the marker is removed. A plain gate that passes...
    lines = test_file.read_text(encoding="utf-8").splitlines(keepends=True)
    marker_lines = [line for line in lines if line.startswith("@testkit.pending_fix(")]
    assert len(marker_lines) == 1
    test_file.write_text("".join(line for line in lines if line not in marker_lines), "utf-8")
    proc = _run(tmp_path, env_extra=live)
    assert proc.returncode == pytest.ExitCode.OK, proc.stdout + proc.stderr
    assert "1 passed" in proc.stdout

    # ...that goes red again if the fix regresses.
    attack_works.touch()
    proc = _run(tmp_path, env_extra=live)
    assert proc.returncode == pytest.ExitCode.TESTS_FAILED, proc.stdout + proc.stderr
    assert "the attack worked on your target" in proc.stdout
