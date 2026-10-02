"""The live re-drive checks a rate, not one run.

``assert_target_resists`` and ``assert_control_holds`` re-drive your own target
up to N times (default 3). A landing on any attempt fails at once; an
inconclusive attempt is never a resist and also stops the check (with an
error, never a pass); a pass needs N clean resists. The re-drive itself is
stubbed here (``_run_target_scan``), so the real verdict logic
(``_exploit_fired`` / ``_assert_from_result``) runs on fabricated scan results
and no target or model is ever called.
"""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Iterable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from mylonite import testkit
from mylonite.contracts._types import (
    AbortReason,
    AdapterResponse,
    ComplianceTags,
    ExploitRecord,
    Payload,
)

_PATTERN_ID = "indirect-injection-note-body-direct"

_TARGET_YAML = """\
family: myapp-notes
command: echo
args: []
weakness_classes:
  - W2
seed_arm:
  tool: remember
  args_template: {content: "{payload}"}
"""


def _target(tmp_path: Path) -> Path:
    p = tmp_path / "target.yaml"
    p.write_text(_TARGET_YAML, encoding="utf-8")
    return p


def _exploit() -> ExploitRecord:
    return ExploitRecord(
        target_id="mcp:myapp-notes",
        pattern_id=_PATTERN_ID,
        payload=Payload(
            pattern_id=_PATTERN_ID,
            channel="tool-result",
            body="x",
            metadata={"seed_id": _PATTERN_ID, "weakness": "W2"},
        ),
        response=AdapterResponse(payload_pattern_id=_PATTERN_ID, raw_response="ok", tool_calls=[]),
        success_reason="test fixture",
        compliance=ComplianceTags(owasp_llm=["LLM01"], owasp_asi=["ASI01"]),
    )


def _result(outcome: str) -> Any:
    """A fabricated scan result. ``outcome`` is ``land``, ``resist``,
    ``no_engagement`` (inconclusive) or ``aborted`` (inconclusive, hit its bound)."""
    if outcome == "land":
        return SimpleNamespace(
            exploits=[SimpleNamespace(pattern_id=_PATTERN_ID)],
            report=SimpleNamespace(
                attempts=[SimpleNamespace(pattern_id=_PATTERN_ID, outcome="finding")],
                aborted=None,
            ),
        )
    if outcome == "resist":
        attempt = SimpleNamespace(pattern_id=_PATTERN_ID, outcome="no_finding")
        return SimpleNamespace(
            exploits=[], report=SimpleNamespace(attempts=[attempt], aborted=None)
        )
    if outcome == "no_engagement":
        attempt = SimpleNamespace(pattern_id=_PATTERN_ID, outcome="skipped_planner_no_engagement")
        return SimpleNamespace(
            exploits=[], report=SimpleNamespace(attempts=[attempt], aborted=None)
        )
    if outcome == "aborted":
        return SimpleNamespace(
            exploits=[],
            report=SimpleNamespace(attempts=[], aborted=AbortReason.WALL_CLOCK_TIMEOUT),
        )
    raise AssertionError(f"unknown outcome {outcome!r}")


class _Scripted:
    """Stands in for ``_run_target_scan``: returns one scripted result per call."""

    def __init__(self, outcomes: Iterable[str]) -> None:
        self._outcomes = list(outcomes)
        self.calls = 0

    def __call__(self, **_kwargs: Any) -> Any:
        self.calls += 1
        if self.calls > len(self._outcomes):
            raise AssertionError(
                f"re-drive ran {self.calls} times, script has {len(self._outcomes)}"
            )
        return _result(self._outcomes[self.calls - 1])


def _resists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, outcomes: list[str], **kw: Any
) -> _Scripted:
    scripted = _Scripted(outcomes)
    monkeypatch.setattr(testkit, "_run_target_scan", scripted)
    testkit.assert_target_resists(
        _exploit(), target_file=_target(tmp_path), model="stub-model", provider="stub", **kw
    )
    return scripted


# --- assert_target_resists ----------------------------------------------------


def test_default_is_three_attempts() -> None:
    assert testkit.DEFAULT_REDRIVE_ATTEMPTS == 3


def test_passes_only_after_three_clean_resists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scripted = _resists(tmp_path, monkeypatch, ["resist", "resist", "resist"])
    assert scripted.calls == 3


@pytest.mark.parametrize("landing_attempt", [1, 2, 3])
def test_a_landing_fails_at_once_and_stops(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, landing_attempt: int
) -> None:
    outcomes = ["resist"] * (landing_attempt - 1) + ["land"] + ["resist"] * (3 - landing_attempt)
    scripted = _Scripted(outcomes)
    monkeypatch.setattr(testkit, "_run_target_scan", scripted)
    with pytest.raises(AssertionError, match="guard did not hold") as excinfo:
        testkit.assert_target_resists(
            _exploit(), target_file=_target(tmp_path), model="stub-model", provider="stub"
        )
    # Early stop: one landing is a regression, so nothing more is spent.
    assert scripted.calls == landing_attempt
    assert f"attempt {landing_attempt} of 3" in str(excinfo.value)


def test_an_inconclusive_attempt_is_not_a_resist_and_stops_the_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scripted = _Scripted(["resist", "no_engagement", "resist"])
    monkeypatch.setattr(testkit, "_run_target_scan", scripted)
    with pytest.raises(testkit.TestkitFixtureError) as excinfo:
        testkit.assert_target_resists(
            _exploit(), target_file=_target(tmp_path), model="stub-model", provider="stub"
        )
    assert not isinstance(excinfo.value, AssertionError)
    # The check can no longer pass, so the third attempt is never spent.
    assert scripted.calls == 2
    msg = str(excinfo.value)
    assert "attempt 2 of 3 was inconclusive after 1 resisted" in msg


def test_an_inconclusive_first_attempt_errors_without_another_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scripted = _Scripted(["no_engagement", "land", "resist"])
    monkeypatch.setattr(testkit, "_run_target_scan", scripted)
    with pytest.raises(testkit.TestkitFixtureError, match="attempt 1 of 3 was inconclusive"):
        testkit.assert_target_resists(
            _exploit(), target_file=_target(tmp_path), model="stub-model", provider="stub"
        )
    assert scripted.calls == 1


def test_an_aborted_attempt_keeps_its_own_error_type(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scripted = _Scripted(["aborted", "resist", "resist"])
    monkeypatch.setattr(testkit, "_run_target_scan", scripted)
    with pytest.raises(testkit.TestkitRedriveAborted, match="wall-clock"):
        testkit.assert_target_resists(
            _exploit(), target_file=_target(tmp_path), model="stub-model", provider="stub"
        )
    # A target that hit its time bound is not re-driven again.
    assert scripted.calls == 1


def test_attempts_keyword_sets_n(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert _resists(tmp_path, monkeypatch, ["resist"] * 5, attempts=5).calls == 5


def test_env_override_sets_n_when_no_keyword(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(testkit.REDRIVE_ATTEMPTS_ENV, "1")
    assert _resists(tmp_path, monkeypatch, ["resist"]).calls == 1


def test_the_cap_itself_is_accepted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(testkit.REDRIVE_ATTEMPTS_ENV, str(testkit.MAX_REDRIVE_ATTEMPTS))
    n = testkit.MAX_REDRIVE_ATTEMPTS
    assert _resists(tmp_path, monkeypatch, ["resist"] * n).calls == n


def test_keyword_wins_over_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(testkit.REDRIVE_ATTEMPTS_ENV, "1")
    assert _resists(tmp_path, monkeypatch, ["resist"] * 2, attempts=2).calls == 2


@pytest.mark.parametrize("bad", ["0", "-1", "three", "2.5", "+3", "3_0", "21", "1000", ""])
def test_a_bad_env_value_fails_before_any_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad: str
) -> None:
    monkeypatch.setenv(testkit.REDRIVE_ATTEMPTS_ENV, bad)
    scripted = _Scripted(["resist"] * 3)
    monkeypatch.setattr(testkit, "_run_target_scan", scripted)
    if bad == "":
        # An empty value means "not set": the default applies.
        testkit.assert_target_resists(
            _exploit(), target_file=_target(tmp_path), model="stub-model", provider="stub"
        )
        assert scripted.calls == 3
        return
    with pytest.raises(testkit.TestkitConfigError, match=testkit.REDRIVE_ATTEMPTS_ENV):
        testkit.assert_target_resists(
            _exploit(), target_file=_target(tmp_path), model="stub-model", provider="stub"
        )
    assert scripted.calls == 0


@pytest.mark.parametrize("bad", [0, -2, True, "3", 2.5, 21])
def test_a_bad_keyword_value_fails_before_any_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad: Any
) -> None:
    scripted = _Scripted(["resist"] * 3)
    monkeypatch.setattr(testkit, "_run_target_scan", scripted)
    with pytest.raises(testkit.TestkitConfigError, match="attempts"):
        testkit.assert_target_resists(
            _exploit(),
            target_file=_target(tmp_path),
            model="stub-model",
            provider="stub",
            attempts=bad,
        )
    assert scripted.calls == 0


# --- assert_control_holds -----------------------------------------------------


class _Legs:
    """Stands in for ``_run_target_scan`` with separate raw and guarded scripts."""

    def __init__(self, raw: list[str], guarded: list[str]) -> None:
        self.raw = _Scripted(raw)
        self.guarded = _Scripted(guarded)
        self.order: list[str] = []

    def __call__(self, *, controls: Any, **kwargs: Any) -> Any:
        leg = "guarded" if controls else "raw"
        self.order.append(leg)
        return self.guarded() if controls else self.raw()


def _control(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, legs: _Legs) -> None:
    monkeypatch.setattr(testkit, "_run_target_scan", legs)
    testkit.assert_control_holds(
        _exploit(), target_file=_target(tmp_path), control="W2", model="stub-model", provider="stub"
    )


def test_control_passes_after_one_raw_landing_and_three_guarded_resists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    legs = _Legs(raw=["land"], guarded=["resist"] * 3)
    _control(tmp_path, monkeypatch, legs)
    # The raw leg only has to show the attack still works once.
    assert legs.order == ["raw", "guarded", "guarded", "guarded"]


def test_control_retries_the_raw_leg_until_it_lands(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    legs = _Legs(raw=["resist", "land"], guarded=["resist"] * 3)
    _control(tmp_path, monkeypatch, legs)
    assert legs.order == ["raw", "guarded", "raw", "guarded", "guarded"]


@pytest.mark.parametrize("landing_attempt", [1, 2, 3])
def test_control_fails_at_the_first_guarded_landing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, landing_attempt: int
) -> None:
    guarded = ["resist"] * (landing_attempt - 1) + ["land"]
    legs = _Legs(raw=["land"], guarded=guarded)
    with pytest.raises(AssertionError, match=f"attempt {landing_attempt} of 3"):
        _control(tmp_path, monkeypatch, legs)
    assert legs.guarded.calls == landing_attempt


def test_control_fails_when_raw_never_lands(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    legs = _Legs(raw=["resist"] * 3, guarded=["resist"] * 3)
    with pytest.raises(
        testkit.TestkitAttackNotReproduced, match="no longer fires against the RAW target"
    ) as excinfo:
        _control(tmp_path, monkeypatch, legs)
    # Its own error, not an AssertionError, so a pending-fix marker can't hide it.
    assert not isinstance(excinfo.value, AssertionError)
    assert legs.raw.calls == 3


def test_control_inconclusive_guarded_attempt_never_passes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    legs = _Legs(raw=["land"], guarded=["resist", "no_engagement", "resist"])
    with pytest.raises(testkit.TestkitFixtureError, match="attempt 2 of 3 was inconclusive"):
        _control(tmp_path, monkeypatch, legs)
    assert legs.guarded.calls == 2


def test_control_inconclusive_guarded_attempt_before_raw_lands_is_inconclusive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The guarded leg was inconclusive before the raw leg ever landed: no
    evidence either way, so the check errors on that attempt and stops."""
    legs = _Legs(raw=["resist"], guarded=["no_engagement"])
    with pytest.raises(testkit.TestkitFixtureError, match="attempt 1 of 3 was inconclusive") as exc:
        _control(tmp_path, monkeypatch, legs)
    assert not isinstance(exc.value, testkit.TestkitAttackNotReproduced)
    assert legs.order == ["raw", "guarded"]


def test_control_honours_the_attempts_keyword(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    legs = _Legs(raw=["land"], guarded=["resist"])
    monkeypatch.setattr(testkit, "_run_target_scan", legs)
    testkit.assert_control_holds(
        _exploit(),
        target_file=_target(tmp_path),
        control="W2",
        model="stub-model",
        provider="stub",
        attempts=1,
    )
    assert legs.order == ["raw", "guarded"]


# --- pending_fix interplay ----------------------------------------------------

# Stubs the re-drive inside the consumer's pytest run: OUTCOMES (one word per
# attempt) scripts each re-drive, and CALLS records how many ran.
_CONFTEST = """
from pathlib import Path
from types import SimpleNamespace

from mylonite import testkit

_HERE = Path(__file__).parent
_PID = "indirect-injection-note-body-direct"


def _result(word):
    if word == "land":
        return SimpleNamespace(
            exploits=[SimpleNamespace(pattern_id=_PID)],
            report=SimpleNamespace(
                attempts=[SimpleNamespace(pattern_id=_PID, outcome="finding")], aborted=None
            ),
        )
    outcome = "no_finding" if word == "resist" else "skipped_planner_no_engagement"
    return SimpleNamespace(
        exploits=[],
        report=SimpleNamespace(
            attempts=[SimpleNamespace(pattern_id=_PID, outcome=outcome)], aborted=None
        ),
    )


def _fake_run(**_kwargs):
    calls = _HERE / "CALLS"
    n = int(calls.read_text()) if calls.exists() else 0
    calls.write_text(str(n + 1))
    words = (_HERE / "OUTCOMES").read_text().split()
    return _result(words[n])


testkit._run_target_scan = _fake_run
"""

_TEST = """
from pathlib import Path

import pytest

from mylonite import testkit
from mylonite.contracts._types import ExploitRecord

_HERE = Path(__file__).parent


@pytest.mark.mylonite_security
@testkit.pending_fix("the attack still worked when this test was committed")
def test_gate():
    exploit = ExploitRecord.model_validate_json((_HERE / "exploit.json").read_text())
    testkit.assert_target_resists(
        exploit, target_file=_HERE / "target.yaml", model="stub-model", provider="stub"
    )
"""


def _pytest(tmp_path: Path) -> subprocess.CompletedProcess[str]:
    env = {
        k: v
        for k, v in os.environ.items()
        if k not in {"MYLONITE_REQUIRE_GATE_RUN", testkit.REDRIVE_ATTEMPTS_ENV, "PYTEST_ADDOPTS"}
    }
    env["PYTHONUTF8"] = "1"
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-rA",
            "-p",
            "no:cacheprovider",
            "-o",
            "addopts=",
            "--rootdir",
            str(tmp_path),
            str(tmp_path),
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )


def _pending_run(tmp_path: Path, outcomes: str) -> tuple[subprocess.CompletedProcess[str], int]:
    (tmp_path / "conftest.py").write_text(_CONFTEST, encoding="utf-8")
    (tmp_path / "test_pending_gate.py").write_text(_TEST, encoding="utf-8")
    (tmp_path / "exploit.json").write_text(_exploit().model_dump_json(), encoding="utf-8")
    _target(tmp_path)
    (tmp_path / "OUTCOMES").write_text(outcomes, encoding="utf-8")
    proc = _pytest(tmp_path)
    calls_file = tmp_path / "CALLS"
    calls = int(calls_file.read_text()) if calls_file.exists() else 0
    return proc, calls


def test_pending_fix_still_open_stops_at_the_first_landing(tmp_path: Path) -> None:
    proc, calls = _pending_run(tmp_path, "resist land resist")
    assert proc.returncode == pytest.ExitCode.OK, proc.stdout + proc.stderr
    assert "1 xfailed" in proc.stdout
    assert calls == 2


def test_pending_fix_says_remove_the_marker_only_after_every_attempt_resists(
    tmp_path: Path,
) -> None:
    proc, calls = _pending_run(tmp_path, "resist resist resist")
    assert proc.returncode == pytest.ExitCode.TESTS_FAILED, proc.stdout + proc.stderr
    assert "remove the `@testkit.pending_fix(...)` line" in proc.stdout
    assert calls == 3


def test_pending_fix_with_an_inconclusive_attempt_is_a_failure_not_xfail(tmp_path: Path) -> None:
    proc, calls = _pending_run(tmp_path, "resist no_engagement resist")
    assert proc.returncode == pytest.ExitCode.TESTS_FAILED, proc.stdout + proc.stderr
    assert "xfailed" not in proc.stdout
    assert "remove the `@testkit.pending_fix(...)` line" not in proc.stdout
    assert calls == 2


_CONTROL_CONFTEST = """
from types import SimpleNamespace

from mylonite import testkit

_PID = "indirect-injection-note-body-direct"


def _fake_run(**_kwargs):
    # Neither leg lands: the attack no longer works even without the control.
    attempt = SimpleNamespace(pattern_id=_PID, outcome="no_finding")
    return SimpleNamespace(exploits=[], report=SimpleNamespace(attempts=[attempt], aborted=None))


testkit._run_target_scan = _fake_run
"""

_CONTROL_TEST = """
from pathlib import Path

import pytest

from mylonite import testkit
from mylonite.contracts._types import ExploitRecord

_HERE = Path(__file__).parent


@pytest.mark.mylonite_security
@testkit.pending_fix("the control was not in place when this test was committed")
def test_control_gate():
    exploit = ExploitRecord.model_validate_json((_HERE / "exploit.json").read_text())
    testkit.assert_control_holds(
        exploit,
        target_file=_HERE / "target.yaml",
        control="W2",
        model="stub-model",
        provider="stub",
    )
"""


def test_pending_fix_control_test_whose_raw_leg_never_lands_fails_red(tmp_path: Path) -> None:
    """A control test that can no longer show the attack works proves nothing.
    Under a pending-fix marker it must fail, never sit green as an expected
    failure."""
    (tmp_path / "conftest.py").write_text(_CONTROL_CONFTEST, encoding="utf-8")
    (tmp_path / "test_pending_control.py").write_text(_CONTROL_TEST, encoding="utf-8")
    (tmp_path / "exploit.json").write_text(_exploit().model_dump_json(), encoding="utf-8")
    _target(tmp_path)
    proc = _pytest(tmp_path)
    assert proc.returncode == pytest.ExitCode.TESTS_FAILED, proc.stdout + proc.stderr
    assert "xfailed" not in proc.stdout
    assert "TestkitAttackNotReproduced" in proc.stdout
