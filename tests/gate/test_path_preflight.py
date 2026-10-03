"""The gate refuses an output path Windows cannot hold, before it spends anything.

Windows without long-path support caps a file path at 259 characters. A gate
that only finds out when it writes the test has already paid for the scan and
the validation, and used to end in a traceback. The short layout (findings
named like ``w4-1a2b3c``, 12-digit recording names) makes a checkout about 200
characters deep fit with the default ``.mylonite/gate``; deeper roots are
refused up front. These tests run on every OS: the limit is passed in, or the
platform probe is patched, so the rule is checked on Linux CI too.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from mylonite._replay import FIXTURE_NAME_LENGTH
from mylonite.contracts._types import (
    AdapterResponse,
    ComplianceTags,
    ExploitRecord,
    Payload,
)
from mylonite.exit_codes import EXIT_CONFIG
from mylonite.gate import orchestrator
from mylonite.gate.orchestrator import (
    FINDING_ID_LENGTH,
    WINDOWS_MAX_PATH,
    ScanOutcomeBundle,
    gate_path_problem,
    gate_paths,
    run_gate,
)
from mylonite.scan.coverage import Coverage, ScanOutcome

#: The default gate dir below a repository root, as Windows spells it.
_GATE_SUFFIX = len("\\.mylonite\\gate")


def _dir_of_length(tmp_path: Path, length: int) -> Path:
    """An absolute directory path exactly ``length`` characters long."""
    base = str(tmp_path.absolute())
    pad = length - len(base) - 1
    assert pad > 0, "tmp_path is already longer than the requested directory"
    return Path(base) / ("d" * pad)


def _default_gate_under_root(tmp_path: Path, root_length: int) -> Path:
    root = _dir_of_length(tmp_path, root_length)
    out = root / ".mylonite" / "gate"
    assert len(str(out)) == root_length + _GATE_SUFFIX
    return out


def _longest(out: Path, *, multi: bool = True) -> int:
    return max(len(str(p)) for p in gate_paths(out, multi=multi))


def test_a_200_character_root_fits_with_the_default_gate_dir(tmp_path: Path) -> None:
    out = _default_gate_under_root(tmp_path, 200)
    assert _longest(out) <= WINDOWS_MAX_PATH
    assert gate_path_problem(out, limit=WINDOWS_MAX_PATH) is None


def test_the_budget_below_the_gate_dir(tmp_path: Path) -> None:
    # 259 - 200 (root) - len("\\.mylonite\\gate") leaves 44 characters, the
    # separator included, for the deepest file a finding folder holds.
    budget = WINDOWS_MAX_PATH - 200 - _GATE_SUFFIX
    assert budget == 44
    deepest = 1 + FINDING_ID_LENGTH + 2 + len("\\fixtures\\") + FIXTURE_NAME_LENGTH + 5
    assert deepest <= budget
    out = tmp_path / "gate"
    below = max(len(str(p)) - len(str(out.absolute())) for p in gate_paths(out))
    # The rejected sibling (`gate-rej`) is the deepest of all and still fits.
    assert below <= budget


def test_a_230_character_root_is_refused(tmp_path: Path) -> None:
    out = _default_gate_under_root(tmp_path, 230)
    problem = gate_path_problem(out, limit=WINDOWS_MAX_PATH)
    assert problem is not None
    longest = max(gate_paths(out), key=lambda p: len(str(p)))
    over = len(str(longest)) - WINDOWS_MAX_PATH
    assert str(longest) in problem
    assert f"by at least {over} characters" in problem
    assert "--out" in problem
    assert "\n" not in problem
    # No glyphs in the wording: only the user's own path could be non-ASCII.
    problem.replace(str(longest), "").encode("ascii")


def test_the_cut_it_names_is_enough(tmp_path: Path) -> None:
    out = _dir_of_length(tmp_path, 240)
    problem = gate_path_problem(out, limit=WINDOWS_MAX_PATH)
    assert problem is not None
    over = int(problem.split("by at least ")[1].split(" ")[0])
    assert gate_path_problem(_dir_of_length(tmp_path, 240 - over), limit=WINDOWS_MAX_PATH) is None
    one_less = _dir_of_length(tmp_path, 240 - over + 1)
    assert gate_path_problem(one_less, limit=WINDOWS_MAX_PATH) is not None


def test_a_short_root_passes(tmp_path: Path) -> None:
    out = Path(tmp_path.absolute().anchor) / "gate"
    assert gate_path_problem(out, limit=WINDOWS_MAX_PATH) is None


def test_no_limit_means_no_refusal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(orchestrator, "_path_limit", lambda: None)
    assert gate_path_problem(_dir_of_length(tmp_path, 250)) is None


def test_the_model_names_files_from_the_ids_the_gate_assigns(tmp_path: Path) -> None:
    out = (tmp_path / "gate").absolute()
    multi = set(gate_paths(out, ["w4-abcdef"], multi=True))
    assert out / "w4-abcdef" / "test_w4-abcdef.py" in multi
    assert out / "w4-abcdef" / "exploit_w4-abcdef.json" in multi
    assert out / "w4-abcdef" / "fixtures" / ("0" * FIXTURE_NAME_LENGTH + ".json") in multi
    assert out.parent / "gate-rej" / "w4-abcdef" / "test_w4-abcdef.py" in multi
    single = set(gate_paths(out, ["w4-abcdef"], multi=False))
    assert out / "test_w4-abcdef.py" in single
    assert out / "exploit_w4-abcdef.json" in single


def test_the_preflight_bound_covers_any_real_id(tmp_path: Path) -> None:
    out = tmp_path / "gate"
    real = ["w1-123456", "w4-abcdef-2", "f-000000"]
    assert _longest(out) >= max(len(str(p)) for p in gate_paths(out, real))


def test_the_limit_follows_the_windows_long_path_setting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(orchestrator.sys, "platform", "linux")
    assert orchestrator._path_limit() is None
    monkeypatch.setattr(orchestrator.sys, "platform", "win32")
    monkeypatch.setattr(orchestrator, "_windows_long_paths_enabled", lambda: True)
    assert orchestrator._path_limit() is None
    monkeypatch.setattr(orchestrator, "_windows_long_paths_enabled", lambda: False)
    assert orchestrator._path_limit() == WINDOWS_MAX_PATH


def _exploit(pattern_id: str) -> ExploitRecord:
    return ExploitRecord(
        target_id="mcp:custom",
        pattern_id=pattern_id,
        payload=Payload(
            pattern_id=pattern_id, channel="user-message", body="b", metadata={"weakness": "W2"}
        ),
        response=AdapterResponse(
            payload_pattern_id=pattern_id, raw_response="r", tool_calls=[], metadata={}
        ),
        success_reason="r",
        compliance=ComplianceTags(owasp_asi=["ASI01"]),
    )


def _found() -> ScanOutcome:
    return ScanOutcome(
        coverage=Coverage.EXERCISED,
        abort=None,
        exercised=1,
        not_tested=0,
        findings=1,
        fallbacks=0,
        exit_code=0,
        operator_message=None,
    )


def test_run_gate_refuses_before_generating_or_validating(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(orchestrator, "_path_limit", lambda: WINDOWS_MAX_PATH)
    out = _dir_of_length(tmp_path, 240)

    def _never(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("must not run after a path refusal")

    result = run_gate(
        out_dir=out,
        scan_fn=lambda: ScanOutcomeBundle(outcome=_found(), exploits=[_exploit("a-seed")]),
        generate_fn=_never,  # type: ignore[arg-type]
        validate_fn=_never,  # type: ignore[arg-type]
        open_pr_fn=_never,
        open_pr=False,
    )
    assert result.exit_code == EXIT_CONFIG
    assert "--out" in capsys.readouterr().out
    assert not out.exists()


def test_cli_gate_refuses_before_any_model_is_configured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(orchestrator, "_path_limit", lambda: WINDOWS_MAX_PATH)
    for var in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "MYLONITE_MODEL", "MYLONITE_PROVIDER"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.chdir(tmp_path)
    out = _default_gate_under_root(tmp_path, 230)

    from mylonite.cli import app

    result = CliRunner().invoke(app, ["gate", "reference:vulnerable", "--out", str(out)])
    assert result.exit_code == EXIT_CONFIG, result.output
    assert "too long for Windows" in result.output
    assert not out.exists()
