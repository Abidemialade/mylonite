"""The demo's kept finding replays offline, and refuses to show a proof it cannot reproduce.

Everything here replays the packaged recording under ``mylonite/demo/kept/``;
nothing reaches a provider. The refusal tests copy that recording to a temp
directory and break one piece of it.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from mylonite.demo import packaged_fixture_dir, packaged_kept_dir
from mylonite.demo import runner as runner_mod
from mylonite.demo.proof import prove_kept
from mylonite.demo.runner import DemoFixtureError


@pytest.fixture
def kept_copy(tmp_path: Path) -> Path:
    target = tmp_path / "kept"
    shutil.copytree(packaged_kept_dir(), target, ignore=shutil.ignore_patterns("__pycache__"))
    return target


def _drop_one_fixture(directory: Path) -> None:
    recorded = sorted(p for p in directory.glob("*.json") if p.name != "_meta.json")
    recorded[0].unlink()


def test_the_packaged_kept_finding_is_kept_and_goes_red_then_green() -> None:
    proof = prove_kept()

    assert proof.report.kept is True
    assert proof.exploit.pattern_id == "excessive-agency-send-email-direct-unconfirmed"
    assert "fired against the vulnerable build" in proof.red_message
    assert proof.test_filename.startswith("test_security_")
    assert proof.metamorphic_strategies


def test_a_missing_red_fixture_refuses_rather_than_showing_a_pass(kept_copy: Path) -> None:
    _drop_one_fixture(kept_copy / "red_fixtures")

    with pytest.raises(DemoFixtureError, match="vulnerable build"):
        prove_kept(kept_copy)


def test_a_missing_differential_fixture_refuses_the_verdict(kept_copy: Path) -> None:
    _drop_one_fixture(kept_copy / "differential_fixtures")

    with pytest.raises(DemoFixtureError):
        prove_kept(kept_copy)


def test_a_missing_guarded_fixture_refuses_the_green_run(kept_copy: Path) -> None:
    _drop_one_fixture(kept_copy / "fixtures")

    with pytest.raises(DemoFixtureError, match="guarded build"):
        prove_kept(kept_copy)


def test_the_demo_replays_under_the_model_its_fixtures_name() -> None:
    meta = json.loads(
        (packaged_fixture_dir() / "vulnerable" / "_meta.json").read_text(encoding="utf-8")
    )
    assert meta["model"] == runner_mod.DEMO_MODEL
    assert runner_mod.DEMO_PROVIDER != "unknown"


def test_fixture_variants_naming_different_models_are_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for variant, model in (("vulnerable", "provider-a/model-a"), ("guarded", "provider-b/model-b")):
        (tmp_path / variant).mkdir()
        (tmp_path / variant / "_meta.json").write_text(
            json.dumps({"model": model}), encoding="utf-8"
        )
    monkeypatch.setattr(runner_mod, "packaged_fixture_dir", lambda: tmp_path)

    with pytest.raises(DemoFixtureError, match="different models"):
        runner_mod._recorded_model()


# --- the recorded model is read lazily: a broken sidecar is exit 2, not a crash ---


def _broken_fixture_root(tmp_path: Path, *, mixed: bool) -> Path:
    for variant, model in (("vulnerable", "provider-a/model-a"), ("guarded", "provider-b/model-b")):
        (tmp_path / variant).mkdir()
        if mixed:
            (tmp_path / variant / "_meta.json").write_text(
                json.dumps({"model": model}), encoding="utf-8"
            )
    return tmp_path


@pytest.mark.parametrize("mixed", [False, True], ids=["missing-sidecar", "mixed-models"])
def test_a_broken_sidecar_exits_2_with_one_line_and_no_traceback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mixed: bool
) -> None:
    from typer.testing import CliRunner

    from mylonite.cli import app

    root = _broken_fixture_root(tmp_path, mixed=mixed)
    monkeypatch.setattr(runner_mod, "packaged_fixture_dir", lambda: root)

    result = CliRunner().invoke(app, ["demo"])

    assert result.exit_code == 2, result.output
    assert "Traceback" not in result.output
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "demo fixtures" in result.output


def test_the_record_script_still_parses_when_the_shipped_sidecars_are_broken(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from scripts import record_demo_fixtures as script

    root = _broken_fixture_root(tmp_path, mixed=True)
    monkeypatch.setattr(runner_mod, "packaged_fixture_dir", lambda: root)

    args = script._parse_args(["--provider", "ollama", "--model", "ollama_chat/llama3.2:3b"])
    assert (args.provider, args.model) == ("ollama", "ollama_chat/llama3.2:3b")

    with pytest.raises(SystemExit):
        script._parse_args([])
    assert "Pass --provider and --model" in capsys.readouterr().err
