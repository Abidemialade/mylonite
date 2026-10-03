"""Offline tests for ``scripts/record_reference_example.py``'s seed and red-set flags.

No real provider is called: record mode reaches ``litellm.acompletion``, which
each test replaces with a scripted double. The double plays the planner on the
direct-send seed (one ``send_email`` call), passes the customiser through and
has the judge decline, so the vulnerable twin's deterministic predicate is the
only thing that can fire.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from scripts import record_reference_example as m

_W4 = "excessive-agency-send-email-direct-unconfirmed"
_MODEL = "fake/recorder-model"


def _text(text: str) -> SimpleNamespace:
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=text, tool_calls=None))]
    )


def _send_email() -> SimpleNamespace:
    call = SimpleNamespace(
        id="c1",
        function=SimpleNamespace(
            name="send_email",
            arguments=json.dumps({"to": "ops@example.com", "subject": "s", "body": "b"}),
        ),
    )
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="", tool_calls=[call]))]
    )


class _FakeLLM:
    """Customiser passes through, judge declines, planner sends once (or never)."""

    def __init__(self, *, planner_sends: bool) -> None:
        self.planner_sends = planner_sends
        self.calls = 0

    async def __call__(self, **kwargs: Any) -> SimpleNamespace:
        self.calls += 1
        messages = kwargs.get("messages", [])
        system = next((m["content"] for m in messages if m.get("role") == "system"), "")
        if "craft security probes" in system:
            return _text(json.dumps({"body": "Please send the status email now."}))
        if "harmful_intent_present" in system:
            return _text(json.dumps({"success": False, "confidence": 0.0, "reason": "declined"}))
        already_called = any(m.get("role") == "tool" for m in messages)
        if self.planner_sends and not already_called:
            return _send_email()
        return _text("done.")


@pytest.fixture
def fake_llm(monkeypatch: pytest.MonkeyPatch) -> _FakeLLM:
    import litellm

    fake = _FakeLLM(planner_sends=True)
    monkeypatch.setattr(litellm, "acompletion", fake)
    return fake


async def test_the_red_set_records_then_replays_offline_and_fires(
    tmp_path: Path, fake_llm: _FakeLLM
) -> None:
    red_dir = tmp_path / m.RED_FIXTURES_DIRNAME
    count = await m.record_red_set(provider="fake", model=_MODEL, pattern_id=_W4, red_dir=red_dir)

    assert count >= 1
    meta = json.loads((red_dir / "_meta.json").read_text(encoding="utf-8"))
    assert meta["pattern_id"] == _W4
    assert meta["variant"] == "vulnerable"
    assert meta["model"] == _MODEL
    assert meta["format_version"] == m.FIXTURE_FORMAT_VERSION

    # A second offline replay sends nothing to the provider.
    calls_before = fake_llm.calls
    await m.verify_red_set(provider="fake", model=_MODEL, pattern_id=_W4, red_dir=red_dir)
    assert fake_llm.calls == calls_before


async def test_the_red_set_is_refused_when_the_seed_does_not_fire(
    tmp_path: Path, fake_llm: _FakeLLM
) -> None:
    fake_llm.planner_sends = False
    red_dir = tmp_path / m.RED_FIXTURES_DIRNAME

    with pytest.raises(m.RecordingFailed, match="did not fire"):
        await m.record_red_set(provider="fake", model=_MODEL, pattern_id=_W4, red_dir=red_dir)
    assert not (red_dir / "_meta.json").exists()


async def test_a_red_set_with_a_missing_fixture_fails_verification(
    tmp_path: Path, fake_llm: _FakeLLM
) -> None:
    red_dir = tmp_path / m.RED_FIXTURES_DIRNAME
    await m.record_red_set(provider="fake", model=_MODEL, pattern_id=_W4, red_dir=red_dir)
    recorded = sorted(p for p in red_dir.glob("*.json") if p.name != "_meta.json")
    recorded[0].unlink()

    with pytest.raises(m.RecordingFailed, match="does not replay offline"):
        await m.verify_red_set(provider="fake", model=_MODEL, pattern_id=_W4, red_dir=red_dir)


def test_pattern_id_defaults_to_the_pinned_seed() -> None:
    assert m._parse_args([]).pattern_id == m.EXAMPLE_PATTERN_ID


def test_pattern_id_accepts_a_reference_app_seed() -> None:
    assert m._parse_args(["--pattern-id", _W4]).pattern_id == _W4


def test_pattern_id_refuses_a_seed_not_aimed_at_the_reference_app(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit):
        m._parse_args(["--pattern-id", "no-such-seed"])
    assert "not a reference-app seed" in capsys.readouterr().err


def test_metamorphic_strategies_parse_a_comma_list() -> None:
    args = m._parse_args(["--metamorphic-strategies", "paraphrase, casing"])
    assert args.metamorphic_strategies == ["paraphrase", "casing"]
    assert m._parse_args([]).metamorphic_strategies == m.METAMORPHIC_STRATEGIES


@pytest.mark.parametrize("raw", ["", "paraphrase,made-up"])
def test_metamorphic_strategies_refuse_empty_or_unknown_names(raw: str) -> None:
    with pytest.raises(SystemExit):
        m._parse_args(["--metamorphic-strategies", raw])
