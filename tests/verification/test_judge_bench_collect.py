"""``verification.judge_bench.collect`` -- offline: a faked completion, no network."""

from __future__ import annotations

import json
import socket
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import litellm
import pytest
from verification.judge_bench import collect

from mylonite.scan.judge import SuccessJudge

_MODEL = "anthropic/claude-haiku-4-5-20251001"


def _reply(content: str, tool_calls: list[Any] | None = None) -> SimpleNamespace:
    message = SimpleNamespace(content=content, tool_calls=tool_calls)
    usage = SimpleNamespace(prompt_tokens=3, completion_tokens=2, total_tokens=5)
    return SimpleNamespace(
        choices=[SimpleNamespace(message=message, finish_reason="stop")], usage=usage
    )


def _benign() -> SimpleNamespace:
    return _reply(json.dumps({"success": False, "confidence": 0.0, "reason": "stub"}))


def _tool_call() -> SimpleNamespace:
    call = SimpleNamespace(
        id="c1",
        function=SimpleNamespace(name="read_note", arguments=json.dumps({"note_id": "n_absent"})),
    )
    return _reply("", [call])


@pytest.fixture
def offline(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, Any]:
    """Fake every provider request and refuse any non-loopback connection."""
    state: dict[str, Any] = {"calls": 0, "remote": []}

    async def acompletion(*_a: object, **kwargs: Any) -> SimpleNamespace:
        state["calls"] += 1
        if not kwargs.get("tools"):
            return _benign()
        messages = kwargs.get("messages") or []
        if any(isinstance(m, dict) and m.get("role") == "tool" for m in messages):
            return _benign()
        return _tool_call()

    def completion(*_a: object, **_kw: Any) -> SimpleNamespace:
        state["calls"] += 1
        return _benign()

    real_connect = socket.socket.connect

    def guarded_connect(self: socket.socket, address: Any) -> Any:
        host = address[0] if isinstance(address, tuple) else str(address)
        if host not in ("127.0.0.1", "::1", "localhost"):
            state["remote"].append(address)
            raise OSError("network disabled in this test")
        return real_connect(self, address)

    monkeypatch.setattr(litellm, "acompletion", acompletion)
    monkeypatch.setattr(litellm, "completion", completion)
    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")  # pragma: allowlist secret
    monkeypatch.chdir(tmp_path)
    return state


def _run(tmp_path: Path, *extra: str, ceiling: int = 5000) -> tuple[int, Path]:
    out = tmp_path / "out"
    code = collect.main(
        ["--model", _MODEL, "--max-llm-requests", str(ceiling), "--out", str(out), *extra]
    )
    return code, out


def _judge_calls(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Count every real ``SuccessJudge.judge`` call, whichever subclass makes it."""
    seen: list[str] = []
    original = SuccessJudge.judge

    async def counting(self: SuccessJudge, payload: Any, response: Any) -> Any:
        seen.append(payload.pattern_id)
        return await original(self, payload, response)

    monkeypatch.setattr(SuccessJudge, "judge", counting)
    return seen


def test_every_judged_attempt_is_captured_once_with_full_fields(
    offline: dict[str, Any], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    seen = _judge_calls(monkeypatch)
    code, out = _run(tmp_path)
    assert code == collect.EXIT_OK
    captures = collect.load_captures(out / "captures.jsonl")
    assert captures, "the reference scans judged nothing"
    assert len(captures) == len(seen)
    assert sorted(c.pattern_id for c in captures) == sorted(seen)
    assert len({c.capture_id for c in captures}) == len(captures)
    assert {c.target for c in captures} == set(collect.DEFAULT_TARGETS)
    for cap in captures:
        assert cap.target_type == "reference"
        assert cap.model == _MODEL
        assert cap.mylonite_version
        assert cap.payload["pattern_id"] == cap.pattern_id
        assert cap.response["payload_pattern_id"] == cap.pattern_id
        assert {"success", "mechanism", "fallback_cause", "applicable", "confidence"} <= set(
            cap.verdict
        )
    # The payload and response are the full model dumps, not excerpts.
    assert all("body" in c.payload and "metadata" in c.payload for c in captures)
    assert all("raw_response" in c.response and "tool_calls" in c.response for c in captures)
    assert offline["remote"] == []
    assert offline["calls"] > 0

    spend = json.loads((out / "spend.json").read_text(encoding="utf-8"))
    assert spend["captures"] == len(captures)
    assert spend["calls_by_role"].get("judge", 0) >= 1
    assert spend["calls"] == sum(spend["calls_by_role"].values())
    assert spend["prompt_tokens"] == 3 * spend["calls_with_usage"]
    assert spend["ceiling_hit"] is False
    assert [s["target"] for s in spend["scans"]] == list(collect.DEFAULT_TARGETS)
    assert sum(s["captures"] for s in spend["scans"]) == len(captures)


def test_the_request_ceiling_is_honoured(offline: dict[str, Any], tmp_path: Path) -> None:
    code, out = _run(tmp_path, "--scans", "2", ceiling=4)
    assert code == collect.EXIT_CEILING
    assert offline["calls"] == 4
    spend = json.loads((out / "spend.json").read_text(encoding="utf-8"))
    assert spend["ceiling_hit"] is True
    assert spend["requests_sent"] == 4
    assert len(spend["scans"]) == 1, "no scan starts after the ceiling trips"
    assert (out / "captures.jsonl").exists()


def test_seed_filter_limits_the_attempts(
    offline: dict[str, Any], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _, everything = _run(tmp_path / "all", "--target", "reference:vulnerable")
    all_caps = collect.load_captures(everything / "captures.jsonl")
    chosen = sorted({c.pattern_id for c in all_caps})[0]
    code, out = _run(tmp_path / "one", "--target", "reference:vulnerable", "--seeds", chosen)
    assert code == collect.EXIT_OK
    caps = collect.load_captures(out / "captures.jsonl")
    assert caps
    assert {c.pattern_id for c in caps} == {chosen}


def test_a_target_file_needs_authorize(tmp_path: Path) -> None:
    target = tmp_path / "target.yaml"
    target.write_text("transport: rest\n", encoding="utf-8")
    code, out = _run(tmp_path, "--target", str(target))
    assert code == collect.EXIT_ERROR
    assert not (out / "captures.jsonl").exists()


def test_target_type_and_argv(tmp_path: Path) -> None:
    rest = tmp_path / "rest.yaml"
    rest.write_text("transport: rest\n", encoding="utf-8")
    mcp = tmp_path / "mcp.yaml"
    mcp.write_text("transport: stdio\n", encoding="utf-8")
    assert collect.target_type_for("reference:guarded") == "reference"
    assert collect.target_type_for(str(rest)) == "rest"
    assert collect.target_type_for(str(mcp)) == "mcp"
    argv = collect.scan_argv(
        str(mcp), model=_MODEL, ceiling=7, out_dir=tmp_path / "s", authorize="me"
    )
    assert argv[:3] == ["--max-llm-requests", "7", "scan"]
    assert argv[argv.index("--authorize") + 1] == "me"
    assert argv[argv.index("--target-file") + 1] == str(mcp)


async def test_the_recording_judge_leaves_the_verdict_unchanged() -> None:
    from mylonite.contracts._types import AdapterResponse, Payload

    payload = Payload(pattern_id="p1", channel="tool-result", body="b", metadata={"seed_id": "s1"})
    response = AdapterResponse(payload_pattern_id="p1", raw_response="ok")
    sink = collect.CaptureSink(mylonite_version="0")
    sink.context = collect.ScanContext("scan-1", "reference:guarded", "reference")
    recording = collect.recording_judge_class(sink)(model="m")
    got = await recording.judge(payload, response)
    want = await SuccessJudge(model="m").judge(payload, response)
    assert got == want
    [cap] = sink.captures
    assert (cap.capture_id, cap.seed_id, cap.pattern_id) == ("scan-1-0001", "s1", "p1")
    assert cap.verdict["mechanism"] == want.mechanism
    assert cap.verdict["success"] is want.success


def test_a_judge_outside_a_scan_is_an_error() -> None:
    sink = collect.CaptureSink(mylonite_version="0")
    with pytest.raises(RuntimeError):
        sink.record("m", None, None, None)  # type: ignore[arg-type]
