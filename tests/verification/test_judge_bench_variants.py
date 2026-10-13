"""``verification.judge_bench.variants`` -- deterministic evidence reshaping."""

from __future__ import annotations

import json
from pathlib import Path

from verification.judge_bench import variants as vt
from verification.judge_bench.cases import BenchCase, dump_cases, load_cases

_TRACE = [
    {"tool": "read_note", "args": {"note_id": "n1"}, "result": "note text", "is_error": False},
    {"tool": "send_note", "args": {"to": "team"}, "result": "sent", "is_error": False},
]


def _case(
    case_id: str = "c1",
    *,
    family: str = "shadow",
    label: str = "landed",
    reply: str = "All done.",
    trace: list[dict[str, object]] | None = None,
) -> BenchCase:
    meta = {"tool_surface": '["read_note", "send_note"]'}
    if trace is not None:
        meta["effect_trace"] = json.dumps(trace)
        meta["mcp_trace_planner"] = json.dumps(trace)
    return BenchCase.model_validate(
        {
            "case_id": case_id,
            "family": family,
            "seed_id": "seed-1",
            "scan_id": "scan-1",
            "target_type": "mcp",
            "label": label,
            "payload": {
                "pattern_id": "p1",
                "channel": "tool-result",
                "body": "neutral body",
                "metadata": {"seed_id": "seed-1"},
            },
            "response": {
                "payload_pattern_id": "p1",
                "raw_response": reply,
                "tool_calls": ["read_note", "send_note"],
                "metadata": meta,
            },
            "provenance": "test",
        }
    )


def _entries(case: BenchCase, key: str = "effect_trace") -> list[dict[str, object]]:
    return list(json.loads(case.response["metadata"][key]))


def _by_kind(cases: list[BenchCase]) -> dict[str, BenchCase]:
    return {c.case_id.split("~", 1)[1]: c for c in cases}


def test_every_transform_keeps_the_label_seed_and_scan() -> None:
    src = _case(trace=_TRACE)
    out = vt.variants_of(src)
    assert sorted(_by_kind(out)) == sorted(vt.TRANSFORMS)
    for v in out:
        assert v.family == "synthetic" and not v.counts_toward_bar
        assert (v.label, v.seed_id, v.scan_id, v.payload) == (
            src.label,
            src.seed_id,
            src.scan_id,
            src.payload,
        )
        assert v.response["tool_calls"] == src.response["tool_calls"]
        assert v.response["metadata"]["tool_surface"] == src.response["metadata"]["tool_surface"]


def test_args_only_blanks_reply_and_results_and_keeps_arguments() -> None:
    v = _by_kind(vt.variants_of(_case(trace=_TRACE)))["args_only"]
    assert v.response["raw_response"] == ""
    for key in vt.TRACE_KEYS:
        got = _entries(v, key)
        assert [e["args"] for e in got] == [e["args"] for e in _TRACE]
        assert [e["tool"] for e in got] == [e["tool"] for e in _TRACE]
        assert all(e["result"] == "" for e in got)


def test_padding_moves_evidence_past_the_excerpt_bounds() -> None:
    src = _case(trace=_TRACE)
    kinds = _by_kind(vt.variants_of(src))
    results = kinds["past_result_excerpt"]
    for before, after in zip(_TRACE, _entries(results), strict=True):
        text = str(after["result"])
        assert text.endswith(str(before["result"]))
        assert text.index(str(before["result"])) >= vt.RESULT_EXCERPT
        assert after["args"] == before["args"]
    assert results.response["raw_response"] == src.response["raw_response"]

    reply = kinds["past_reply_excerpt"]
    text = reply.response["raw_response"]
    assert text.endswith(src.response["raw_response"])
    assert len(text) - len(src.response["raw_response"]) >= vt.REPLY_EXCERPT
    assert reply.response["metadata"] == src.response["metadata"]


def test_duplicated_json_repeats_the_reply_only() -> None:
    src = _case(trace=_TRACE)
    v = _by_kind(vt.variants_of(src))["duplicated_json"]
    first, block = v.response["raw_response"].split("\n", 1)
    assert first == src.response["raw_response"]
    assert json.loads(block) == {"reply": src.response["raw_response"]}
    assert v.response["metadata"] == src.response["metadata"]


def test_filler_is_neutral_and_long_enough() -> None:
    text = vt.filler(vt.REPLY_EXCERPT)
    assert len(text) > vt.REPLY_EXCERPT
    assert text.startswith("Lorem ipsum")


def test_nothing_to_move_yields_no_variant() -> None:
    assert vt.variants_of(_case(reply="", trace=None)) == []
    kinds = _by_kind(vt.variants_of(_case(trace=None)))
    assert sorted(kinds) == ["duplicated_json", "past_reply_excerpt"]


def test_only_landed_shadow_and_llm_routed_cases_are_sources() -> None:
    cases = [
        _case("a", trace=_TRACE),
        _case("b", family="llm_routed", trace=_TRACE),
        _case("c", label="not_landed", trace=_TRACE),
        _case("d", family="shadow_stripped", trace=_TRACE),
        _case("e", family="llm_routed", label="undecidable", trace=_TRACE),
    ]
    sources = {c.case_id.split("~", 1)[0] for c in vt.derive(cases)}
    assert sources == {"a", "b"}


def test_derive_is_deterministic(tmp_path: Path) -> None:
    src = tmp_path / "shadow.jsonl"
    dump_cases(src, [_case("b", trace=_TRACE), _case("a", trace=_TRACE)])
    outs = []
    for i in range(2):
        out = tmp_path / f"synthetic{i}.jsonl"
        assert vt.main(["--cases", str(src), "--out", str(out)]) == 0
        outs.append(out.read_bytes())
    assert outs[0] == outs[1]
    ids = [c.case_id for c in load_cases(tmp_path / "synthetic0.jsonl")]
    assert ids == sorted(ids) and len(ids) == 8
