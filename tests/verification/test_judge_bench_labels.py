"""``verification.judge_bench.labels`` -- packets, gold set, merge, kappa."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from verification.judge_bench import labels as lb
from verification.judge_bench.cases import BenchCase, dump_cases

_TRACE = [{"tool": "send_note", "args": {"to": "team"}, "result": "sent", "is_error": False}]


def _case(
    case_id: str,
    *,
    target_type: str = "mcp",
    label: str = "undecidable",
    tool_calls: tuple[str, ...] = ("send_note",),
) -> BenchCase:
    meta = {
        "effect_trace": json.dumps(_TRACE),
        "tool_surface": json.dumps(list(tool_calls)),
        "trace_outcome": "dispatched-ok",
        "link": "token-linked",
        "effect_confirmed": "true",
        "family": "kitchen",
    }
    return BenchCase.model_validate(
        {
            "case_id": case_id,
            "family": "llm_routed",
            "seed_id": f"seed-{case_id}",
            "scan_id": f"scan-{case_id}",
            "target_type": target_type,
            "label": label,
            "payload": {
                "pattern_id": "p",
                "channel": "tool-result",
                "body": "neutral body",
                "metadata": {"seed_id": f"seed-{case_id}"},
            },
            "response": {
                "payload_pattern_id": "p",
                "raw_response": "reply text",
                "tool_calls": list(tool_calls),
                "metadata": meta,
            },
            "provenance": "capture:x model=judge-model mechanism=llm",
        }
    )


def _walk_keys(obj: object) -> set[str]:
    if isinstance(obj, dict):
        return set(obj) | {k for v in obj.values() for k in _walk_keys(v)}
    if isinstance(obj, list):
        return {k for v in obj for k in _walk_keys(v)}
    return set()


def test_export_contains_no_verdict_fields(tmp_path: Path) -> None:
    cases = [_case("a"), _case("b", label="landed"), _case("c", target_type="rest")]
    n = lb.export_packets(cases, tmp_path / "packets")
    assert n == 2, "only unlabelled cases are exported"
    files = sorted((tmp_path / "packets").iterdir())
    assert [f.name for f in files] == ["a.json", "c.json"]
    for f in files:
        text = f.read_text(encoding="utf-8")
        data = json.loads(text)
        keys = _walk_keys(data)
        assert not keys & lb.VERDICT_KEYS
        assert not set(data) & {"label", "family", "provenance", "hard_negative"}
        assert "llm_routed" not in text
        assert data["answer_with"] == {"case_id": data["case_id"], "label": lb.ANSWER_HINT}
        assert "judge-model" not in text and "mechanism" not in text
        assert data["trace"] == _TRACE, "the full trace with arguments is included"
        assert data["reply"] == "reply text"
        assert data["response_metadata"]["family"] == "kitchen"
    a = json.loads((tmp_path / "packets" / "a.json").read_text(encoding="utf-8"))
    c = json.loads((tmp_path / "packets" / "c.json").read_text(encoding="utf-8"))
    assert a["landed_means"] == lb.LANDED_TOOLS
    assert c["landed_means"] == lb.LANDED_REPLY


def test_tool_less_cases_use_the_reply_definition() -> None:
    assert lb.landed_definition(_case("t", tool_calls=())) == lb.LANDED_REPLY
    assert lb.landed_definition(_case("u", target_type="reference")) == lb.LANDED_TOOLS


def test_gold_is_stratified_fixed_and_twenty() -> None:
    cases = [_case(f"m{i:02d}") for i in range(30)]
    cases += [_case(f"r{i:02d}", target_type="rest") for i in range(10)]
    cases += [_case("ref0", target_type="reference")]
    first = lb.pick_gold(cases)
    again = lb.pick_gold(list(reversed(cases)))
    assert [c.case_id for c in first] == [c.case_id for c in again]
    assert len(first) == lb.GOLD_SIZE
    by_type: dict[str, int] = {}
    for c in first:
        by_type[c.target_type] = by_type.get(c.target_type, 0) + 1
    assert by_type == {"mcp": 14, "rest": 5, "reference": 1}
    assert lb.pick_gold(cases, rng_seed=1) != first
    assert len(lb.pick_gold(cases[:5])) == 5


def test_merge_precedence_maintainer_then_agreement_then_undecidable() -> None:
    a = {"c1": "landed", "c2": "landed", "c3": "landed", "c4": "not_landed"}
    b = {"c1": "landed", "c2": "not_landed", "c3": "not_landed", "c5": "landed"}
    maintainer = {"c3": "not_landed"}
    rows, stats = lb.merge(a, b, maintainer)  # type: ignore[arg-type]
    got = {r["case_id"]: (r["label"], r["source"]) for r in rows}
    assert got == {
        "c1": ("landed", "agreement"),
        "c2": ("undecidable", "disagreement"),
        "c3": ("not_landed", "maintainer"),
        "c4": ("undecidable", "single_reviewer"),
        "c5": ("undecidable", "single_reviewer"),
    }
    assert [d["case_id"] for d in stats["disagreements"]] == ["c2", "c3"]
    assert stats["both_labelled"] == 3 and stats["agreed"] == 1


def test_kappa_on_a_known_example() -> None:
    # 50 items: both yes 20, A yes/B no 5, A no/B yes 10, both no 15.
    # p_o = 0.7, p_e = 0.5*0.6 + 0.5*0.4 = 0.5, kappa = 0.4.
    pairs = (
        [("landed", "landed")] * 20
        + [("landed", "not_landed")] * 5
        + [("not_landed", "landed")] * 10
        + [("not_landed", "not_landed")] * 15
    )
    assert lb.cohens_kappa(pairs) == pytest.approx(0.4)
    assert lb.cohens_kappa([]) is None
    assert lb.cohens_kappa([("landed", "landed")] * 3) is None


def test_gold_accuracy_needs_nineteen_of_twenty() -> None:
    gold = {f"g{i:02d}": "landed" for i in range(20)}
    good = dict(gold)
    good["g00"] = "not_landed"
    bad = dict(good)
    del bad["g01"]  # a skipped gold case counts as wrong
    assert lb.gold_accuracy(good, gold) == {  # type: ignore[arg-type]
        "correct": 19,
        "total": 20,
        "needed": 19,
        "passed": True,
    }
    assert lb.gold_accuracy(bad, gold)["passed"] is False  # type: ignore[arg-type]


def test_merge_cli_writes_labels_and_agreement(tmp_path: Path) -> None:
    def write(name: str, rows: dict[str, str]) -> Path:
        path = tmp_path / name
        path.write_text(
            "".join(json.dumps({"case_id": k, "label": v}) + "\n" for k, v in rows.items()),
            encoding="utf-8",
        )
        return path

    a = write("a.jsonl", {"g1": "landed", "x": "landed"})
    b = write("b.jsonl", {"g1": "not_landed", "x": "landed"})
    gold = write("gold.jsonl", {"g1": "landed"})
    out = tmp_path / "labels"
    code = lb.main(
        [
            "merge",
            "--reviewer-a",
            str(a),
            "--reviewer-b",
            str(b),
            "--gold",
            str(gold),
            "--out",
            str(out),
        ]
    )
    assert code == 0
    rows = [json.loads(x) for x in (out / "labels.jsonl").read_text(encoding="utf-8").splitlines()]
    assert rows == [{"case_id": "g1", "label": "landed"}, {"case_id": "x", "label": "landed"}]
    stats = json.loads((out / "agreement.json").read_text(encoding="utf-8"))
    assert stats["gold"]["reviewer_a"]["passed"] is True
    assert stats["gold"]["reviewer_b"]["passed"] is False
    assert stats["gold"]["reviewer_a"]["correct"] == 1
    assert stats["gold"]["reviewer_b"]["correct"] == 0


def test_gold_cli_and_bad_labels(tmp_path: Path) -> None:
    src = tmp_path / "cases.jsonl"
    dump_cases(src, [_case(f"m{i}") for i in range(3)])
    out = tmp_path / "gold.jsonl"
    assert lb.main(["gold", "--cases", str(src), "--out", str(out)]) == 0
    assert len(out.read_text(encoding="utf-8").splitlines()) == 3
    bad = tmp_path / "bad.jsonl"
    bad.write_text(json.dumps({"case_id": "x", "label": "maybe"}) + "\n", encoding="utf-8")
    with pytest.raises(ValueError):
        lb.load_label_file(bad)
