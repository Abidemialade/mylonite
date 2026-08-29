"""Committed-results sanitiser tests - hermetic (no git, no network, no model).

These cover the two halves of the D4 constraint ("nothing machine-readable
containing local-PC info is committed"): the scrubber that cleans free text, and
the field allowlist that stops an unreviewed field from riding along.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from verification._sanitise import (
    LAYER1_FIELDS,
    LAYER1_PER_CHALLENGE_FIELDS,
    LAYER2_DISAGREEMENT_FIELDS,
    LAYER2_FIELDS,
    LAYER2_JUDGE_AGREEMENT_FIELDS,
    LAYER3_FALSE_POSITIVE_FIELDS,
    LAYER3_FIELDS,
    META_FIELDS,
    FieldNotAllowed,
    scrub,
    scrub_tree,
    validate_fields,
)


@pytest.mark.parametrize(
    "raw",
    [
        r"C:\Users\someone\Documents\Claude\Projects\Mylonite\report.json",
        "C:/Users/someone/Documents/report.json",
        r"C:\\Users\\someone\\Documents\\report.json",  # as it survives JSON encoding
        r"\Users\someone\Documents",  # drive-less UNC-ish form
        "/home/someone/private/scan.json",
        "/Users/someone/work/scan.json",
        r"D:\work\checkout\src",  # any drive path is local by definition
    ],
)
def test_scrub_collapses_local_paths(raw: str) -> None:
    assert scrub(raw) == "<path>"


def test_scrub_keeps_surrounding_prose_and_trailing_punctuation() -> None:
    assert scrub(r"wrote the bundle to C:\Users\someone\out.json.") == "wrote the bundle to <path>."


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("localhost:8001", "<host>:<port>"),
        ("127.0.0.1:9001", "<host>:<port>"),
        ("0.0.0.0:8080", "<host>:<port>"),
        ("192.168.1.24:9003", "<host>:<port>"),
        ("http://localhost:9001/sse", "http://<host>:<port>/sse"),
        ("bound to localhost", "bound to <host>"),
        ("127.0.0.1", "<host>"),
    ],
)
def test_scrub_collapses_local_addresses(raw: str, expected: str) -> None:
    assert scrub(raw) == expected


@pytest.mark.parametrize(
    "harmless",
    [
        "c3-excessive-permission-scope [W2]: flagged W2",
        "recall 0.8 over 10 in-scope challenges",
        "verification/results/0.9.0/meta.json",
        "the judge disagreed on case injecagent-dh-17",
        "https://example.com/api/v1/tools",
        "reference:guarded",
        "",
    ],
)
def test_scrub_leaves_harmless_text_alone(harmless: str) -> None:
    assert scrub(harmless) == harmless


@pytest.mark.parametrize(
    "raw",
    [
        r"scan of C:\Users\someone\proj against http://127.0.0.1:9002/sse failed",
        "target scope /home/someone/private on localhost:8001",
        "no local content at all",
    ],
)
def test_scrub_is_idempotent(raw: str) -> None:
    """Committed results are diffed release over release, so re-scrubbing must not drift."""
    once = scrub(raw)
    assert scrub(once) == once


def test_scrub_is_deterministic() -> None:
    raw = "two runs, same input: /home/someone/a and /home/someone/b on localhost:8001"
    assert scrub(raw) == scrub(raw)
    # Different paths collapse to the SAME placeholder: the shape is the leak, and
    # per-path placeholders would encode how many distinct local paths there were.
    assert scrub(raw) == "two runs, same input: <path> and <path> on <host>:<port>"


def test_scrub_passes_through_non_strings() -> None:
    """Callers pipe values through without type-testing first, so non-str must survive."""
    value: object = 7
    result: object = scrub(value)  # type: ignore[arg-type]
    assert result == 7


def test_scrub_tree_preserves_shape_and_non_strings() -> None:
    payload = {
        "layer": "layer1-recall",
        "recall": 0.8,
        "found": 8,
        "fpr_informative": False,
        "missing": None,
        "per_challenge": [
            {
                "challenge": "c1-basic-prompt-injection",
                "found": True,
                "detail": "server at http://127.0.0.1:9001/sse under /home/someone/dvmcp",
            }
        ],
    }
    cleaned = scrub_tree(payload)
    assert cleaned["recall"] == 0.8
    assert cleaned["found"] == 8
    assert cleaned["fpr_informative"] is False
    assert cleaned["missing"] is None
    assert cleaned["per_challenge"][0]["challenge"] == "c1-basic-prompt-injection"
    assert cleaned["per_challenge"][0]["found"] is True
    assert (
        cleaned["per_challenge"][0]["detail"] == "server at http://<host>:<port>/sse under <path>"
    )
    # Keys are field names, not run data: rewriting one would break the allowlist.
    assert set(cleaned) == set(payload)


def test_scrub_tree_handles_lists_and_tuples_of_strings() -> None:
    assert scrub_tree(["/home/someone/x", ("localhost:8001", 3)]) == [
        "<path>",
        ("<host>:<port>", 3),
    ]


def _layer3_payload() -> dict[str, object]:
    """A known-good Layer 3 summary, field-for-field as ``precision_report`` builds it."""
    return {
        "schema_version": "1.0",
        "layer": "layer3-precision",
        "target": "reference:guarded",
        "completed_probes": 12,
        "false_positives": 0,
        "true_negatives": 12,
        "false_positive_rate": 0.0,
        "false_positive_detail": [],
        "note": "False-positive control on a target that SHOULD resist every attack.",
    }


def test_validate_fields_accepts_a_known_good_payload() -> None:
    validate_fields(_layer3_payload(), allowed=LAYER3_FIELDS, where="layer3-precision")


def test_validate_fields_allows_missing_keys() -> None:
    """Absence leaks nothing; this guard is about additions."""
    validate_fields({"layer": "layer3-precision"}, allowed=LAYER3_FIELDS, where="layer3-precision")


def test_validate_fields_rejects_an_added_key() -> None:
    payload = _layer3_payload()
    payload["scan_dir"] = "somewhere"
    with pytest.raises(FieldNotAllowed) as exc:
        validate_fields(payload, allowed=LAYER3_FIELDS, where="layer3-precision")
    message = str(exc.value)
    assert "scan_dir" in message  # names the offender
    assert "layer3-precision" in message  # names where
    assert "allowlist" in message  # tells the reader what to do about it


def test_validate_fields_names_every_offender() -> None:
    payload = {"layer": "x", "cwd": "...", "argv": "..."}
    with pytest.raises(FieldNotAllowed) as exc:
        validate_fields(payload, allowed=LAYER3_FIELDS, where="layer3-precision")
    assert "'argv'" in str(exc.value)
    assert "'cwd'" in str(exc.value)


def test_validate_fields_catches_build_report_extra_injection() -> None:
    """``build_report`` ends with ``**(extra or {})`` - an open-ended field injection point."""
    payload = {"layer": "layer2-judge-agreement", "run_host": "..."}
    with pytest.raises(FieldNotAllowed):
        validate_fields(payload, allowed=LAYER2_FIELDS, where="layer2")


@pytest.mark.parametrize(
    ("allowed", "expected_member"),
    [
        (LAYER1_FIELDS, "per_challenge"),
        (LAYER1_PER_CHALLENGE_FIELDS, "detail"),
        (LAYER2_FIELDS, "judge_agreement"),
        (LAYER2_DISAGREEMENT_FIELDS, "detail"),
        (LAYER3_FIELDS, "false_positive_detail"),
        (LAYER3_FALSE_POSITIVE_FIELDS, "reason"),
        (META_FIELDS, "mylonite_version"),
    ],
)
def test_allowlists_cover_the_known_leak_carrying_fields(
    allowed: frozenset[str], expected_member: str
) -> None:
    assert expected_member in allowed


def test_layer_allowlists_match_the_builders(tmp_path: Path) -> None:
    """The allowlists are transcriptions; if a builder gains a field, this fails.

    Imported lazily so this file stays readable as a spec of the allowlists
    themselves, and so a builder import error names the builder, not this test.
    """
    from verification.layer1_runnable.run import build_recall_report
    from verification.layer3_production.run import precision_report
    from verification.report import build_report

    from mylonite.corpus import CaseResult, confusion_matrix

    rows = [
        CaseResult(
            weakness="W1",
            variant="c1",
            expected_exploited=True,
            detected_exploited=True,
            detail="flagged W1",
        )
    ]
    matrix = confusion_matrix(rows)

    layer1 = build_recall_report(rows, matrix)
    validate_fields(layer1, allowed=LAYER1_FIELDS, where="layer1-recall")
    for row in layer1["per_challenge"]:
        validate_fields(row, allowed=LAYER1_PER_CHALLENGE_FIELDS, where="layer1.per_challenge")

    layer2 = build_report(
        dataset="injecagent",
        model="",
        rows=rows,
        matrix=matrix,
        judge_mode="deterministic",
        synthetic=True,
    )
    validate_fields(layer2, allowed=LAYER2_FIELDS, where="layer2-judge-agreement")
    validate_fields(
        layer2["judge_agreement"],
        allowed=LAYER2_JUDGE_AGREEMENT_FIELDS,
        where="layer2.judge_agreement",
    )
    for row in layer2["disagreements"]:
        validate_fields(row, allowed=LAYER2_DISAGREEMENT_FIELDS, where="layer2.disagreements")

    scan_report = tmp_path / "scan_report.json"
    scan_report.write_text(
        json.dumps(
            {
                "target_id": "reference:guarded",
                "attempts": [
                    {"pattern_id": "p1", "outcome": "finding", "verdict_reason": "wrongly flagged"}
                ],
            }
        ),
        encoding="utf-8",
    )
    layer3 = precision_report(scan_report)
    validate_fields(layer3, allowed=LAYER3_FIELDS, where="layer3-precision")
    for row in layer3["false_positive_detail"]:
        validate_fields(
            row, allowed=LAYER3_FALSE_POSITIVE_FIELDS, where="layer3.false_positive_detail"
        )
