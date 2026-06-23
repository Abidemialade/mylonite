"""Layer 1 (DVMCP) scaffolding tests — hermetic, no clone/network/scan.

Guards the catalogue scope mapping, port extraction, target-file construction,
bundle parsing, recall math, and the unlicensed-opt-in gate.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from verification.layer1_runnable import dvmcp
from verification.layer1_runnable import run as layer1_run

from mylonite.corpus import confusion_matrix
from verification import fetch


def test_catalogue_scope_and_mapping() -> None:
    in_scope = dvmcp.in_scope_challenges()
    # 1-7 and 10 are in scope; 8 and 9 (RCE / command injection) are not.
    assert {c.number for c in in_scope} == {1, 2, 3, 4, 5, 6, 7, 10}
    assert not dvmcp.CATALOGUE_BY_NUMBER[8].in_scope
    assert not dvmcp.CATALOGUE_BY_NUMBER[9].in_scope
    assert dvmcp.CATALOGUE_BY_NUMBER[2].weakness_classes == ("W1",)  # tool poisoning
    assert dvmcp.CATALOGUE_BY_NUMBER[6].weakness_classes == ("W2",)  # indirect injection
    # out-of-scope challenges map to no weakness class
    assert dvmcp.CATALOGUE_BY_NUMBER[8].weakness_classes == ()


def test_extract_port(tmp_path: Path) -> None:
    sp = tmp_path / "server.py"
    sp.write_text('uvicorn.run("server:mcp", host="0.0.0.0", port=8002)\n', encoding="utf-8")
    assert dvmcp.extract_port(sp) == 8002

    sp2 = tmp_path / "noport.py"
    sp2.write_text("x = 1\n", encoding="utf-8")
    assert dvmcp.extract_port(sp2, default=8005) == 8005
    with pytest.raises(ValueError, match="no uvicorn port"):
        dvmcp.extract_port(sp2)


def test_build_target_file() -> None:
    ch = dvmcp.CATALOGUE_BY_NUMBER[6]
    tf = dvmcp.build_target_file(ch, port=8006)
    assert tf.transport == "sse"
    assert tf.url == "http://localhost:8006/sse"
    assert tf.family == "dvmcp-c6"
    assert tf.weakness_classes == ["W2"]

    with pytest.raises(ValueError, match="out of Mylonite's scope"):
        dvmcp.build_target_file(dvmcp.CATALOGUE_BY_NUMBER[8], port=8008)


def test_weaknesses_from_bundle(tmp_path: Path) -> None:
    bundle = {"findings": [{"weakness_class": "W2"}, {"weakness_class": "W3"}, {"x": 1}]}
    p = tmp_path / "dvmcp-c6.json"
    p.write_text(json.dumps(bundle), encoding="utf-8")
    assert layer1_run.weaknesses_from_bundle(p) == {"W2", "W3"}


def test_recall_rows_and_matrix() -> None:
    # Mylonite flagged challenge 2 (W1) and challenge 6 (W2); missed the rest.
    found = {2: {"W1"}, 6: {"W2", "W4"}}
    rows = layer1_run.recall_rows(found)
    assert len(rows) == 8  # in-scope count
    matrix = confusion_matrix(rows)
    assert matrix.tp == 2
    assert matrix.fn == 6
    assert matrix.fp == 0
    assert matrix.recall == pytest.approx(0.25)
    # every in-scope challenge is a positive (vulnerable target)
    assert all(r.expected_exploited for r in rows)


def test_score_reports_reads_directory(tmp_path: Path) -> None:
    (tmp_path / "dvmcp-c2.json").write_text(
        json.dumps({"findings": [{"weakness_class": "W1"}]}), encoding="utf-8"
    )
    _rows, matrix, report = layer1_run.score_reports(tmp_path)
    assert report["layer"] == "layer1-recall"
    assert matrix.tp == 1  # only challenge 2 scanned + found
    assert report["found"] == 1


def test_fetch_dvmcp_requires_optin() -> None:
    # No network: the gate raises before any clone.
    with pytest.raises(RuntimeError, match="no LICENSE"):
        fetch.fetch_dvmcp()
    assert len(fetch.DVMCP_COMMIT) == 40
