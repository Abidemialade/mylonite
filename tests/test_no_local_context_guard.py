"""Tests for the local-context guard (``scripts/check_no_local_context.py``).

Hermetic: every case runs the guard's ``scan`` over files this test writes, or
over files already tracked in the repo. Nothing shells out to git and nothing
depends on which files happen to be staged.

The guard has two jobs and both are load-bearing. It must FIRE on a local path
or a local address that reaches a committed verification result (the leak class
that once forced a force-push), and it must STAY QUIET on the project's own
prose - a guard that cries wolf gets bypassed, which is worse than no guard.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
GUARD_PATH = REPO_ROOT / "scripts" / "check_no_local_context.py"


def _load_guard() -> ModuleType:
    """Import the guard by path: ``scripts/`` is not a package on ``sys.path``."""
    spec = importlib.util.spec_from_file_location("check_no_local_context", GUARD_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


guard = _load_guard()


def _results_file(tmp_path: Path, name: str, payload: object) -> Path:
    """Write ``payload`` as JSON at a path the guard recognises as committed evidence."""
    dest = tmp_path / "verification" / "results" / "0.9.0" / name
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return dest


def test_flags_a_posix_home_path_in_a_results_json(tmp_path: Path) -> None:
    path = _results_file(
        tmp_path, "layer3-precision.json", {"target": "/home/somebody/private-target"}
    )
    problems = guard.scan([path])
    assert problems, "a home-directory path in a committed result must be flagged"
    assert "/home/somebody/" in problems[0]


def test_flags_a_windows_path_that_survived_json_encoding(tmp_path: Path) -> None:
    """JSON doubles the separators, which is exactly what the prose rule misses."""
    path = _results_file(
        tmp_path, "layer1-recall.json", {"detail": r"C:\Users\somebody\dvmcp\server.py"}
    )
    raw = path.read_text(encoding="utf-8")
    assert r"C:\\Users\\somebody" in raw  # the escaped form the guard must handle
    assert guard.scan([path])


@pytest.mark.parametrize(
    "leak",
    [
        "server at http://localhost:9001/sse",
        "bound 127.0.0.1:8001",
        "listening on 0.0.0.0:8080",
        "reached 192.168.1.24:9003",
    ],
)
def test_flags_local_addresses_in_a_results_json(tmp_path: Path, leak: str) -> None:
    path = _results_file(tmp_path, "layer1-recall.json", {"per_challenge": [{"detail": leak}]})
    assert guard.scan([path]), f"expected a leak report for {leak!r}"


def test_flags_a_results_jsonl_transcript(tmp_path: Path) -> None:
    """Layer 2 transcripts are committed as JSONL and get the same rules."""
    dest = tmp_path / "verification" / "results" / "0.9.0" / "layer2-transcripts" / "dh.jsonl"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(
        json.dumps({"final_output": "read /home/somebody/notes.txt"}) + "\n", encoding="utf-8"
    )
    assert guard.scan([dest])


def test_accepts_a_sanitised_results_json(tmp_path: Path) -> None:
    """The scrubbed form of every vector above must pass, or the sanitiser is useless."""
    path = _results_file(
        tmp_path,
        "layer1-recall.json",
        {
            "schema_version": "1.0",
            "layer": "layer1-recall",
            "target": "dvmcp",
            "recall": 0.8,
            "per_challenge": [
                {"challenge": "c1", "found": True, "detail": "server at http://<host>:<port>/sse"},
                {"challenge": "c2", "found": False, "detail": "target scope <path>: MISSED"},
            ],
        },
    )
    assert guard.scan([path]) == []


def test_sanitiser_output_survives_the_guard(tmp_path: Path) -> None:
    """End to end: scrub a leaky payload, write it, and the guard is satisfied."""
    from verification._sanitise import scrub_tree

    leaky = {
        "target": r"C:\Users\somebody\targets\custom.yaml",
        "false_positive_detail": [
            {"pattern_id": "p1", "reason": "planted note via http://127.0.0.1:9001/sse"}
        ],
        "note": "scope /home/somebody/private",
    }
    assert guard.scan([_results_file(tmp_path, "leaky.json", leaky)])
    assert guard.scan([_results_file(tmp_path, "clean.json", scrub_tree(leaky))]) == []


def test_local_addresses_are_not_flagged_outside_results(tmp_path: Path) -> None:
    """Prose keeps its existing rules: docs legitimately show a localhost endpoint."""
    doc = tmp_path / "quickstart.md"
    doc.write_text("Point Mylonite at http://localhost:8000/sse.\n", encoding="utf-8")
    assert guard.scan([doc]) == []


def test_json_outside_results_is_out_of_scope() -> None:
    """Only committed evidence gets the data rules; source JSON is not prose to police."""
    assert not guard.is_results_data(Path("src/mylonite/contracts/schemas/finding.json"))
    assert guard.is_results_data(Path("verification/results/0.9.0/layer1-recall.json"))
    assert not guard.is_results_data(Path("verification/results/0.9.0/README.md"))


def test_placeholder_paths_still_pass(tmp_path: Path) -> None:
    """The documented placeholder allowlist is how docs SHOULD write an example path."""
    doc = tmp_path / "example.md"
    doc.write_text("Set `scope: /home/alice/private` in your target file.\n", encoding="utf-8")
    assert guard.scan([doc]) == []


@pytest.mark.parametrize(
    "relpath",
    ["README.md", "CHANGELOG.md", "ROADMAP.md", "SECURITY.md", "verification/README.md"],
)
def test_no_false_positives_on_existing_repo_prose(relpath: str) -> None:
    """The extension must not start failing files that pass today."""
    path = REPO_ROOT / relpath
    if not path.is_file():
        pytest.skip(f"{relpath} not present")
    assert guard.scan([path]) == []
