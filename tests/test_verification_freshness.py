"""The verification-freshness release gate must require evidence, not a claim of it.

`check_verification_freshness.py` gates a minor/major release on committed
third-party verification results. It verified that `meta.json` existed, parsed,
and carried a matching `mylonite_version` — and then stopped. It never looked at
`layers` and never opened a single result file, so a `meta.json` containing
nothing but the right version string passed the gate, and so did one claiming
`{"layer1": "ran"}` with no such file on disk.

A release gate that accepts a claim of evidence instead of the evidence is the
same false-assurance shape this project fixes everywhere else — and this one sat
in the release path, where the whole point is to stop a release citing numbers
for a product that no longer exists.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import check_verification_freshness as gate
from verification.campaign import LAYER_FILES

_ALL_RAN = {key: "ran" for key in LAYER_FILES}


def _write(root: Path, version: str, meta: dict, *, files: list[str] | None = None) -> Path:
    d = root / version
    d.mkdir(parents=True, exist_ok=True)
    (d / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    for name in files if files is not None else list(LAYER_FILES.values()):
        (d / name).write_text("{}", encoding="utf-8")
    return d


def _meta(**over: object) -> dict:
    base: dict = {"mylonite_version": "0.10.0", "layers": dict(_ALL_RAN)}
    base.update(over)
    return base


# --- the duplication is deliberate, so pin it -------------------------------


def test_the_duplicated_layer_filenames_match_the_harness() -> None:
    """The script is stdlib-only by design (it runs with nothing installed), so it
    carries its own copy of the filenames. A rename in the harness must not
    silently orphan the gate — the same idiom campaign<->trends already uses."""
    assert gate._LAYER_FILES == LAYER_FILES


def test_every_layer_is_classified_as_core_or_best_effort() -> None:
    """A new layer must be a deliberate decision about whether a release may ship
    without it, not silently unchecked."""
    assert set(gate._CORE_LAYERS) | set(gate._BEST_EFFORT_LAYERS) == set(LAYER_FILES)
    assert not set(gate._CORE_LAYERS) & set(gate._BEST_EFFORT_LAYERS)


# --- what the gate used to let through --------------------------------------


def test_a_meta_with_no_layers_is_rejected(tmp_path: Path) -> None:
    """THE hole: this passed. A matching version string and nothing else."""
    _write(tmp_path, "0.10.0", {"mylonite_version": "0.10.0"})

    problems = gate.check("0.10.0", results_root=tmp_path)

    assert problems and "no 'layers' object" in problems[0]


def test_a_layer_claiming_to_have_run_must_have_left_its_file(tmp_path: Path) -> None:
    """The other hole: `{"layer1": "ran"}` with no file on disk."""
    _write(tmp_path, "0.10.0", _meta(), files=[])

    problems = gate.check("0.10.0", results_root=tmp_path)

    assert problems
    assert all("the claim and the evidence disagree" in p.lower() for p in problems)


def test_a_campaign_where_nothing_ran_is_rejected(tmp_path: Path) -> None:
    nothing = {key: "not-run" for key in LAYER_FILES}
    _write(tmp_path, "0.10.0", _meta(layers=nothing), files=[])

    problems = gate.check("0.10.0", results_root=tmp_path)

    assert any("measured nothing" in p for p in problems)


def test_an_omitted_layer_key_is_rejected(tmp_path: Path) -> None:
    """An absent key is indistinguishable from a silently skipped layer."""
    partial = {k: v for k, v in _ALL_RAN.items() if k != "layer3"}
    _write(tmp_path, "0.10.0", _meta(layers=partial))

    problems = gate.check("0.10.0", results_root=tmp_path)

    assert any("omits" in p and "layer3" in p for p in problems)


@pytest.mark.parametrize(
    "core", ["layer2-agentdojo", "layer2-injecagent-dh", "layer2-injecagent-ds"]
)
def test_a_core_layer_that_did_not_run_is_fatal(tmp_path: Path, core: str) -> None:
    """The layer-2 scorers replay committed trajectories and need no live server,
    so "could not run" is never a legitimate state for a release."""
    layers = dict(_ALL_RAN) | {core: "not-run"}
    files = [name for key, name in LAYER_FILES.items() if key != core]
    _write(tmp_path, "0.10.0", _meta(layers=layers), files=files)

    problems = gate.check("0.10.0", results_root=tmp_path)

    assert any(core in p and "must run for every release" in p for p in problems)


@pytest.mark.parametrize("best_effort", ["layer1", "layer3"])
def test_a_best_effort_layer_that_did_not_run_is_not_fatal(
    tmp_path: Path, best_effort: str
) -> None:
    """These need third-party servers standing up. Their absence is reported, not
    fatal — otherwise the gate would make a release impossible without a lab."""
    layers = dict(_ALL_RAN) | {best_effort: "not-run"}
    files = [name for key, name in LAYER_FILES.items() if key != best_effort]
    _write(tmp_path, "0.10.0", _meta(layers=layers), files=files)

    assert gate.check("0.10.0", results_root=tmp_path) == []


def test_an_unknown_layer_key_is_rejected(tmp_path: Path) -> None:
    layers = dict(_ALL_RAN) | {"layer9-imaginary": "ran"}
    _write(tmp_path, "0.10.0", _meta(layers=layers))

    problems = gate.check("0.10.0", results_root=tmp_path)

    assert any("unknown layer" in p for p in problems)


# --- and what it must still accept ------------------------------------------


def test_a_complete_campaign_passes(tmp_path: Path) -> None:
    """Non-regression: the gate must not have become unsatisfiable."""
    _write(tmp_path, "0.10.0", _meta())

    assert gate.check("0.10.0", results_root=tmp_path) == []


def test_the_committed_0_9_0_results_still_satisfy_the_gate() -> None:
    """Run against the real evidence in the repo, not a fixture: a stricter gate
    that rejects the project's own honest campaign would be a bad gate."""
    root = Path(__file__).resolve().parent.parent / "verification" / "results"

    assert gate.check("0.9.0", results_root=root) == []


def test_a_patch_release_is_still_exempt(tmp_path: Path) -> None:
    """Patch releases do not re-run a live, key-consuming campaign."""
    assert gate.check("0.10.1", results_root=tmp_path) == []
