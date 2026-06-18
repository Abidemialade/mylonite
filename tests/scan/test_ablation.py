"""Tests for the control-ablation matrix orchestration (offline, injected scan)."""

from __future__ import annotations

from mylonite.scan.ablation import (
    ControlContribution,
    run_control_ablation,
    seeds_for_weaknesses,
)


def test_contribution_classification() -> None:
    lb = ControlContribution.compute(weakness="W2", raw_fired=1, guarded_fired=0, total=1)
    assert lb.status == "load-bearing" and lb.load_bearing and lb.contribution == 1.0

    theater = ControlContribution.compute(weakness="W4", raw_fired=1, guarded_fired=1, total=1)
    assert theater.status == "theater" and not theater.load_bearing and theater.contribution == 0.0

    no_attack = ControlContribution.compute(weakness="W1", raw_fired=0, guarded_fired=0, total=1)
    assert no_attack.status == "no-attack"

    empty = ControlContribution.compute(weakness="W3", raw_fired=0, guarded_fired=0, total=0)
    assert empty.status == "no-attack"


def test_run_control_ablation_scores_each_control() -> None:
    # W2 control is load-bearing (raw fires, resisted when applied); W4 is theater.
    def scan_fires(applied: tuple[str, ...], pattern_id: str) -> bool:
        if pattern_id.startswith("indirect"):  # W2 seed
            return applied == ()  # fires raw, resisted when W2 applied
        # W4 seed: fires regardless of the control applied -> theater.
        return pattern_id.startswith("excessive-agency-send")

    seeds = {
        "W2": ["indirect-injection-note-body-direct"],
        "W4": ["excessive-agency-send-email-direct-unconfirmed"],
    }
    out = run_control_ablation(controls=["W2", "W4"], seeds_by_weakness=seeds, scan_fires=scan_fires)
    by = {c.weakness: c for c in out}
    assert by["W2"].status == "load-bearing"
    assert by["W2"].contribution == 1.0
    assert by["W4"].status == "theater"


def test_run_control_ablation_no_attack_when_raw_never_fires() -> None:
    out = run_control_ablation(
        controls=["W3"],
        seeds_by_weakness={"W3": ["excessive-agency-fetch-attacker-url-direct"]},
        scan_fires=lambda applied, pid: False,
    )
    assert out[0].status == "no-attack"


def test_run_control_ablation_iterations_and_progress() -> None:
    calls: list[tuple[tuple[str, ...], str]] = []
    msgs: list[str] = []

    def scan_fires(applied: tuple[str, ...], pattern_id: str) -> bool:
        calls.append((applied, pattern_id))
        return applied == ()  # load-bearing

    out = run_control_ablation(
        controls=["W2"],
        seeds_by_weakness={"W2": ["s"]},
        scan_fires=scan_fires,
        iterations=3,
        progress=msgs.append,
    )
    assert out[0].total == 3 and out[0].raw_fired == 3 and out[0].guarded_fired == 0
    assert len(msgs) == 3  # one progress line per iteration
    assert len(calls) == 6  # raw + guarded per iteration


# -- redundancy mode + multi-seed (2f) ----------------------------------------


def test_compute_redundancy_statuses() -> None:
    lb = ControlContribution.compute_redundancy(
        weakness="W2", raw_fired=1, full_fired=0, minus_c_fired=1, total=1
    )
    assert lb.status == "load-bearing"  # removing it re-enables the attack
    red = ControlContribution.compute_redundancy(
        weakness="W3", raw_fired=1, full_fired=0, minus_c_fired=0, total=1
    )
    assert red.status == "redundant"  # set resists without it -> another covers it
    th = ControlContribution.compute_redundancy(
        weakness="W4", raw_fired=1, full_fired=1, minus_c_fired=1, total=1
    )
    assert th.status == "theater"  # set doesn't resist and it doesn't help
    na = ControlContribution.compute_redundancy(
        weakness="W1", raw_fired=0, full_fired=0, minus_c_fired=0, total=1
    )
    assert na.status == "no-attack"


def test_redundancy_mode_distinguishes_redundant_from_theater() -> None:
    seeds = {"W2": ["s_w2"], "W3": ["s_w3"], "W4": ["s_w4"]}

    def scan_fires(applied: tuple[str, ...], pattern_id: str) -> bool:
        if pattern_id == "s_w2":
            return "W2" not in applied  # only W2 stops it -> load-bearing
        if pattern_id == "s_w3":
            return len(applied) == 0  # any control stops it -> redundant in the full set
        return True  # s_w4: nothing stops it -> theater

    out = run_control_ablation(
        controls=["W2", "W3", "W4"],
        seeds_by_weakness=seeds,
        scan_fires=scan_fires,
        redundancy=True,
        all_controls=["W2", "W3", "W4"],
    )
    by = {c.weakness: c.status for c in out}
    assert by["W2"] == "load-bearing"
    assert by["W3"] == "redundant"
    assert by["W4"] == "theater"


def test_seeds_for_weaknesses_multi_and_excludes_family() -> None:
    out = seeds_for_weaknesses(["W2", "W3"], max_per_weakness=2)
    assert 1 <= len(out["W2"]) <= 2  # W2 has several kitchen-sink seeds, capped
    for seeds in out.values():
        for pid in seeds:
            assert not pid.startswith(("filesystem-", "fetch-", "github-"))
