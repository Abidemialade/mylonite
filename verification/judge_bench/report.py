"""Summarise judge outcomes and render the report.

The summary is a plain dict (written as ``summary.json``); :func:`to_markdown`
renders it for people. Neither ever folds accuracy and false-clean into one
pass/fail word.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any

from verification.judge_bench.cases import BAR_FAMILIES, BenchCase
from verification.judge_bench.runner import (
    CaseOutcome,
    headline,
    majority_of,
    repeat_agreement,
)
from verification.judge_bench.split import Manifest
from verification.judge_bench.stats import bar_family_cases, evaluate_bar, figures, hard_set

UNIT_OF_ANALYSIS = "one unique case, single call (repeat 1); repeats never add to n"
INTERVAL_METHOD = "two-sided Wilson 95% (z = 1.96); seed-clustered bootstrap as a sensitivity check"
BAR_FAMILY_NOTE = (
    "Only the llm_routed and agentdojo families count toward the bar. The injecagent, "
    "synthetic, shadow and shadow_stripped families are supporting evidence and never "
    "count toward the bar."
)


def summarize(
    outcomes: Sequence[CaseOutcome],
    cases: Sequence[BenchCase],
    manifest: Manifest | None,
    split: str,
) -> dict[str, Any]:
    """Build the full summary: the bar per model, family tables, secondary figures.

    ``split`` is ``dev``, ``test``, ``all`` or ``partial`` (a run cut short by
    ``--max-cases``). A partial run is never the held-out result, and its bar
    results are insufficient evidence. Any ``provider_error`` outcome marks the
    whole summary ``incomplete``.
    """
    partial = split == "partial"
    models = sorted({o.model for o in outcomes})
    case_ids = {c.case_id for c in cases}
    per_model: dict[str, Any] = {}
    for model in models:
        head = [o for o in headline(outcomes, model) if o.case_id in case_ids]
        bar = evaluate_bar(head, cases, partial=partial)
        head_counts = _counts(head)
        majority = [o for o in majority_of(outcomes, model) if o.case_id in case_ids]
        secondary: dict[str, Any] = {
            "repeat_agreement": repeat_agreement(
                (o for o in outcomes if o.case_id in case_ids), model
            ),
        }
        if majority:
            bar_cases, _ = bar_family_cases(cases)
            hard = hard_set(bar_cases)
            maj_by_id = {o.case_id: o for o in majority}
            secondary["majority_of_3"] = {
                "note": "secondary only; majority voting lowers measured error, never the bar",
                "hard": figures(hard, maj_by_id)[0],
                "production_mix": figures(bar_cases, maj_by_id)[0],
            }
        per_model[model] = {
            "bar": bar,
            "headline_counts": head_counts,
            "secondary": secondary,
        }
    return {
        "unit_of_analysis": UNIT_OF_ANALYSIS,
        "interval_method": INTERVAL_METHOD,
        "bar_families": sorted(BAR_FAMILIES),
        "bar_family_note": BAR_FAMILY_NOTE,
        "split": split,
        "held_out": split == "test",
        "incomplete": any(o.category == "provider_error" for o in outcomes),
        "provider_errors": sum(1 for o in outcomes if o.category == "provider_error"),
        "manifest": None
        if manifest is None
        else {
            "test_sha256": manifest.test_sha256,
            "rng_seed": manifest.rng_seed,
            "created": manifest.created,
            "n_dev": len(manifest.dev_ids),
            "n_test": len(manifest.test_ids),
        },
        "n_cases": len(cases),
        "repeats": max((o.repeat for o in outcomes), default=0),
        "models": per_model,
    }


def _counts(outcomes: Iterable[CaseOutcome]) -> dict[str, int]:
    counts = {
        "landed": 0,
        "not_landed": 0,
        "abstain": 0,
        "routed_deterministic": 0,
        "provider_error": 0,
    }
    for o in outcomes:
        counts[o.category] += 1
    return counts


def _pct(x: float | None) -> str:
    return "n/a" if x is None else f"{x:.1%}"


def _interval(rate: dict[str, Any], key: str = "wilson95") -> str:
    lo, hi = rate[key]
    return f"[{lo:.4f}, {hi:.4f}]"


def _family_rows(per_family: dict[str, Any]) -> list[str]:
    rows = [
        "| Family | Counts toward bar | Cases | Decided | Accuracy | Accuracy 95% | "
        "Positives | False-clean | False-clean 95% | Abstain | Routed deterministic |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for family, f in per_family.items():
        acc, fc = f["accuracy"], f["false_clean"]
        rows.append(
            f"| {family} | {'yes' if f['counts_toward_bar'] else 'no'} | {f['n_cases']} | "
            f"{f['n_decided']} | {acc['k']}/{acc['n']} ({_pct(acc['rate'])}) | "
            f"{_interval(acc)} | {f['n_positives']} | {fc['k']}/{fc['n']} "
            f"({_pct(fc['rate'])}) | {_interval(fc)} | {f['abstain']} | "
            f"{f['routed_deterministic']} |"
        )
    return rows


def _metric_line(name: str, m: dict[str, Any]) -> list[str]:
    lines = [
        f"- **{name}: {m['result']}.** {m['k']}/{m['n']} ({_pct(m['rate'])}); "
        f"Wilson 95% {_interval(m)}; seed-cluster bootstrap 95% "
        f"{_interval(m, 'bootstrap95_by_seed')}. Bar: {m['bar']}."
    ]
    lines.extend(f"  - insufficient evidence: {r}" for r in m["insufficient_reasons"])
    return lines


def to_markdown(summary: dict[str, Any]) -> str:
    """Render the summary as Markdown."""
    out: list[str] = ["# Judge measurement", ""]
    out.append(f"- **Unit of analysis:** {summary['unit_of_analysis']}.")
    out.append(f"- **Interval method:** {summary['interval_method']}.")
    out.append(f"- **Families:** {summary['bar_family_note']}")
    split = summary["split"]
    if summary.get("incomplete"):
        out.append(
            f"- **INCOMPLETE RUN:** {summary['provider_errors']} judge call(s) got no answer "
            "from the provider (rate limit, timeout, network, auth or a content filter). "
            "Every bar result below is insufficient evidence."
        )
    if split == "partial":
        out.append(
            "- **Split:** partial. The run was cut short by --max-cases, so these figures "
            "are not the preregistered result."
        )
    elif summary["held_out"]:
        out.append("- **Split:** test (the held-out set).")
    else:
        out.append(
            f"- **Split:** {split}. This is not the held-out set, so these figures are "
            "not the preregistered result."
        )
    manifest = summary["manifest"]
    if manifest is not None:
        out.append(
            f"- **Manifest:** held-out SHA-256 `{manifest['test_sha256']}`, "
            f"{manifest['n_test']} held-out and {manifest['n_dev']} dev cases, "
            f"split seed {manifest['rng_seed']}."
        )
    out.append(f"- **Cases scored:** {summary['n_cases']}; repeats: {summary['repeats']}.")
    out.append("")
    for model, m in summary["models"].items():
        bar = m["bar"]
        out.append(f"## {model}")
        out.append("")
        out.append(
            "Bar, scored on the hard set (landed cases plus hard negatives) of the bar "
            "families. Accuracy and false-clean are separate results."
        )
        out.append("")
        out.extend(_metric_line("Accuracy", bar["accuracy"]))
        out.extend(_metric_line("False-clean", bar["false_clean"]))
        ab = bar["abstention"]
        flag = " **(flagged: above 10%)**" if ab["flagged"] else ""
        out.append(
            f"- Abstentions (bar families, never counted as negatives): {ab['count']} "
            f"({_pct(ab['rate'])}){flag}."
        )
        landed_flag = " **(flagged: above 10%)**" if ab["landed_flagged"] else ""
        cons = bar["false_clean_conservative"]
        out.append(
            f"- Abstentions on landed-label cases: {ab['landed_count']} "
            f"({_pct(ab['landed_rate'])}){landed_flag}. Conservative false-clean, "
            f"counting each as a miss (secondary): {cons['k']}/{cons['n']} "
            f"({_pct(cons['rate'])}), Wilson 95% {_interval(cons)}."
        )
        out.append(
            f"- Per-seed cap: at most {bar['seed_cap']['cap']} cases per family and seed; "
            f"{bar['seed_cap']['dropped']} bar-family case(s) dropped before scoring."
        )
        out.append(f"- Provider errors (no answer, not abstentions): {bar['provider_error']}.")
        out.append(
            f"- Routed deterministic (decided by a predicate, excluded from every judge "
            f"figure): {bar['routed_deterministic']}."
        )
        out.append(
            f"- Positives: {bar['n_positives']} landed-label decided cases from "
            f"{bar['n_seeds_positive']} distinct seeds."
        )
        mix = bar["sets"]["production_mix"]
        out.append("")
        out.append("Production mix (every bar-family case, ordinary negatives included):")
        out.append("")
        out.extend(_metric_line("Accuracy", mix["accuracy"]))
        out.extend(_metric_line("False-clean", mix["false_clean"]))
        out.append("")
        out.append("### Per family (headline, single call)")
        out.append("")
        out.extend(_family_rows(bar["per_family"]))
        out.append("")
        sec = m["secondary"]
        out.append("### Secondary figures (never used for the bar)")
        out.append("")
        ra = sec["repeat_agreement"]
        out.append(
            f"- Repeat agreement: {ra['agree']}/{ra['cases']} cases where every repeat "
            f"agrees ({_pct(ra['rate'])})."
        )
        maj = sec.get("majority_of_3")
        if maj is not None:
            for set_name in ("hard", "production_mix"):
                f = maj[set_name]
                acc, fc = f["accuracy"], f["false_clean"]
                out.append(
                    f"- Majority of 3, {set_name.replace('_', ' ')}: accuracy {acc['k']}/"
                    f"{acc['n']} ({_pct(acc['rate'])}), false-clean {fc['k']}/{fc['n']} "
                    f"({_pct(fc['rate'])})."
                )
        else:
            out.append("- Majority of 3: not computed (fewer than 3 repeats).")
        out.append("")
    return "\n".join(out).rstrip() + "\n"


__all__ = ["INTERVAL_METHOD", "UNIT_OF_ANALYSIS", "summarize", "to_markdown"]
