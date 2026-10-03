"""The pre-spend LLM call estimate for ``scan``, ``validate`` and ``gate``.

Before this module, nothing told an operator how many model calls a live run
was ABOUT to make -- only ``docs/ci-gating.md``'s sizing box described the
formula in prose, and the only numbers printed were AFTER the spend (``mylonite
validate``'s ``spend_summary``) or inside an already-tripped budget error
(:func:`mylonite.gate.wiring.validation_cost_note`). A caller who wanted to
know "is this going to be 20 calls or 2000" had to read the docs and do the
arithmetic themselves.

Each public function here returns a ``(low, high)`` call range from what the
run will actually do -- the seed count after filters, ``--iterations``, the
twin count and the metamorphic variant count -- never a made-up constant. The
per-unit call ranges (``SCAN_CALLS_PER_SEED_*``, ``VALIDATE_CALLS_PER_REDRIVE_*``)
are calibrated against ``scripts/count_llm_calls.py``'s measured offline
counts for the bundled reference target; see ``tests/test_cost_estimate.py``,
which asserts a freshly-measured count always falls inside the range this
module predicts for the same inputs.

No price table: :mod:`mylonite.providers.registry` carries no per-call price
for any provider yet, so :func:`format_estimate_line` always says cost is
unknown rather than inventing a number. The moment a provider row gains a
price, :func:`_price_hint` is the one place to wire it in.
"""

from __future__ import annotations

from collections.abc import Sequence

from mylonite.scan._llm import REQUEST_CEILING_ENV, request_ceiling

#: Observed low/high LLM calls per scanned seed -- one customiser call (when
#: the seed needs it), one or more planner turns, and a judge call when the
#: deterministic predicate is inconclusive. Calibrated against
#: ``scripts/count_llm_calls.py``'s reference scan counts: 34-36 calls over 9
#: kitchen-sink seeds (~3.8/seed average); see
#: ``tests/test_cost_estimate.py::test_scan_estimate_brackets_the_measured_reference_count``.
SCAN_CALLS_PER_SEED_LOW = 2
SCAN_CALLS_PER_SEED_HIGH = 5

#: Observed low/high LLM calls per validation re-drive -- one customiser
#: call, a few planner turns, one judge call. Calibrated against the
#: committed differential fixture (``examples/reference_validation``): 1
#: iteration + 1 metamorphic strategy x 2 twins = 4 re-drives for 12 measured
#: calls (3/re-drive); see
#: ``tests/test_cost_estimate.py::test_validate_estimate_brackets_the_measured_reference_count``.
VALIDATE_CALLS_PER_REDRIVE_LOW = 2
VALIDATE_CALLS_PER_REDRIVE_HIGH = 6


def _reference_metamorphic_variant_count() -> int:
    """The number of built-in metamorphic re-paraphrasing strategies.

    Read by inspection from :mod:`mylonite.plugins._reference.reference_validator`
    (the source of truth) so this can never drift out of sync with it the way
    a hand-copied "7" would.
    """
    from mylonite.plugins._reference.reference_validator import _deterministic_strategies

    return len(_deterministic_strategies())


def estimate_scan_seed_count(
    target_id: str,
    *,
    weakness_classes: Sequence[str] | None = None,
    declared_classes: Sequence[str] | None = None,
) -> tuple[int, int]:
    """``(low, high)`` seeds this scan will attempt, after filters.

    Exact for the bundled reference/``mcp:<family>`` targets: a catalogue
    lookup by family, the same filter
    :func:`mylonite.scan.seeds.seed_coverage`'s legacy branch applies, so it
    needs no adapter and makes no call of its own.

    Approximate for a custom target that DECLARES its own
    ``weakness_classes`` (``declared_classes``): seed synthesis depends on
    the live tool surface (describe()'d only once the real run starts), so
    this uses a 1-3-seed-per-class range instead of probing the target just
    to print an estimate.
    """
    if declared_classes:
        classes = set(declared_classes)
        if weakness_classes:
            classes &= set(weakness_classes)
        n = len(classes)
        return (n, n * 3)
    from mylonite.scan.seeds import SEED_CATALOGUE, target_family

    family = target_family(target_id)
    seeds = [s for s in SEED_CATALOGUE if family in s.applicable_targets]
    if weakness_classes:
        wanted = set(weakness_classes)
        seeds = [s for s in seeds if s.weakness in wanted]
    n = len(seeds)
    return (n, n)


def estimate_scan_calls(seed_low: int, seed_high: int) -> tuple[int, int]:
    """``(low, high)`` LLM calls for a scan over this many seeds."""
    return (seed_low * SCAN_CALLS_PER_SEED_LOW, seed_high * SCAN_CALLS_PER_SEED_HIGH)


def redrives_per_finding(*, iterations: int, metamorphic_variants: int, twins: int) -> int:
    """Re-drives ONE finding costs: ``(iterations + metamorphic) x twins``.

    ``metamorphic_variants`` is 0 for a custom target (no metamorphic pass --
    see ``docs/ci-gating.md``'s sizing box).
    """
    return (iterations + metamorphic_variants) * twins


def estimate_validate_calls(
    *, iterations: int, metamorphic_variants: int, twins: int, findings: int = 1
) -> tuple[int, int]:
    """``(low, high)`` LLM calls to validate ``findings`` finding(s)."""
    redrives = findings * redrives_per_finding(
        iterations=iterations, metamorphic_variants=metamorphic_variants, twins=twins
    )
    return (
        redrives * VALIDATE_CALLS_PER_REDRIVE_LOW,
        redrives * VALIDATE_CALLS_PER_REDRIVE_HIGH,
    )


def _ceiling_clause() -> str:
    """One clause naming the hard request ceiling, or that none is set."""
    ceiling = request_ceiling()
    if ceiling is not None:
        return (
            f" The hard ceiling (--max-llm-requests / {REQUEST_CEILING_ENV}) stops "
            f"any run at {ceiling} requests."
        )
    return (
        f" No hard ceiling is set; pass --max-llm-requests (or {REQUEST_CEILING_ENV}) to cap spend."
    )


def _range(low: int, high: int) -> str:
    """``"9"`` when the range is a single number, else ``"9-24"``."""
    return str(low) if low == high else f"{low}-{high}"


def _price_hint() -> str:
    """Cost, in money -- always unknown today.

    :mod:`mylonite.providers.registry` carries no per-call price for any
    provider yet (see its module docstring), so there is nothing to multiply
    the call estimate by. This is the one place to wire a price in once the
    registry gains one; every caller of :func:`format_estimate_line` picks it
    up automatically.
    """
    return " Cost depends on the provider and model; Mylonite does not price calls."


def format_estimate_line(run_label: str, low: int, high: int, detail: str) -> str:
    """One plain line: the call estimate, the hard ceiling, and the cost caveat.

    ``detail`` names what the range is a range OF (seed/re-drive counts) so
    the line explains itself without a second line.
    """
    return (
        f"Estimated LLM calls for this {run_label}: {_range(low, high)} ({detail})."
        f"{_ceiling_clause()}{_price_hint()}"
    )


def scan_estimate_line(
    target_id: str,
    *,
    weakness_classes: Sequence[str] | None = None,
    declared_classes: Sequence[str] | None = None,
) -> str:
    """The pre-spend line ``scan`` prints once seed filters are resolved."""
    seed_low, seed_high = estimate_scan_seed_count(
        target_id, weakness_classes=weakness_classes, declared_classes=declared_classes
    )
    low, high = estimate_scan_calls(seed_low, seed_high)
    detail = (
        f"{_range(seed_low, seed_high)} seed(s) after filters x "
        f"~{SCAN_CALLS_PER_SEED_LOW}-{SCAN_CALLS_PER_SEED_HIGH} calls each"
    )
    return format_estimate_line("scan", low, high, detail)


def validate_estimate_line(*, is_reference: bool, iterations: int, twins: int, fast: bool) -> str:
    """The pre-spend line ``validate`` prints before driving the differential.

    ``twins`` is 1 for a custom target with no inferable control (no
    differential leg at all) or 2 otherwise. The reference path always drives
    2 twins and adds the metamorphic pass (1 strategy under ``--fast``, every
    built-in strategy otherwise); a custom target never runs a metamorphic
    pass regardless of ``--fast`` (see ``docs/ci-gating.md``'s sizing box).
    """
    metamorphic_variants = (
        (1 if fast else _reference_metamorphic_variant_count()) if is_reference else 0
    )
    low, high = estimate_validate_calls(
        iterations=iterations, metamorphic_variants=metamorphic_variants, twins=twins
    )
    redrives = redrives_per_finding(
        iterations=iterations, metamorphic_variants=metamorphic_variants, twins=twins
    )
    detail = (
        f"{redrives} re-drive(s): {iterations} iteration(s)"
        + (f" + {metamorphic_variants} metamorphic" if metamorphic_variants else "")
        + f" x {twins} twin(s), x ~{VALIDATE_CALLS_PER_REDRIVE_LOW}-"
        f"{VALIDATE_CALLS_PER_REDRIVE_HIGH} calls each"
    )
    return format_estimate_line("validation", low, high, detail)


def gate_estimate_line(
    target_id: str,
    *,
    weakness_classes: Sequence[str] | None = None,
    declared_classes: Sequence[str] | None = None,
    is_reference: bool,
    iterations: int,
    fast: bool,
) -> str:
    """The pre-spend line ``gate`` prints before the scan phase starts.

    The scan-phase part of the estimate is exact-ish (seed count after
    filters); the validation part is unknown until the scan decides how many
    findings it kept, so this names the per-finding cost instead of a false
    total -- "each finding kept adds about X-Y more calls", not "the whole
    run costs X-Y".
    """
    seed_low, seed_high = estimate_scan_seed_count(
        target_id, weakness_classes=weakness_classes, declared_classes=declared_classes
    )
    scan_low, scan_high = estimate_scan_calls(seed_low, seed_high)
    twins = 2 if is_reference else (1 if fast else 2)
    metamorphic_variants = (
        (1 if fast else _reference_metamorphic_variant_count()) if is_reference else 0
    )
    per_finding_low, per_finding_high = estimate_validate_calls(
        iterations=iterations, metamorphic_variants=metamorphic_variants, twins=twins, findings=1
    )
    detail = (
        f"{_range(seed_low, seed_high)} seed(s) to scan x "
        f"~{SCAN_CALLS_PER_SEED_LOW}-{SCAN_CALLS_PER_SEED_HIGH} calls each, plus about "
        f"{_range(per_finding_low, per_finding_high)} more per finding kept and validated"
    )
    return format_estimate_line("gate run", scan_low, scan_high, detail)
