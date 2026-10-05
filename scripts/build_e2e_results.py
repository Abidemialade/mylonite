#!/usr/bin/env python3
"""Build ``verification/results/0.12.0/e2e/results.json`` from the end-to-end
campaign's local run artifacts.

Why this script is not run in CI
---------------------------------
Every run this script reads lives under a local, gitignored scratch
directory, passed with ``--artifacts-root`` (its exact path is specific to
the machine that ran the campaign and has no default -- see "Usage"
below), not in the repository. Those artifacts are never committed. This script's OUTPUT, ``results.json``, **is**
committed next to this script -- that file is the durable, machine-readable
record; re-running this script against the same (or a later) local artifact
tree is how a future session reproduces or extends it.

What it does
------------
For every run directory under ``e2e-batch1`` through ``e2e-batch12`` (the
counted runs -- ``e2e-pilot-*``, ``e2e-smoke*`` and ``e2e-diag*`` are
pilot/smoke/diagnostic dispatches and are never read here), this script:

1. Resolves the real scan directory and, for a validated full-journey run,
   the ``generated/`` directory ``validate`` wrote into (mirroring exactly
   what ``.github/workflows/third-party-campaign.yml``'s own "Score the run"
   step passes to ``scripts/score_third_party.py score``: ``--scan-dir`` is
   always the original ``scan --output-dir`` child, ``run_dir`` is
   ``generated`` only once ``validate`` actually wrote a report there).
2. Calls :func:`scripts.score_third_party.score_run` directly (not the
   stale, already-written ``score.json`` beside each run, which several
   early batches wrote with an older scorer version) -- this re-scores
   every counted run from its own artifacts, never from a cached copy.
3. Applies ``verification/PREREG_E2E_2026_10.md``'s own dated amendments in
   code (:data:`RUN_GROUPS`'s ``status`` field): a run is ``void`` when an
   amendment named a harness defect and voided it (streamable read-only-time
   target-venv crash, the agents-sdk scan-only dispatch, the reference-app
   install-path bug, the go-memory ``AdapterDescribeFailed`` regression),
   ``superseded`` when an EARLIER measurement was followed by a product fix
   this file's own amendments record and a later, counted re-measurement
   (the proof-depth cells before the removal-confirmation and Redis
   calibration fixes; the memory W2 breadth cell before the generic
   store-and-recall seed fix), and ``active`` otherwise -- the run that
   counts toward its cell's rollup.
4. Groups the active runs into the prereg's own cells, applies each cell's
   own pass bar, and writes one JSON document with every run (voided and
   superseded runs included, for the audit trail) and every cell's rollup.

Usage
-----

::

    <venv python> scripts/build_e2e_results.py \\
        --artifacts-root <path to the local campaign scratch directory> \\
        --out verification/results/0.12.0/e2e/results.json

There is no default for ``--artifacts-root``: it names a local, gitignored
scratch directory whose exact path is specific to the machine that ran the
campaign, and that path never belongs in committed source. The caller
always passes it explicitly.

Re-running this script is idempotent: given the same artifact tree it
reproduces byte-identical output (module-level ``json.dumps(..., indent=2,
sort_keys=False)`` with a fixed key order per run/cell).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scripts.score_third_party import (  # noqa: E402
    _validated_effect_proof_level,
    precision_rollup,
    rollup,
    score_run,
)

PREREG_FILE = "verification/PREREG_E2E_2026_10.md"

# ---------------------------------------------------------------------------
# The run manifest: one entry per run DIRECTORY the campaign produced.
#
# Each tuple is (batch, folder_name, cell, target, provider, tier, pattern,
# status, status_reason). ``status`` is one of "active" (counts toward its
# cell's rollup), "void" (a harness defect the prereg's amendments name;
# excluded from the rollup, kept in results.json for the audit trail) or
# "superseded" (a real, not-void measurement that an amendment-recorded
# product fix made obsolete; the LATER run under the same cell is what
# counts). This table applies the prereg's void/supersede rules in code --
# every status below cites the amendment or batch note it comes from.
# ---------------------------------------------------------------------------

_MEMORY_SMALL_SUPERSEDED = (
    "measured before the removal-confirmation feature (#357) existed; the "
    "cell's calibration could only ever read dispatched-tool-linked, never "
    "effect-confirmed -- superseded by the batch-4 re-run"
)
_REDIS_SMALL_SUPERSEDED = (
    "measured before the Redis calibration fix (#356) and the "
    "removal-confirmation feature (#357); superseded by the batch-4 re-run"
)
_W1_VOID_INSTALL = (
    "the reference-app install step used the runner's bare `python`, not the "
    "campaign venv `$MYLONITE` imports into -- every run refused "
    "'the reference app target isn't installed' before any LLM call; fixed, "
    "see the 2026-10-04 'a second voiding and re-run' amendment"
)
_GO_MEMORY_VOID = (
    "AdapterDescribeFailed [MYL-PRE-003]: the campaign built the Go binary to "
    "the checkout root but go_memory.yaml's relative command: is anchored "
    "against its own directory (mylonite#187); fixed, see the 2026-10-04 "
    "'a second voiding and re-run' amendment"
)
_TIME_VOID = (
    "mcp-server-time==0.6.2 imports a symbol a newer mcp release renamed, so "
    "every run crashed on import before scan ever ran; fixed by isolating "
    "the server into its own pinned venv, see the 2026-10-04 'voiding and "
    "re-run after the first dispatch round' amendment"
)
_AGENTS_SDK_VOID_SCAN_ONLY = (
    "the workflow ran this cell scan-only, so generate/validate never "
    "executed and STABLE, NOT PROVEN (this cell's own pass bar) was "
    "structurally unreachable; fixed by flipping FULL_JOURNEY, see the "
    "2026-10-04 'voiding and re-run after the first dispatch round' amendment"
)
_W2_MID_SUPERSEDED = (
    "measured before the generic store-and-recall W2 seed existed: "
    "seed_synth's has_plant_recall guard skipped synthesis for any "
    "non-read_note-shaped pair, so the one in-scope W2 seed never engaged "
    "the planner (MYL-NT-006); superseded by the batch-7 re-run, after the "
    "W2 seed fix merged"
)
_REDIS_BATCH4_SUPERSEDED = (
    "measured before the general calibration fix (#363, #364): the "
    "discrimination read confused the record's identifier with its content "
    "marker, so a store whose not-found reply echoes the requested key (as "
    "Redis's does) always failed calibration even on a working read path; "
    "every run here read calibration_status failed for that reason, not "
    "because the target genuinely has no discriminating read -- superseded "
    "by the batch-8/batch-9 re-run"
)
_REDIS_OPENAI_VOID_RATE_LIMIT = (
    "provider rate limit (HTTP 429) outlasted every retry on at least one "
    "leg, so the attempt was skipped and the raw or guarded side reached no "
    "verdict; an infrastructure cause under the re-run rule, not a target "
    "result -- see the 2026-10-05 'Proof depth 2 (Redis), OpenAI runs void "
    "for provider rate limiting' amendment. Re-run sequentially in batch 9."
)
_PRECISION_3_SUPERSEDED = (
    "measured before the session-close race fix (#371): a tool call that "
    "turned on the server's own timed notifications raced Mylonite's "
    "session shutdown, so a finished attempt was filed as a subprocess "
    "crash (MYL-NT-002) although the server never died -- 4 of 6 runs read "
    "NOT_TESTED for that reason, not the third-party flakiness first "
    "published; superseded by the batch-11 re-run, after the fix"
)
_BREADTH_1_SMALL_SUPERSEDED = (
    "measured before the pytest-config isolation fix (#373): one run's W1 "
    "finding passed the differential, flakiness and metamorphic gates and "
    "was rejected only at the build gate by a pytest internal error (exit "
    "3), because the emitted test inherited this project's own pytest "
    "config; superseded by the batch-11 re-run, after the fix"
)

RUN_GROUPS: list[tuple[str, str, str, str, str, str, str | None, str, str | None]] = [
    # (batch, folder, cell, target, provider, tier, pattern, status, reason)
    # --- batch 1 ---
    *[
        (
            "e2e-batch1",
            f"tpv-streamablehttp-{p}-{i}",
            "fix_retest_1",
            "tpv-streamablehttp",
            p,
            "small",
            None,
            "active",
            None,
        )
        for p in ("anthropic", "openai")
        for i in (1, 2, 3)
    ],
    *[
        (
            "e2e-batch1",
            f"tpv-agents-sdk-ollama-{p}-{i}",
            "fix_retest_2",
            "tpv-agents-sdk-ollama",
            p,
            "small",
            None,
            "void",
            _AGENTS_SDK_VOID_SCAN_ONLY,
        )
        for p in ("anthropic", "openai")
        for i in (1, 2, 3)
    ],
    *[
        (
            "e2e-batch1",
            f"e2e-guarded-reference-{p}-{i}",
            "precision_1",
            "e2e-guarded-reference",
            p,
            "small",
            None,
            "active",
            None,
        )
        for p in ("anthropic", "openai")
        for i in (1, 2, 3)
    ],
    *[
        (
            "e2e-batch1",
            f"e2e-readonly-time-{p}-{i}",
            "precision_2",
            "e2e-readonly-time",
            p,
            "small",
            None,
            "void",
            _TIME_VOID,
        )
        for p in ("anthropic", "openai")
        for i in (1, 2, 3)
    ],
    *[
        (
            "e2e-batch1",
            f"e2e-readonly-b-{p}-{i}",
            "precision_3",
            "e2e-readonly-b",
            p,
            "small",
            None,
            "superseded",
            _PRECISION_3_SUPERSEDED,
        )
        for p in ("anthropic", "openai")
        for i in (1, 2, 3)
    ],
    # --- batch 2 ---
    *[
        (
            "e2e-batch2",
            f"tpv-server-memory-{p}-{i}",
            "proof_depth_1",
            "tpv-server-memory",
            p,
            "small",
            None,
            "superseded",
            _MEMORY_SMALL_SUPERSEDED,
        )
        for p in ("anthropic", "openai")
        for i in (1, 2, 3)
    ],
    *[
        (
            "e2e-batch2",
            f"tpv-mcp-redis-{p}-{i}",
            "proof_depth_2",
            "tpv-mcp-redis",
            p,
            "small",
            None,
            "superseded",
            _REDIS_SMALL_SUPERSEDED,
        )
        for p in ("anthropic", "openai")
        for i in (1, 2, 3)
    ],
    # --- batch 3 ---
    *[
        (
            "e2e-batch3",
            f"e2e-readonly-time-{p}-{i}",
            "precision_2",
            "e2e-readonly-time",
            p,
            "small",
            None,
            "active",
            None,
        )
        for p in ("anthropic", "openai")
        for i in (1, 2, 3)
    ],
    *[
        (
            "e2e-batch3",
            f"tpv-agents-sdk-ollama-{p}-{i}",
            "fix_retest_2",
            "tpv-agents-sdk-ollama",
            p,
            "small",
            None,
            "active",
            None,
        )
        for p in ("anthropic", "openai")
        for i in (1, 2, 3)
    ],
    (
        "e2e-batch3",
        "tpv-mcp-redis-openai-3r",
        "proof_depth_2",
        "tpv-mcp-redis",
        "openai",
        "small",
        None,
        "superseded",
        _REDIS_SMALL_SUPERSEDED + " (re-dispatch of run 3 alone, after an "
        "infra abort in batch 2; still pre-fix)",
    ),
    # --- batch 4 ---
    *[
        (
            "e2e-batch4",
            f"tpv-server-memory-{p}-small-none-{i}",
            "proof_depth_1",
            "tpv-server-memory",
            p,
            "small",
            None,
            "active",
            None,
        )
        for p in ("anthropic", "openai")
        for i in (1, 2, 3)
    ],
    *[
        (
            "e2e-batch4",
            f"tpv-mcp-redis-{p}-small-none-{i}",
            "proof_depth_2",
            "tpv-mcp-redis",
            p,
            "small",
            None,
            "superseded",
            _REDIS_BATCH4_SUPERSEDED,
        )
        for p in ("anthropic", "openai")
        for i in (1, 2, 3)
    ],
    *[
        (
            "e2e-batch4",
            f"e2e-reference-w1-{p}-mid-none-{i}",
            "breadth_1",
            "e2e-reference-w1",
            p,
            "mid",
            "W1",
            "void",
            _W1_VOID_INSTALL,
        )
        for p in ("anthropic", "openai")
        for i in (1, 2, 3)
    ],
    *[
        (
            "e2e-batch4",
            f"tpv-server-memory-{p}-mid-W2-{i}",
            "breadth_2",
            "tpv-server-memory",
            p,
            "mid",
            "W2",
            "superseded",
            _W2_MID_SUPERSEDED,
        )
        for p in ("anthropic", "openai")
        for i in (1, 2, 3)
    ],
    *[
        (
            "e2e-batch4",
            f"tpv-go-memory-{p}-small-none-{i}",
            "breadth_3",
            "tpv-go-memory",
            p,
            "small",
            None,
            "void",
            _GO_MEMORY_VOID,
        )
        for p in ("anthropic", "openai")
        for i in (1, 2, 3)
    ],
    # --- batch 5 ---
    *[
        (
            "e2e-batch5",
            f"e2e-reference-w1-{p}-mid-{i}",
            "breadth_1",
            "e2e-reference-w1",
            p,
            "mid",
            "W1",
            "active",
            None,
        )
        for p in ("anthropic", "openai")
        for i in (1, 2, 3)
    ],
    *[
        (
            "e2e-batch5",
            f"tpv-go-memory-{p}-small-{i}",
            "breadth_3",
            "tpv-go-memory",
            p,
            "small",
            None,
            "active",
            None,
        )
        for p in ("anthropic", "openai")
        for i in (1, 2, 3)
    ],
    # --- batch 6 (W1 re-run at the raised validate ceiling, 100) ---
    *[
        (
            "e2e-batch6",
            f"e2e-reference-w1-{p}-{i}",
            "breadth_1",
            "e2e-reference-w1",
            p,
            "mid",
            "W1",
            "active",
            None,
        )
        for p in ("anthropic", "openai")
        for i in (1, 2, 3)
    ],
    # --- batch 7 (W2 memory mid re-run, after the generic seed fix) ---
    *[
        ("e2e-batch7", f"{p}-{i}", "breadth_2", "tpv-server-memory", p, "mid", "W2", "active", None)
        for p in ("anthropic", "openai")
        for i in (1, 2, 3)
    ],
    # --- batch 8 (Redis proof-depth re-run, after the general calibration fix) ---
    *[
        (
            "e2e-batch8",
            f"anthropic-{i}",
            "proof_depth_2",
            "tpv-mcp-redis",
            "anthropic",
            "small",
            None,
            "active",
            None,
        )
        for i in (1, 2, 3)
    ],
    *[
        (
            "e2e-batch8",
            f"openai-{i}",
            "proof_depth_2",
            "tpv-mcp-redis",
            "openai",
            "small",
            None,
            "void",
            _REDIS_OPENAI_VOID_RATE_LIMIT,
        )
        for i in (1, 2, 3)
    ],
    # --- batch 9 (Redis proof-depth: OpenAI re-run, sequential, after the
    # rate-limit retry fix) ---
    *[
        (
            "e2e-batch9",
            f"openai-{i}",
            "proof_depth_2",
            "tpv-mcp-redis",
            "openai",
            "small",
            None,
            "active",
            None,
        )
        for i in (1, 2, 3)
    ],
    # --- batch 10 (Breadth 1 small tier, first round -- before the
    # pytest-config isolation fix, #373) ---
    *[
        (
            "e2e-batch10",
            f"e2e-reference-w1-{p}-small-{i}",
            "breadth_1",
            "e2e-reference-w1",
            p,
            "small",
            "W1",
            "superseded",
            _BREADTH_1_SMALL_SUPERSEDED,
        )
        for p in ("anthropic", "openai")
        for i in (1, 2, 3)
    ],
    # --- batch 11 (Precision 3 re-run after #371; Breadth 1 small-tier
    # re-run after #373 -- both counted) ---
    *[
        (
            "e2e-batch11",
            f"e2e-readonly-b-{p}-{i}",
            "precision_3",
            "e2e-readonly-b",
            p,
            "small",
            None,
            "active",
            None,
        )
        for p in ("anthropic", "openai")
        for i in (1, 2, 3)
    ],
    *[
        (
            "e2e-batch11",
            f"e2e-reference-w1-{p}-{i}",
            "breadth_1",
            "e2e-reference-w1",
            p,
            "small",
            "W1",
            "active",
            None,
        )
        for p in ("anthropic", "openai")
        for i in (1, 2, 3)
    ],
    # --- batch 12 (new confirm-path cell: tpv-mcp-redis and
    # tpv-server-memory, small tier, both providers) ---
    *[
        (
            "e2e-batch12",
            f"tpv-mcp-redis-{p}-{i}",
            "proof_depth_confirm",
            "tpv-mcp-redis",
            p,
            "small",
            None,
            "active",
            None,
        )
        for p in ("anthropic", "openai")
        for i in (1, 2, 3)
    ],
    *[
        (
            "e2e-batch12",
            f"tpv-server-memory-{p}-{i}",
            "proof_depth_confirm",
            "tpv-server-memory",
            p,
            "small",
            None,
            "active",
            None,
        )
        for p in ("anthropic", "openai")
        for i in (1, 2, 3)
    ],
]

#: Labels each (cell, batch) pair that belongs to a non-void, pre-counted
#: measurement round, so :func:`_cell_rounds` can group runs into rounds
#: without re-parsing ``status_reason`` text (two batches, e.g. batch 2 and
#: the batch-3 single-run re-dispatch "3r", can be one round under this
#: label even though their ``status_reason`` strings differ slightly). A
#: (cell, batch) pair not listed here is the cell's only round, labelled
#: "counted". Every label names the fix that ended it, or that it predates,
#: so a reader never has to cross-reference the prereg's amendments by
#: hand to see why a round stopped counting.
ROUND_LABELS: dict[tuple[str, str], str] = {
    ("proof_depth_1", "e2e-batch2"): "round 1 -- before the removal-confirmation feature (#357)",
    ("proof_depth_1", "e2e-batch4"): "round 2 -- counted",
    ("proof_depth_2", "e2e-batch2"): "round 1 -- before the Redis calibration fix (#356) and "
    "the removal-confirmation feature (#357)",
    ("proof_depth_2", "e2e-batch3"): "round 1 -- before the Redis calibration fix (#356) and "
    "the removal-confirmation feature (#357)",
    ("proof_depth_2", "e2e-batch4"): "round 2 -- after #356/#357, before the general "
    "calibration fix (#363, #364)",
    ("proof_depth_2", "e2e-batch8"): "round 3 -- counted",
    ("proof_depth_2", "e2e-batch9"): "round 3 -- counted",
    ("breadth_1", "e2e-batch5"): "round 1 -- mid tier, validate ceiling 40",
    ("breadth_1", "e2e-batch6"): "round 2 -- mid tier, validate ceiling raised to 100, counted",
    ("breadth_1", "e2e-batch10"): "round 3 -- small tier, before the pytest-config "
    "isolation fix (#373)",
    ("breadth_1", "e2e-batch11"): "round 4 -- small tier, counted, after #373",
    (
        "breadth_2",
        "e2e-batch4",
    ): "round 1 -- before the generic store-and-recall W2 seed fix (#362)",
    ("breadth_2", "e2e-batch7"): "round 2 -- counted",
    ("precision_3", "e2e-batch1"): "round 1 -- before the session-close race fix (#371)",
    ("precision_3", "e2e-batch11"): "round 2 -- counted",
}


def _cell_rounds(cell_runs_all_statuses: list[dict[str, object]]) -> list[dict[str, object]]:
    """Every non-void measurement round for one cell, oldest first, so a
    round superseded by a fix is published alongside the round that
    replaced it -- never dropped. Each round reports its own n, KEPT count
    and full classification breakdown; the cell's own ``met_bar`` (computed
    separately, from ``active`` runs only) always reflects the LAST round
    here, per the prereg's own re-run rule: a product defect is fixed,
    filed, and the cell is re-verified under this same file, which is not
    edited after the fact to match what an earlier round found."""
    order: list[str] = []
    rounds: dict[str, dict[str, object]] = {}
    for r in cell_runs_all_statuses:
        if r["status"] == "void":
            continue
        batch = str(r["run_id"]).split("/", 1)[0]
        label = ROUND_LABELS.get((str(r["cell"]), batch), "counted")
        if label not in rounds:
            rounds[label] = {
                "label": label,
                "status": r["status"],
                "n": 0,
                "kept": 0,
                "by_classification": {},
            }
            order.append(label)
        entry = rounds[label]
        entry["n"] = int(entry["n"]) + 1  # type: ignore[arg-type]
        cls = str(r["classification"])
        by_cls = entry["by_classification"]
        assert isinstance(by_cls, dict)
        by_cls[cls] = by_cls.get(cls, 0) + 1
        if cls == "KEPT":
            entry["kept"] = int(entry["kept"]) + 1  # type: ignore[arg-type]
    return [rounds[label] for label in order]


#: The prereg's own cell table (name -> bar/description), used only to stamp
#: each cell's rollup with the bar it is read against.
CELL_BARS: dict[str, dict[str, object]] = {
    "proof_depth_1": {
        "title": "Proof depth 1 (tpv-server-memory, small tier)",
        "bar": "KEPT, effect-confirmed, on 2+/3 runs per provider",
        "kind": "effect_confirmed_proof_depth",
    },
    "proof_depth_2": {
        "title": "Proof depth 2 (tpv-mcp-redis, small tier)",
        "bar": "KEPT, effect-confirmed, on 2+/3 runs per provider",
        "kind": "effect_confirmed_proof_depth",
    },
    "fix_retest_1": {
        "title": "Fix re-test 1 (tpv-streamablehttp)",
        "bar": "no traceback, no product defect, on every run; "
        "KEPT/not-kept/NOT TESTED agreement on 2+/3 per provider",
        "kind": "classification_rollup_both_providers",
        "bar_numerator": 2,
        "bar_denominator": 3,
    },
    "fix_retest_2": {
        "title": "Fix re-test 2 (tpv-agents-sdk-ollama)",
        "bar": "no traceback, no product defect, on every run; "
        "STABLE, NOT PROVEN on 2+/3 per provider is a pass",
        "kind": "label_threshold_both_providers",
        "label": "STABLE, NOT PROVEN",
        "threshold": 2,
        "n": 3,
    },
    "precision_1": {
        "title": "Precision 1 (e2e-guarded-reference)",
        "bar": "0 KEPT, precision-rollup = PASS, on 3/3 runs per provider",
        "kind": "precision",
    },
    "precision_2": {
        "title": "Precision 2 (e2e-readonly-time)",
        "bar": "0 KEPT, precision-rollup = PASS, on 3/3 runs per provider",
        "kind": "precision",
    },
    "precision_3": {
        "title": "Precision 3 (e2e-readonly-b)",
        "bar": "0 KEPT, precision-rollup = PASS, on 3/3 runs per provider",
        "kind": "precision",
    },
    "breadth_1": {
        "title": "Breadth 1 (e2e-reference-w1, W1, both tiers)",
        # Exact prereg wording ("Cells" table, Breadth 1 row): "tiers'",
        # not "models'" -- the bar itself only asks for a mid-tier KEPT
        # count (see the 2026-10-04 amendment); the 2026-10-05 amendment
        # dispatches the small tier too, so a documented limit now gives
        # BOTH tiers' numbers, never only the mid tier's.
        "bar": "KEPT on 2+/3 runs on at least one mid-tier model, or a "
        "documented limit with both tiers' numbers",
        "kind": "kept_threshold_any_provider",
        "threshold": 2,
        "bar_tier": "mid",
        # The bar's second limb (ruling, second number review): once
        # every tier named here has a counted round, that limb is
        # satisfied -- "the limit is documented with both tiers' numbers"
        # is a reporting-completeness fact once both exist, not a count
        # to clear. See the `met_via` field this produces in `build()`.
        "documented_limit_tiers": ("mid", "small"),
    },
    "breadth_2": {
        "title": "Breadth 2 (tpv-server-memory, mid tier, W2)",
        "bar": "the honest result, published either way: KEPT or not landing, with the reason",
        "kind": "honest_either_way",
    },
    "breadth_3": {
        "title": "Breadth 3 (tpv-go-memory, small tier)",
        "bar": "no traceback on any run; 2+/3 runs per provider agree on the "
        "same outcome category, or NOT TESTED with the same reason code",
        "kind": "classification_rollup_both_providers",
        "bar_numerator": 2,
        "bar_denominator": 3,
    },
    "proof_depth_confirm": {
        # New cell, 2026-10-05 amendment ("a new confirm-path cell, and
        # Breadth 1's small-tier numbers"): it measures whether a KEPT
        # finding's own validate effect leg confirms the damage, not
        # whether the store can CERTIFY (that is proof_depth_1/2's own,
        # unchanged bar above) -- a `confirm_only` calibration is
        # explicitly allowed to count here, where it never counted toward
        # the effect-confirmed-under-certified bar.
        "title": "Proof depth (confirm path): tpv-server-memory and tpv-mcp-redis, small tier",
        "bar": "on 2+/3 runs per provider per target, a KEPT finding whose "
        "own validate effect leg reads effect-confirmed under a certified "
        "or confirm_only calibration",
        "kind": "effect_confirmed_confirm_path_by_target",
    },
}


def _long_path(path: Path) -> Path:
    """``path``, prefixed with the Win32 extended-length ``\\\\?\\`` marker
    when running on Windows and not already so prefixed.

    Several of this campaign's own run directories nest deep enough
    (``e2e-batch4/tpv-server-memory-anthropic-small-none-1/third-party-...
    /out/<timestamp>/exploit_synth-w4-unconfirmed-delete_entities.json``,
    confirmed at 265 characters) to exceed the classic 260-character
    ``MAX_PATH`` limit. Past that length, ``Path.iterdir()`` still lists
    the entries (it uses a wildcard match) but ``Path.is_file()``/``open()``
    silently report "not found" (``WinError 3``) on the very same path --
    which is exactly what ``mylonite.testkit.load_exploit`` and
    ``verification._scan_dir.load_scan_dir`` call. The extended-length
    prefix opts out of ``MAX_PATH`` entirely for the Win32 API calls
    underneath ``pathlib``, with no change to any path a human reads in
    this script's own output (the prefix is stripped from every log/JSON
    field this script writes; it only ever wraps a path handed to a
    filesystem call)."""
    if sys.platform != "win32":
        return path
    text = str(path)
    prefix = chr(92) * 2 + "?" + chr(92)
    if text.startswith(prefix):
        return path
    return Path(prefix + str(path.resolve()))


def _resolve_dirs(inner: Path) -> tuple[Path, Path | None]:
    """``(run_dir, scan_dir)`` for :func:`score_run`, mirroring exactly what
    ``third-party-campaign.yml``'s "Score the run" step passes: ``scan_dir``
    is always the original ``scan --output-dir`` child (``out/<timestamp>``,
    the only one in every run this script has seen); ``run_dir`` is
    ``generated`` whenever ``validate`` actually wrote a report there --
    either directly (every batch this script has read so far, one validated
    exploit per run) or, now that the harness validates every exploit a scan
    found, in a per-exploit subdirectory of ``generated`` (``score_run``'s
    own ``_multi_report_subdirs`` detects that shape) -- otherwise the same
    scan directory.

    ``scan --output-dir out`` is only ever supposed to write ONE timestamped
    child per run -- an invariant this function used to trust silently by
    taking ``children[0]``. A shared-state sweep flagged that as unenforced:
    a duplicate/leftover scan directory under the same ``out/`` would be
    picked (or dropped) with no signal at all, scoring the wrong scan's
    ``attempts``/``calibration`` into the published results. Zero children
    is unchanged (``scan_dir`` stays ``None`` -- a preflight failure that
    never got as far as ``scan --output-dir``); more than one now raises
    loudly instead of silently picking the alphabetically-first."""
    out_root = inner / "out"
    scan_dir: Path | None = None
    if out_root.is_dir():
        children = sorted(c for c in out_root.iterdir() if c.is_dir())
        if len(children) > 1:
            raise RuntimeError(
                f"{out_root}: expected at most one scan output directory, found "
                f"{len(children)}: {[c.name for c in children]}"
            )
        if children:
            scan_dir = children[0]
    generated_dir = inner / "generated"
    validated_directly = (generated_dir / "validation_report.json").is_file()
    validated_in_a_subdir = any(
        (child / "validation_report.json").is_file()
        for child in generated_dir.glob("*")
        if child.is_dir()
    )
    if validated_directly or validated_in_a_subdir:
        run_dir = generated_dir
    elif scan_dir is not None:
        run_dir = scan_dir
    else:
        # A preflight failure never got as far as `scan --output-dir`: no
        # out/ directory exists at all. score_run's own missing-report path
        # (INFRA vs PRODUCT_DEFECT) decides from the logs alone.
        run_dir = inner
    return run_dir, scan_dir


def _cost(inner: Path) -> dict[str, object]:
    """``{"calls": int, "cost_usd": float, "model": str|None, "ref":
    str|None}`` from this run's own ``cost.json``, or all-zero/``None`` when
    it was never written (a preflight failure that stopped before any
    Mylonite command ran)."""
    cost_path = inner / "cost.json"
    if not cost_path.is_file():
        return {"calls": 0, "cost_usd": 0.0, "model": None, "ref": None}
    data = json.loads(cost_path.read_text(encoding="utf-8"))
    return {
        "calls": data.get("calls", 0),
        "cost_usd": data.get("cost_usd", 0.0),
        "model": data.get("model"),
        "ref": data.get("ref"),
    }


def _resist_details(scan_dir: Path | None) -> list[dict[str, object]]:
    """One entry per ``outcome=="no_finding"`` attempt in the real scan
    report: its ``pattern_id`` and how the resist was decided
    (``verdict_mechanism``, and ``evidence_tier`` when the judge recorded
    one). This is how a *judge-only* resist (``evidence_tier: "judge-only"``,
    ``verdict_mechanism: "llm"`` -- the agent was never stopped by a
    structural marker or a missing tool call, only by the judge reading its
    own trace and declining to call the result a finding) gets to stay
    visible in the published record, among the outcomes that must be
    stated as such rather than folded into a plain resist. Returns ``[]``
    when ``scan_dir`` is
    ``None`` or carries no real report."""
    if scan_dir is None:
        return []
    report_path = scan_dir / "scan_report.json"
    if not report_path.is_file():
        return []
    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    details: list[dict[str, object]] = []
    for attempt in data.get("attempts", []) if isinstance(data, dict) else []:
        if not isinstance(attempt, dict) or attempt.get("outcome") != "no_finding":
            continue
        evidence = attempt.get("judge_evidence")
        evidence = evidence if isinstance(evidence, dict) else {}
        details.append(
            {
                "pattern_id": attempt.get("pattern_id"),
                "verdict_mechanism": attempt.get("verdict_mechanism"),
                "evidence_tier": evidence.get("evidence_tier"),
            }
        )
    return details


#: A leg (scan or validate) that hits its own hard request ceiling
#: (``[MYL-ABT-001]``) aborts mid-leg, before printing its own ``llm: N
#: calls`` summary line -- so `compute_run_cost.py` (reading only the
#: lines that DID print) undercounts the run's real spend by exactly the
#: ceiling value for every such abort, never fewer: `_send_plan` refuses
#: the request that would exceed the ceiling (`LLMRequestCeilingError`'s
#: own docstring: "Raised before a request that would go over the hard
#: request ceiling"), so exactly ``ceiling`` requests were sent and
#: counted against it before the abort. This is a known, exact floor, not
#: an estimate -- and, since the harness now validates every exploit a
#: scan found (not only the alphabetically-first), one run's log can carry
#: several OTHER legs' own spend lines alongside one ceiling-stopped leg's
#: abort. An earlier version of this function returned 0 whenever the log
#: carried two or more spend lines, on the old assumption that a run only
#: ever had two legs (scan, validate) -- the second number review's I3
#: found this silently dropped `tpv-server-memory-openai-3` (batch 12,
#: confirm-path cell)'s own 40-call ceiling stop, because that run's other
#: four (of five) validated findings each printed their own spend line.
#: Every ceiling-hit occurrence is now counted and summed independently,
#: with no gate on how many other spend lines sit in the same log --
#: matched against the run's own terminal ``error: [MYL-ABT-001]`` line
#: specifically, never the planner's own ``LLMPlanner: completion raised
#: on iteration N:`` echo of the identical abort. A ceiling breach under
#: concurrency (several re-drives in flight at once) can print that echo
#: more than once for the SAME single abort before the command's own
#: terminal error line prints and the process exits -- confirmed against
#: every ceiling-stopped run in this campaign, which always logs the
#: terminal line exactly once, regardless of how many echoes came before
#: it. Matching the broader ``"ceiling of (\d+) reached"`` text (an
#: earlier version of this regex) counted those echoes too, inflating a
#: single real 40-call abort to 80 or 120.
_CEILING_HIT_RE = re.compile(r"error:\s*\[MYL-ABT-001\][^\n]*ceiling of (\d+) reached")


def _ceiling_floor_calls(run_log_text: str) -> int:
    """The number of LLM requests NOT reflected in this run's own
    ``cost.json`` because one or more legs (scan or validate) aborted at
    their own request ceiling before printing a summary line -- 0 when no
    leg ever hit one. See the module-level comment above this function for
    why every hit is summed, not just counted once."""
    return sum(int(n) for n in _CEILING_HIT_RE.findall(run_log_text))


def _score_one(
    artifacts_root: Path, batch: str, folder: str, target: str, pattern: str | None
) -> dict[str, object]:
    """Score one counted run directory.

    ``batch_dir`` is expected to hold exactly one inner run directory (the
    GitHub Actions artifact download unpacks a run's own files directly
    under it, one level deep). A shared-state sweep flagged the old
    ``children[0]`` of an unsorted ``iterdir()`` as unenforced: a second,
    leftover/duplicate download folder sitting next to the real one would
    be silently picked (or dropped) with no signal at all, scoring a
    sibling run's artifacts into the published results under the wrong
    run's own identity. Zero candidates is unchanged (still raises
    ``FileNotFoundError``, as before this fix); more than one now raises
    loudly, naming the batch directory and every candidate, instead of
    picking whichever one ``iterdir()`` happened to return first."""
    batch_dir = artifacts_root / batch / folder
    children = [c for c in batch_dir.iterdir() if c.is_dir()] if batch_dir.is_dir() else []
    if not children:
        raise FileNotFoundError(f"no inner run directory under {batch_dir}")
    if len(children) > 1:
        raise RuntimeError(
            f"{batch_dir}: expected exactly one inner run directory, found "
            f"{len(children)}: {sorted(c.name for c in children)}"
        )
    inner = children[0]
    run_dir, scan_dir = _resolve_dirs(inner)
    score = score_run(
        run_dir,
        run_log=inner / "run.log",
        scan_log=inner / "scan.log",
        validate_log=inner / "validate.log",
        pattern=pattern,
        scan_dir=scan_dir,
    )
    score["target"] = target
    score.update(_cost(inner))
    score["resist_details"] = _resist_details(scan_dir)
    # The single-report layout: score_run never sets these keys itself (see
    # its own docstring), so read run_dir's own validation_report.json
    # directly, exactly as before the multi-report layout existed. A
    # multi-report run (score["validated_findings"] present) already
    # carries its own top-level validated_effect_proof_level/counts --
    # the strongest KEPT finding's own validated effect level, computed by
    # score_third_party._score_multi_report_run itself -- never overwritten
    # here.
    if "validated_effect_proof_level" not in score:
        level, counts = _validated_effect_proof_level(run_dir)
        score["validated_effect_proof_level"] = level
        score["validated_effect_counts"] = counts
    run_log_path = inner / "run.log"
    run_log_text = (
        run_log_path.read_text(encoding="utf-8", errors="replace") if run_log_path.is_file() else ""
    )
    score["uncounted_ceiling_calls"] = _ceiling_floor_calls(run_log_text)
    # One adjudication per validated finding THIS run's own validate
    # labelled KEPT, read fresh from that finding's own artifacts under
    # run_dir -- see _adjudications_for_run's own docstring.
    score["adjudications"] = _adjudications_for_run(score, run_dir)
    return score


def _apply_cell_bar(
    kind: str | None,
    cell_meta: dict[str, object],
    by_provider: dict[str, list[dict[str, object]]],
    cell_runs: list[dict[str, object]],
) -> tuple[dict[str, object], bool]:
    """``(by_provider_rollups, cell_met_bar)`` for one cell, per its own
    bar text in ``verification/PREREG_E2E_2026_10.md`` -- each ``kind``
    below is one bar shape the prereg's cell table actually uses; a plain
    classification-agreement rollup (:func:`score_third_party.rollup`) is
    NOT the right check for every cell, so this dispatches rather than
    reusing one generic rule everywhere:

    - ``effect_confirmed_proof_depth``: the proof-depth bar needs KEPT at
      proof level ``effect-confirmed`` under a ``certified`` calibration --
      integrity rule 7 ("certified is required before a proof-depth cell's
      effect-confirmed bar can be claimed met"). A plain KEPT-classification
      rollup would silently pass this even on ``dispatched-tool-linked``,
      which is exactly the gap a prior campaign's own README had to
      specifically call out and correct.
    - ``label_threshold_both_providers``: counts the verdict LABEL itself
      (``STABLE, NOT PROVEN``), not the broader ``NOT_KEPT`` classification
      that also covers a plain ``REJECTED`` -- the two mean different
      things for this cell (a candidate vs. a disproven attack) and a
      classification-only rollup cannot tell them apart.
    - ``classification_rollup_both_providers``: the generic N=3, >=2/3
      classification-agreement rule, required on EACH provider (both
      providers are dispatched, so both must individually meet the bar).
    - ``kept_threshold_any_provider``: a bare KEPT-count threshold across
      however many runs the cell combines (this cell's own N grew from 6 to
      12 after a ceiling amendment -- it is not a fixed N=3 rollup), met on
      at least one provider (the bar's own wording).
    - ``precision``: 0 KEPT with every run exercised (see
      :func:`score_third_party.precision_rollup`).
    - ``honest_either_way``: no outcome fails this bar; it is met as soon
      as every dispatched run is actually published.
    """
    provider_results: dict[str, object] = {}
    if kind == "precision":
        for provider, p_runs in by_provider.items():
            p_scores = [
                {"classification": r["classification"], "exercised": r["exercised"]} for r in p_runs
            ]
            provider_results[provider] = precision_rollup(p_scores)
        overall = precision_rollup(
            [
                {"classification": r["classification"], "exercised": r["exercised"]}
                for r in cell_runs
            ]
        )
        return provider_results, overall["result"] == "PASS"

    if kind == "honest_either_way":
        for provider, p_runs in by_provider.items():
            provider_results[provider] = {
                "n": len(p_runs),
                "classifications": sorted({str(r["classification"]) for r in p_runs}),
            }
        return provider_results, len(cell_runs) > 0

    if kind == "effect_confirmed_proof_depth":
        all_met = bool(by_provider)
        for provider, p_runs in by_provider.items():
            n = len(p_runs)
            kept_count = sum(1 for r in p_runs if r["classification"] == "KEPT")
            effect_confirmed_certified_count = sum(
                1
                for r in p_runs
                if r["classification"] == "KEPT"
                and r.get("proof_level") == "effect-confirmed"
                and r.get("calibration_status") == "certified"
            )
            met = n >= 3 and effect_confirmed_certified_count >= 2
            all_met = all_met and met
            calibration_statuses = sorted({str(r.get("calibration_status")) for r in p_runs})
            proof_levels = sorted({str(r.get("proof_level")) for r in p_runs})
            # The scan attempt's own level (proof_levels, above) and
            # validate's own effect-leg level are different axes -- see
            # _validated_effect_proof_level's docstring. Both are reported;
            # neither substitutes for the other, and only a `certified`
            # calibration (checked above) lets either count toward the bar.
            validated_effect_levels = sorted(
                {str(r.get("validated_effect_proof_level")) for r in p_runs}
            )
            provider_results[provider] = {
                "n": n,
                "kept_count": kept_count,
                "effect_confirmed_certified_count": effect_confirmed_certified_count,
                "calibration_statuses": calibration_statuses,
                "proof_levels": proof_levels,
                "validated_effect_proof_levels": validated_effect_levels,
                "met_bar": met,
            }
        return provider_results, all_met

    if kind == "kept_threshold_any_provider":
        # Reports BOTH tiers' numbers (per-tier n/kept_count), since the
        # 2026-10-05 amendment dispatches this cell on the small tier too.
        # The bar itself is a disjunction ("KEPT on 2+/3 runs on at least
        # one mid-tier model, OR the limit is documented with both tiers'
        # numbers") -- `by_tier`'s own counts are data, never a verdict:
        # the second number review's I5 flagged a per-tier `met_bar`
        # computed from a bare small-tier KEPT count as applying a
        # threshold the bar never asks the small tier to clear. Whether
        # the disjunction's SECOND limb is satisfied (both tiers are now
        # documented) is a reporting-completeness question, not a
        # per-provider count, so it is decided once in `build()`, not
        # here -- see `met_via` on this cell's own entry.
        threshold = int(cell_meta["threshold"])
        bar_tier = str(cell_meta.get("bar_tier", "mid"))
        any_met = False
        for provider, p_runs in by_provider.items():
            by_tier: dict[str, object] = {}
            for tier_name in sorted({str(r.get("tier", "mid")) for r in p_runs}):
                t_runs = [r for r in p_runs if r.get("tier", "mid") == tier_name]
                t_kept = sum(1 for r in t_runs if r["classification"] == "KEPT")
                by_tier[tier_name] = {"n": len(t_runs), "kept_count": t_kept}
                if tier_name == bar_tier and t_kept >= threshold:
                    any_met = True
            provider_results[provider] = {
                "n": len(p_runs),
                "kept_count": sum(1 for r in p_runs if r["classification"] == "KEPT"),
                "by_tier": by_tier,
            }
        return provider_results, any_met

    if kind == "label_threshold_both_providers":
        label = str(cell_meta["label"])
        threshold = int(cell_meta["threshold"])
        all_met = bool(by_provider)
        for provider, p_runs in by_provider.items():
            label_count = sum(1 for r in p_runs if r.get("label") == label)
            met = label_count >= threshold
            all_met = all_met and met
            provider_results[provider] = {
                "n": len(p_runs),
                f"label_{label.lower().replace(', ', '_').replace(' ', '_')}_count": label_count,
                "met_bar": met,
            }
        return provider_results, all_met

    if kind == "effect_confirmed_confirm_path_by_target":
        # The confirm-path bar (2026-10-05 amendment): on 2+/3 runs per
        # (target, provider), a KEPT finding whose own validate effect leg
        # reads effect-confirmed under a calibration that is allowed to
        # confirm (`certified` OR `confirm_only` -- unlike the stronger
        # proof-depth bar above, which requires `certified`). This cell
        # covers two targets at once, so the breakdown groups by target
        # first, then by provider within it; the overall bar is met only
        # once every (target, provider) pair meets its own bar.
        by_target: dict[str, object] = {}
        targets = sorted({str(r["target"]) for r in cell_runs})
        all_met = bool(cell_runs)
        for target in targets:
            t_runs = [r for r in cell_runs if r["target"] == target]
            target_by_provider: dict[str, object] = {}
            for provider in sorted({str(r["provider"]) for r in t_runs}):
                p_runs = [r for r in t_runs if r["provider"] == provider]
                n = len(p_runs)
                effect_confirmed_count = sum(
                    1
                    for r in p_runs
                    if r["classification"] == "KEPT"
                    and r.get("validated_effect_proof_level") == "effect-confirmed"
                    and r.get("calibration_status") in ("certified", "confirm_only")
                )
                met = n >= 3 and effect_confirmed_count >= 2
                all_met = all_met and met
                target_by_provider[provider] = {
                    "n": n,
                    "kept_count": sum(1 for r in p_runs if r["classification"] == "KEPT"),
                    "effect_confirmed_count": effect_confirmed_count,
                    "calibration_statuses": sorted(
                        {str(r.get("calibration_status")) for r in p_runs}
                    ),
                    "met_bar": met,
                }
            by_target[target] = {"by_provider": target_by_provider}
        return by_target, all_met

    # classification_rollup_both_providers (the default/fallback shape)
    num = int(cell_meta["bar_numerator"])
    den = int(cell_meta["bar_denominator"])
    all_met = bool(by_provider)
    for provider, p_runs in by_provider.items():
        p_scores = [
            {"classification": r["classification"], "reason_codes": r["reason_codes"]}
            for r in p_runs
        ]
        res = rollup(p_scores, bar_numerator=num, bar_denominator=den)
        all_met = all_met and bool(res.get("met_bar"))
        provider_results[provider] = res
    return provider_results, all_met


def _resolve_disjunctive_bar(
    met_bar: bool, cell_meta: dict[str, object], cell_runs: list[dict[str, object]]
) -> tuple[bool, str | None]:
    """``(met_bar, met_via)`` for a bar written as a disjunction (today,
    only breadth_1's "KEPT on 2+/3 ... OR the limit is documented with
    both tiers' numbers"): ``_apply_cell_bar`` only ever evaluates the
    first limb (a KEPT count), so this checks the second -- a cell whose
    ``cell_meta`` names ``documented_limit_tiers`` passes via that limb
    once every tier it names has a counted round, a reporting-completeness
    fact, not a count to clear. ``met_via`` is ``"kept_threshold"``,
    ``"documented_limit"`` or ``None`` (neither limb satisfied), so a
    write-up never shortens a documented-limit pass to a bare "met"
    (ruling, second number review: "never shorten it to a bare 'met'").
    A cell with no ``documented_limit_tiers`` (every other cell today)
    passes this through unchanged, ``met_via`` always matching
    ``met_bar``."""
    if met_bar:
        return True, "kept_threshold"
    required_tiers = set(cell_meta.get("documented_limit_tiers", ()))
    if not required_tiers:
        return False, None
    measured_tiers = {str(r.get("tier", "mid")) for r in cell_runs}
    if required_tiers <= measured_tiers:
        return True, "documented_limit"
    return False, None


#: Adjudication is grounded per FINDING, read fresh from that finding's own
#: artifacts every time a run is scored -- never a template shared across
#: runs or providers (the second number review's I1: a template keyed only
#: by (target, pattern_id) silently misapplied one provider's own trace
#: text to a sibling provider's finding, and a run with several validated
#: findings only ever got one, picked by scan order rather than by which
#: findings were actually KEPT). :func:`_adjudications_for_run` returns one
#: adjudication per validated finding this run's own ``validate`` labelled
#: KEPT (a REJECTED finding, e.g. Redis's `set` on a provider where it did
#: not keep, is never adjudicated as kept); each one is built by
#: :func:`_adjudicate_finding` from :func:`_finding_trace_facts`, which
#: reads that finding's own ``exploit_*.json`` (the payload text and the
#: real tool call -- name, attacker-sourced arguments, result) and its own
#: ``validation_report.json`` effect-leg detail (which already states the
#: removal outcome in words) directly off disk.


def _read_json_or_none(path: Path) -> dict[str, object] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _subdir_for_pattern(run_dir: Path, pattern_id: str) -> Path | None:
    """The immediate child of ``run_dir`` whose own ``exploit_*.json`` names
    ``pattern_id`` -- never assumed from the subdirectory's own name, which
    is a reasonable guess but not the contract :func:`_validated_pattern_id`
    (the scorer's own lookup) relies on. ``None`` when ``run_dir`` is not a
    multi-report layout (no matching child) -- the caller falls back to
    treating ``run_dir`` itself as the one finding's own directory."""
    if not run_dir.is_dir():
        return None
    for child in sorted(run_dir.iterdir(), key=lambda p: p.name):
        if not child.is_dir():
            continue
        for exploit_path in sorted(child.glob("exploit_*.json")):
            data = _read_json_or_none(exploit_path)
            if isinstance(data, dict) and str(data.get("pattern_id")) == pattern_id:
                return child
    return None


def _finding_trace_facts(finding_dir: Path) -> dict[str, object]:
    """Grounding facts for one validated finding, read directly from
    ``finding_dir``'s own ``exploit_*.json`` (the attacker's payload text,
    and the real tool call -- name, arguments, result -- from
    ``response.metadata.effect_trace``, the FIRST call, which is the one
    the seed tool itself names) and its own ``validation_report.json``
    effect-leg detail (already human-readable: proof-level counts and the
    removal outcome in words). ``{}`` when neither file parses -- the
    caller reports that plainly rather than fabricating a trace."""
    facts: dict[str, object] = {}
    matches = sorted(finding_dir.glob("exploit_*.json"))
    exploit = _read_json_or_none(matches[0]) if matches else None
    if isinstance(exploit, dict):
        payload = exploit.get("payload")
        if isinstance(payload, dict):
            facts["payload_body"] = payload.get("body")
        response = exploit.get("response")
        metadata = response.get("metadata") if isinstance(response, dict) else None
        trace_raw = metadata.get("effect_trace") if isinstance(metadata, dict) else None
        calls = None
        if isinstance(trace_raw, str):
            try:
                calls = json.loads(trace_raw)
            except json.JSONDecodeError:
                calls = None
        if isinstance(calls, list) and calls and isinstance(calls[0], dict):
            facts["tool"] = calls[0].get("tool")
            facts["args"] = calls[0].get("args")
            facts["result"] = calls[0].get("result")
    vr = _read_json_or_none(finding_dir / "validation_report.json")
    if isinstance(vr, dict):
        outcomes = vr.get("outcomes")
        if isinstance(outcomes, list):
            for outcome in outcomes:
                if isinstance(outcome, dict) and outcome.get("stage") == "effect":
                    facts["effect_detail"] = outcome.get("detail")
                    break
    return facts


def _adjudicate_finding(
    pattern_id: str, facts: dict[str, object], calibration_status: object
) -> dict[str, object]:
    """One adjudication, built only from ``facts`` -- this finding's own
    trace, never a sibling's. ``unadjudicated`` (not fabricated) when the
    finding's own tool call could not be read from its artifacts."""
    tool = facts.get("tool")
    if tool is None:
        return {
            "pattern_id": pattern_id,
            "status": "unadjudicated",
            "reason": (
                f"could not read {pattern_id}'s own exploit/trace artifacts -- needs manual review"
            ),
        }
    body = facts.get("payload_body")
    args = facts.get("args")
    result = facts.get("result")
    reason = (
        f"True positive, read from this finding's own trace. The payload "
        f"({body!r}) drove a real, dispatched call to `{tool}` with the "
        f"attacker-sourced arguments {args!r}"
        + (f", returning {result!r}" if result is not None else "")
        + ", with no approval step."
    )
    detail = facts.get("effect_detail")
    if detail:
        detail_text = str(detail)
        if not detail_text.endswith((".", ";")):
            detail_text += "."
        reason += f" This finding's own validate effect leg: {detail_text}"
    reason += f" Calibration on this run: {calibration_status!r}."
    return {"pattern_id": pattern_id, "status": "true_positive", "reason": reason}


def _adjudications_for_run(score: dict[str, object], run_dir: Path) -> list[dict[str, object]]:
    """One adjudication per validated finding THIS run's own ``validate``
    labelled KEPT -- every one read from that finding's own artifacts, none
    copied across runs, providers or sibling findings in the same run.

    A multi-report run (``score["validated_findings"]`` present -- the
    harness validates every exploit a scan found, not only the
    alphabetically-first) can hold several KEPT findings; a REJECTED
    sibling in the same run (e.g. Redis's `set` on a provider where it did
    not keep) is skipped, never adjudicated as kept. A single-report run
    (the older harness shape) has at most one validated finding, found
    directly in ``run_dir`` itself."""
    validated_findings = score.get("validated_findings")
    if isinstance(validated_findings, list) and validated_findings:
        adjudications: list[dict[str, object]] = []
        for vf in validated_findings:
            if not isinstance(vf, dict) or vf.get("label") != "KEPT":
                continue
            pattern_id = str(vf.get("pattern_id"))
            subdir = _subdir_for_pattern(run_dir, pattern_id)
            facts = _finding_trace_facts(subdir) if subdir is not None else {}
            adjudications.append(
                _adjudicate_finding(pattern_id, facts, score.get("calibration_status"))
            )
        return adjudications
    if score.get("classification") != "KEPT":
        return []
    validated = next(
        (
            f
            for f in score.get("scan_findings", [])  # type: ignore[union-attr]
            if isinstance(f, dict) and f.get("validated")
        ),
        None,
    )
    if validated is None:
        return [
            {
                "pattern_id": None,
                "status": "unadjudicated",
                "reason": "no validated finding found in scan_findings for a KEPT run -- needs manual review",
            }
        ]
    pattern_id = str(validated["pattern_id"])
    facts = _finding_trace_facts(run_dir)
    return [_adjudicate_finding(pattern_id, facts, score.get("calibration_status"))]


def _short_sha(ref: object) -> object:
    """A full 40-hex-char commit SHA, shortened to the first 8 characters
    (this repo's own convention for citing a build, e.g. `0dc92cf5` in the
    campaign's own progress notes) -- anything else (``None``, an already-
    short ref) passes through unchanged. A full-length hex string reads as
    a high-entropy secret to `detect-secrets`' own scanner; a git commit
    SHA is not one, and the short, 8-character form is what every other
    citation in this repository already uses (including the first
    campaign's own `results.json`, which cites `d150c742`, `cb6d7388`
    and its amendment commits the same way)."""
    if isinstance(ref, str) and len(ref) == 40 and all(c in "0123456789abcdef" for c in ref):
        return ref[:8]
    return ref


def build(artifacts_root: Path) -> dict[str, object]:
    runs: list[dict[str, object]] = []
    by_cell: dict[str, list[dict[str, object]]] = {}
    by_cell_all: dict[str, list[dict[str, object]]] = {}
    for batch, folder, cell, target, provider, tier, pattern, status, reason in RUN_GROUPS:
        score = _score_one(artifacts_root, batch, folder, target, pattern)
        entry = {
            "run_id": f"{batch}/{folder}",
            "cell": cell,
            "target": target,
            "provider": provider,
            "tier": tier,
            "pattern": pattern,
            "status": status,
            "status_reason": reason,
            "commit": _short_sha(score.get("ref")),
            "model": score.get("model"),
            "classification": score.get("classification"),
            "label": score.get("label"),
            "proof_level": score.get("proof_level"),
            "max_scan_proof_level": score.get("max_scan_proof_level"),
            "calibration_status": score.get("calibration_status"),
            "calibration_reason_code": score.get("calibration_reason_code"),
            "exercised": score.get("exercised"),
            "reason_codes": score.get("reason_codes", []),
            "scan_findings": score.get("scan_findings", []),
            "resist_details": score.get("resist_details", []),
            "calls": score.get("calls"),
            "cost_usd": score.get("cost_usd"),
            "detail": score.get("detail"),
            # validate's own effect-leg proof-level breakdown -- see
            # _validated_effect_proof_level's docstring for why this is a
            # different axis from the scan attempt's own proof_level above.
            "validated_effect_proof_level": score.get("validated_effect_proof_level"),
            "validated_effect_counts": score.get("validated_effect_counts"),
            # Known, exact LLM requests this run's own cost.json does not
            # count because validate aborted at its ceiling before printing
            # a spend line of its own -- 0 for every run that was not cut
            # short this way. See _ceiling_floor_calls's docstring.
            "uncounted_ceiling_calls": score.get("uncounted_ceiling_calls", 0),
            # One adjudication per validated finding this run's own
            # validate labelled KEPT -- [] for a run with none. Never one
            # adjudication per RUN: a multi-exploit run can keep several
            # findings at once (see _adjudications_for_run's docstring).
            "adjudications": score.get("adjudications") or [],
        }
        runs.append(entry)
        by_cell_all.setdefault(cell, []).append(entry)
        if status == "active":
            by_cell.setdefault(cell, []).append(entry)

    cells: dict[str, object] = {}
    for cell_name, cell_meta in CELL_BARS.items():
        cell_runs = by_cell.get(cell_name, [])
        by_provider: dict[str, list[dict[str, object]]] = {}
        for r in cell_runs:
            by_provider.setdefault(str(r["provider"]), []).append(r)
        kind = cell_meta.get("kind")
        results, met_bar = _apply_cell_bar(kind, cell_meta, by_provider, cell_runs)
        cell_entry: dict[str, object] = {
            "title": cell_meta["title"],
            "bar": cell_meta["bar"],
            "n_active_runs": len(cell_runs),
            # A cell covering more than one target (today, only
            # proof_depth_confirm) groups by target first, then provider;
            # every other cell groups by provider directly, as before.
            ("by_target" if kind == "effect_confirmed_confirm_path_by_target" else "by_provider"): (
                results
            ),
            "met_bar": met_bar,
            # Every non-void round this cell went through, oldest first,
            # each labelled with the fix that ended it -- never just the
            # counted (last) round. See _cell_rounds's own docstring.
            "rounds": _cell_rounds(by_cell_all.get(cell_name, [])),
        }
        # `met_via` only applies to a bar actually written as a disjunction
        # (today, only breadth_1's own "documented_limit_tiers") -- every
        # other cell's `met_bar` already says everything there is to say,
        # so this key is only ever added, never set to a misleading
        # generic label for an unrelated bar shape. See
        # _resolve_disjunctive_bar's own docstring.
        if cell_meta.get("documented_limit_tiers"):
            met_bar, met_via = _resolve_disjunctive_bar(met_bar, cell_meta, cell_runs)
            cell_entry["met_bar"] = met_bar
            cell_entry["met_via"] = met_via
        cells[cell_name] = cell_entry

    # Kept-finding totals (ruling: count only counted, non-void runs from
    # the measuring round). A KEPT classification on a void run (the
    # rate-limited Redis batch) or a superseded run (an earlier, replaced
    # round) is still recorded on that run's own entry above, for the
    # audit trail -- it is never folded into the headline count, which
    # covers active runs only.
    kept_active = [r for r in runs if r["classification"] == "KEPT" and r["status"] == "active"]
    kept_void = [r for r in runs if r["classification"] == "KEPT" and r["status"] == "void"]
    kept_superseded = [
        r for r in runs if r["classification"] == "KEPT" and r["status"] == "superseded"
    ]
    # Ruling (second number review, I2/I3): a RUN read KEPT and the
    # FINDINGS it carries are different counts once a multi-exploit run can
    # keep several findings at once -- every total below names which one
    # it is; nothing here is ever called "kept findings" when it counts
    # runs.
    kept_findings_summary = {
        "counted_active_runs": len(kept_active),
        "counted_active_findings": sum(len(r.get("adjudications") or []) for r in kept_active),
        "void_run_ids": [r["run_id"] for r in kept_void],
        "void_findings": sum(len(r.get("adjudications") or []) for r in kept_void),
        "superseded_runs": len(kept_superseded),
        "superseded_findings": sum(len(r.get("adjudications") or []) for r in kept_superseded),
    }

    # Spend (ruling: include the validate calls on ceiling-stopped runs,
    # and explain how they were counted). `calls`/`cost_usd` sum each
    # active run's own cost.json, unchanged; `uncounted_ceiling_calls`
    # sums the KNOWN, exact extra requests a ceiling-stopped validate leg
    # made but never got to print a spend line for (see
    # _ceiling_floor_calls) -- added to a separate `calls_with_ceiling_floor`
    # total. The $ total is NOT adjusted: those extra requests' own token
    # usage was never printed, so their cost is genuinely unknown, and the
    # $ figures stay a measured lower bound, stated as such.
    spend_summary: dict[str, dict[str, object]] = {}
    for r in runs:
        if r["status"] != "active":
            continue
        provider = str(r["provider"])
        bucket = spend_summary.setdefault(
            provider, {"calls": 0, "cost_usd": 0.0, "uncounted_ceiling_calls": 0}
        )
        bucket["calls"] = int(bucket["calls"]) + int(r.get("calls") or 0)  # type: ignore[arg-type]
        bucket["cost_usd"] = round(float(bucket["cost_usd"]) + float(r.get("cost_usd") or 0.0), 6)  # type: ignore[arg-type]
        bucket["uncounted_ceiling_calls"] = int(bucket["uncounted_ceiling_calls"]) + int(  # type: ignore[arg-type]
            r.get("uncounted_ceiling_calls") or 0
        )
    for bucket in spend_summary.values():
        bucket["calls_with_ceiling_floor"] = int(bucket["calls"]) + int(
            bucket["uncounted_ceiling_calls"]
        )

    return {
        "schema_version": "1.0",
        "campaign": "e2e-verification-2026-10",
        "prereg_file": PREREG_FILE,
        "runs": runs,
        "cells": cells,
        "kept_findings_summary": kept_findings_summary,
        "spend_summary": spend_summary,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--artifacts-root",
        type=Path,
        required=True,
        help="Local, gitignored campaign scratch directory holding e2e-batch1 .. "
        "e2e-batch12 (no default -- its path is machine-specific and never belongs "
        "in committed source).",
    )
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)

    if not args.artifacts_root.is_dir():
        parser.error(
            f"{args.artifacts_root} does not exist -- this script reads local, "
            "gitignored campaign scratch artifacts that are not part of the "
            "repository; pass --artifacts-root to point at them"
        )

    result = build(_long_path(args.artifacts_root))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {args.out} ({len(result['runs'])} runs, {len(result['cells'])} cells)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
