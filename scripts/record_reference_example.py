"""Record the committed reference-validation example (dev-time, run once).

What this is
------------
The one set of real LLM calls behind the repository's central claim: *the
differential oracle keeps a test, and you can replay the proof offline with no
API key.* It produces a committed ``examples/reference_validation/`` artefact —
the exploit discovered against the live vulnerable twin, the emitted regression
test, the recorded fixtures for both the single-seed guarded replay and the full
differential loop, and the validation report — after which
``tests/plugins/test_reference_validation_example.py`` re-derives the KEPT
verdict from those files with no provider at all.

Why the validator does the writing
----------------------------------
This script used to hand-roll the guarded recording and the test emission
alongside the validator's own. That was two writers for one artefact, and they
had already drifted: the validator records with ``pattern_id_filter`` set (the
asymmetry fix — ``testkit.assert_guard_holds`` replays *with* the filter) while
the hand-rolled version recorded a whole-bank scan, so the committed fixtures
did not match the keys the offline gate looks up.

``DifferentialValidator._record_and_full_pass`` already does all of it: records
the canonical guarded fixtures under the correct filter, stamps
``format_version`` + ``cache_key_version`` + ``model`` + ``provider`` off the
recorder and its own config rather than local literals, writes the on-disk test
and its co-located exploit, and runs that committed test offline requiring
pytest exit 0. So this script discovers the exploit, hands it to the validator,
and checks the result. The validator is the single writer.

Two fixture sets, one live pass
-------------------------------
``completion_fn`` is a record-mode recorder over ``differential_fixtures/``, so
the whole differential loop — both twins, every iteration, the metamorphic
probes — is captured. ``record_fixtures_dir`` points at ``fixtures/``, which the
validator fills with the single-seed guarded set the emitted test replays. One
live pass produces both.

A third set, ``red_fixtures/``
------------------------------
The guarded set proves the test passes when the safeguard holds. Showing the
same test FAIL on the build without the safeguard needs the vulnerable twin's
single-seed run recorded too, keyed exactly as the offline replay looks it up:
``pattern_id_filter`` set, a fresh note-id counter, and the customiser and judge
ON (``build_scan``'s default, the same wiring ``testkit`` and the validator use).
The differential set cannot stand in for it: it is one flat directory for the
whole loop, so it is not a guaranteed match for a standalone single-seed replay.
After recording, the script replays ``red_fixtures/`` offline and refuses to
finish unless every lookup hits and the exploit fires.

Choosing the seed and the metamorphic strategies
------------------------------------------------
``--pattern-id`` records any kitchen-sink seed (default: the W2 seed below).
``--metamorphic-strategies`` takes a comma-separated subset of the validator's
deterministic transforms (default: ``paraphrase``); every strategy recorded
costs a few more calls per twin.

Bounding the spend
------------------
Set ``MYLONITE_MAX_LLM_REQUESTS`` to cap the provider requests this process may
send, retries included. Past the cap no further request goes out, the run is
not kept, and the script exits non-zero without writing a validation report.

Why ``--iterations`` defaults to 1
----------------------------------
Recording at more than one iteration is broken by construction, not merely
wasteful. Record mode raises ``FixtureConflictError`` when a key resolves to
different content; iteration 2 replays byte-identical messages (the note-id
counter is reset per run) against a live model that answers differently, so
every key collides — and the engine swallows those exceptions into per-attempt
skips, leaving a quietly incomplete fixture set. One iteration is the only
sound recording mode.

Zero-cost path
--------------
The default provider/model pair is self-hosted, so no key is needed::

    python scripts/record_reference_example.py --force

To record against a hosted provider instead, pass ``--provider``/``--model``
and set that provider's key in the environment via LiteLLM's normal mechanism.
Never hardcode or print a key.

There is deliberately no ``--api-base`` flag: ``api_base`` is folded into the v2
replay cache key, so a non-default endpoint would bake a machine-local URL into
every committed fixture. Set ``OLLAMA_API_BASE`` in the environment if the local
server is not on its default port, and accept that the resulting fixtures are
not portable.

After recording, review the written exploit JSON and fixtures for anything that
should not be committed.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import shutil
import sys
from pathlib import Path

from mylonite._replay import LiteLLMRecorder
from mylonite.contracts import ExploitRecord
from mylonite.plugins._reference.reference_pytest_generator import ReferencePytestGenerator
from mylonite.plugins._reference.reference_validator import (
    DifferentialValidator,
    ReferenceVulnerableOracle,
    _deterministic_strategies,
)
from mylonite.scan.engine import ScanEngine, ScanResult
from mylonite.scan.llm_types import CompletionFn
from mylonite.scan.seeds import SEED_CATALOGUE
from mylonite.scan.wiring import build_scan, note_id_counter
from mylonite.testkit import FIXTURE_FORMAT_VERSION

#: Default provider/model: self-hosted, so the artefact can be reproduced with
#: no account. Kept in step with the demo's default pair.
DEFAULT_PROVIDER = "ollama"
DEFAULT_MODEL = "ollama_chat/qwen3:4b-instruct-2507-q4_K_M"

#: The W2 seed the example is pinned to: the planner reads a poisoned note and
#: follows it into an egress call, which the guarded twin's taint gate refuses in
#: server code. Deterministic predicate on both sides
#: (``read_note_returned_poisoned_content_acted_on``), so the committed verdict
#: does not rest on a model-graded judgement.
#:
#: Chosen by measurement, not preference. The differential runs with the
#: per-seed LLM customiser ON — `DifferentialValidator` builds its scans that
#: way and `testkit._run_guarded_scan` replays an emitted test the same way, so
#: an example recorded with it off would cache-miss on every customiser call.
#: Under those conditions the sibling ``indirect-injection-note-body-direct``
#: seed does not land on a 4B planner (measured 0/2, against 2/2 with the raw
#: seed body: the customised wording gets the agent to *narrate* the forward
#: rather than perform it). This seed lands with the customiser on, so it is the
#: one whose differential the oracle can actually demonstrate end to end.
EXAMPLE_PATTERN_ID = "indirect-injection-note-body-tool-chain"

#: Where the committed example lives in the source tree.
DEFAULT_EXAMPLE_DIR = Path("examples/reference_validation")

#: Metamorphic strategies to record. Restricted to the deterministic ones so the
#: committed fixtures are reproducible; `tests/plugins/
#: test_reference_validation_example.py` pins that this stays a subset.
METAMORPHIC_STRATEGIES = ["paraphrase"]


class RecordingFailed(RuntimeError):
    """Raised when the live pass did not produce a committable artefact."""


#: Where the vulnerable twin's single-seed run is recorded, beside the guarded
#: ``fixtures/`` set the emitted test replays.
RED_FIXTURES_DIRNAME = "red_fixtures"


def kitchen_sink_pattern_ids() -> list[str]:
    """Every seed this script can record: the ones aimed at the reference app."""
    return sorted(s.pattern_id for s in SEED_CATALOGUE if "kitchen-sink" in s.applicable_targets)


async def _discover_exploit(
    *, provider: str, model: str, example_dir: Path, pattern_id: str = EXAMPLE_PATTERN_ID
) -> ExploitRecord:
    """Run a LIVE vulnerable scan and return the chosen seed's exploit record."""
    engine = build_scan(
        "vulnerable",
        completion_fn=None,  # live litellm.acompletion
        note_id_factory=note_id_counter(),
        provider=provider,
        model=model,
        pattern_id_filter=pattern_id,
    )
    result = await engine.run()
    exploit = next((e for e in result.exploits if e.pattern_id == pattern_id), None)
    if exploit is None:
        fired = sorted(e.pattern_id for e in result.exploits)
        outcomes = {a.pattern_id: a.outcome for a in result.report.attempts}
        raise RecordingFailed(
            f"the live vulnerable scan did not fire the pinned seed "
            f"{pattern_id!r}. Exploits: {fired or '<none>'}. Attempt "
            f"outcomes: {outcomes}. The seed is model-dependent — re-run, or "
            f"pick a planner that lands it, before committing anything."
        )
    print(f"[discover] exploit found for {exploit.pattern_id}")
    return exploit


def _red_scan(
    *, completion_fn: CompletionFn, provider: str, model: str, pattern_id: str
) -> ScanEngine:
    """The vulnerable twin's single-seed scan, wired as the offline replay wires it.

    Same call shape as ``testkit._run_guarded_scan`` with the variant swapped:
    ``pattern_id_filter`` set, a fresh note-id counter, and ``build_scan``'s
    default ``llm_assist`` (customiser and judge on). Recording and replaying
    through this one function keeps the two keyed alike.
    """
    return build_scan(
        "vulnerable",
        completion_fn=completion_fn,
        note_id_factory=note_id_counter(),
        provider=provider,
        model=model,
        pattern_id_filter=pattern_id,
    )


def _fired(result: ScanResult, pattern_id: str) -> bool:
    return any(e.pattern_id == pattern_id for e in result.exploits) or any(
        a.pattern_id == pattern_id and a.outcome == "finding" for a in result.report.attempts
    )


def _outcomes(result: ScanResult) -> dict[str, str]:
    return {a.pattern_id: str(a.outcome) for a in result.report.attempts}


async def record_red_set(*, provider: str, model: str, pattern_id: str, red_dir: Path) -> int:
    """Record the vulnerable twin's single-seed run, then prove it replays.

    Returns the number of fixture files written. Raises :class:`RecordingFailed`
    unless the live run fired the exploit with a clean recorder and an offline
    replay of the written set hits every lookup and fires it again.
    """
    red_dir.mkdir(parents=True, exist_ok=True)
    recorder = LiteLLMRecorder(red_dir, mode="record")
    result = await _red_scan(
        completion_fn=recorder, provider=provider, model=model, pattern_id=pattern_id
    ).run()
    if recorder.last_error is not None or recorder.cache_misses:
        raise RecordingFailed(
            f"the vulnerable single-seed recording is incomplete "
            f"(error: {recorder.last_error!r}, misses: {recorder.cache_misses})"
        )
    if not _fired(result, pattern_id):
        raise RecordingFailed(
            f"the vulnerable single-seed run did not fire {pattern_id!r} "
            f"(outcomes: {_outcomes(result)}), so the recorded test has no failing "
            "run to show. Re-run, or pick a model that lands the seed."
        )
    (red_dir / "_meta.json").write_text(
        json.dumps(
            {
                "cache_key_version": recorder.key_version,
                "format_version": FIXTURE_FORMAT_VERSION,
                "provider": provider,
                "model": model,
                "pattern_id": pattern_id,
                "variant": "vulnerable",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    await verify_red_set(provider=provider, model=model, pattern_id=pattern_id, red_dir=red_dir)
    return len(list(red_dir.glob("*.json"))) - 1


async def verify_red_set(*, provider: str, model: str, pattern_id: str, red_dir: Path) -> None:
    """Replay ``red_dir`` offline; raise unless every lookup hits and it fires."""
    replay = LiteLLMRecorder(red_dir, mode="replay")
    result = await _red_scan(
        completion_fn=replay, provider=provider, model=model, pattern_id=pattern_id
    ).run()
    if replay.last_error is not None or replay.cache_misses:
        raise RecordingFailed(
            f"the recorded vulnerable set does not replay offline "
            f"(error: {replay.last_error!r}, misses: {replay.cache_misses})"
        )
    if not _fired(result, pattern_id):
        raise RecordingFailed(
            f"the recorded vulnerable set replays but does not fire {pattern_id!r} "
            f"(outcomes: {_outcomes(result)})"
        )
    print(f"[red] offline replay of {red_dir} fires {pattern_id} with every lookup hit")


def _redacted_report(
    report: object, *, provider: str, model: str, iterations: int
) -> dict[str, object]:
    """The committed `validation_report.json`.

    Carries the verdict and every gating leg so the offline test can assert the
    committed verdict matches the one it re-derives — not just that both say
    KEPT. Deliberately excludes the raw per-iteration payload bodies and model
    replies: the artefact is a proof of the verdict, not a transcript dump, and
    recorded model output already lives in the fixture files.
    """
    dumped = report.model_dump(mode="json")  # type: ignore[attr-defined]
    return {
        "provenance": {"provider": provider, "model": model, "iterations": iterations},
        "test_filename": dumped["test_filename"],
        "kept": dumped["kept"],
        "gating_formula": dumped["gating_formula"],
        "gating_legs": dumped["gating_legs"],
        "mutation_score": dumped["mutation_score"],
        "reproducibility": dumped["reproducibility"],
        "outcomes": [
            {
                "stage": o["stage"],
                "passed": o["passed"],
                "detail": o["detail"],
                "metric": o["metric"],
                "report_only": o["report_only"],
            }
            for o in dumped["outcomes"]
        ],
    }


def _stamp_differential_meta(
    fixtures_dir: Path,
    *,
    provider: str,
    model: str,
    iterations: int,
    recorder: LiteLLMRecorder,
    pattern_id: str = EXAMPLE_PATTERN_ID,
    metamorphic_strategies: list[str] | None = None,
) -> None:
    """Sidecar for the full-bank fixture set.

    Deliberately carries NO ``format_version``. That constant means *single-seed
    scope* (see `mylonite.testkit.FIXTURE_FORMAT_VERSION`); stamping it on a
    whole-bank set would assert an isolation property this directory does not
    have. ``cache_key_version`` is a different axis and is read off the recorder
    so it cannot drift from what actually keyed the files.
    """
    (fixtures_dir / "_meta.json").write_text(
        json.dumps(
            {
                "cache_key_version": recorder.key_version,
                "provider": provider,
                "model": model,
                "pattern_id": pattern_id,
                "iterations": iterations,
                "metamorphic_strategies": (
                    METAMORPHIC_STRATEGIES
                    if metamorphic_strategies is None
                    else metamorphic_strategies
                ),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    example_dir: Path = args.example_dir
    differential_dir = example_dir / "differential_fixtures"
    guarded_dir = example_dir / "fixtures"
    red_dir = example_dir / RED_FIXTURES_DIRNAME
    pattern_id: str = args.pattern_id
    strategies: list[str] = args.metamorphic_strategies

    if example_dir.exists() and any(example_dir.iterdir()):
        if not args.force:
            print(
                f"{example_dir} is not empty. Re-recording over an existing artefact "
                "would leave files from two different runs side by side — the "
                "committed verdict and the fixtures it was derived from must come "
                "from one pass. Re-run with --force to clear it first.",
                file=sys.stderr,
            )
            return 2
        shutil.rmtree(example_dir)
        print(f"[force] cleared {example_dir}")

    example_dir.mkdir(parents=True, exist_ok=True)
    print(f"Recording the reference example with {args.provider}/{args.model}")
    print(f"Seed: {pattern_id}; metamorphic strategies: {', '.join(strategies)}")
    print(f"Example dir: {example_dir}")

    exploit = asyncio.run(
        _discover_exploit(
            provider=args.provider,
            model=args.model,
            example_dir=example_dir,
            pattern_id=pattern_id,
        )
    )
    test = ReferencePytestGenerator().emit(exploit)

    differential_dir.mkdir(parents=True, exist_ok=True)
    recorder = LiteLLMRecorder(differential_dir, mode="record")
    validator = DifferentialValidator(
        iterations=args.iterations,
        provider=args.provider,
        model=args.model,
        completion_fn=recorder,
        record_fixtures_dir=guarded_dir,
        metamorphic_strategies=strategies,
    )
    report = validator.validate(
        test, ReferenceVulnerableOracle().adapter(), ReferenceVulnerableOracle()
    )

    # The artefact is only worth committing if it proves the claim. Fail loudly
    # rather than leave a KEPT-less example that a reader would reasonably take
    # as evidence of one.
    if not report.kept:
        legs = "; ".join(
            f"{o.stage}={'pass' if o.passed else 'FAIL'}"
            + (" (report-only)" if o.report_only else "")
            + f": {o.detail}"
            for o in report.outcomes
        )
        raise RecordingFailed(
            f"the validator did NOT keep the test, so there is no proof to commit. "
            f"Legs: {legs}. Notes: {report.notes}"
        )
    # `cache_misses == 0` is what turns 'one flat directory is probably safe for
    # planner/customiser/judge calls' into *verified* for this artefact: every
    # lookup the loop made resolved to a fixture this pass recorded.
    if recorder.last_error is not None:
        raise RecordingFailed(
            f"the differential recorder reported an error, so the fixture set is "
            f"not a complete record of this pass: {recorder.last_error!r}"
        )
    if recorder.cache_misses:
        raise RecordingFailed(
            f"the differential recorder saw {recorder.cache_misses} cache miss(es); "
            "the recorded set does not cover the pass it came from"
        )

    _stamp_differential_meta(
        differential_dir,
        provider=args.provider,
        model=args.model,
        iterations=args.iterations,
        recorder=recorder,
        pattern_id=pattern_id,
        metamorphic_strategies=strategies,
    )
    red_count = asyncio.run(
        record_red_set(
            provider=args.provider, model=args.model, pattern_id=pattern_id, red_dir=red_dir
        )
    )
    (example_dir / "validation_report.json").write_text(
        json.dumps(
            _redacted_report(
                report, provider=args.provider, model=args.model, iterations=args.iterations
            ),
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    guarded_count = len(list(guarded_dir.glob("*.json"))) - 1
    differential_count = len(list(differential_dir.glob("*.json"))) - 1
    print("\n=== Recording summary ===")
    print(f"  pattern_id             {pattern_id}")
    print(f"  kept                   {report.kept}")
    print(f"  guarded fixtures       {guarded_count}")
    print(f"  differential fixtures  {differential_count}")
    print(f"  red fixtures           {red_count}")
    print(f"  example dir            {example_dir}")
    print(
        "\nReview the written exploit JSON and fixtures for anything that should "
        "not be committed before committing them."
    )
    return 0


def _pattern_id(raw: str) -> str:
    known = kitchen_sink_pattern_ids()
    if raw not in known:
        raise argparse.ArgumentTypeError(
            f"{raw!r} is not a reference-app seed; choose one of: {', '.join(known)}"
        )
    return raw


def _strategies(raw: str) -> list[str]:
    chosen = [name.strip() for name in raw.split(",") if name.strip()]
    if not chosen:
        raise argparse.ArgumentTypeError("name at least one metamorphic strategy")
    known = _deterministic_strategies()
    unknown = [name for name in chosen if name not in known]
    if unknown:
        raise argparse.ArgumentTypeError(
            f"unknown metamorphic strateg{'y' if len(unknown) == 1 else 'ies'} "
            f"{', '.join(unknown)}; choose from: {', '.join(known)}"
        )
    return chosen


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(__doc__ or "").splitlines()[0],
        epilog=(
            "No --api-base: api_base is part of the fixture cache key, so a "
            "non-default endpoint would bake a machine-local URL into every "
            "committed fixture. Use OLLAMA_API_BASE in the environment."
        ),
    )
    parser.add_argument(
        "--provider",
        default=DEFAULT_PROVIDER,
        help=(
            f"provider label for this recording (default: {DEFAULT_PROVIDER}). "
            "Stamped into both sidecars and read back by "
            "testkit.assert_guard_holds, so it must name the provider that "
            "actually served the run."
        ),
    )
    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help=(
            "model to record against, provider-prefixed as LiteLLM expects "
            f"(default: {DEFAULT_MODEL})."
        ),
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=1,
        help=(
            "differential iterations to record (default: 1). More than 1 is "
            "broken by construction in record mode — see the module docstring — "
            "so raise it only if you have changed how recording keys collide."
        ),
    )
    parser.add_argument(
        "--pattern-id",
        default=EXAMPLE_PATTERN_ID,
        type=_pattern_id,
        help=(
            f"the reference-app seed to record (default: {EXAMPLE_PATTERN_ID}). "
            "Must be a seed aimed at the kitchen-sink reference app."
        ),
    )
    parser.add_argument(
        "--metamorphic-strategies",
        default=",".join(METAMORPHIC_STRATEGIES),
        type=_strategies,
        help=(
            "comma-separated deterministic rewordings the validator drives through "
            f"both twins (default: {','.join(METAMORPHIC_STRATEGIES)}; choices: "
            f"{','.join(_deterministic_strategies())})."
        ),
    )
    parser.add_argument(
        "--example-dir",
        type=Path,
        default=DEFAULT_EXAMPLE_DIR,
        help=f"where to write the artefact (default: {DEFAULT_EXAMPLE_DIR}).",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help=(
            "clear the example directory first. Required to re-record, so a "
            "committed verdict can never sit next to fixtures from another run."
        ),
    )
    return parser.parse_args(argv)


if __name__ == "__main__":
    try:
        raise SystemExit(_main())
    except RecordingFailed as exc:
        print(f"\nrecording aborted: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
