"""Reference validators.

Two implementations ship here:

* ``NullValidator`` — the Phase 0 stub. Returns a "not implemented" report;
  useful as a default and as the ``null`` entry point.
* ``DifferentialValidator`` — the Phase 2 validation-engine **moat**. It proves
  a generated security test is *meaningful* by running the full attack scan
  against BOTH reference twins across a multi-run flakiness filter, then
  reporting a mutation score and one metamorphic-perturbation check.

The pipeline (per ``mylonite.contracts.validator``):

1. **build** — proves the emitted test artefact is a runnable regression gate.
   There are two modes:

   * *collect-only* (``record_fixtures_dir=None``, the offline-differential and
     unit-test path): the committed replay fixtures don't exist, so only that
     the file imports the testkit, registers its markers, and *collects* under
     pytest is asserted.
   * *full offline pass* (``record_fixtures_dir`` set, the live ``mylonite
     validate`` path): after the differential loop finds a clean discriminating
     run, the validator RECORDS the canonical guarded fixtures into
     ``record_fixtures_dir``, writes the on-disk test + co-located exploit next
     to them, and runs that ON-DISK committed test offline. The build leg passes
     only on a FULL pass (pytest exit 0 — the guard held against the recorded
     fixtures), not merely on collection. This closes the
     ``validate``→committed-artefact loop: the command leaves behind a
     ready-to-commit, replayable test + fixtures and proves it passes offline.
2. **differential** — across ``iterations`` runs of the full attack scan, does
   the exploit's ``pattern_id`` FIRE on the vulnerable twin and RESIST on the
   guarded twin *at all*? (discrimination)
3. **flakiness** — does it do both *reliably* — vulnerable fires
   ``>= vuln_threshold`` times and guarded resists ``>= guard_threshold`` times
   across the runs? (reproducibility)
4. **mutation-score** (report-only) — a PER-SEED kill matrix over every
   kitchen-sink seed: of all kitchen-sink seeds, how many did this run "kill"
   (vulnerable FIRED that seed's pattern_id AND guarded RESISTED it)? The
   headline ``mutation_score`` is ``killed / total`` in [0,1]; the per-seed
   matrix (``W1:…✓ W2:…✓ W3:…✗ …``) is surfaced in the report notes. Computed
   for free from the full scans already run.
5. **metamorphic** (report-only) — apply MULTIPLE deterministic, neutral
   perturbations (paraphrase / casing / whitespace / unicode confusables — pure
   string transforms, NO LLM, NO randomness) to the exploit body and re-run the
   differential check once per strategy; report the ROBUSTNESS fraction
   (held / total) in [0,1] plus a per-strategy breakdown.

``kept = build ∧ differential ∧ flakiness``. Mutation + metamorphic are
*reported*, not gating, for the MVP — even if EVERY perturbation breaks, ``kept``
is unaffected.

The live-vs-offline seam is ``completion_fn``: ``None`` ⇒ the real
``litellm.acompletion`` path (genuine, stochastic validation); an injected
callable ⇒ deterministic offline replay (the unit tests inject one).
"""

from __future__ import annotations

import asyncio
import json
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar, Literal

from mylonite.contracts import (
    ExploitRecord,
    GeneratedTest,
    ValidationOutcome,
    ValidationReport,
    ValidatorBase,
)
from mylonite.contracts._types import Payload
from mylonite.contracts.target_adapter import TargetAdapter
from mylonite.contracts.validator import CONTRACT_VERSION, VulnerableOracle
from mylonite.demo._replay import LiteLLMRecorder
from mylonite.plugins._reference.reference_target_adapter import InProcessReferenceAdapter
from mylonite.scan.engine import ScanResult
from mylonite.scan.pytest_runner import run_test_file
from mylonite.scan.seeds import SEED_CATALOGUE
from mylonite.scan.wiring import build_scan, note_id_counter
from mylonite.testkit import FIXTURE_FORMAT_VERSION

#: The individual kitchen-sink seeds, ordered, that the per-seed mutation kill
#: matrix scores. Each entry is (pattern_id, weakness). Resolved from the
#: catalogue so it never drifts from the seeds.
_KITCHEN_SINK_SEEDS: tuple[tuple[str, str], ...] = tuple(
    (s.pattern_id, s.weakness) for s in SEED_CATALOGUE if "kitchen-sink" in s.applicable_targets
)


def _deterministic_strategies() -> dict[str, Callable[[str], str]]:
    """The built-in, deterministic metamorphic perturbation strategies.

    Each entry maps a strategy name to a *pure* ``body -> body`` string
    transform: NO LLM, NO randomness. Re-applying the same transform to the
    same body always yields the same result. The strategies produce DISTINCT
    bodies from each other and from the original, so each genuinely re-paraphrases
    the exploit.
    """
    return {
        # Existing neutral paraphrase: prefix + whitespace normalisation.
        "paraphrase": lambda body: "Please note: " + " ".join(body.split()),
        # Case fold: swap the case of every cased character.
        "casing": lambda body: body.swapcase(),
        # Whitespace expansion: split into words then rejoin with newlines so the
        # body differs from both the original and the (single-space) paraphrase.
        "whitespace": lambda body: "\n".join(body.split()),
        # Unicode confusables: a fixed ASCII -> fullwidth substitution.
        "unicode": _unicode_confusables,
    }


#: Fixed, deterministic ASCII -> fullwidth confusable substitution table used by
#: the ``unicode`` metamorphic strategy. Only a few chars are mapped so the body
#: stays human-readable but is byte-distinct from the original. Built via chr()
#: from the Halfwidth-and-Fullwidth-Forms block (U+FF01..U+FF5E maps to ASCII
#: U+0021..U+007E by a fixed +0xFEE0 offset) to avoid embedding ambiguous
#: confusable literals in source.
_FULLWIDTH_OFFSET = 0xFEE0
_CONFUSABLE_MAP: dict[str, str] = {ch: chr(ord(ch) + _FULLWIDTH_OFFSET) for ch in "aeos"}


def _unicode_confusables(body: str) -> str:
    """Substitute a fixed set of ASCII chars with fullwidth confusables."""
    return "".join(_CONFUSABLE_MAP.get(ch, ch) for ch in body)


class NullValidator(ValidatorBase):
    """Returns a 'not implemented' report. Useful as a default."""

    contract_version: ClassVar[str] = CONTRACT_VERSION

    def validate(
        self,
        test: GeneratedTest,
        target: TargetAdapter,
        oracle: VulnerableOracle,
    ) -> ValidationReport:
        del target, oracle
        return ValidationReport(
            test_filename=test.filename,
            outcomes=[
                ValidationOutcome(
                    stage="build",
                    passed=False,
                    detail="NullValidator: real validation engine arrives in Phase 2.",
                ),
            ],
            kept=False,
            notes="reference plugin — does not validate",
        )


class ReferenceVulnerableOracle:
    """A tiny :class:`VulnerableOracle` for the bundled reference target.

    ``adapter()`` returns the in-process vulnerable twin. The
    :class:`DifferentialValidator` actually drives *both* twins itself via
    ``build_scan`` keyed by variant; this oracle exists so ``validate`` has a
    structurally-valid oracle argument for the reference, satisfying the
    contract signature.
    """

    def adapter(self) -> TargetAdapter:
        return InProcessReferenceAdapter(variant="vulnerable")  # type: ignore[return-value]


@dataclass(frozen=True)
class _IterationTally:
    """Per-iteration result of running the full scan against both twins."""

    vuln_fired: bool
    guard_resisted: bool
    vuln_result: ScanResult
    guard_result: ScanResult


@dataclass(frozen=True)
class _MutationResult:
    """Per-seed mutation kill matrix over the kitchen-sink seeds."""

    score: float
    matrix: str
    killed: int
    total: int


@dataclass(frozen=True)
class _Decision:
    """Pure outcome of the differential + flakiness decision over N iterations."""

    differential_passed: bool
    differential_metric: float
    flakiness_passed: bool
    flakiness_metric: float


class DifferentialValidator(ValidatorBase):
    """Differential-oracle validator — the Phase 2 validation-engine moat.

    Config lives in ``__init__`` because the contract ``validate`` signature is
    fixed (it cannot take extra params). ``completion_fn=None`` is the live
    path (real ``litellm.acompletion``); an injected callable is the
    deterministic offline seam the unit tests use.
    """

    contract_version: ClassVar[str] = CONTRACT_VERSION

    def __init__(
        self,
        *,
        iterations: int = 5,
        vuln_threshold: int | None = None,
        guard_threshold: int | None = None,
        provider: str = "anthropic",
        model: str = "claude-haiku-4-5-20251001",
        completion_fn: Callable[..., Any] | None = None,
        run_build: bool = True,
        record_fixtures_dir: Path | None = None,
        metamorphic_strategies: list[str] | None = None,
    ) -> None:
        if iterations < 1:
            raise ValueError("iterations must be >= 1")
        self._iterations = iterations
        # Defaults: vulnerable should fire almost-always (N-1), guard must
        # resist every single run (N) — a guard that leaks even once is not a
        # guard.
        self._vuln_threshold = vuln_threshold if vuln_threshold is not None else iterations - 1
        self._guard_threshold = guard_threshold if guard_threshold is not None else iterations
        self._provider = provider
        self._model = model
        self._completion_fn = completion_fn
        self._run_build = run_build
        self._record_fixtures_dir = record_fixtures_dir
        # Metamorphic perturbation strategies (report-only robustness check).
        # Default = all built-in deterministic transforms; a caller can restrict
        # to a subset (e.g. for focused tests). Unknown names raise.
        all_strategies = _deterministic_strategies()
        if metamorphic_strategies is None:
            chosen = list(all_strategies)
        else:
            unknown = [n for n in metamorphic_strategies if n not in all_strategies]
            if unknown:
                raise ValueError(f"unknown metamorphic strategies: {unknown}")
            chosen = list(metamorphic_strategies)
        self._metamorphic_strategies: list[tuple[str, Callable[[str], str]]] = [
            (name, all_strategies[name]) for name in chosen
        ]

    # -- public contract ------------------------------------------------------

    def validate(
        self,
        test: GeneratedTest,
        target: TargetAdapter,
        oracle: VulnerableOracle,
    ) -> ValidationReport:
        del target, oracle  # the validator drives both twins itself by variant
        pattern_id = test.exploit.pattern_id

        # 1+2. differential + flakiness — the one live loop (the moat).
        tallies = [self._run_iteration(pattern_id) for _ in range(self._iterations)]
        vuln_fires = sum(1 for t in tallies if t.vuln_fired)
        guard_resists = sum(1 for t in tallies if t.guard_resisted)
        decision = self._decide(
            vuln_fires=vuln_fires,
            guard_resists=guard_resists,
            iterations=self._iterations,
            vuln_threshold=self._vuln_threshold,
            guard_threshold=self._guard_threshold,
        )

        differential = ValidationOutcome(
            stage="differential",
            passed=decision.differential_passed,
            detail=(
                f"vulnerable fired the exploit {vuln_fires}/{self._iterations}, "
                f"guarded resisted {guard_resists}/{self._iterations} "
                f"(agreement={decision.differential_metric:.2f}); the test "
                f"{'discriminates' if decision.differential_passed else 'does NOT discriminate'} "
                "between the twins"
            ),
            metric=decision.differential_metric,
        )
        flakiness = ValidationOutcome(
            stage="flakiness",
            passed=decision.flakiness_passed,
            detail=(
                f"vulnerable fired {vuln_fires}/{self._iterations} "
                f"(need >= {self._vuln_threshold}), guarded resisted "
                f"{guard_resists}/{self._iterations} (need >= {self._guard_threshold}) "
                f"(reproducibility={decision.flakiness_metric:.2f})"
            ),
            metric=decision.flakiness_metric,
        )

        # 3. mutation-score (report-only) — per-seed kill matrix from the scans
        #    already run.
        mutation = self._mutation_score(tallies)

        # 4. metamorphic-lite (report-only) — one neutral perturbation.
        metamorphic = self._metamorphic_outcome(test.exploit)

        # build stage — collect-only, OR (when recording) record the canonical
        # guarded fixtures and run the on-disk committed test offline (full pass).
        build = self._build_outcome(test, tallies)

        kept = build.passed and differential.passed and flakiness.passed
        notes = (
            f"reproducibility: vulnerable fired {vuln_fires}/{self._iterations}, "
            f"guarded resisted {guard_resists}/{self._iterations} "
            f"(flakiness reproducibility={decision.flakiness_metric:.2f}); "
            f"mutation: killed {mutation.killed}/{mutation.total} kitchen-sink seeds "
            f"(mutation_score={mutation.score:.2f}): {mutation.matrix}; "
            f"metamorphic robustness={(metamorphic.metric or 0.0):.2f} "
            f"(report-only, not gating); "
            f"{'KEPT' if kept else 'REJECTED'} (kept = build ∧ differential ∧ flakiness)."
        )

        return ValidationReport(
            test_filename=test.filename,
            outcomes=[build, differential, flakiness, metamorphic],
            kept=kept,
            notes=notes,
            mutation_score=mutation.score,
        )

    # -- pure decision helper (unit-tested directly) --------------------------

    @staticmethod
    def _decide(
        *,
        vuln_fires: int,
        guard_resists: int,
        iterations: int,
        vuln_threshold: int,
        guard_threshold: int,
    ) -> _Decision:
        """Pure decision over the differential/flakiness tallies.

        * differential: the test discriminates *at all* (vuln fired ≥1 AND
          guard resisted ≥1); metric is the agreement fraction over the 2N
          observations.
        * flakiness: the test discriminates *reliably* (≥ thresholds); metric
          is the reproducibility fraction = min(fires, resists) / N.
        """
        differential_passed = vuln_fires >= 1 and guard_resists >= 1
        differential_metric = (vuln_fires + guard_resists) / (2 * iterations)
        flakiness_passed = vuln_fires >= vuln_threshold and guard_resists >= guard_threshold
        flakiness_metric = min(vuln_fires, guard_resists) / iterations
        return _Decision(
            differential_passed=differential_passed,
            differential_metric=differential_metric,
            flakiness_passed=flakiness_passed,
            flakiness_metric=flakiness_metric,
        )

    # -- per-iteration "run attack xN, tally" (reused by metamorphic) ---------

    def _run_iteration(self, pattern_id: str) -> _IterationTally:
        """Run the full attack scan against BOTH twins once and tally.

        Factored out so the metamorphic stage can reuse the exact same
        per-iteration differential check.
        """
        vuln_result = self._run_scan("vulnerable")
        guard_result = self._run_scan("guarded")
        return _IterationTally(
            vuln_fired=self._fired(vuln_result, pattern_id),
            guard_resisted=self._resisted(guard_result, pattern_id),
            vuln_result=vuln_result,
            guard_result=guard_result,
        )

    def _run_scan(self, variant: Literal["vulnerable", "guarded"]) -> ScanResult:
        """Build and run one full attack scan for ``variant``."""
        engine = build_scan(
            variant,
            completion_fn=self._completion_fn,
            note_id_factory=note_id_counter(),
            provider=self._provider,
            model=self._model,
        )
        return asyncio.run(engine.run())

    @staticmethod
    def _fired(result: ScanResult, pattern_id: str) -> bool:
        """True iff the scan produced a finding/exploit for ``pattern_id``."""
        if any(e.pattern_id == pattern_id for e in result.exploits):
            return True
        return any(
            a.pattern_id == pattern_id and a.outcome == "finding" for a in result.report.attempts
        )

    @staticmethod
    def _resisted(result: ScanResult, pattern_id: str) -> bool:
        """True iff the scan CLEANLY resisted ``pattern_id``.

        Clean resistance = a ``no_finding`` attempt for that pattern_id and no
        finding for it. A skip/error attempt is NOT clean resistance — the guard
        wasn't actually exercised, so it doesn't count.
        """
        matching = [a for a in result.report.attempts if a.pattern_id == pattern_id]
        if any(a.outcome == "finding" for a in matching):
            return False
        if any(e.pattern_id == pattern_id for e in result.exploits):
            return False
        return any(a.outcome == "no_finding" for a in matching)

    # -- mutation score -------------------------------------------------------

    def _mutation_score(self, tallies: list[_IterationTally]) -> _MutationResult:
        """Per-seed kill matrix over every kitchen-sink seed.

        A seed is "killed" iff, across all the scans already run, the vulnerable
        twin FIRED that seed's ``pattern_id`` (a finding/exploit for it) AND the
        guarded twin RESISTED it (a ``no_finding`` for it, with no finding/exploit
        on the guarded side). This mirrors the per-exploit ``_fired`` / ``_resisted``
        helpers but applied to EVERY kitchen-sink seed, not just the exploit's.

        Nearly free — the validator's differential loop runs the FULL attack bank
        each iteration (``_run_scan`` calls ``build_scan`` with NO
        ``pattern_id_filter``), so every kitchen-sink seed is observable.

        ``mutation_score = killed_seeds / total_kitchen_sink_seeds``, bounded
        [0,1]. The matrix string (``W1✓ W2✓ W3✓ W4✗`` style) is surfaced in the
        report notes.
        """
        if not _KITCHEN_SINK_SEEDS:
            return _MutationResult(score=0.0, matrix="(no kitchen-sink seeds)", killed=0, total=0)

        vuln_fired: set[str] = set()
        guard_resisted: set[str] = set()
        guard_fired: set[str] = set()
        for tally in tallies:
            for pattern_id, _ in _KITCHEN_SINK_SEEDS:
                if self._fired(tally.vuln_result, pattern_id):
                    vuln_fired.add(pattern_id)
                if self._fired(tally.guard_result, pattern_id):
                    guard_fired.add(pattern_id)
                if self._resisted(tally.guard_result, pattern_id):
                    guard_resisted.add(pattern_id)

        killed_flags: list[tuple[str, str, bool]] = []
        for pattern_id, weakness in _KITCHEN_SINK_SEEDS:
            killed = (
                pattern_id in vuln_fired
                and pattern_id in guard_resisted
                and pattern_id not in guard_fired
            )
            killed_flags.append((pattern_id, weakness, killed))

        killed_count = sum(1 for *_, k in killed_flags if k)
        total = len(killed_flags)
        score = killed_count / total
        matrix = " ".join(
            f"{weakness}:{pattern_id}{'✓' if killed else '✗'}"
            for pattern_id, weakness, killed in killed_flags
        )
        return _MutationResult(score=score, matrix=matrix, killed=killed_count, total=total)

    # -- metamorphic-lite -----------------------------------------------------

    def _metamorphic_outcome(self, exploit: ExploitRecord) -> ValidationOutcome:
        """Multiple deterministic perturbations, each re-checked once on both twins.

        Each configured strategy is a *pure string transform* of the exploit body
        (NO LLM, NO randomness). For each, we rebuild the exploit with the
        perturbed body and re-run the SAME per-iteration differential check once,
        recording whether the differential still held (vuln fired AND guard
        resisted). The reported ``metric`` is the ROBUSTNESS fraction
        (held / total) in [0,1], and ``detail`` carries a per-strategy breakdown.

        The stage is **report-only** (not gating): it answers "does the
        differential survive trivial, semantically-neutral rewordings?". ``passed``
        is true iff ALL perturbations held (the strict reading), but neither
        ``passed`` nor ``metric`` feeds the ``kept`` gate.
        """
        results: list[tuple[str, bool]] = []
        for name, transform in self._metamorphic_strategies:
            perturbed_exploit = self._perturb_exploit(exploit, transform)
            tally = self._run_iteration(perturbed_exploit.pattern_id)
            held = tally.vuln_fired and tally.guard_resisted
            results.append((name, held))

        total = len(results)
        held_count = sum(1 for _, held in results if held)
        robustness = held_count / total if total else 0.0
        all_held = total > 0 and held_count == total
        breakdown = ", ".join(f"{name}:{'held' if held else 'broke'}" for name, held in results)
        return ValidationOutcome(
            stage="metamorphic",
            passed=all_held,
            detail=(
                f"{total} deterministic perturbation(s) of the exploit body "
                f"(pure string transforms, no LLM): {breakdown} "
                f"(robustness={robustness:.2f}); report-only — does not gate kept"
            ),
            metric=robustness,
        )

    @staticmethod
    def _perturb_exploit(exploit: ExploitRecord, transform: Callable[[str], str]) -> ExploitRecord:
        """Apply a deterministic ``body -> body`` transform to the exploit payload."""
        perturbed_body = transform(exploit.payload.body)
        perturbed_payload = Payload(
            pattern_id=exploit.payload.pattern_id,
            channel=exploit.payload.channel,
            body=perturbed_body,
            metadata=dict(exploit.payload.metadata),
        )
        return exploit.model_copy(update={"payload": perturbed_payload})

    # -- build stage ----------------------------------------------------------

    def _build_outcome(
        self, test: GeneratedTest, tallies: list[_IterationTally]
    ) -> ValidationOutcome:
        """Prove the emitted test is a runnable regression gate.

        Two modes (see the class docstring):

        * ``record_fixtures_dir is None`` → *collect-only*: write ``test.source``
          to a temp dir and assert pytest can COLLECT it. The committed replay
          fixtures don't exist, so a full PASS isn't asserted.
        * ``record_fixtures_dir`` set AND a clean discriminating iteration exists
          → *full offline pass*: record the canonical guarded fixtures, write the
          on-disk test + co-located exploit next to them, and run that ON-DISK
          committed test offline — the build leg passes only on a FULL pass
          (pytest exit 0). If recording is requested but no canonical run
          qualifies, fall back to collect-only (the kept verdict already reflects
          the differential/flakiness failure).
        """
        if not self._run_build:
            return ValidationOutcome(
                stage="build",
                passed=True,
                detail="build stage skipped (run_build=False)",
            )

        if self._record_fixtures_dir is not None:
            canonical = self._canonical_run_index(tallies)
            if canonical is not None:
                return self._record_and_full_pass(test)
            # No clean discriminating iteration → don't record; collect-only.
            return self._collect_only_outcome(
                test,
                suffix=(
                    " — no clean discriminating run to record; "
                    "fixtures not recorded (kept verdict reflects the failure)"
                ),
            )

        return self._collect_only_outcome(test)

    @staticmethod
    def _canonical_run_index(tallies: list[_IterationTally]) -> int | None:
        """Index of the FIRST iteration that BOTH fired and resisted (D4), or None.

        That clean, discriminating run is the canonical reproduction worth
        recording. If none qualifies (flaky / failed loop), recording is skipped.
        """
        for i, tally in enumerate(tallies):
            if tally.vuln_fired and tally.guard_resisted:
                return i
        return None

    def _collect_only_outcome(self, test: GeneratedTest, *, suffix: str = "") -> ValidationOutcome:
        """Collect-only build: assert the emitted source collects under pytest."""
        with tempfile.TemporaryDirectory() as tmp:
            test_path = Path(tmp) / test.filename
            test_path.write_text(test.source, encoding="utf-8")
            result = run_test_file(test_path)
        return ValidationOutcome(
            stage="build",
            passed=result.collected,
            detail=(
                f"collect-only: emitted test "
                f"{'collected' if result.collected else 'did NOT collect'} under pytest "
                f"(exit_code={result.exit_code}: {result.detail}){suffix}"
            ),
        )

    def _record_and_full_pass(self, test: GeneratedTest) -> ValidationOutcome:
        """Record canonical guarded fixtures, then full-offline-pass the on-disk test.

        A SEPARATE single-seed guarded scan (not mid-loop) records the canonical
        fixtures: single-seed scoping (``pattern_id_filter``) + deterministic note
        IDs make it self-consistent (one seed, ``n_demo_0001…``), so it cannot
        collide with itself (no ``FixtureConflictError``). The on-disk test +
        co-located exploit are written next to the recorded ``fixtures/`` so the
        emitted test resolves its data, then run offline as a FULL pass.
        """
        assert self._record_fixtures_dir is not None  # guarded by caller
        fixtures_dir = self._record_fixtures_dir
        exploit = test.exploit

        # 1. Record the canonical guarded fixtures (one separate single-seed scan).
        recorder = LiteLLMRecorder(fixtures_dir, mode="record")
        engine = build_scan(
            "guarded",
            completion_fn=recorder,
            note_id_factory=note_id_counter(),
            provider=self._provider,
            model=self._model,
            pattern_id_filter=exploit.pattern_id,
        )
        asyncio.run(engine.run())

        # 2. Stamp the _meta.json sidecar the offline gate reads.
        meta_path = fixtures_dir / "_meta.json"
        meta_path.write_text(
            json.dumps(
                {
                    "format_version": FIXTURE_FORMAT_VERSION,
                    "model": self._model,
                    "pattern_id": exploit.pattern_id,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

        # 3. Co-locate the on-disk test + exploit NEXT TO the recorded fixtures so
        #    the emitted test (`here/"exploit_<pid>.json"`, `here/"fixtures"`)
        #    resolves its data.
        artefact_dir = fixtures_dir.parent
        test_path = artefact_dir / test.filename
        test_path.write_text(test.source, encoding="utf-8")
        exploit_path = artefact_dir / f"exploit_{exploit.pattern_id}.json"
        exploit_path.write_text(exploit.model_dump_json(indent=2) + "\n", encoding="utf-8")

        # 4. Run the ON-DISK committed test offline — FULL pass required (exit 0).
        result = run_test_file(test_path)
        return ValidationOutcome(
            stage="build",
            passed=result.passed,
            detail=(
                f"full offline pass: on-disk committed test "
                f"{'PASSED' if result.passed else 'did NOT pass'} against the recorded "
                f"canonical guarded fixtures (exit_code={result.exit_code}: {result.detail})"
            ),
        )
