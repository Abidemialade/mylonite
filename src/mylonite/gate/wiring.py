"""Factory functions for the four collaborators ``gate()`` injects into
``run_gate`` (``scan_fn``, ``generate_fn``, ``validate_fn``, ``open_pr_fn``),
plus the PR check-run annotation helper only ``open_pr_fn`` calls.

Moved out of ``cli.py`` (#91 thin-shell refactor): these were four closures
nested inside the ``gate`` Typer command, together closing over ~20 of its
local variables. They are now factory functions that take those values as
explicit keyword parameters and return the callable ``run_gate`` expects;
``gate()``'s body calls the factories in place of defining nested closures.
No logic changed — every closure's body is moved verbatim, with its free
variables turned into parameters.

``generate_fn`` closed over none of ``gate()``'s locals, so it needs no
factory: it's a plain module-level function here, used directly.
"""

from __future__ import annotations

import asyncio
import functools
import hashlib
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import typer

from mylonite._cli_io import echo_err, echo_exc
from mylonite.contracts.exec_context import ExecContext
from mylonite.exit_codes import EXIT_CONFIG, EXIT_PR_FAILED
from mylonite.gate.orchestrator import ScanOutcomeBundle
from mylonite.generate.wiring import _dispatch_emit, _map_compliance
from mylonite.scan.assembly import (
    build_scan_engine,
    load_attack_modules,
    no_usable_modules_message,
    select_attack_modules,
)

if TYPE_CHECKING:
    from collections.abc import Callable

#: Explicit timeout for the outbound GitHub check-run API call in
#: _post_gate_annotations -- DCR-0008: a stalled call must not hang the gate
#: job indefinitely.
_GH_API_TIMEOUT_S: Final = 30.0


def _post_gate_annotations(
    repo_root: Path,
    findings: list[tuple[Any, Any]],
    target_file: Path | None,
    pr_mod: Any,
    *,
    gate_dir: Path,
    head_sha: str | None = None,
) -> None:
    """Best-effort GitHub check-run annotation for every KEPT finding that maps
    to a committed prompt line (R4). Untestable live glue (needs a real PR +
    ``checks:write``); the payload assembly and localization it calls are
    unit-tested. Never raises.

    ``findings`` is every kept ``(exploit, report)`` pair from this gate run
    (#202: gate no longer stops at the first finding, so annotations must not
    either) — ``annotations_from_findings`` already accepted a sequence of
    pairs; only this caller used to narrow it to one.

    ``gate_dir`` is the resolved ``gate --out`` directory — threaded through to
    :func:`mylonite.gate.annotate.post_check_run` so its scratch file lands
    alongside the rest of this run's gate artefacts rather than always under
    the hardcoded default.
    """
    try:
        from mylonite.gate.annotate import (
            annotations_from_findings,
            check_run_payload,
            post_check_run,
        )

        sp_path: str | None = None
        sp_text: str | None = None
        if target_file is not None:
            from mylonite.plugins._mcp.target_file import (
                load_target_file,
                resolved_system_prompt_path,
            )

            tf = load_target_file(target_file)
            spf = resolved_system_prompt_path(tf)  # raises PathEscapesBase on escape
            if spf is not None:
                sp_text = spf.read_text(encoding="utf-8")
                try:
                    sp_path = str(spf.relative_to(repo_root.resolve()))
                except ValueError:
                    # Contained in the target-file dir but outside the repo — do not
                    # publish content we cannot name relative to the PR.
                    sp_text = None

        anns = annotations_from_findings(
            findings, system_prompt=sp_path, system_prompt_text=sp_text
        )
        if not anns:
            return
        # The gate commit's SHA comes from the PR result: `--open-pr` returns
        # to the operator's original branch after committing, so HEAD is no
        # longer the commit the PR (and its check run) points at.
        if not head_sha:
            head = pr_mod._default_run(["git", "rev-parse", "HEAD"], cwd=str(repo_root))
            head_sha = (getattr(head, "stdout", "") or "").strip()
        if not head_sha:
            return
        payload = check_run_payload(
            head_sha=head_sha,
            annotations=anns,
            title="Mylonite AI-layer findings",
            summary=f"{len(anns)} finding(s) localized to a source line.",
        )
        # DCR-0008: no visible timeout on this outbound GitHub API call — a
        # stalled call could hang the gate job indefinitely. Bind a sane
        # explicit timeout onto the runner at this call site rather than
        # changing post_check_run's/Runner's signature.
        _bounded_run = functools.partial(pr_mod._default_run, timeout=_GH_API_TIMEOUT_S)
        post_check_run(repo_root, payload, gate_dir=gate_dir, _run=_bounded_run)
    except Exception:  # live glue must never break the gate
        return


def make_scan_fn(
    *,
    target: str | None,
    tf: Any,
    custom_spec: Any,
    effective_provider: str,
    effective_model: str,
    effective_planner_model: str,
    planner_model: str | None,
    effective_customiser_model: str,
    customiser_model: str | None,
    effective_judge_model: str,
    judge_model: str | None,
    max_llm_calls: int,
    adapter: Any,
    purpose: str | None,
    fast: bool,
    is_reference: bool,
    prove_input_control: bool,
    effective_policy: Any,
) -> Callable[[], ScanOutcomeBundle]:
    def scan_fn() -> ScanOutcomeBundle:
        from mylonite.scan._llm import llm_scope
        from mylonite.scan.coverage import ScanOutcome
        from mylonite.scan.engine import ScanConfig

        # Calibrate the effect probe with real writes before it's trusted --
        # only for a custom MCP target (`tf` is None for a bundled mcp:<family>
        # or reference route); --authorize already matched before `adapter`
        # was built.
        if tf is not None and custom_spec is not None and custom_spec.transport != "rest":
            from mylonite.plugins._mcp.calibration import calibrate_custom_target

            asyncio.run(calibrate_custom_target(adapter, authorized=True))

        try:
            all_modules, module_load_failures = load_attack_modules()
        except Exception as exc:
            echo_exc("plugin discovery failed", exc)
            raise typer.Exit(code=EXIT_CONFIG) from exc

        attack_modules = select_attack_modules(all_modules)
        if not attack_modules:
            echo_err(no_usable_modules_message(module_load_failures))
            raise typer.Exit(code=EXIT_CONFIG)

        config = ScanConfig(
            # DCR-0015: the custom route is reachable via TWO equivalent
            # inputs -- an explicit `mcp:custom` positional target, or just
            # `--target-file` with no positional target at all -- and both
            # describe the exact same target. Deriving target_id from the
            # literal `target` string (falling back to `tf.family` only when
            # `target is None`) gave the SAME custom target a DIFFERENT
            # target_id depending on which spelling the operator happened to
            # use: `"mcp:custom"` when typed, `f"mcp:{tf.family}"` when not.
            # Always derive it from `tf.family` on the custom route so it's
            # identical either way; `tf` is always set whenever
            # `routed_to == "custom"` (the only other custom-route branch,
            # inline `mcp:custom` flags, exits before routed_to is assigned)
            # -- branching on `tf is not None` rather than `routed_to ==
            # "custom"` also lets mypy narrow `tf` in this branch.
            target_id=(
                f"mcp:{tf.family}"
                if tf is not None
                else target
                if target is not None
                else "mcp:custom"
            ),
            provider=effective_provider,
            model=effective_model,
            planner_model=effective_planner_model if planner_model else None,
            customiser_model=effective_customiser_model if customiser_model else None,
            judge_model=effective_judge_model if judge_model else None,
            max_llm_calls=max_llm_calls,
        )
        engine = build_scan_engine(
            config,
            adapter,
            customiser_model=effective_customiser_model,
            judge_model=effective_judge_model,
            purpose=purpose or (tf.purpose if tf else None),
            attack_modules=attack_modules,
            module_load_failures=module_load_failures,
        )
        with llm_scope(policy=effective_policy):
            result = asyncio.run(engine.run())
        # The typed verdict for "did this scan actually run" (A1 fix) — carried
        # alongside the exploits so run_gate can tell a genuine clean scan apart
        # from one that never meaningfully ran (e.g. provider_unreachable).
        outcome = ScanOutcome.from_report(result.report, abort_detail=result.abort_detail)
        # Enrich compliance (derive NIST) once so both the emitted test and the PR
        # carry it.
        exploits = [_map_compliance(ex) for ex in result.exploits]
        # M1: tag each controllable CUSTOM finding BY DEFAULT so generate_fn emits the
        # control test and validate_fn runs the differential (the safeguard, not the
        # model, carries the security). --fast opts out; reference targets use the
        # in-repo differential and are not tagged here. This tagging is the default
        # behaviour; the old --prove-control opt-in flag was removed in 0.7.7.
        if fast or is_reference:
            return ScanOutcomeBundle(outcome=outcome, exploits=exploits)
        if custom_spec is None:
            echo_err("internal: expected a resolved TargetSpec for custom scan_fn tagging")
            raise typer.Exit(code=EXIT_CONFIG)
        from mylonite.gate.mitigation import weakness_class_for
        from mylonite.plugins._mcp.twins import plan_twins

        # plan_twins is the SAME function validate_fn calls below to build the
        # actual twin — tagging each exploit with plan.control_weakness (rather
        # than independently re-deriving "is this controllable") is what makes it
        # structurally impossible for the tag and the later twin to disagree.
        tagged: list[Any] = []
        announced: set[str] = set()
        for ex in exploits:
            cw = weakness_class_for(ex)
            plan = plan_twins(
                custom_spec, weakness=cw, fast=False, prove_input_control=prove_input_control
            )
            if plan.banner and plan.banner not in announced:
                announced.add(plan.banner)
                for line in plan.banner.split("\n"):
                    echo_err(f"gate: {line}")
            if plan.control_weakness is None:
                tagged.append(ex)
                continue
            meta = {**ex.payload.metadata, "synthetic_control": plan.control_weakness}
            tagged.append(
                ex.model_copy(update={"payload": ex.payload.model_copy(update={"metadata": meta})})
            )
        return ScanOutcomeBundle(outcome=outcome, exploits=tagged)

    return scan_fn


def generate_fn(exploit: Any) -> Any:
    # run_gate() is Typer-agnostic by design (its docstring: "Collaborators
    # are injected so the Typer command supplies live ones") -- the CLI-
    # framework-specific degrade-cleanly behaviour belongs in this function,
    # not in the orchestrator, mirroring scan_fn's own echo_exc + typer.Exit
    # for plugin-discovery failures.
    from mylonite.plugins._reference.reference_pytest_generator import (
        ReferencePytestGenerator,
        UnsafeExploitRecord,
    )

    try:
        exec_ctx = ExecContext.from_metadata(exploit.payload.metadata)
        return _dispatch_emit(ReferencePytestGenerator(), exploit, exec_ctx)
    except UnsafeExploitRecord as exc:
        echo_exc("could not generate a regression test for this finding", exc)
        raise typer.Exit(code=EXIT_CONFIG) from exc


def make_validate_fn(
    *,
    is_reference: bool,
    iterations: int,
    effective_provider: str,
    effective_model: str,
    effective_planner_model: str,
    planner_model: str | None,
    effective_customiser_model: str,
    customiser_model: str | None,
    effective_judge_model: str,
    judge_model: str | None,
    out: Path,
    effective_policy: Any,
    routed_to: str,
    custom_spec: Any,
    mcp_scope: str | None,
    tf: Any,
    fast: bool,
    randomize_exfil: bool,
) -> Callable[[Any], Any]:
    def validate_fn(generated: Any) -> Any:
        from mylonite.plugins._reference.reference_validator import (
            DifferentialValidator,
            ReferenceVulnerableOracle,
        )
        from mylonite.scan._llm import llm_scope

        if is_reference:
            # DCR-0009: same "all but one" reproducibility rule the custom/mcp
            # branch below explicitly sets (vuln_threshold = iterations - 1) --
            # this branch used to fall back to the constructor default instead,
            # so the reference target's pass/fail reproducibility bar was
            # silently looser than every other target type for no stated reason.
            validator = DifferentialValidator(
                iterations=iterations,
                vuln_threshold=max(1, iterations - 1),
                provider=effective_provider,
                model=effective_model,
                planner_model=effective_planner_model if planner_model else None,
                customiser_model=effective_customiser_model if customiser_model else None,
                judge_model=effective_judge_model if judge_model else None,
                record_fixtures_dir=out / "fixtures",
                progress_cb=lambda msg: echo_err(f"  … {msg}"),
            )
            with llm_scope(policy=effective_policy):
                return validator.validate(
                    generated,
                    ReferenceVulnerableOracle().adapter(),
                    ReferenceVulnerableOracle(),
                )
        # Custom / mcp: both re-drive the REAL target via a TargetSpec-driven
        # twin, mirroring _validate_custom. DCR-0014: the bundled
        # `mcp:<family>[:<scope>]` route never sets `tf` (there is no
        # TargetFile to load for a bundled target) but DOES set custom_spec /
        # mcp_scope at routing time above — branch on routed_to instead of
        # assuming every non-reference route went through the target_file
        # path (which used to make `gate mcp:<family>` exit here on ANY
        # finding).
        from mylonite.plugins._mcp import target_registry
        from mylonite.plugins._mcp.factory import build_adapter_for_spec
        from mylonite.plugins._mcp.twins import plan_twins

        if routed_to == "mcp":
            # custom_spec/mcp_scope are set unconditionally in the mcp routing
            # branch above; BUNDLED_TARGETS is already resolvable as-is, and
            # target_registry.register_target() would raise trying to shadow
            # a bundled family — skip the custom route's registration step.
            if custom_spec is None:
                echo_err("internal: expected a resolved TargetSpec for mcp validate_fn")
                raise typer.Exit(code=EXIT_CONFIG)
            spec = custom_spec
            scope_for_factory = mcp_scope
        else:
            if tf is None:
                echo_err("internal: expected a loaded TargetFile for custom validate_fn")
                raise typer.Exit(code=EXIT_CONFIG)
            from mylonite.plugins._mcp.target_file import build_target_spec

            spec = custom_spec if custom_spec is not None else build_target_spec(tf)
            target_registry.clear_runtime_targets()
            target_registry.register_target(spec)
            scope_for_factory = tf.scope

        # Control-efficacy leg: a controllable finding (tagged in scan_fn, via the
        # SAME plan_twins) gets a guarded twin so the differential leg proves the
        # control is load-bearing (model held constant). Re-deriving the plan from
        # the tagged weakness — rather than re-deciding server_layer/rest/boundary
        # ad hoc here — is what makes it structurally impossible for this twin to
        # disagree with scan_fn's tag or with `validate`'s own plan for the same
        # spec+weakness (the bug this closes: the raw side here used to be a plain
        # adapter that never honoured control_env at all).
        #
        # `fast` (gate()'s own flag) is threaded through explicitly here too —
        # defense-in-depth. Today control_weakness is already None whenever
        # `fast` is set (scan_fn's own early-return under --fast never tags an
        # exploit), so plan_twins would short-circuit on `weakness is None`
        # regardless of what `fast` says — but hardcoding `fast=False` here
        # relied entirely on that separate, implicit cross-closure guarantee
        # holding forever. Passing the real value removes that coupling.
        control_weakness = generated.exploit.payload.metadata.get("synthetic_control") or None
        plan = plan_twins(spec, weakness=control_weakness, fast=fast)

        def _factory() -> Any:
            return build_adapter_for_spec(
                spec, scope=scope_for_factory, model=effective_planner_model, intent=plan.raw
            )

        guarded_factory: Any = None
        if plan.control_weakness is not None:

            def _guarded() -> Any:
                return build_adapter_for_spec(
                    spec,
                    scope=scope_for_factory,
                    model=effective_planner_model,
                    intent=plan.guarded,
                )

            guarded_factory = _guarded

        # gate validates across `iterations` re-drives (default 3) so the kept verdict
        # reflects reproducibility: the attack must fire in all but one run
        # (vuln_threshold = iterations - 1) and the guarded side must resist every run.
        # `--iterations 1` restores the fastest, weakest gate (fire once). Deeper nightly
        # discovery still complements this via the committed test's regression assert.
        validator = DifferentialValidator(
            iterations=iterations,
            vuln_threshold=max(1, iterations - 1),
            provider=effective_provider,
            model=effective_model,
            planner_model=effective_planner_model if planner_model else None,
            customiser_model=effective_customiser_model if customiser_model else None,
            judge_model=effective_judge_model if judge_model else None,
            target_adapter_factory=_factory,
            guarded_adapter_factory=guarded_factory,
            control_weakness=plan.control_weakness,
            guarded_is_server_layer=plan.guarded_is_server_layer,
            control_context=plan.control_context,
            randomize_exfil=randomize_exfil,
            progress_cb=lambda msg: echo_err(f"  … {msg}"),
        )
        with llm_scope(policy=effective_policy):
            return validator.validate(generated, _factory(), ReferenceVulnerableOracle())

    return validate_fn


def resolve_gate_out_dir(
    out: Path, *, open_pr: bool, workflows: bool, pr_mod: Any, base: str | None = None
) -> Path:
    """Anchor ``out`` at the git repository root, and confirm it stays there,
    whenever either ``--open-pr`` or ``--workflows`` was requested.

    A no-op (returns ``out`` unchanged) for a plain ``gate`` run that touches
    neither git nor ``.github/workflows/`` — that path needs no repository at
    all, and many offline tests run it from a bare ``tmp_path`` with no `git
    init`. A RELATIVE ``out`` (the default ``.mylonite/gate`` layout) is
    anchored at the repository root. An already-absolute ``out`` (an
    explicit ``--out``) is left as-is, but still checked: it must resolve
    under the repository root, or later steps (the committed `git add`
    paths, the workflow's rendered ``__GATE_DIR__``) could not express it
    relative to the repo at all.

    Raises :class:`mylonite.gate.pr.GatePrError` in both failure shapes —
    the process isn't inside a git repository at all, or an explicit
    absolute ``--out`` sits outside one — via
    :func:`mylonite.gate.pr.resolve_repo_root`. This runs as a pre-flight,
    called before ``scan_fn``/``validate_fn``/``open_pr_fn`` are even built,
    so the failure is reported before any scan or LLM spend, not after
    paying for the whole pipeline.

    The same pre-flight also rejects a malformed ``--base``, and, with
    ``--open-pr``, a working tree with staged or uncommitted changes to
    tracked files (``pr.ensure_clean_tree``): the PR flow switches branch and
    commits, so it must not sweep the operator's own work into the gate PR.
    """
    if base is not None:
        pr_mod.validate_base(base)
    if not (open_pr or workflows):
        return out
    root = Path(pr_mod.resolve_repo_root())
    if out.is_absolute():
        try:
            out.relative_to(root)
        except ValueError as exc:
            raise pr_mod.GatePrError(
                f"--out {out} is not inside the repository root {root} — gate cannot "
                "commit or scaffold workflows outside the repository."
            ) from exc
    if open_pr:
        pr_mod.ensure_clean_tree(root)
    return out if out.is_absolute() else root / out


def resolve_gate_out_dir_or_exit(
    out: Path, *, open_pr: bool, workflows: bool, pr_mod: Any, base: str | None = None
) -> Path:
    """``resolve_gate_out_dir`` wrapped in ``gate()``'s own error handling, so
    its call site in ``cli.py`` is one line: reports a ``GatePrError`` as the
    named, actionable error every other repo-boundary failure in this
    package already is, on exit code 8, instead of leaking the raw
    exception past the CLI layer.
    """
    try:
        return resolve_gate_out_dir(
            out, open_pr=open_pr, workflows=workflows, pr_mod=pr_mod, base=base
        )
    except pr_mod.GatePrError as exc:
        echo_err(f"\nerror: {exc}")
        raise typer.Exit(code=EXIT_PR_FAILED) from exc


def budget_hint(routed_to: str, target_file: Path | None) -> str:
    """The gate-specific "what to do about an exhausted budget" hint.
    ``gate`` has no ``--weakness-class(es)`` flag at all — that's `scan`'s
    (singular) — so this never suggests it.
    For a custom target the real lever is the target file's own
    ``weakness_classes:`` key; for a reference or bundled target `gate` has
    no per-class filter, so the only lever is the budget itself. Reused by
    both `cli.py`'s own direct ``BudgetExceededError`` handler and (via the
    precomputed text threaded into ``run_gate``) `orchestrator.py`'s
    abort-carrying path, so the two can never disagree.
    """
    if routed_to == "custom" and target_file is not None:
        return f"Raise --max-llm-calls, or narrow the scan by editing weakness_classes: in {target_file}."
    return "Raise --max-llm-calls — gate has no per-class filter for this target."


#: The 7 built-in deterministic metamorphic re-paraphrasing strategies the
#: reference-target differential drives, each against both twins, on top of
#: its `iterations` full drives — see
#: ``reference_validator._deterministic_strategies()``, the source of truth
#: this number is read from by inspection at call time so the two can never
#: drift silently out of sync.
def _reference_redrives_per_finding(iterations: int) -> int:
    from mylonite.plugins._reference.reference_validator import _deterministic_strategies

    perturbations = len(_deterministic_strategies())
    return (iterations + perturbations) * 2


def validation_cost_note(*, is_reference: bool, iterations: int) -> str:
    """The per-finding validation-cost note for the console's multi-finding
    header. The reference-target differential and the custom-target one
    drive a genuinely different number of re-drives per finding (see
    docs/ci-gating.md's sizing box for the full breakdown from the code),
    so a single "about Nx" multiplier on its own doesn't say what N is a
    multiple OF. This names it for whichever path the current run takes.
    """
    if is_reference:
        redrives = _reference_redrives_per_finding(iterations)
        return f"roughly {redrives} re-drives per finding (iterations + metamorphic, x2 twins)"
    return (
        f"roughly {iterations} re-drives per finding, {iterations * 2} when a control "
        "differential applies (the default unless --fast)"
    )


def _gate_branch(findings: list[tuple[Any, Any]]) -> str:
    """The gate branch name (#202): today's exact name for a single kept
    finding, a stable short hash of the sorted kept pattern_ids for several.

    No live scan id reaches this far (``run_gate`` is handed a bare
    ``ScanOutcomeBundle``, not the report's id/timestamp), so the hash is
    always what a multi-finding run gets. Both shapes keep the
    ``mylonite/gate-`` prefix so anything that matches on it keeps working.
    """
    if len(findings) == 1:
        return f"mylonite/gate-{findings[0][0].pattern_id}"
    pattern_ids = sorted(exploit.pattern_id for exploit, _report in findings)
    digest = hashlib.sha256("|".join(pattern_ids).encode("utf-8")).hexdigest()[:10]
    return f"mylonite/gate-{digest}"


def make_open_pr_fn(
    *,
    runs_on: str,
    workflows: bool,
    target_file: Path | None,
    pr_mod: Any,
    base: str | None = None,
) -> Callable[..., Any]:
    def open_pr_fn(
        *,
        out_dir: Path,
        findings: list[tuple[Any, Any]],
        body: str,
        open_pr: bool,
        kept_dirs: list[Path] | None = None,
    ) -> Any:
        from mylonite._redaction import target_env_refs
        from mylonite._target_env import repo_secret_lines, write_redacted_target
        from mylonite.gate.workflows import write_workflows

        # The true git repository root, not Path.cwd() -- but ONLY when this
        # run actually touches git or .github/workflows/ (open_pr or
        # workflows); a plain print-mode `gate` (neither flag) needs no
        # repository at all, mirroring resolve_gate_out_dir's identical
        # condition so the two never anchor `out_dir` and `repo_root`
        # differently for the same run.
        repo_root = pr_mod.resolve_repo_root() if (open_pr or workflows) else Path.cwd()
        # kept_dirs names the exact directory each finding in `findings` was
        # written to (run_gate's own bookkeeping, never re-derived here) --
        # `out_dir` itself for a single-finding run, `out_dir/<slug>` per
        # finding for a multi-finding one. Falls back to `[out_dir] * n` for
        # a caller that doesn't pass it.
        dirs = kept_dirs if kept_dirs is not None else [out_dir] * len(findings)

        # Write the redacted target BEFORE rendering the workflows, and read
        # its `${MYLONITE_TARGET_...}` variables back from what was actually
        # written -- rendering the workflows first left the scaffolded
        # workflow's `env:` (and the console/PR-body secrets notice below)
        # with nothing to substitute, and `load_target_file` then raised on
        # the undefined variables in CI.
        env_refs: list[tuple[str, str]] = []
        if target_file is not None:
            # A gate PR is pushed to the operator's remote — never carry a live
            # credential from request.headers/env into that history (DCR-0019).
            written_text = write_redacted_target(
                out_dir / "target.yaml", target_file.read_text(encoding="utf-8")
            )
            env_refs = target_env_refs(written_text)
            # The emitted test's `here = Path(__file__).parent` loads
            # `target.yaml` from ITS OWN directory, not the gate root. A
            # multi-finding run puts each kept test under out_dir/<slug>/,
            # so each needs its own (already-redacted) copy too — the root
            # copy stays for the discovery workflow's `--target-file
            # out_dir/target.yaml`.
            for finding_dir in dirs:
                if finding_dir != out_dir:
                    (finding_dir / "target.yaml").write_text(written_text, encoding="utf-8")
        wf_files = (
            write_workflows(
                repo_root,
                runs_on=runs_on,
                gate_dir=out_dir,
                target_env_vars=[var for var, _key in env_refs],
            )
            if workflows
            else []
        )
        secret_lines = repo_secret_lines(env_refs)
        if secret_lines:
            from mylonite._cli_io import echo_err

            for line in secret_lines:
                echo_err(line)
            body = body.rstrip("\n") + "\n\n" + "\n".join(secret_lines) + "\n"
        # An explicit list of exactly what's committed -- never the bare
        # gate_dir, whether this is a single- or multi-finding run: a `git
        # add` that just sweeps gate_dir wholesale would stage ANYTHING
        # sitting there, including leftover content a previous run under the
        # same --out never cleaned up. Listing exact per-finding files
        # (rather than whole directories) also means a stray file left in a
        # finding's own directory by something else can't ride along either.
        add_paths: list[Path] = []
        for (exploit, report), finding_dir in zip(findings, dirs, strict=True):
            add_paths.append(finding_dir / report.test_filename)
            add_paths.append(finding_dir / f"exploit_{exploit.pattern_id}.json")
            add_paths.append(finding_dir / "validation_report.json")
            if target_file is not None:
                add_paths.append(finding_dir / "target.yaml")
        if target_file is not None and out_dir not in dirs:
            add_paths.append(out_dir / "target.yaml")
        # The reference-target differential leg records replay fixtures for
        # the whole run (not per finding) when it recorded any -- committed
        # so the emitted test(s) can run offline in CI.
        fixtures_dir = out_dir / "fixtures"
        if fixtures_dir.is_dir():
            add_paths.append(fixtures_dir)
        add_paths.append(out_dir / "PR_BODY.md")
        paths = pr_mod.GatePaths(
            repo_root=repo_root, gate_dir=out_dir, workflow_files=wf_files, add_paths=add_paths
        )
        branch = _gate_branch(findings)
        pr_title = (
            f"Mylonite gate: {findings[0][0].pattern_id}"
            if len(findings) == 1
            else f"Mylonite gate: {len(findings)} findings"
        )
        pr = pr_mod.open_or_print_pr(
            paths,
            branch=branch,
            pr_title=pr_title,
            pr_body=body,
            open_pr=open_pr,
            # --base wins; otherwise the repo's own default branch (read-only
            # git queries that fall back to "main"), never a hardcoded name.
            base=base if base is not None else pr_mod.resolve_default_base(repo_root),
        )
        # R4: best-effort inline check-run annotation on the exact prompt line, when
        # the AI layer is a committed file GitHub can render against. Tool loci (a
        # remote MCP description/handler/return path) have no source line and ride in
        # the PR body + SARIF instead. Live-only glue; never fails the gate.
        if open_pr and getattr(pr, "opened", False):
            _post_gate_annotations(
                repo_root,
                findings,
                target_file,
                pr_mod,
                gate_dir=out_dir,
                head_sha=getattr(pr, "commit_sha", None),
            )
        return pr

    return open_pr_fn
