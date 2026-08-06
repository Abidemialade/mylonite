"""Public runtime helpers that Mylonite-emitted security tests import.

Stability promise
-----------------
This module is a **stability-promised public surface**, on the same footing as
``mylonite.contracts``. The signatures of :func:`load_exploit` and
:func:`assert_guard_holds` are frozen; any change to them is a public-API
change and must be gated through ``CHANGELOG.md`` (and, for breaking changes, a
major version bump). Emitted tests living in *consumer* repositories import
these by name, so silent drift breaks every downstream regression gate.

What this is for
----------------
``mylonite generate`` emits a pytest file that, for each confirmed exploit,
calls::

    from mylonite import testkit

    def test_guard_holds_<pattern>():
        exploit = testkit.load_exploit("exploit_<pattern>.json")
        testkit.assert_guard_holds(exploit)

:func:`assert_guard_holds` is the **offline gate**: it replays the recorded
attack against the in-process GUARDED reference twin and asserts the exploit's
predicate did NOT fire. A guard that genuinely holds → the test passes; a guard
that lets the exploit through → ``AssertionError`` (the gate caught a
regression).

The single most important property here is **honesty** (R4): a stale, missing,
corrupt, or version-mismatched fixture, or an inconclusive run, must RAISE —
never silently pass. The scan engine swallows ``completion_fn`` exceptions (a
missing fixture degrades to a clean, finding-free run), so this module inspects
recorder state *after* the run and raises :class:`TestkitFixtureError` on any
trouble. A gate that silently passes is worse than no gate.

MVP target note
---------------
The "guarded twin" replayed here is the bundled ``mcp_kitchen_sink`` reference
server, wired via :func:`mylonite.scan.wiring.build_scan`. Importing this module
therefore transitively imports the reference adapter (and the kitchen sink). For
the MVP that coupling is intentional — the bundled twin *is* the differential
oracle. A later phase will let emitted tests target a consumer-owned agent.

Synchronous API
---------------
:func:`assert_guard_holds` is synchronous (it wraps ``asyncio.run``) because the
emitted pytest function is a plain ``def``. It is intended for standalone pytest
invocation; calling it from inside an already-running event loop raises
``RuntimeError`` from ``asyncio.run`` (the same constraint the ``mylonite demo``
CLI lives under). Library callers already inside a loop should ``await``
:func:`_run_guarded_scan` directly.
"""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

from mylonite.contracts._types import ExploitRecord
from mylonite.demo._replay import (
    FixtureError,
    LiteLLMRecorder,
    packaged_fixture_dir,
)
from mylonite.scan.engine import ScanResult
from mylonite.scan.exec_context import ExecContext
from mylonite.scan.wiring import build_scan, note_id_counter

#: On-disk format version for a ``fixtures_dir`` sidecar (``_meta.json``). Bumped
#: whenever the recorded-fixture layout or the (model, messages) keying changes.
#: Fixtures stamped with a different version cannot be trusted to replay, so the
#: gate refuses them rather than risk a false pass.
#:
#: v2 (per-exploit fixture isolation): the offline gate now scopes its scan to
#: the exploit's single seed (``pattern_id_filter``), so a v2 fixture set records
#: ONLY that one seed's (model, messages) pairs rather than every seed's. v1
#: fixtures (full-scan scope) are refused by :func:`_read_meta`.
FIXTURE_FORMAT_VERSION = 2

#: Re-record guidance surfaced in every fixture-trouble error. Names the
#: consumer-facing regeneration command (mirrors the demo's
#: ``DEMO_RERECORD_HINT`` but points at the user-run ``mylonite generate``).
TESTKIT_RERECORD_HINT = (
    "Regenerate the fixtures with `mylonite generate` (or re-run "
    "`mylonite scan` + `mylonite generate` against a live provider) so the "
    "recorded attack replays against the current guarded twin."
)


class TestkitFixtureError(FixtureError):
    """Raised when the offline gate cannot trust its replay fixtures.

    Subclasses the recorder's :class:`~mylonite.demo._replay.FixtureError` so
    consumers can catch either. Covers four honest-fail cases:

    * a missing / corrupt fixture (recorder ``cache_misses`` or ``last_error``);
    * a ``_meta.json`` that is absent or stamped with an unsupported
      ``format_version``;
    * a run that produced no conclusive attempt for the exploit's pattern_id
      (only ``skipped_*`` / ``error`` outcomes) — we cannot confirm the guard
      held, so we refuse to pass.

    The message always names the re-record path so the gate stays honest rather
    than silently green.
    """


class TestkitConfigError(ValueError):
    """Raised when the model/provider execution context an emitted LIVE test
    needs to re-drive its target cannot be resolved from any source (T12).

    :func:`assert_target_resists` and :func:`assert_control_holds` used to
    default their ``model``/``provider`` parameters to a hardcoded value
    (``"claude-haiku-4-5"`` / ``"anthropic"``) — meaning a committed regression
    test could silently gate CI using a DIFFERENT model than the one that
    actually discovered/validated the exploit. Both now resolve, per field,
    independently: an explicit keyword argument -> the exploit's own
    ``mylonite.exec.*`` :class:`~mylonite.contracts._types.Payload.metadata`
    (stamped by :class:`~mylonite.scan.engine.ScanEngine` at scan time) -> a
    sibling ``scan_report.json`` next to ``target_file`` (back-fill for an
    exploit committed before T12) -> this error. A missing execution context
    must be a LOUD failure, never a silent wrong-model run.
    """


def load_exploit(path: str | os.PathLike[str]) -> ExploitRecord:
    """Load an ``exploit_*.json`` artefact into an :class:`ExploitRecord`.

    ``path`` points at one of the ``exploit_<pattern_id>.json`` files written by
    ``mylonite scan`` (see ``mylonite.scan.artefacts.write_artefacts``). Raises
    :class:`FileNotFoundError` if the file is absent and :class:`ValueError`
    (wrapping the Pydantic validation error) if it is present but not a valid
    serialised ``ExploitRecord`` — never returns a partially-populated record.
    """
    file_path = Path(path)
    try:
        raw = file_path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise FileNotFoundError(
            f"exploit artefact not found: {file_path}. Point load_exploit at an "
            "exploit_<pattern_id>.json written by `mylonite scan`."
        ) from exc
    try:
        return ExploitRecord.model_validate_json(raw)
    except ValueError as exc:
        raise ValueError(
            f"exploit artefact at {file_path} is not a valid ExploitRecord: {exc}"
        ) from exc


def _read_meta(fixtures_dir: Path) -> dict[str, Any]:
    """Read + version-check a ``fixtures_dir/_meta.json`` sidecar.

    Returns the parsed metadata (at least ``model`` and ``pattern_id``). Raises
    :class:`TestkitFixtureError` if the sidecar is absent, unparseable, or
    stamps an unsupported ``format_version`` — the gate must not replay fixtures
    it cannot vouch for.

    As of ``FIXTURE_FORMAT_VERSION == 2`` the supported scope is single-seed: a
    v2 fixture set records only the exploit's own seed (the gate runs the scan
    with ``pattern_id_filter`` set), so stale v1 (full-scan-scoped) fixtures are
    refused here.
    """
    meta_path = fixtures_dir / "_meta.json"
    if not meta_path.is_file():
        raise TestkitFixtureError(
            f"fixtures at {fixtures_dir} are missing the _meta.json sidecar "
            f"(format/model provenance). {TESTKIT_RERECORD_HINT}"
        )
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise TestkitFixtureError(
            f"fixtures _meta.json at {meta_path} is not valid JSON ({exc}). {TESTKIT_RERECORD_HINT}"
        ) from exc
    if not isinstance(meta, dict):
        raise TestkitFixtureError(
            f"fixtures _meta.json at {meta_path} is not a JSON object. {TESTKIT_RERECORD_HINT}"
        )
    version = meta.get("format_version")
    if version != FIXTURE_FORMAT_VERSION:
        raise TestkitFixtureError(
            f"fixtures at {fixtures_dir} were generated by an incompatible "
            f"mylonite version (fixture format_version={version!r}, this "
            f"mylonite supports {FIXTURE_FORMAT_VERSION}). {TESTKIT_RERECORD_HINT}"
        )
    return meta


def _raise_if_fixture_trouble(
    *, cache_misses: int, last_error: Exception | None, hint: str
) -> None:
    """Raise :class:`TestkitFixtureError` if recorder state shows fixture trouble (R4).

    The engine swallows ``completion_fn`` exceptions, so the recorder's cumulative
    ``cache_misses`` / ``last_error`` is the only reliable signal a fixture was
    missing or corrupt. A corrupt fixture bumps ``last_error`` without
    ``cache_misses``, so both are checked.
    """
    if cache_misses > 0 or last_error is not None:
        detail = f" ({last_error})" if last_error is not None else ""
        raise TestkitFixtureError(
            f"replay hit a missing or corrupt fixture{detail}; the guard's "
            f"resistance could not be confirmed and the gate refuses to pass. {hint}"
        )


def _check_replay_recorder(recorder: LiteLLMRecorder) -> None:
    """Strict R4 check for the real replay path (statically-typed recorder).

    Reads ``cache_misses`` / ``last_error`` / ``missing_fixture_hint`` as direct
    attributes (NOT ``getattr`` with a default) so a future rename of that public
    ``LiteLLMRecorder`` surface fails loudly here — this is the one check the whole
    gate exists to keep honest. Mirrors ``demo.runner._check_replay_recorder``.
    """
    _raise_if_fixture_trouble(
        cache_misses=recorder.cache_misses,
        last_error=recorder.last_error,
        hint=recorder.missing_fixture_hint or TESTKIT_RERECORD_HINT,
    )


def _check_injected_double(double: Any) -> None:
    """Duck-typed R4 check for the ``_completion_fn`` injection seam (tests only).

    Tolerates a bare callable with no recorder state (nothing to inspect → no-op)
    or a test double that mimics the ``cache_misses`` / ``last_error`` surface.
    """
    _raise_if_fixture_trouble(
        cache_misses=getattr(double, "cache_misses", 0),
        last_error=getattr(double, "last_error", None),
        hint=getattr(double, "missing_fixture_hint", None) or TESTKIT_RERECORD_HINT,
    )


def _assert_from_result(result: ScanResult, exploit: ExploitRecord) -> None:
    """Turn a guarded ``ScanResult`` into the gate verdict (A1).

    Reads the ``ScanResult`` structure — NOT a re-run of the predicate (the
    engine discards the raw ``AdapterResponse`` on a resisting run, so there is
    nothing to re-run a predicate against). Decision table over attempts whose
    ``pattern_id`` matches the exploit:

    * any ``finding`` (or the pattern_id in ``result.exploits``) → guard FAILED
      → :class:`AssertionError`;
    * at least one ``no_finding`` → guard held → return;
    * otherwise (no matching attempt, or only ``skipped_*`` / ``error``) →
      INCONCLUSIVE → :class:`TestkitFixtureError` (never a silent pass).
    """
    pattern_id = exploit.pattern_id
    matching = [a for a in result.report.attempts if a.pattern_id == pattern_id]

    exploit_fired = any(e.pattern_id == pattern_id for e in result.exploits) or any(
        a.outcome == "finding" for a in matching
    )
    if exploit_fired:
        raise AssertionError(
            f"guard did not hold: the exploit {pattern_id!r} fired against the "
            "guarded twin. The guarded reference agent followed the attacker's "
            "intent — this is a regression in the guard."
        )

    if any(a.outcome == "no_finding" for a in matching):
        return

    outcomes: list[str] = sorted({str(a.outcome) for a in matching}) or ["<no attempt>"]
    # An undelivered indirect payload is a distinct, common cause on a LIVE custom
    # target: either the app defended by never surfacing the poison, OR the
    # seed_arm/drive needs tuning so the planter actually retrieves it. Naming both
    # avoids the misleading "replay/fixture problem" hint (there are no fixtures on
    # the live path). It still RAISES — an unexercised attack must not pass green.
    if matching and all(a.outcome == "skipped_payload_not_delivered" for a in matching):
        raise TestkitFixtureError(
            f"inconclusive: the attack {pattern_id!r} was never delivered to the model "
            "(the planted payload wasn't retrieved). Either the target defended by "
            "blocking delivery, or the seed_arm/drive needs tuning so the poison is "
            "surfaced. Resistance was NOT confirmed, so the gate refuses to pass."
        )
    raise TestkitFixtureError(
        f"inconclusive: no conclusive attempt for {pattern_id!r} against the "
        f"guarded twin (outcomes seen: {outcomes}). The guard's resistance could "
        f"not be confirmed — likely a replay/fixture problem. {TESTKIT_RERECORD_HINT}"
    )


def _exploit_fired(result: ScanResult, exploit: ExploitRecord) -> bool:
    """True iff the scan fired the exploit for ``exploit.pattern_id``."""
    pid = exploit.pattern_id
    return any(e.pattern_id == pid for e in result.exploits) or any(
        a.outcome == "finding" for a in result.report.attempts if a.pattern_id == pid
    )


def _resolve_exec_context(
    exploit: ExploitRecord,
    *,
    model: str | None,
    provider: str | None,
    target_file: Path,
) -> tuple[str, str]:
    """Resolve the (model, provider) a LIVE re-drive gates on (T12).

    Each field resolves INDEPENDENTLY through the same three-step order:

    1. The explicit ``model=``/``provider=`` keyword argument, if the caller
       (or the emitted test source, when the generator had exec context at
       ``mylonite generate`` time) passed one.
    2. The exploit's own ``mylonite.exec.*`` ``Payload.metadata`` (stamped by
       ``ScanEngine._finalize`` when the exploit was originally scanned) — see
       :class:`~mylonite.scan.exec_context.ExecContext`.
    3. A sibling ``scan_report.json`` next to ``target_file`` — back-fill for
       an exploit committed BEFORE T12, which carries no exec-context
       metadata at all.

    Raises :class:`TestkitConfigError` if either field is still unresolved
    after all three steps — a missing execution context must be a loud
    failure, never a silent fall-through to a hardcoded default model.
    """
    ctx = ExecContext.from_metadata(exploit.payload.metadata)
    resolved_model = model or (ctx.model if ctx is not None else None)
    resolved_provider = provider or (ctx.provider if ctx is not None else None)

    sibling_report = Path(target_file).parent / "scan_report.json"
    if (resolved_model is None or resolved_provider is None) and sibling_report.is_file():
        try:
            report_data: Any = json.loads(sibling_report.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            report_data = None
        if isinstance(report_data, dict):
            raw_model = report_data.get("model")
            raw_provider = report_data.get("provider")
            if resolved_model is None and isinstance(raw_model, str):
                resolved_model = raw_model
            if resolved_provider is None and isinstance(raw_provider, str):
                resolved_provider = raw_provider

    if resolved_model is None or resolved_provider is None:
        missing = [
            name
            for name, value in (("model", resolved_model), ("provider", resolved_provider))
            if value is None
        ]
        raise TestkitConfigError(
            f"cannot resolve {' and '.join(missing)} to re-drive exploit "
            f"{exploit.pattern_id!r}: no explicit model=/provider= kwarg was passed, the "
            "exploit carries no 'mylonite.exec.*' execution-context metadata, and no "
            f"sibling scan_report.json was found at {sibling_report}. Pass model=/provider= "
            "explicitly, or re-run `mylonite scan` + `mylonite generate` against a current "
            "scan so the exploit carries its execution context."
        )
    return resolved_model, resolved_provider


def _run_target_scan(
    *,
    spec: Any,
    scope: str | None,
    pattern_id: str,
    model: str,
    provider: str,
    controls: list[Any] | None,
    completion_fn: Callable[..., Any] | None,
    disable_controls: tuple[str, ...] = (),
    input_frame: bool = False,
) -> ScanResult:
    """Re-drive the declared target once, scoped to one seed.

    ``controls`` (when non-empty) wraps the adapter boundary to synthesize a
    guarded twin of the real target — the model is held constant, only the
    control differs. ``disable_controls`` (when non-empty) instead toggles OFF
    the named SERVER-LAYER guard(s) via the target's declared ``control_env``,
    so the re-drive exercises the target's own real guard rather than only the
    low-fidelity adapter-boundary shim. ``input_frame`` wraps the payload as
    untrusted data for a ``transport: rest`` target's input data-framing
    ("spotlighting") differential — ignored by every other transport. Shared by
    :func:`assert_target_resists` (raw, no controls/disables/framing) and
    :func:`assert_control_holds` (raw vs one of: boundary-guarded,
    raw-with-server-guard-disabled + real-guard-on, or input-framed) — every
    combination a :class:`~mylonite.plugins._mcp.twins.TwinPlan` can produce.

    Builds its adapter through :func:`~mylonite.plugins._mcp.factory.build_adapter_for_spec`
    — the shared transport-dispatching chokepoint — rather than constructing an
    MCP adapter class directly. That is what lets ``disable_controls`` actually
    take effect (the launch triple is threaded, not skipped), and what makes
    this correct for a non-stdio custom target (``transport: sse/http/rest``),
    which a hardcoded ``MCPStdioAdapter`` would silently mis-drive.
    """
    from mylonite.plugins._mcp.factory import LaunchIntent, build_adapter_for_spec
    from mylonite.plugins.registry import discover
    from mylonite.scan.customiser import PayloadCustomiser
    from mylonite.scan.engine import ScanConfig, ScanEngine
    from mylonite.scan.judge import SuccessJudge

    modules = [
        m
        for m in discover("mylonite.attack_modules")
        if m.attack_metadata().id in {"prompt-injection-family", "excessive-agency-family"}
    ]
    adapter = build_adapter_for_spec(
        spec,
        scope=scope,
        model=model,
        completion_fn=completion_fn,
        intent=LaunchIntent(
            boundary_controls=tuple(controls or ()),
            disable_controls=disable_controls,
            input_frame=input_frame,
        ),
    )
    config = ScanConfig(
        target_id=f"mcp:{spec.family}",
        provider=provider,
        model=model,
        max_concurrent=1,
        pattern_id_filter=pattern_id,
    )
    engine = ScanEngine(
        config=config,
        adapter=adapter,
        attack_modules=modules,
        customiser=PayloadCustomiser(model=model, completion_fn=completion_fn),
        judge=SuccessJudge(model=model, completion_fn=completion_fn),
    )
    return asyncio.run(engine.run())


async def _run_guarded_scan(
    exploit: ExploitRecord,
    *,
    completion_fn: Callable[..., Any],
    provider: str,
    model: str,
) -> ScanResult:
    """Run the guarded reference scan once with the given completion driver.

    The async core of :func:`assert_guard_holds`; library callers already inside
    an event loop (and the offline unit tests) ``await`` this directly to avoid
    nesting ``asyncio.run``. ``max_concurrent`` is forced to 1 by
    :func:`build_scan`, so the recorder's single-threaded state stays coherent.

    The scan is scoped to the exploit's single seed via ``pattern_id_filter`` so
    the gate replays ONLY that seed (per-exploit fixture isolation): committed
    fixtures stay small and decoupled, and the offline gate never drives the
    customiser/judge/planner for unrelated seeds.
    """
    engine = build_scan(
        "guarded",
        completion_fn=completion_fn,
        note_id_factory=note_id_counter(),
        provider=provider,
        model=model,
        pattern_id_filter=exploit.pattern_id,
    )
    return await engine.run()


def assert_guard_holds(
    exploit: ExploitRecord,
    *,
    fixtures_dir: str | os.PathLike[str] | None = None,
    _completion_fn: Callable[..., Any] | None = None,
) -> None:
    """Assert the GUARDED twin resists ``exploit`` — the offline regression gate.

    Replays the recorded attack against the in-process guarded reference twin
    and asserts the exploit's predicate did NOT fire. Returns ``None`` when the
    guard holds; otherwise raises (never silently passes).

    Parameters
    ----------
    exploit:
        The :class:`ExploitRecord` to re-drive (typically from
        :func:`load_exploit`). Its ``pattern_id`` selects which scan attempt the
        verdict is read from.
    fixtures_dir:
        Directory of recorded replay fixtures plus a ``_meta.json`` sidecar
        (``{"format_version": int, "model": str, "pattern_id": str}``). When a
        real directory, the recorded ``model`` is used for the replay keying.
        When ``None`` (the default), the packaged guarded reference fixtures
        (``packaged_fixture_dir() / "guarded"``) are used; ``model`` is read from
        their ``_meta.json``.
    _completion_fn:
        Test-only injection seam. When provided, it drives the scan directly and
        fixtures / ``_meta.json`` are skipped entirely. The post-run recorder
        check still runs against it duck-typed, so a double exposing
        ``cache_misses`` can simulate a missing-fixture gate.

    Raises
    ------
    AssertionError:
        The guard did not hold — the exploit fired against the guarded twin.
    TestkitFixtureError:
        The fixtures are missing / corrupt / version-mismatched, or the run was
        inconclusive (only skip/error outcomes) — the gate refuses to pass.
    """
    # Inert on the offline replay path (the recorder opens no sockets); a free
    # defensive call so a future record-mode library caller gets TLS set up too.
    from mylonite._bootstrap import enable_truststore

    enable_truststore()

    if _completion_fn is not None:
        # Test seam: drive directly, no fixtures/meta. Use a stub model; the
        # injected fn ignores it.
        result = asyncio.run(
            _run_guarded_scan(
                exploit,
                completion_fn=_completion_fn,
                provider="stub",
                model="stub",
            )
        )
        _check_injected_double(_completion_fn)
        _assert_from_result(result, exploit)
        return

    if fixtures_dir is not None:
        fixtures_path = Path(fixtures_dir)
        meta = _read_meta(fixtures_path)
        model = str(meta.get("model", "")) or "unknown"
    else:
        fixtures_path = Path(str(packaged_fixture_dir() / "guarded"))
        meta = _read_meta(fixtures_path)
        model = str(meta.get("model", "")) or "unknown"

    recorder = LiteLLMRecorder(
        fixtures_path,
        mode="replay",
        missing_fixture_hint=TESTKIT_RERECORD_HINT,
    )
    result = asyncio.run(
        _run_guarded_scan(
            exploit,
            completion_fn=recorder,
            provider="anthropic",
            model=model,
        )
    )
    _check_replay_recorder(recorder)
    _assert_from_result(result, exploit)


def assert_target_resists(
    exploit: ExploitRecord,
    *,
    target_file: str | os.PathLike[str],
    model: str | None = None,
    provider: str | None = None,
    _completion_fn: Callable[..., Any] | None = None,
) -> None:
    """Assert the REAL declared target still RESISTS ``exploit`` — fails on regression.

    Unlike :func:`assert_guard_holds` (which replays against the bundled
    kitchen-sink twin), this re-drives the *actual* target declared by
    ``target_file`` (scoped to the exploit's seed) and asserts the attack does NOT
    take effect. A target that has regressed — the attack lands, or its declared
    effect probe confirms the damage materialised — raises ``AssertionError``. So
    a test named for ``mcp:<your-app>`` fails when *your app* regresses, not when
    the reference does.

    This is a LIVE check (it launches the target's MCP server and calls the
    provider), so emitted tests gate it behind ``MYLONITE_LIVE_TARGET=1``.
    ``_completion_fn`` is the test-only offline seam.

    Parameters
    ----------
    model, provider:
        The model/provider to re-drive with. ``None`` (the default) resolves
        via :func:`_resolve_exec_context` — the exploit's own execution-context
        metadata, then a sibling ``scan_report.json``, else
        :class:`TestkitConfigError` (T12: this used to silently default to a
        hardcoded model, so an emitted gate could validate a DIFFERENT model
        than the one that found the exploit).
    """
    from mylonite._bootstrap import enable_truststore
    from mylonite.plugins._mcp import target_registry
    from mylonite.plugins._mcp.target_file import build_target_spec, load_target_file

    # The CLI's _root callback never runs under pytest, so set up the OS trust
    # store here too — otherwise this live check fails CERTIFICATE_VERIFY_FAILED
    # behind a TLS-inspecting proxy though `mylonite scan`/`validate` work.
    enable_truststore()

    target_path = Path(target_file)
    if not target_path.is_file():
        # An actionable error beats a bare FileNotFoundError: `generate` writes the
        # test next to a target.yaml only when given --target-file (mirrors how
        # load_exploit names the missing artefact).
        raise FileNotFoundError(
            f"target file {target_path} not found. The emitted custom-target test needs "
            "the target YAML co-located as 'target.yaml'. Re-run "
            "`mylonite generate <exploit> --target-file <your-target>.yaml`, or copy your "
            "scan's target YAML next to this test as target.yaml."
        )
    resolved_model, resolved_provider = _resolve_exec_context(
        exploit, model=model, provider=provider, target_file=target_path
    )
    tf = load_target_file(target_path)
    spec = build_target_spec(tf)
    target_registry.clear_runtime_targets()
    target_registry.register_target(spec)
    try:
        result = _run_target_scan(
            spec=spec,
            scope=tf.scope,
            pattern_id=exploit.pattern_id,
            model=resolved_model,
            provider=resolved_provider,
            controls=None,
            completion_fn=_completion_fn,
        )
    finally:
        target_registry.clear_runtime_targets()
    _assert_from_result(result, exploit)


def assert_control_holds(
    exploit: ExploitRecord,
    *,
    target_file: str | os.PathLike[str],
    control: str,
    model: str | None = None,
    provider: str | None = None,
    _completion_fn: Callable[..., Any] | None = None,
) -> None:
    """Assert a boundary CONTROL is load-bearing for ``exploit`` on the real target.

    Differential, model held constant: the attack must FIRE against the raw
    target and be RESISTED once ``control`` (e.g. ``"W2"``) is applied at the
    adapter boundary (see :mod:`mylonite.scan.control_shim`). This is the
    committed control-efficacy gate — it FAILS if either:

    * the control stops carrying the security (the boundary-guarded variant now
      fires — a regression in the control, or in your server-side implementation
      of it), or
    * the underlying attack no longer reproduces on the raw target, in which
      case the test would be theater and must not pass green.

    LIVE check (launches the target's MCP server and calls the provider), so
    emitted tests gate it behind ``MYLONITE_LIVE_TARGET=1``. ``_completion_fn``
    is the test-only offline seam.

    Raises
    ------
    AssertionError:
        The control did not hold (guarded variant fired), or the attack no
        longer reproduces on the raw target.
    TestkitFixtureError:
        The guarded run was inconclusive (only skip/error outcomes).
    ValueError:
        ``control`` names a weakness class with no implemented boundary control,
        or ``plan_twins`` found no differential to build at all for this
        target+control combination (e.g. a real W1-W4 class on a ``transport:
        rest`` target with no ``control_env`` toggle for it and no input-frame
        request — a boundary-control differential does not apply to a black
        box). Raised BEFORE any scan runs, never discovered by running an
        identical raw/guarded pair and misreading the result as a regression.

    Notes
    -----
    The raw-vs-guarded decision is delegated to
    :func:`~mylonite.plugins._mcp.twins.plan_twins` — the SAME pure function
    ``mylonite validate``/``mylonite gate`` call for this target+control, so an
    emitted test's twin can never disagree with what those commands proved.
    When the target declares a SERVER-LAYER toggle for ``control`` (its target
    file's ``control_env``), the raw leg re-drives with that REAL guard turned
    OFF (via ``disable_controls``) rather than relying only on the adapter-
    boundary shim, and the guarded leg is simply the plain default launch (the
    real guard is ON by default, so no shim is layered on top of it). A target
    with no ``control_env`` entry for ``control`` is unaffected: both legs
    behave exactly as before (boundary shim only). ``control="input-frame"``
    (the sentinel ``mylonite gate``/``validate --prove-input-control`` tag a
    ``transport: rest`` finding with) runs the input data-framing differential
    instead of a W1-W4 boundary control.

    ``model``/``provider`` resolve the same way as :func:`assert_target_resists`
    (T12): ``None`` (the default) reads the exploit's own execution-context
    metadata, then a sibling ``scan_report.json``, else :class:`TestkitConfigError`.
    Resolved AFTER the ``control``/``plan_twins`` fail-fast checks above (a bad
    control name or a non-differential target+control pair is diagnosed first —
    those are unconditional preconditions, independent of which model is used).
    """
    from mylonite._bootstrap import enable_truststore
    from mylonite.plugins._mcp import target_registry
    from mylonite.plugins._mcp.target_file import build_target_spec, load_target_file
    from mylonite.plugins._mcp.twins import INPUT_FRAME_CONTROL, plan_twins
    from mylonite.scan.control_shim import make_control

    enable_truststore()

    target_path = Path(target_file)
    if not target_path.is_file():
        raise FileNotFoundError(
            f"target file {target_path} not found. The emitted control test needs "
            "the target YAML co-located as 'target.yaml'. Re-run "
            "`mylonite generate <exploit> --target-file <your-target>.yaml`, or copy your "
            "scan's target YAML next to this test as target.yaml."
        )
    tf = load_target_file(target_path)
    spec = build_target_spec(tf)
    # Resolve the control up front so a bad name fails clearly (ValueError)
    # before any subprocess spawns. This is a hard, fail-fast check specific to
    # this explicit, hand-picked argument — unlike plan_twins' own "no
    # implemented control" branch, which is a SOFT degrade-to-no-differential
    # for gate/validate's auto-detected weakness class, not appropriate here (a
    # committed control-efficacy gate must never silently become a no-op).
    # INPUT_FRAME_CONTROL is not a W1-W4 class and has no boundary control to
    # resolve; plan_twins handles it directly below.
    if control != INPUT_FRAME_CONTROL:
        make_control(control)
    plan = plan_twins(spec, weakness=control, fast=False)
    # plan_twins' "no differential" outcome (control_weakness is None) is a SOFT
    # degrade for gate/validate's auto-detected weakness class (fall back to a
    # non-differential gate) — but here `control` is explicit and hand-picked, so
    # "no differential buildable" must be a hard, fail-fast error, not a silent
    # raw==guarded run. Without this check, an identical raw/guarded pair (e.g. a
    # real W1-W4 class on a rest target with no control_env toggle for it) would
    # re-fire the confirmed exploit on the "guarded" leg and raise a misleading
    # AssertionError("guard did not hold") even though no guard was ever applied.
    if plan.control_weakness is None:
        raise ValueError(
            f"control {control!r} has no differential to build on target "
            f"{spec.family!r} (transport={spec.transport!r}): "
            f"{plan.banner or 'plan_twins found nothing to differentiate.'} "
            "Use assert_target_resists for a non-differential regression check "
            "instead, or declare control_env / pass control='input-frame' so a "
            "real twin exists to test."
        )
    resolved_model, resolved_provider = _resolve_exec_context(
        exploit, model=model, provider=provider, target_file=target_path
    )
    target_registry.clear_runtime_targets()
    target_registry.register_target(spec)
    try:
        raw = _run_target_scan(
            spec=spec,
            scope=tf.scope,
            pattern_id=exploit.pattern_id,
            model=resolved_model,
            provider=resolved_provider,
            controls=list(plan.raw.boundary_controls) or None,
            completion_fn=_completion_fn,
            disable_controls=plan.raw.disable_controls,
            input_frame=plan.raw.input_frame,
        )
        guarded = _run_target_scan(
            spec=spec,
            scope=tf.scope,
            pattern_id=exploit.pattern_id,
            model=resolved_model,
            provider=resolved_provider,
            controls=list(plan.guarded.boundary_controls) or None,
            completion_fn=_completion_fn,
            disable_controls=plan.guarded.disable_controls,
            input_frame=plan.guarded.input_frame,
        )
    finally:
        target_registry.clear_runtime_targets()

    if not _exploit_fired(raw, exploit):
        raise AssertionError(
            f"control {control!r} could not be shown load-bearing: the attack "
            f"{exploit.pattern_id!r} no longer fires against the RAW target, so there is "
            "nothing for the control to stop (this test would be theater). Re-discover "
            "the exploit with `mylonite scan`."
        )
    # Guarded must resist — reuse the canonical resist / inconclusive / regression logic.
    _assert_from_result(guarded, exploit)


__all__ = [
    "TestkitConfigError",
    "TestkitFixtureError",
    "assert_control_holds",
    "assert_guard_holds",
    "assert_target_resists",
    "load_exploit",
]
