"""Offline demo runner for ``mylonite demo`` (v0.3.0, PR A, Task A3).

Runs the existing :class:`~mylonite.scan.engine.ScanEngine` twice — once
against ``reference:vulnerable`` and once against ``reference:guarded`` — and
returns both ``ScanResult``s plus the resolved mode/provider/model so the CLI
(Task A5) can hand them straight to ``render_demo``.

Single source of wiring truth
------------------------------
:func:`mylonite.scan.wiring.build_scan` (re-exported here as ``_build_scan``)
is the ONE place that wires adapter + customiser + judge + attack modules +
config into a ``ScanEngine``. The record script (Task A4) imports and reuses
*this exact function* so the (model, messages) pairs it records are
byte-for-byte the ones replay will look up. Any wiring drift between record and
replay means every fixture misses — so do not duplicate this wiring anywhere
else.

Error-surfacing contract
------------------------
The scan engine's ``_llm.py`` fallback chain and the adapter's
skip-conversion swallow exceptions raised by ``completion_fn`` (see the
``_replay`` module docstring). A stale or missing fixture therefore does NOT
propagate as an exception — it silently degrades the vulnerable scan to a
clean result and the demo lies. So after each replay variant we inspect the
recorder's cumulative state (``cache_misses`` / ``last_error``) and raise
:class:`DemoFixtureError`. This is the only reliable surfacing path.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Literal

from mylonite.demo._replay import (
    DEMO_RERECORD_HINT,
    FixtureError,
    LiteLLMRecorder,
    packaged_fixture_dir,
)
from mylonite.scan.engine import ScanResult
from mylonite.scan.wiring import build_scan, note_id_counter

#: Back-compat private aliases. The neutral wiring helpers were promoted to
#: :mod:`mylonite.scan.wiring` (Phase 2 PR 1); these names keep existing
#: importers (the record script, the CLI, and tests that monkeypatch
#: ``runner._build_scan``) working unchanged.
_build_scan = build_scan
_note_id_counter = note_id_counter

#: The provider the demo fixtures are recorded against. Replay forces this;
#: live runs default to it but honour caller overrides.
DEMO_PROVIDER = "anthropic"
#: The exact model the demo fixtures are recorded with. Binding for this
#: project — the recorded fixtures use this model and replay keys on it, so
#: changing it invalidates every fixture. Do NOT swap to claude-sonnet-4-6.
DEMO_MODEL = "claude-haiku-4-5-20251001"

#: The two reference variants the demo runs, in render order.
_VARIANTS: tuple[Literal["vulnerable", "guarded"], ...] = ("vulnerable", "guarded")


class DemoFixtureError(FixtureError):
    """Raised when a replay variant hit a missing/corrupt fixture.

    Subclasses the recorder's :class:`~mylonite.demo._replay.FixtureError` so
    callers can catch either. The message names the re-record procedure
    (``DEMO_RERECORD_HINT``) because a stale fixture otherwise renders the
    vulnerable scan clean and the demo silently lies.
    """


@dataclass
class DemoResult:
    """Both variants' results plus the resolved run metadata.

    Carries everything the CLI needs to call
    ``render_demo(vulnerable, guarded, mode=..., elapsed_s=...)`` directly.
    ``elapsed_s`` is the wall-clock time the runner observed; the CLI may use
    it or recompute its own.
    """

    vulnerable: ScanResult
    guarded: ScanResult
    mode: str
    provider: str
    model: str
    elapsed_s: float


def _raise_if_fixture_problem(
    *, cache_misses: int, last_error: Exception | None, hint: str, variant: str
) -> None:
    """Raise :class:`DemoFixtureError` if recorder state shows a fixture problem.

    A cache miss OR any recorded error (corrupt fixture sets ``last_error``
    without bumping ``cache_misses``) means the demo would otherwise show a
    falsely-clean vulnerable scan.
    """
    if cache_misses > 0 or last_error is not None:
        detail = f" ({last_error})" if last_error is not None else ""
        raise DemoFixtureError(
            f"demo fixtures for the {variant!r} variant are stale or missing"
            f"{detail}. The vulnerable scan would falsely show clean. {hint}"
        ) from last_error


def _check_replay_recorder(recorder: LiteLLMRecorder, variant: str) -> None:
    """Strict fixture-state check for the replay path (statically-typed recorder).

    The engine swallows ``completion_fn`` exceptions, so the recorder's
    cumulative state is the only reliable signal. Reads ``cache_misses`` /
    ``last_error`` / ``missing_fixture_hint`` as direct attributes so a future
    rename of that public surface fails loudly here — this is the one check the
    whole module exists to keep honest.
    """
    _raise_if_fixture_problem(
        cache_misses=recorder.cache_misses,
        last_error=recorder.last_error,
        hint=recorder.missing_fixture_hint or DEMO_RERECORD_HINT,
        variant=variant,
    )


def _check_recorder_state(recorder: Any, variant: str) -> None:
    """Duck-typed fixture-state check for the ``_recorder`` injection seam.

    Mirrors :func:`_check_replay_recorder` but tolerates an injected test
    double or a bare ``completion_fn`` without recorder state (no
    ``cache_misses`` attribute → nothing to inspect, skipped).
    """
    _raise_if_fixture_problem(
        cache_misses=getattr(recorder, "cache_misses", 0),
        last_error=getattr(recorder, "last_error", None),
        hint=getattr(recorder, "missing_fixture_hint", None) or DEMO_RERECORD_HINT,
        variant=variant,
    )


async def run_demo(
    *,
    live: bool,
    provider: str | None = None,
    model: str | None = None,
    _recorder: LiteLLMRecorder | None = None,
) -> DemoResult:
    """Run the vulnerable + guarded reference scans and return both results.

    Replay path (``live=False``)
        For each variant, a per-variant ``LiteLLMRecorder`` is built over the
        packaged fixtures (``packaged_fixture_dir() / variant``, ``mode=
        "replay"``) and used as the shared ``completion_fn``. Provider/model
        are FORCED to ``DEMO_PROVIDER``/``DEMO_MODEL`` (caller overrides are
        ignored — replay must key on the recorded model). Note IDs are
        deterministic (``n_demo_0001`` …), reset per variant. After each
        variant the recorder state is inspected and a missing/stale fixture
        raises :class:`DemoFixtureError`.

    Live path (``live=True``)
        ``completion_fn=None`` so adapter/customiser/judge fall back to real
        ``litellm.acompletion``. Provider/model default to ``DEMO_PROVIDER``/
        ``DEMO_MODEL`` but HONOUR caller overrides (LiteLLM is model-agnostic;
        live runs are not pinned to Anthropic). Note IDs are random. No
        recorder, so no fixture-state check.

    ``_recorder`` injection seam (tests only)
        When provided, the given recorder/completion_fn is used as the shared
        ``completion_fn`` for BOTH variants instead of constructing packaged-
        fixture recorders, and no packaged fixtures need to exist. The
        post-variant fixture-state check still runs against the injected
        recorder if it exposes ``cache_misses``/``last_error``/
        ``missing_fixture_hint`` — so a test can drive a simulated cache miss
        and assert :class:`DemoFixtureError` is raised. Implies the replay
        path (provider/model forced, deterministic note IDs); ``live`` is
        ignored when ``_recorder`` is set.

    This runner is side-effect-free: it never writes artefacts and never sets
    an output_dir that gets written. The default ``ScanConfig.output_dir`` is
    fine because the engine does not write — artefacts are a separate CLI
    concern.
    """
    start = time.monotonic()

    if _recorder is not None:
        result = await _run_injected(_recorder)
        elapsed = time.monotonic() - start
        return DemoResult(
            vulnerable=result["vulnerable"],
            guarded=result["guarded"],
            mode="replay (offline)",
            provider=DEMO_PROVIDER,
            model=DEMO_MODEL,
            elapsed_s=elapsed,
        )

    if live:
        used_provider = provider or DEMO_PROVIDER
        used_model = model or DEMO_MODEL
        results: dict[str, ScanResult] = {}
        for variant in _VARIANTS:
            engine = _build_scan(
                variant,
                completion_fn=None,
                note_id_factory=None,
                provider=used_provider,
                model=used_model,
            )
            results[variant] = await engine.run()
        elapsed = time.monotonic() - start
        return DemoResult(
            vulnerable=results["vulnerable"],
            guarded=results["guarded"],
            mode=f"live ({used_provider}/{used_model})",
            provider=used_provider,
            model=used_model,
            elapsed_s=elapsed,
        )

    # Replay path — provider/model forced to the recorded pair.
    results = {}
    fixture_root = packaged_fixture_dir()
    for variant in _VARIANTS:
        recorder = LiteLLMRecorder(fixture_root / variant, mode="replay")
        engine = _build_scan(
            variant,
            completion_fn=recorder,
            note_id_factory=_note_id_counter(),
            provider=DEMO_PROVIDER,
            model=DEMO_MODEL,
        )
        results[variant] = await engine.run()
        _check_replay_recorder(recorder, variant)
    elapsed = time.monotonic() - start
    return DemoResult(
        vulnerable=results["vulnerable"],
        guarded=results["guarded"],
        mode="replay (offline)",
        provider=DEMO_PROVIDER,
        model=DEMO_MODEL,
        elapsed_s=elapsed,
    )


async def _run_injected(recorder: Any) -> dict[str, ScanResult]:
    """Drive both variants off one injected recorder/completion_fn.

    Used by the ``_recorder`` seam. Forces the recorded provider/model and
    deterministic per-variant note IDs (mirrors the replay path), and runs the
    fixture-state check against the injected object when it exposes recorder
    state so tests can simulate a cache miss.
    """
    results: dict[str, ScanResult] = {}
    for variant in _VARIANTS:
        engine = _build_scan(
            variant,
            completion_fn=recorder,
            note_id_factory=_note_id_counter(),
            provider=DEMO_PROVIDER,
            model=DEMO_MODEL,
        )
        results[variant] = await engine.run()
        # Duck-typed: a recorder/double exposing cache_misses/last_error is
        # checked; a bare completion_fn without that surface is a no-op.
        _check_recorder_state(recorder, variant)
    return results


__all__ = [
    "DEMO_MODEL",
    "DEMO_PROVIDER",
    "DemoFixtureError",
    "DemoResult",
    "_build_scan",
    "run_demo",
]
