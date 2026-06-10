"""Neutral scan-wiring home — the single source of truth for assembling a
vulnerable/guarded reference ScanEngine. Imported by the demo, the record
script, mylonite.testkit (Phase 2), and the validator. Lives under scan/ (not
demo/) so non-demo consumers don't import the playground surface.
"""

from __future__ import annotations

from collections.abc import Callable
from itertools import count
from typing import TYPE_CHECKING, Any, Literal

from mylonite.plugins._reference.excessive_agency_module import ExcessiveAgencyAttackModule
from mylonite.plugins._reference.prompt_injection_module import PromptInjectionAttackModule
from mylonite.plugins._reference.reference_target_adapter import InProcessReferenceAdapter
from mylonite.scan.customiser import PayloadCustomiser
from mylonite.scan.engine import ScanConfig, ScanEngine
from mylonite.scan.judge import SuccessJudge

if TYPE_CHECKING:
    from collections.abc import Awaitable


def note_id_counter() -> Callable[[], str]:
    """Deterministic ``n_demo_0001``, ``n_demo_0002``, … note-id factory.

    A fresh counter is constructed per variant so each variant starts at
    ``0001`` — safe because fixtures are variant-namespaced
    (``fixtures/vulnerable/`` vs ``fixtures/guarded/``), so the embedded note
    IDs never collide across variants.
    """
    counter = count(1)

    def factory() -> str:
        return f"n_demo_{next(counter):04d}"

    return factory


def build_scan(
    variant: Literal["vulnerable", "guarded"],
    *,
    completion_fn: Callable[..., Awaitable[Any]] | None,
    note_id_factory: Callable[[], str] | None,
    provider: str,
    model: str,
    pattern_id_filter: str | None = None,
) -> ScanEngine:
    """Build a ready-to-run ``ScanEngine`` for one reference variant.

    THE single source of wiring truth for the demo — the record script
    (Task A4) imports and reuses this exact function so recorded and replayed
    (model, messages) keys match. ``completion_fn=None`` makes the adapter,
    customiser, and judge fall back to the real ``litellm.acompletion`` (the
    live path). The attack modules are instantiated directly here, not via
    entry-point discovery, so the demo wiring is fully deterministic.
    """
    adapter = InProcessReferenceAdapter(
        variant=variant,
        model=model,
        completion_fn=completion_fn,
        note_id_factory=note_id_factory,
    )
    customiser = PayloadCustomiser(model=model, completion_fn=completion_fn)
    judge = SuccessJudge(model=model, completion_fn=completion_fn)
    prompt_injection = PromptInjectionAttackModule()
    excessive_agency = ExcessiveAgencyAttackModule()
    config = ScanConfig(
        target_id=f"reference:{variant}",
        provider=provider,
        model=model,
        max_llm_calls=100,
        max_concurrent=1,
        pattern_id_filter=pattern_id_filter,
    )
    return ScanEngine(
        config=config,
        adapter=adapter,
        attack_modules=[prompt_injection, excessive_agency],
        customiser=customiser,
        judge=judge,
    )


__all__ = [
    "build_scan",
    "note_id_counter",
]
