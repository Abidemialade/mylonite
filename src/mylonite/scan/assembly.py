"""Single assembly point for a ScanEngine over a target.

The scan pipeline -- discover attack modules, filter to the supported families,
then construct a ``ScanEngine`` with a ``PayloadCustomiser`` and a
``SuccessJudge`` -- was duplicated across the ``scan`` command, the gate's scan
closure, the custom-target re-drive, ablation, and the emitted-test runtime.
Each also re-spelled the attack-family allowlist. This module is the one place
that assembly lives.

Every production caller routes through :func:`build_scan_engine`; the supported
attack families are named once in :data:`ATTACK_FAMILIES`. ``scan/wiring.py``
keeps the reference/demo twin wiring but delegates engine assembly here, passing
its explicitly-instantiated modules.

The plugin-loader / engine / customiser / judge imports are function-local (as
every original call site had them) so this module adds no module-level
``scan -> plugins`` import edge.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from mylonite.scan.llm_types import CompletionFn

if TYPE_CHECKING:
    from mylonite.scan.engine import ScanConfig, ScanEngine

#: The attack-module families Mylonite currently ships and runs. Named once here
#: so callers filter discovered modules against it rather than re-spelling the ids
#: (adding a family is one edit; the error messages read from ``sorted(...)``).
ATTACK_FAMILIES: frozenset[str] = frozenset({"prompt-injection-family", "excessive-agency-family"})


def discover_attack_modules(*, restrict_to_families: bool = True) -> list[Any]:
    """Discover installed attack modules, filtered to :data:`ATTACK_FAMILIES` by default.

    ``restrict_to_families=False`` returns every registered module (the emitted-test
    runtime deliberately does not filter, so a third-party module's pattern still
    finds its own payload producer).
    """
    from mylonite.plugins.registry import discover

    modules = list(discover("mylonite.attack_modules"))
    if restrict_to_families:
        modules = [m for m in modules if m.attack_metadata().id in ATTACK_FAMILIES]
    return modules


def build_scan_engine(
    config: ScanConfig,
    adapter: Any,
    *,
    completion_fn: CompletionFn | None = None,
    customiser_model: str | None = None,
    judge_model: str | None = None,
    purpose: str | None = None,
    llm_fallback: bool = True,
    restrict_to_families: bool = True,
    attack_modules: list[Any] | None = None,
) -> ScanEngine:
    """Assemble a ready-to-run ``ScanEngine`` for ``adapter`` under ``config``.

    Discovers + family-filters the attack modules (unless ``attack_modules`` is
    supplied, e.g. the reference path passing explicitly-instantiated ones), and
    builds the customiser + judge. The customiser/judge model default to the
    config's role model, then to ``config.model``. ``completion_fn=None`` leaves
    the customiser and judge on the live ``litellm`` path.
    """
    from mylonite.scan.customiser import PayloadCustomiser
    from mylonite.scan.engine import ScanEngine
    from mylonite.scan.judge import SuccessJudge

    if attack_modules is None:
        attack_modules = discover_attack_modules(restrict_to_families=restrict_to_families)
    cust_model = customiser_model or config.resolved_customiser_model
    jud_model = judge_model or config.resolved_judge_model
    return ScanEngine(
        config=config,
        adapter=adapter,
        attack_modules=attack_modules,
        customiser=PayloadCustomiser(
            model=cust_model, completion_fn=completion_fn, purpose=purpose
        ),
        judge=SuccessJudge(model=jud_model, completion_fn=completion_fn, llm_fallback=llm_fallback),
    )
