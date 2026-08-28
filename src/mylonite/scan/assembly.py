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

import os
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from mylonite.scan.llm_types import CompletionFn

if TYPE_CHECKING:
    from mylonite.scan.engine import ScanConfig, ScanEngine

#: The attack-module families Mylonite currently ships and runs BY DEFAULT. Named
#: once here so callers filter discovered modules against it rather than
#: re-spelling the ids (adding a family is one edit; the error messages read from
#: ``sorted(...)``).
#:
#: This is an allowlist, not a registry of everything installed. A scan runs only
#: what is named here plus what the operator explicitly opts into via
#: :data:`ATTACK_MODULES_ENV` — see :func:`select_attack_modules`.
ATTACK_FAMILIES: frozenset[str] = frozenset({"prompt-injection-family", "excessive-agency-family"})

#: Comma-separated attack-module ids to run IN ADDITION to :data:`ATTACK_FAMILIES`.
#:
#: Before this existed, a third-party ``AttackModule`` installed cleanly, appeared
#: in ``mylonite plugins``, and was then silently dropped from every scan — the
#: extension point was published API that nothing external could actually use.
#:
#: Opt-in by explicit id rather than "run everything discovered", deliberately.
#: This is a security tool: which code gets to drive an attack against your app
#: should be a decision you made, not a consequence of what happens to be in the
#: environment. It also keeps the shipped ``reference-indirect-injection`` stub
#: (an authoring example, not a real probe) out of real scans.
ATTACK_MODULES_ENV = "MYLONITE_ATTACK_MODULES"


def extra_attack_module_ids() -> frozenset[str]:
    """Attack-module ids the operator opted into via :data:`ATTACK_MODULES_ENV`."""
    raw = os.environ.get(ATTACK_MODULES_ENV, "")
    return frozenset(part.strip() for part in raw.split(",") if part.strip())


def select_attack_modules(
    modules: Sequence[Any], *, extra_ids: frozenset[str] | None = None
) -> list[Any]:
    """Filter discovered modules to the shipped families plus any opted-in ids.

    ``extra_ids=None`` reads :func:`extra_attack_module_ids`; pass an explicit
    frozenset to bypass the environment (the tests do).
    """
    allowed = ATTACK_FAMILIES | (extra_attack_module_ids() if extra_ids is None else extra_ids)
    return [m for m in modules if m.attack_metadata().id in allowed]


def no_usable_modules_message() -> str:
    """Operator-facing text when selection came back empty.

    Names the opt-in path, because "no usable attack modules" is exactly the
    message a plugin author sees when their module IS installed but not enabled,
    and a message that does not mention the switch leaves them guessing.
    """
    return (
        f"no usable attack modules discovered (looking for one of {sorted(ATTACK_FAMILIES)}). "
        f"To run a third-party module as well, set {ATTACK_MODULES_ENV} to its "
        "comma-separated attack_metadata().id — `mylonite plugins` lists what is installed."
    )


def discover_attack_modules(*, restrict_to_families: bool = True) -> list[Any]:
    """Discover installed attack modules, filtered by :func:`select_attack_modules`.

    ``restrict_to_families=False`` returns every registered module (the emitted-test
    runtime deliberately does not filter, so a third-party module's pattern still
    finds its own payload producer).
    """
    from mylonite.plugins.registry import discover

    modules = list(discover("mylonite.attack_modules"))
    if restrict_to_families:
        modules = select_attack_modules(modules)
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
