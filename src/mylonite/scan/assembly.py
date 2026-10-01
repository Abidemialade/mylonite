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

import dataclasses
import os
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any, Final

from mylonite.scan.llm_types import CompletionFn

if TYPE_CHECKING:
    from mylonite.plugins.registry import PluginLoadFailure
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


#: What the host knows about the attack modules Mylonite ships, keyed by
#: entry-point name: the attack id and the weakness classes each covers.
#:
#: A module that fails to IMPORT can't be asked: there is no class to read. One
#: that fails to CONSTRUCT can't either, because ``attack_metadata()`` is an
#: instance method. So for a failed module this table is the only source of its
#: classes; a test pins it against the shipped modules and ``pyproject.toml``.
#: A third-party module that fails to load has unknown classes and is reported
#: with one scan-level NOT TESTED line instead (#222).
SHIPPED_ATTACK_MODULES: Final[dict[str, tuple[str, tuple[str, ...]]]] = {
    "prompt_injection": ("prompt-injection-family", ("W1", "W2")),
    "excessive_agency": ("excessive-agency-family", ("W3", "W4")),
    "markdown_egress": ("w3-markdown-image-link-egress", ("W3",)),
    "reference_example": ("reference-indirect-injection", ()),
}


def relevant_load_failures(
    failures: Sequence[PluginLoadFailure],
    loaded: Sequence[Any],
    *,
    extra_ids: frozenset[str] | None = None,
) -> list[PluginLoadFailure]:
    """The attack-module load failures that cost this scan coverage.

    Each is returned with its attack id and weakness classes filled in from
    :data:`SHIPPED_ATTACK_MODULES` when known. A failure counts when the
    module would have run had it loaded: a known id that
    :func:`select_attack_modules` would keep, or, for an unknown module, an
    entry-point name the operator opted into, or any opted-in id that no loaded
    module answers to (the failed module may be the one that would have). A
    module nobody enabled costs nothing, so its failure stays a log warning.
    """
    extra = extra_attack_module_ids() if extra_ids is None else extra_ids
    allowed = ATTACK_FAMILIES | extra
    loaded_ids = {m.attack_metadata().id for m in loaded}
    unmatched_opt_in = bool(extra - loaded_ids)
    out: list[PluginLoadFailure] = []
    for failure in failures:
        known = SHIPPED_ATTACK_MODULES.get(failure.entry_point)
        if known is not None:
            attack_id, classes = known
            if attack_id in allowed and attack_id not in loaded_ids:
                out.append(
                    dataclasses.replace(failure, attack_id=attack_id, weakness_classes=classes)
                )
        elif failure.entry_point in extra or unmatched_opt_in:
            out.append(failure)
    return out


def describe_load_failure(failure: PluginLoadFailure) -> str:
    """``prompt_injection (import failed: ImportError; covers W1, W2)``."""
    covers = (
        f"covers {', '.join(failure.weakness_classes)}"
        if failure.weakness_classes
        else "its weakness classes are unknown"
    )
    return f"{failure.entry_point} ({failure.stage} failed: {failure.error_type}; {covers})"


def no_usable_modules_message(failures: Sequence[PluginLoadFailure] = ()) -> str:
    """Operator-facing text when selection came back empty.

    Names the opt-in path, because "no usable attack modules" is exactly the
    message a plugin author sees when their module IS installed but not enabled,
    and a message that does not mention the switch leaves them guessing. Names
    each module that failed to load, because that is the other way to get here.
    """
    message = (
        f"no usable attack modules discovered (looking for one of {sorted(ATTACK_FAMILIES)}). "
        f"To run a third-party module as well, set {ATTACK_MODULES_ENV} to its "
        "comma-separated attack_metadata().id — `mylonite plugins` lists what is installed."
    )
    if failures:
        from mylonite import reason_codes

        named = "; ".join(describe_load_failure(f) for f in failures)
        message += " " + reason_codes.tag(
            reason_codes.NT_MODULE_LOAD_FAILED, f"Failed to load: {named}."
        )
    return message


def discover_attack_modules_with_failures(
    *, restrict_to_families: bool = True
) -> tuple[list[Any], list[PluginLoadFailure]]:
    """Discover installed attack modules plus the load failures that cost coverage.

    ``restrict_to_families=False`` returns every registered module (the emitted-test
    runtime deliberately does not filter, so a third-party module's pattern still
    finds its own payload producer).
    """
    from mylonite.plugins.registry import discover_with_failures

    modules, failures = discover_with_failures("mylonite.attack_modules")
    relevant = relevant_load_failures(failures, modules)
    if restrict_to_families:
        modules = select_attack_modules(modules)
    return modules, relevant


def load_attack_modules() -> tuple[list[Any], list[PluginLoadFailure]]:
    """Every installed attack module, unfiltered, plus the load failures that cost
    coverage. For a caller that applies :func:`select_attack_modules` itself."""
    return discover_attack_modules_with_failures(restrict_to_families=False)


def discover_attack_modules(*, restrict_to_families: bool = True) -> list[Any]:
    """:func:`discover_attack_modules_with_failures` without the failures."""
    return discover_attack_modules_with_failures(restrict_to_families=restrict_to_families)[0]


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
    module_load_failures: Sequence[PluginLoadFailure] | None = None,
) -> ScanEngine:
    """Assemble a ready-to-run ``ScanEngine`` for ``adapter`` under ``config``.

    Discovers + family-filters the attack modules (unless ``attack_modules`` is
    supplied, e.g. the reference path passing explicitly-instantiated ones), and
    builds the customiser + judge. The customiser/judge model default to the
    config's role model, then to ``config.model``. ``completion_fn=None`` leaves
    the customiser and judge on the live ``litellm`` path.

    ``module_load_failures`` are the attack modules that failed to load (see
    :func:`relevant_load_failures`); the engine reports their weakness classes
    NOT TESTED. Discovered alongside the modules when ``attack_modules`` is
    ``None``; a caller passing its own modules passes these too, or none.
    """
    from mylonite.scan.customiser import PayloadCustomiser
    from mylonite.scan.engine import ScanEngine
    from mylonite.scan.judge import SuccessJudge

    if attack_modules is None:
        attack_modules, discovered_failures = discover_attack_modules_with_failures(
            restrict_to_families=restrict_to_families
        )
        if module_load_failures is None:
            module_load_failures = discovered_failures
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
        module_load_failures=module_load_failures or (),
    )
