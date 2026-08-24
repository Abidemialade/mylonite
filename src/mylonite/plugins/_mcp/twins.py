"""Twin construction as a pure, testable plan.

Root cause (E, remediation plan §1): ``gate`` and ``validate`` each used to
independently decide "what counts as the raw launch vs the guarded launch" for
a custom target, and the two decisions drifted. ``validate`` (via
``_validate_custom``) honoured a target's ``control_env`` / ``vulnerable_launch``
server-layer toggles; ``gate`` held a parallel copy that built the raw side with
a plain, unmodified adapter — so for a target whose control lives INSIDE the
server (toggled by ``control_env``, not by Mylonite's own boundary shim),
``gate``'s "raw" side WAS the guarded server. Both legs ran identically, the
differential could never fire, and a real finding was silently rejected.

:func:`plan_twins` is the fix: the ONE place that decides raw-vs-guarded for a
single weakness. It is PURE — no adapter construction, no LLM call, no
``typer``/console output — so every combination of (``control_env`` x
``vulnerable_launch`` x transport x weakness) is table-testable with no live
target and no LLM. ``gate``, ``validate``, and ``testkit.assert_control_holds``
all call it with the same inputs (the target's :class:`TargetSpec` and the
weakness under test) and get the same :class:`TwinPlan` back — eliminating the
possibility of the twin decision drifting between them.

A caller builds the actual adapters from the returned :class:`LaunchIntent`\\ s
via :func:`~mylonite.plugins._mcp.factory.build_adapter_for_spec`; banner text
is returned as data (``TwinPlan.banner``) for the CLI to print verbatim, not
printed here.

Scope note (ablate): ``mylonite ablate`` scores each declared control's
MARGINAL contribution by toggling controls against each other (raw = every
control off, "only C" = every control off except C, or in ``--redundancy``
mode a three-way raw/full/minus-c comparison) — an inherently N-ary decision
over the FULL requested control set, not a single-weakness binary twin. That is
a different question from "is this ONE control load-bearing on top of the
target's normal, otherwise-default-configured behaviour" (what ``gate``/
``validate``/``assert_control_holds`` ask), so ``ablate`` does not route its
raw/guarded SET through ``plan_twins`` — forcing its combinatorial toggles
through a single-weakness function would either be wrong or require smuggling
the whole control set through ``weakness``. It does, however, share
:func:`boundary_control_for` (the same target-``ControlConfig``-aware control
factory ``plan_twins`` uses) and builds its adapters through the same
:func:`~mylonite.plugins._mcp.factory.build_adapter_for_spec` chokepoint, so the
only thing that varies between ``ablate`` and the rest is the (deliberately
different) policy over WHICH controls to disable — not how a control is built
or how an adapter is constructed from a decision.
"""

from __future__ import annotations

from dataclasses import dataclass

from mylonite.gate.mitigation import _snippet
from mylonite.plugins._mcp.factory import LaunchIntent
from mylonite.plugins._mcp.target_registry import TargetSpec
from mylonite.scan.control_shim import BoundaryControl, make_control

#: The sentinel ``weakness``/``control`` value meaning "test the rest
#: (HTTP-agent) input data-framing guard", not a W1-W4 boundary control. Also
#: the literal tagged into an exploit's ``synthetic_control`` metadata by
#: ``gate``/``generate --prove-control`` for a rest target validated with
#: ``--prove-input-control`` — an emitted test's ``assert_control_holds(...,
#: control="input-frame")`` round-trips back through this same sentinel.
INPUT_FRAME_CONTROL = "input-frame"


def boundary_control_for(spec: TargetSpec, weakness: str) -> BoundaryControl:
    """Build the boundary control for ``weakness``, applying ``spec``'s ``ControlConfig``.

    Applies the target's declared hints (egress / consequential / read tools,
    URL param, allowlist) when present; falls back to the control's own name
    heuristics, then a fail-closed default, otherwise. Raises ``ValueError`` for
    a weakness class with no implemented boundary control (``make_control``'s
    contract) — never returns a no-op control.

    Shared by :func:`plan_twins` (the single-weakness differential) and
    ``mylonite ablate`` (which builds one of these per control in its requested
    set) — the only piece of "how do I build a control for a spec" both need.
    """
    cfg = spec.control_config
    if cfg is None:
        return make_control(weakness)
    return make_control(
        weakness,
        read_tool_names=frozenset(cfg.read_tool_names) or None,
        egress_tools=frozenset(cfg.egress_tools) or None,
        url_param=cfg.egress_url_param,
        fetch_allowlist=tuple(cfg.fetch_allowlist) or None,
        consequential_tools=frozenset(cfg.consequential_tools) or None,
        accepts_untrusted=frozenset(cfg.accepts_untrusted_tools) or None,
        description_pins=dict(cfg.description_pins) or None,
    )


@dataclass(frozen=True)
class TwinPlan:
    """The raw-vs-guarded decision for one weakness on one target — pure data.

    ``raw``/``guarded``:
        The :class:`~mylonite.plugins._mcp.factory.LaunchIntent`\\ s a caller
        feeds straight into ``build_adapter_for_spec`` to build each twin's
        adapter. When ``control_weakness`` is ``None`` (no differential should
        run at all — ``--fast``, an unresolved weakness, or no implemented
        control), ``raw == guarded`` (both the plain default launch): there is
        nothing to differentiate, and a caller checking ``control_weakness is
        not None`` before building/running the guarded leg (mirroring today's
        ``guarded_factory: Any = None`` pattern) never even looks at ``guarded``
        in that case.
    ``control_weakness``:
        The weakness this plan differentiates, or ``None`` when no differential
        should run. May be :data:`INPUT_FRAME_CONTROL` for a rest target's input
        data-framing differential — not a W1-W4 class.
    ``guarded_is_server_layer``:
        True when ``guarded`` is the target's own REAL default launch (the
        target's server-layer guard, toggled via ``control_env``) rather than a
        synthetic adapter-boundary shim. Feeds ``DifferentialValidator``'s
        ``guarded_is_server_layer`` so the verdict is reported honestly (a
        server-layer differential proves the actual implementation; a boundary
        shim proves a canonical control WOULD be load-bearing for this model).
    ``control_context``:
        One-line human-readable description of what's being differentially
        tested (e.g. ``"Control W2: <mitigation snippet>"``), for a report/PR
        body. ``None`` alongside ``control_weakness is None``.
    ``banner``:
        User-facing message explaining the decision (why the differential is
        on/off, and — when the raw side deliberately runs unguarded — a loud
        authorization reminder). The CLI prints this verbatim; it does not
        re-derive it. ``None`` when there is nothing worth telling the operator
        beyond silence (only reachable when ``weakness`` was already ``None``
        going in).
    """

    raw: LaunchIntent
    guarded: LaunchIntent
    control_weakness: str | None
    guarded_is_server_layer: bool
    control_context: str | None
    banner: str | None


def _no_diff_plan(*, banner: str | None) -> TwinPlan:
    """The "nothing to differentiate" plan: raw and guarded are identical."""
    return TwinPlan(
        raw=LaunchIntent(),
        guarded=LaunchIntent(),
        control_weakness=None,
        guarded_is_server_layer=False,
        control_context=None,
        banner=banner,
    )


_FAST_BANNER = (
    "--fast: skipping the differential leg "
    "(weaker guarantee: kept = build ∧ stability ∧ effect ∧ consensus)."
)

_FAST_OVERRIDES_INPUT_CONTROL_BANNER = (
    "--fast overrides --prove-input-control — the differential leg "
    "(including the input data-framing check) stays skipped."
)

_REST_NOT_APPLICABLE_BANNER = (
    "rest (HTTP-agent) target — the boundary-control differential does not "
    "apply to a black box, so `kept` is decided by stability + effect + consensus "
    "(not the control-efficacy differential). Declare control_env / vulnerable_launch "
    "for a server-layer differential, or pass --prove-input-control to test input "
    "data-framing."
)

_INPUT_FRAME_BANNER = (
    "rest input-control differential — raw vs input data-framing "
    "(spotlighting). `kept` means input framing IS load-bearing for this attack."
)


def _no_control_banner(weakness: str) -> str:
    return (
        f"no boundary control implemented for weakness {weakness!r} — running WITHOUT the "
        "differential leg (weaker guarantee: kept = build ∧ stability ∧ effect ∧ "
        "consensus). Add a control for this weakness, or pass --fast to silence."
    )


def _diff_on_banner(weakness: str) -> str:
    return (
        f"differential ON (default): proving control {weakness} is load-bearing — "
        "the differential gates `kept` (the safeguard, not the model, carries the security)."
    )


def _guard_disabled_banner(spec: TargetSpec, weakness: str) -> str:
    return (
        f"the raw side runs {spec.family!r} with the {weakness} guard DISABLED "
        "(deliberately unguarded) — ensure you are authorized to run it. Env values "
        "are never logged."
    )


def _server_layer_plan(spec: TargetSpec, weakness: str) -> TwinPlan:
    """Raw disables ``weakness``'s server-layer guard via ``control_env``; guarded
    is the plain default launch (the real guard, ON) — no boundary shim."""
    return TwinPlan(
        raw=LaunchIntent(disable_controls=(weakness,)),
        guarded=LaunchIntent(),
        control_weakness=weakness,
        guarded_is_server_layer=True,
        control_context=f"Control {weakness}: real server-layer guard (control_env)",
        banner=_guard_disabled_banner(spec, weakness),
    )


def _input_frame_plan() -> TwinPlan:
    """Raw is the plain black-box call; guarded wraps the payload as untrusted
    data (input data-framing / "spotlighting")."""
    return TwinPlan(
        raw=LaunchIntent(),
        guarded=LaunchIntent(input_frame=True),
        control_weakness=INPUT_FRAME_CONTROL,
        guarded_is_server_layer=False,
        control_context="Control: input data-framing (spotlighting)",
        banner=_INPUT_FRAME_BANNER,
    )


def plan_twins(
    spec: TargetSpec,
    *,
    weakness: str | None,
    fast: bool,
    prove_input_control: bool = False,
) -> TwinPlan:
    """Decide the raw-vs-guarded twin for ``weakness`` on ``spec``. PURE.

    ``weakness`` is the ALREADY-RESOLVED candidate weakness class for the
    finding under test (e.g. ``weakness_class_for(exploit)`` for ``gate``/
    ``validate``, or the explicit ``control`` argument for
    ``testkit.assert_control_holds``) — or :data:`INPUT_FRAME_CONTROL` when a
    caller (a re-validated emitted test) already knows it wants the rest
    input-framing differential. ``None`` means "no weakness could be resolved
    for this finding" and short-circuits to no differential.

    Decision order (mirrors the pre-refactor ``_validate_custom``/``gate``
    logic byte-for-byte, MINUS the bug: both callers now derive it from here):

    1. ``fast`` → no differential (the explicit opt-out).
    2. ``weakness is None`` → no differential (nothing to test).
    3. ``weakness in spec.control_env`` (a SERVER-LAYER toggle is declared for
       it) → the server-layer twin: raw disables the REAL guard via
       ``control_env``, guarded is the plain default launch. Takes priority
       over transport/``prove_input_control`` — a declared server-layer control
       is always the highest-fidelity twin available.
    4. ``spec.transport == "rest"`` (a black-box HTTP agent has no
       adapter-boundary tool surface) → the input data-framing differential
       when ``weakness == INPUT_FRAME_CONTROL`` or ``prove_input_control`` is
       set; otherwise no differential (the boundary-control shim does not apply
       to a black box).
    5. Otherwise, the boundary-shim twin: raw honours ``vulnerable_launch`` when
       declared (the target's own deliberately-unguarded variant), guarded
       synthesizes the canonical boundary control for ``weakness``
       (:func:`boundary_control_for`). A weakness with no implemented boundary
       control (``ValueError``) falls back to no differential, loudly.
    """
    if fast:
        banner = _FAST_BANNER
        if prove_input_control and spec.transport == "rest":
            banner = f"{banner}\n{_FAST_OVERRIDES_INPUT_CONTROL_BANNER}"
        return _no_diff_plan(banner=banner)

    if weakness is None:
        return _no_diff_plan(banner=None)

    if weakness in spec.control_env:
        return _server_layer_plan(spec, weakness)

    if spec.transport == "rest":
        if weakness == INPUT_FRAME_CONTROL or prove_input_control:
            return _input_frame_plan()
        return _no_diff_plan(banner=_REST_NOT_APPLICABLE_BANNER)

    try:
        boundary = boundary_control_for(spec, weakness)
    except ValueError:
        return _no_diff_plan(banner=_no_control_banner(weakness))

    raw = LaunchIntent(vulnerable=spec.vulnerable_launch is not None)
    guarded = LaunchIntent(boundary_controls=(boundary,))
    banner = _diff_on_banner(weakness)
    if spec.vulnerable_launch is not None:
        banner = f"{banner}\n{_guard_disabled_banner(spec, weakness)}"
    return TwinPlan(
        raw=raw,
        guarded=guarded,
        control_weakness=weakness,
        guarded_is_server_layer=False,
        control_context=f"Control {weakness}: {_snippet(weakness)}",
        banner=banner,
    )


__all__ = ["INPUT_FRAME_CONTROL", "TwinPlan", "boundary_control_for", "plan_twins"]
