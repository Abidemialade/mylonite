"""Tests for T11: ``plan_twins`` — the ONE place that decides raw-vs-guarded.

Root cause (remediation plan §1, finding E): ``gate`` held a drifted parallel
copy of ``validate``'s raw/guarded decision that ignored a target's
``control_env`` server-layer toggle entirely — so for a server-layer-controlled
target, ``gate``'s "raw" side WAS the guarded server, the differential could
never fire, and a real finding was silently rejected. ``testkit.assert_control_holds``
independently re-derived a THIRD copy of the same decision (T10 added an
ad-hoc stopgap).

``plan_twins`` is PURE — no adapter, no LLM, no console output — so every
combination of (``control_env`` x ``vulnerable_launch`` x transport x weakness)
is table-tested here with no live target and no LLM. ``tests/test_cli.py``
covers the CLI-layer integration (gate/validate calling through it identically);
``tests/testkit/test_assert_control_holds.py`` covers testkit's routing.
"""

from __future__ import annotations

from typing import Any

import pytest

from mylonite.plugins._mcp.factory import LaunchIntent
from mylonite.plugins._mcp.target_file import TargetFile, build_target_spec
from mylonite.plugins._mcp.target_registry import TargetSpec
from mylonite.plugins._mcp.twins import (
    INPUT_FRAME_CONTROL,
    TwinPlan,
    boundary_control_for,
    plan_twins,
)


def _spec(
    *,
    family: str = "myapp",
    weakness_classes: list[str] | None = None,
    control_env: dict[str, dict[str, str]] | None = None,
    vulnerable_launch: dict[str, Any] | None = None,
    transport: str = "stdio",
    url: str | None = None,
    request: dict[str, Any] | None = None,
) -> TargetSpec:
    tf = TargetFile(
        family=family,
        command="python" if transport == "stdio" else "",
        args=["-m", "srv"] if transport == "stdio" else [],
        weakness_classes=weakness_classes or ["W2"],
        control_env=control_env or {},
        vulnerable_launch=vulnerable_launch,
        transport=transport,
        url=url,
        request=request,
    )
    return build_target_spec(tf)


_REST_REQUEST = {"url": "https://agent.example/chat", "body": '{"prompt": "{prompt}"}'}


# ---------------------------------------------------------------------------
# Table-driven: at least 6 distinct TargetSpec shapes x weakness x fast.
# ---------------------------------------------------------------------------


def test_plain_stdio_no_declarations_boundary_shim_differential() -> None:
    """No control_env, no vulnerable_launch, stdio: the classic boundary-shim
    twin — raw is the plain launch, guarded synthesizes the W2 control."""
    spec = _spec()
    plan = plan_twins(spec, weakness="W2", fast=False)
    assert plan.raw == LaunchIntent()
    assert plan.guarded.boundary_controls and len(plan.guarded.boundary_controls) == 1
    assert plan.guarded.boundary_controls[0].weakness == "W2"
    assert plan.guarded.disable_controls == ()
    assert plan.guarded.vulnerable is False
    assert plan.control_weakness == "W2"
    assert plan.guarded_is_server_layer is False
    assert plan.control_context is not None and "W2" in plan.control_context
    assert plan.banner is not None and "differential ON" in plan.banner


def test_server_layer_control_env_declared_for_weakness() -> None:
    """control_env declares W2: raw disables the REAL guard via control_env;
    guarded is the plain default launch (real guard ON, no boundary shim) —
    THE fix for the E finding (gate ignoring control_env)."""
    spec = _spec(control_env={"W2": {"DISABLE_MARKING": "1"}})
    plan = plan_twins(spec, weakness="W2", fast=False)
    assert plan.raw == LaunchIntent(disable_controls=("W2",))
    assert plan.guarded == LaunchIntent()
    assert plan.control_weakness == "W2"
    assert plan.guarded_is_server_layer is True
    assert plan.control_context == "Control W2: real server-layer guard (control_env)"
    assert plan.banner is not None
    assert "DISABLED" in plan.banner and "myapp" in plan.banner


def test_control_env_declared_for_a_different_weakness_is_unaffected() -> None:
    """control_env declares W4, but the weakness under test is W2: the W2
    differential is unaffected (still the boundary shim) — control_env is
    keyed per-weakness, not a blanket 'this target is server-layer' switch."""
    spec = _spec(weakness_classes=["W2", "W4"], control_env={"W4": {"AUTONOMY": "full"}})
    plan = plan_twins(spec, weakness="W2", fast=False)
    assert plan.guarded_is_server_layer is False
    assert plan.raw == LaunchIntent(vulnerable=False)
    assert plan.guarded.boundary_controls[0].weakness == "W2"


def test_vulnerable_launch_declared_boundary_shim_raw_side_uses_it() -> None:
    """vulnerable_launch declared, no control_env for this weakness: raw side
    launches the declared unguarded variant; guarded is still the boundary
    shim (vulnerable_launch and control_env are independent knobs)."""
    spec = _spec(
        vulnerable_launch={
            "command": "python",
            "args": ["-m", "srv", "--raw"],
            "env": {"PROFILE": "vuln"},
        }
    )
    plan = plan_twins(spec, weakness="W2", fast=False)
    assert plan.raw == LaunchIntent(vulnerable=True)
    assert plan.guarded.boundary_controls[0].weakness == "W2"
    assert plan.guarded_is_server_layer is False
    # The raw side deliberately runs unguarded -- the banner must say so.
    assert plan.banner is not None and "DISABLED" in plan.banner


def test_fast_skips_the_differential_regardless_of_spec_shape() -> None:
    """--fast short-circuits before ANY spec inspection: raw == guarded (no
    differential), even for a target that otherwise declares control_env."""
    spec = _spec(control_env={"W2": {"DISABLE_MARKING": "1"}})
    plan = plan_twins(spec, weakness="W2", fast=True)
    assert plan.raw == plan.guarded == LaunchIntent()
    assert plan.control_weakness is None
    assert plan.guarded_is_server_layer is False
    assert plan.control_context is None
    assert plan.banner is not None and "--fast" in plan.banner


def test_unimplemented_weakness_falls_back_to_no_differential_loudly() -> None:
    """A weakness class with no implemented boundary control (e.g. 'generic')
    degrades to no differential -- loudly (a banner explains why), never a
    silent downgrade."""
    spec = _spec()
    plan = plan_twins(spec, weakness="generic", fast=False)
    assert plan.raw == plan.guarded == LaunchIntent()
    assert plan.control_weakness is None
    assert plan.banner is not None
    assert "no boundary control implemented" in plan.banner
    assert "generic" in plan.banner


def test_weakness_none_short_circuits_to_no_differential() -> None:
    """No weakness could be resolved for the finding at all -> no differential,
    silently (nothing to warn about -- the caller never had a candidate)."""
    spec = _spec()
    plan = plan_twins(spec, weakness=None, fast=False)
    assert plan.raw == plan.guarded == LaunchIntent()
    assert plan.control_weakness is None
    assert plan.banner is None


def test_rest_transport_without_prove_input_control_is_not_applicable() -> None:
    """A black-box HTTP agent has no adapter-boundary tool surface: no
    differential unless the operator opts into --prove-input-control (or the
    target ALSO declares a server-layer control_env for this weakness, which
    takes priority -- see the next test)."""
    spec = _spec(transport="rest", url=None, request=_REST_REQUEST)
    plan = plan_twins(spec, weakness="W2", fast=False, prove_input_control=False)
    assert plan.raw == plan.guarded == LaunchIntent()
    assert plan.control_weakness is None
    assert plan.banner is not None and "does not apply to a black box" in plan.banner


def test_rest_transport_with_prove_input_control_builds_input_frame_differential() -> None:
    """--prove-input-control on a rest target: raw is the plain call, guarded
    wraps the payload as untrusted data (input_frame=True) -- NOT a boundary
    control (rest has no tool-call boundary to shim)."""
    spec = _spec(transport="rest", url=None, request=_REST_REQUEST)
    plan = plan_twins(spec, weakness="W2", fast=False, prove_input_control=True)
    assert plan.raw == LaunchIntent()
    assert plan.guarded == LaunchIntent(input_frame=True)
    assert plan.control_weakness == INPUT_FRAME_CONTROL
    assert plan.guarded_is_server_layer is False
    assert plan.control_context == "Control: input data-framing (spotlighting)"


def test_rest_transport_weakness_already_input_frame_sentinel() -> None:
    """A caller that already knows it wants the input-frame differential (e.g.
    testkit re-validating an emitted control='input-frame' test) gets it
    WITHOUT passing prove_input_control -- the sentinel alone is enough. This
    is what lets testkit.assert_control_holds(..., control='input-frame')
    round-trip through the exact tag gate's scan_fn wrote."""
    spec = _spec(transport="rest", url=None, request=_REST_REQUEST)
    plan = plan_twins(spec, weakness=INPUT_FRAME_CONTROL, fast=False)
    assert plan.guarded == LaunchIntent(input_frame=True)
    assert plan.control_weakness == INPUT_FRAME_CONTROL


def test_rest_transport_server_layer_takes_priority_over_input_frame() -> None:
    """A rest target that ALSO declares control_env for this weakness gets the
    (higher-fidelity) server-layer twin, not the input-framing one, even with
    --prove-input-control set."""
    spec = _spec(
        transport="rest",
        url=None,
        request=_REST_REQUEST,
        control_env={"W2": {"W2_GUARD": "off"}},
    )
    plan = plan_twins(spec, weakness="W2", fast=False, prove_input_control=True)
    assert plan.guarded_is_server_layer is True
    assert plan.raw == LaunchIntent(disable_controls=("W2",))
    assert plan.guarded == LaunchIntent()


def test_fast_and_prove_input_control_on_rest_notes_the_override() -> None:
    """--fast still wins over --prove-input-control (DCR-0017): no differential,
    and the banner explicitly says --fast overrode it (not just silently)."""
    spec = _spec(transport="rest", url=None, request=_REST_REQUEST)
    plan = plan_twins(spec, weakness="W2", fast=True, prove_input_control=True)
    assert plan.control_weakness is None
    assert plan.banner is not None
    assert "--fast" in plan.banner and "--prove-input-control" in plan.banner


# ---------------------------------------------------------------------------
# boundary_control_for: applies the target's ControlConfig hints.
# ---------------------------------------------------------------------------


def test_boundary_control_for_uses_control_config_hints() -> None:
    tf = TargetFile(
        family="cfg-app",
        command="python",
        args=["-m", "srv"],
        weakness_classes=["W3"],
        control_config={
            "egress_tools": ["fetch_url"],
            "egress_url_param": "url",
            "fetch_allowlist": ["allowed.example"],
        },
    )
    spec = build_target_spec(tf)
    control = boundary_control_for(spec, "W3")
    assert control.weakness == "W3"


def test_boundary_control_for_no_control_config_falls_back_to_name_heuristics() -> None:
    spec = _spec()
    control = boundary_control_for(spec, "W2")
    assert control.weakness == "W2"


def test_boundary_control_for_unimplemented_weakness_raises() -> None:
    spec = _spec()
    with pytest.raises(ValueError, match="W9"):
        boundary_control_for(spec, "W9")


def test_boundary_control_for_threads_mode_approval_and_private_markers() -> None:
    """The four knobs previously dropped here — enforcement_mode,
    approval_policy, private_markers — now reach the control from a target file,
    so the documented approve-mode and confidentiality canary are reachable from
    the CLI."""
    from mylonite.scan.labels import ApproveWhenTrusted

    tf = TargetFile(
        family="conf-app",
        command="python",
        args=["-m", "srv"],
        weakness_classes=["W4"],
        control_config={
            "consequential_tools": ["send_email"],
            "enforcement_mode": "approve",
            "approval_policy": "approve_when_trusted",
            "private_markers": ["INTERNAL-SECRET-"],
        },
    )
    spec = build_target_spec(tf)
    control = boundary_control_for(spec, "W4")
    assert control.weakness == "W4"
    assert control._mode == "approve"
    assert isinstance(control._approval_policy, ApproveWhenTrusted)

    w2 = boundary_control_for(spec, "W2")
    assert w2._private_markers == ("INTERNAL-SECRET-",)


def test_boundary_control_for_unknown_mode_degrades_to_safe_default() -> None:
    """A typo'd enforcement_mode must degrade to the control's safe default
    (block), never raise mid-run."""
    tf = TargetFile(
        family="typo-app",
        command="python",
        args=["-m", "srv"],
        weakness_classes=["W4"],
        control_config={"consequential_tools": ["send_email"], "enforcement_mode": "bloc"},
    )
    control = boundary_control_for(build_target_spec(tf), "W4")
    assert control._mode == "block"


# ---------------------------------------------------------------------------
# TwinPlan is a plain, comparable, frozen dataclass -- pure data.
# ---------------------------------------------------------------------------


def test_twin_plan_is_frozen_and_comparable() -> None:
    """TwinPlan is a plain frozen dataclass -- equal inputs give equal, hashable-
    shape output, modulo BoundaryControl instances (constructed fresh each call,
    identity-compared -- not plan_twins' concern) so we compare through their
    ``weakness`` rather than object identity."""
    spec = _spec()
    plan_a = plan_twins(spec, weakness="W2", fast=False)
    plan_b = plan_twins(spec, weakness="W2", fast=False)
    assert isinstance(plan_a, TwinPlan)
    assert plan_a.raw == plan_b.raw
    assert plan_a.control_weakness == plan_b.control_weakness == "W2"
    assert plan_a.guarded_is_server_layer == plan_b.guarded_is_server_layer is False
    assert plan_a.control_context == plan_b.control_context
    assert plan_a.banner == plan_b.banner
    assert [c.weakness for c in plan_a.guarded.boundary_controls] == [
        c.weakness for c in plan_b.guarded.boundary_controls
    ]
    with pytest.raises(AttributeError):
        plan_a.control_weakness = "W3"  # type: ignore[misc]
