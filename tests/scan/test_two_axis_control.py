"""Regression tests for GUARD_DENIES_ALL — a benign-retention failure in the
single-axis W2 control.

The single-axis ``InformationFlowControl`` carried
``guard_denies_all: benign retention 0.00`` — it refused EVERY read-then-act
workflow: ``read_note -> send_email`` refused, ``list_files -> write_file``
refused. Declaring ``read_tool_names`` precisely did NOT restore function — only
``accepts_untrusted`` did, which just switches the control off for that sink.

So the guard discriminated workflow SHAPE, not attack from legitimate work, and
"resisted 5/5" was true by construction. These tests pin the property that
makes the differential mean something: benign work survives, exfiltration does
not.
"""

from __future__ import annotations

import asyncio

from mylonite.scan.control_shim import (
    ConfirmGateControl,
    ControlServerShim,
    InformationFlowControl,
)
from mylonite.scan.labels import (
    ApproveWhenTrusted,
    ContentLabel,
    DenyAll,
    SinkPolicy,
    combine_labels,
)
from mylonite.scan.llm_types import ToolDescription, ToolResult

SECRET = "CANARY-SECRET-do-not-disclose"  # pragma: allowlist secret


class _Server:
    """Two readers (one returning a secret) and two sinks."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    async def list_tools(self) -> list[ToolDescription]:
        schema = {"type": "object", "properties": {}}
        return [
            ToolDescription(name=n, description="d", input_schema=schema)
            for n in ("read_note", "read_secret", "send_email", "write_file")
        ]

    async def call_tool(self, name: str, arguments: dict) -> ToolResult:
        self.calls.append(name)
        body = SECRET if name == "read_secret" else "ordinary meeting notes"
        return ToolResult(name=name, content=body, isError=False)


def _run(shim: ControlServerShim, steps: list[str]) -> list[bool]:
    """Returns per-step 'was allowed through'."""

    async def go() -> list[bool]:
        await shim.list_tools()
        out = []
        for step in steps:
            result = await shim.call_tool(step, {})
            out.append(not result.isError)
        return out

    return asyncio.run(go())


def _w2(**kw) -> InformationFlowControl:
    kw.setdefault("private_markers", (SECRET,))
    return InformationFlowControl(**kw)


# --- the label algebra (FIDES combine_labels) --------------------------------


def test_most_restrictive_wins_per_axis_independently() -> None:
    combined = combine_labels(
        ContentLabel(integrity="untrusted", confidentiality="public"),
        ContentLabel(integrity="trusted", confidentiality="private"),
    )
    assert combined == ContentLabel(integrity="untrusted", confidentiality="private")


def test_confidentiality_ordering() -> None:
    worst = combine_labels(
        ContentLabel(confidentiality="public"),
        ContentLabel(confidentiality="user_identity"),
        ContentLabel(confidentiality="private"),
    )
    assert worst.confidentiality == "user_identity"


def test_a_public_sink_refuses_a_private_context() -> None:
    policy = SinkPolicy(accepts_untrusted=True, max_allowed_confidentiality="public")
    assert policy.violated_by(ContentLabel(confidentiality="private")) is not None
    assert policy.violated_by(ContentLabel(confidentiality="public")) is None


# --- THE fix: benign read-then-act survives ----------------------------------


def test_benign_read_then_act_now_succeeds() -> None:
    """Pre-fix this was refused, which is what made benign_retention 0.0."""
    server = _Server()
    shim = ControlServerShim(server, [_w2()])
    assert _run(shim, ["read_note", "send_email"]) == [True, True]
    assert server.calls == ["read_note", "send_email"]


def test_reading_a_secret_then_acting_is_still_refused() -> None:
    """The attack the control exists to stop, caught on the CONFIDENTIALITY
    axis — exactly how FIDES's own canonical example catches exfiltration."""
    server = _Server()
    shim = ControlServerShim(server, [_w2()])
    assert _run(shim, ["read_secret", "send_email"]) == [True, False]
    assert "send_email" not in server.calls


def test_the_control_discriminates_rather_than_denying_everything() -> None:
    """The two runs differ ONLY in which document was read. A control that
    denies all read-then-act cannot produce this asymmetry."""
    benign = _run(ControlServerShim(_Server(), [_w2()]), ["read_note", "send_email"])
    attack = _run(ControlServerShim(_Server(), [_w2()]), ["read_secret", "send_email"])
    assert benign[-1] is True and attack[-1] is False


def test_acting_before_any_read_is_unaffected() -> None:
    assert _run(ControlServerShim(_Server(), [_w2()]), ["send_email"]) == [True]


def test_a_private_tool_can_be_declared_without_a_marker() -> None:
    """Operators who know which tool returns sensitive data say so directly;
    the marker path exists for a scan against an app nobody has annotated."""
    shim = ControlServerShim(
        _Server(),
        [InformationFlowControl(private_tools=frozenset({"read_secret"}))],
    )
    assert _run(shim, ["read_secret", "send_email"]) == [True, False]


def test_accepts_untrusted_does_not_lift_the_confidentiality_cap() -> None:
    """Exempting a sink from taint must not also license it to leak a secret —
    the two axes stay independent."""
    shim = ControlServerShim(_Server(), [_w2(accepts_untrusted=frozenset({"send_email"}))])
    assert _run(shim, ["read_secret", "send_email"]) == [True, False]


# --- enforcement modes -------------------------------------------------------


def test_observe_mode_records_without_blocking() -> None:
    """FIDES's dry-run: the oracle's measurement instrument, and the 'what would
    break if I adopted this' mode."""
    server = _Server()
    shim = ControlServerShim(server, [_w2(mode="observe")])
    assert _run(shim, ["read_secret", "send_email"]) == [True, True]
    assert server.calls == ["read_secret", "send_email"]
    violations = shim.controls[0].observed_violations  # type: ignore[attr-defined]
    assert [v["tool"] for v in violations] == ["send_email"]


def test_block_mode_is_the_default() -> None:
    assert _run(ControlServerShim(_Server(), [_w2()]), ["read_secret", "send_email"])[-1] is False


# --- W4: out-of-band approval ------------------------------------------------


def test_w4_benign_action_completes_through_the_approval_flow() -> None:
    """A confirm gate is SUPPOSED to stop an unconfirmed benign action too, so
    the benign leg must complete THROUGH confirmation, not around it. Pre-fix it
    could not: the model had to echo a token its schema forbade, which no model
    managed in 6/6 trials."""
    server = _Server()
    gate = ConfirmGateControl(
        consequential_tools=frozenset({"send_email"}),
        approval_policy=ApproveWhenTrusted(),
        mode="approve",
    )
    shim = ControlServerShim(server, [gate])
    assert _run(shim, ["send_email"]) == [True]
    assert server.calls == ["send_email"]


def test_w4_injection_driven_action_is_denied() -> None:
    """Same policy, same tool — denied because untrusted content is in scope."""
    server = _Server()
    w2 = _w2(mode="observe")  # label tracker only; W4 makes the decision
    gate = ConfirmGateControl(
        consequential_tools=frozenset({"send_email"}),
        approval_policy=ApproveWhenTrusted(),
        mode="approve",
        context_source=w2,
    )
    shim = ControlServerShim(server, [w2, gate])
    assert _run(shim, ["read_note", "send_email"]) == [True, False]
    assert "send_email" not in server.calls


def test_w4_never_asks_the_model_for_a_token() -> None:
    """The refusal must not put a token in the model's context or instruct a
    retry — that protocol is what failed 0/6."""
    shim = ControlServerShim(_Server(), [ConfirmGateControl(approval_policy=DenyAll())])

    async def go() -> ToolResult:
        return await shim.call_tool("send_email", {"to": "x"})

    refusal = asyncio.run(go())
    assert refusal.isError is True
    assert "confirm_token=" not in refusal.content
    token = shim.controls[0].pending_token("send_email")  # type: ignore[attr-defined]
    assert token and token not in refusal.content


def test_w4_default_policy_denies() -> None:
    """No policy supplied means nobody is available to approve — deny."""
    shim = ControlServerShim(_Server(), [ConfirmGateControl(mode="approve")])
    assert _run(shim, ["send_email"]) == [False]


def test_w4_approval_decisions_are_auditable() -> None:
    shim = ControlServerShim(
        _Server(),
        [ConfirmGateControl(approval_policy=ApproveWhenTrusted(), mode="approve")],
    )
    _run(shim, ["send_email"])
    assert shim.controls[0].approvals == [  # type: ignore[attr-defined]
        {"tool": "send_email", "decision": "approve"}
    ]


# --- the config advice must match the role of the tool it names --------------


def test_w2_snippet_for_a_refused_sink_offers_the_exemption() -> None:
    """The fail-closed warning fires from `intercept_call`, so it names the SINK.
    Telling the operator to add a sink to `read_tool_names` was wrong advice —
    that labels the sink's own OUTPUT untrusted rather than exempting it."""
    from mylonite.scan.control_shim import config_snippet_for

    snippet = config_snippet_for("W2", "send_email", role="sink")
    assert "accepts_untrusted_tools: [send_email]" in snippet
    assert "read_tool_names" not in snippet


def test_w2_snippet_for_a_read_tool_actually_blocks_the_exfil() -> None:
    """A recommendation generated FROM a confirmed exfiltration has to block
    that exfiltration when applied. `read_tool_names` alone marks content
    untrusted, which gates only destructive sinks — so the snippet must also
    name the confidentiality axis."""
    from mylonite.scan.control_shim import config_snippet_for

    snippet = config_snippet_for("W2", "read_secret")
    assert "read_tool_names: [read_secret]" in snippet
    assert "private_tools: [read_secret]" in snippet

    shim = ControlServerShim(
        _Server(),
        [InformationFlowControl(private_tools=frozenset({"read_secret"}))],
    )
    assert _run(shim, ["read_secret", "send_email"]) == [True, False]
