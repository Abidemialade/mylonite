"""Prove an effect probe works before its "no change" is trusted.

A custom target's ``effect_probe`` reads target state after the agent runs. A
"no change" from it means something only if the probe can see a change at all,
and does not see one when nothing happened. This module runs those checks
without a model, against the live target:

* **Schema check.** The verify arguments and each control write must satisfy
  the tool's ``inputSchema``. A failure is ``MYL-INC-005`` and stops the
  controls before any call.
* **Negative control.** Two verify reads with nothing written between them must
  not read as a change under the probe's own rule. A failure is ``MYL-INC-004``.
* **Positive control.** A write through a consequential tool, carrying a fresh
  ``myl-cal-<hex>`` token, must read as a change. A failure is ``MYL-INC-003``.
* **W2 seed control.** A token planted through the target's ``seed_arm`` must
  come back from a recall tool. A failure is ``MYL-INC-006``; no recall tool to
  try is ``MYL-INC-007``.

The controls are real writes, so :func:`calibrate` makes no call at all unless
the caller passes ``allow_writes=True``; the result is then ``MYL-INC-002``.
Each control write leaves a record carrying its ``myl-cal-`` token behind.

Only "create" effects are calibrated: destructive tools (delete, overwrite,
transfer and the like) are never written to.

Results live in a process-level registry keyed by :func:`spec_key`, so an
adapter rebuilt for another run of the same target (validate, gate, ablate, the
testkit) finds the same result. ``target_registry.clear_runtime_targets()``
does not clear it; :func:`clear_calibrations` does.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final

from jsonschema.exceptions import SchemaError
from jsonschema.validators import validator_for

from mylonite._redaction import redact
from mylonite.contracts import ToolSpec
from mylonite.plugins._mcp import target_registry
from mylonite.plugins._mcp._session_adapter import (
    _render_seed_args,
    _serialise_tools,
    _truncate_result,
)
from mylonite.plugins._mcp.server_shim import MCPSessionAsServerLike
from mylonite.scan._types import SeedArmUnavailable
from mylonite.scan.class_verdict import CalibrationSummary
from mylonite.scan.control_shim import _DESTRUCTIVE_HINTS, consequential_tool_names
from mylonite.scan.tool_classifier import hint_matches
from mylonite.scan.tool_roles import _classify_tools, _content_slot_template

if TYPE_CHECKING:
    from mcp import ClientSession

    from mylonite.plugins._mcp._session_adapter import MCPSessionAdapterBase

INC_NOT_CALIBRATED: Final = "MYL-INC-002"
INC_POSITIVE_FAILED: Final = "MYL-INC-003"
INC_NEGATIVE_FAILED: Final = "MYL-INC-004"
INC_SCHEMA: Final = "MYL-INC-005"
INC_SEED_FAILED: Final = "MYL-INC-006"
INC_SEED_NOT_RUN: Final = "MYL-INC-007"

#: Every reason code this module can put in a result.
EMITTED_CODES: Final = (
    INC_NOT_CALIBRATED,
    INC_POSITIVE_FAILED,
    INC_NEGATIVE_FAILED,
    INC_SCHEMA,
    INC_SEED_FAILED,
    INC_SEED_NOT_RUN,
)

#: The probe passed both controls through at least one tool.
STATUS_CERTIFIED: Final = "certified"
#: The controls ran and the probe did not pass them.
STATUS_FAILED: Final = "failed"
#: The target declares no effect probe with a verify tool.
STATUS_NO_PROBE: Final = "no_probe"
#: Writes were not allowed, so nothing ran.
STATUS_NOT_AUTHORIZED: Final = "not_authorized"

SEED_PASSED: Final = "passed"
SEED_FAILED: Final = "failed"
SEED_NOT_RUN: Final = "not_run"
SEED_NOT_DECLARED: Final = "not_declared"

TOOL_CERTIFIED: Final = "certified"
TOOL_FAILED: Final = "failed"

#: The most consequential tools one calibration run writes through.
MAX_CANDIDATE_TOOLS: Final = 5

#: The most tools the seed control tries to recall a planted record through.
MAX_RECALL_TOOLS: Final = 3

#: Every control record carries this prefix, so an operator can find and remove them.
TOKEN_PREFIX: Final = "myl-cal-"  # noqa: S105 - a record label, not a secret

#: How much target-controlled text a result detail may quote.
_DETAIL_QUOTE_CHARS: Final = 200


@dataclass(frozen=True)
class ToolControl:
    """The controls run through one consequential tool."""

    tool: str
    status: str
    reason_code: str | None
    detail: str
    #: True when ``detail`` reports that a verify read itself raised or timed
    #: out (as opposed to a control mismatch). An explicit flag, not a string
    #: comparison against ``_read_failed()``'s wording, so a later rewording
    #: of that message cannot silently stop matching and change behaviour.
    is_read_failure: bool = False


@dataclass(frozen=True)
class SeedControl:
    """The W2 plant-and-recall control."""

    status: str
    reason_code: str | None
    detail: str
    recall_tool: str = ""


@dataclass(frozen=True)
class CalibrationResult:
    """What one calibration run proved about a target's effect probe."""

    spec_key: str
    status: str
    reason_code: str | None
    detail: str
    tools: tuple[ToolControl, ...]
    seed_control: SeedControl

    @property
    def calibrated(self) -> bool:
        """True only when the probe passed both controls."""
        return self.status == STATUS_CERTIFIED

    @property
    def certified_tools(self) -> tuple[str, ...]:
        """The tools whose writes the probe was shown to see."""
        return tuple(t.tool for t in self.tools if t.status == TOOL_CERTIFIED)


# --- the registry ---------------------------------------------------------------

_REGISTRY: dict[str, CalibrationResult] = {}


def spec_key(spec: target_registry.TargetSpec, scope: str | None) -> str:
    """A stable digest of everything about a target that calibration depends on.

    Env and header values are left out (they may carry secrets); their names
    are kept. The timeout is left out: it bounds the run but changes nothing
    the run proves.
    """

    def dump(model: Any) -> Any:
        return model.model_dump(mode="json") if model is not None else None

    material = {
        "family": spec.family,
        "scope": scope,
        "transport": spec.transport,
        "command": spec.command,
        "args": list(spec.args_template),
        "url": spec.url,
        "env_keys": sorted(spec.extra_env),
        "header_keys": sorted(spec.headers),
        "weakness_classes": list(spec.weakness_classes),
        "effect_probe": dump(spec.effect_probe),
        "seed_arm": dump(spec.seed_arm),
        "control_config": dump(spec.control_config),
    }
    blob = json.dumps(material, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def record(result: CalibrationResult) -> None:
    """Store ``result`` under its spec key, replacing any earlier one."""
    _REGISTRY[result.spec_key] = result


def lookup(spec: target_registry.TargetSpec, scope: str | None) -> CalibrationResult | None:
    """The recorded result for this target, or ``None`` if it was never calibrated."""
    return _REGISTRY.get(spec_key(spec, scope))


def clear_calibrations() -> None:
    """Drop every recorded result (test isolation)."""
    _REGISTRY.clear()


def summarise(result: CalibrationResult) -> CalibrationSummary:
    """``result`` as the plain summary a scan result and ``verdicts.json`` carry."""
    return CalibrationSummary(
        status=result.status,
        reason_code=result.reason_code,
        seed_status=result.seed_control.status,
        seed_reason_code=result.seed_control.reason_code,
        certified_tools=result.certified_tools,
    )


def summary_for(spec: target_registry.TargetSpec, scope: str | None) -> CalibrationSummary | None:
    """The calibration summary for this target, as a scan reports it.

    The recorded result when calibration ran. When it did not (controls set to
    ``skip``, or never authorized) but the target declares an effect probe or a
    seed arm, that is reported as not calibrated (``MYL-INC-002``), never as
    nothing. ``None`` for a target with nothing to calibrate.
    """
    recorded = lookup(spec, scope)
    if recorded is not None:
        return summarise(recorded)
    if spec.effect_probe is None and spec.seed_arm is None:
        return None
    return CalibrationSummary(
        status=STATUS_NOT_AUTHORIZED,
        reason_code=INC_NOT_CALIBRATED,
        seed_status=SEED_NOT_RUN,
        seed_reason_code=INC_NOT_CALIBRATED if spec.seed_arm is not None else None,
    )


# --- schema check ---------------------------------------------------------------


def validate_args(schema: Any, args: Any) -> list[str]:
    """Each way ``args`` fails ``schema``, as a message; empty when they pass.

    A schema that is itself invalid is the server's problem, not the target
    file's, so it yields no errors rather than blaming the operator's arguments.
    """
    if not isinstance(schema, dict):
        return []
    try:
        cls = validator_for(schema)
        cls.check_schema(schema)
        validator = cls(schema)
        errors = sorted(validator.iter_errors(args), key=lambda e: list(e.absolute_path))
    except SchemaError:
        return []
    return [e.message for e in errors]


# --- calibrate --------------------------------------------------------------------


async def calibrate(adapter: MCPSessionAdapterBase, allow_writes: bool) -> CalibrationResult:
    """Run the calibration controls against ``adapter``'s target and record the result.

    With ``allow_writes`` False nothing is launched or called, and the result
    (not recorded) is ``MYL-INC-002``. Every call is bounded by the adapter's
    timeout, which a target file's ``timeout_s`` sets. A failure to launch the
    target or list its tools propagates to the caller.
    """
    spec = adapter._spec
    scope = adapter._scope
    key = spec_key(spec, scope)
    if not allow_writes:
        return CalibrationResult(
            spec_key=key,
            status=STATUS_NOT_AUTHORIZED,
            reason_code=INC_NOT_CALIBRATED,
            detail="calibration writes were not authorized, so no control ran",
            tools=(),
            seed_control=SeedControl(
                status=SEED_NOT_RUN,
                reason_code=INC_NOT_CALIBRATED,
                detail="calibration writes were not authorized",
            ),
        )

    async with adapter._session(
        extra_env=adapter._effective_env(),
        command=adapter._launch_command,
        args=adapter._launch_args,
    ) as session:
        shim = MCPSessionAsServerLike(session)
        specs = _serialise_tools(await adapter._bounded(shim.list_tools()))
        status, code, detail, tools = await _probe_controls(adapter, session, specs)
        seed = await _seed_control(adapter, session, specs)

    result = CalibrationResult(
        spec_key=key,
        status=status,
        reason_code=code,
        detail=detail,
        tools=tools,
        seed_control=seed,
    )
    record(result)
    return result


async def calibrate_custom_target(
    adapter: MCPSessionAdapterBase, *, authorized: bool
) -> CalibrationResult:
    """Calibrate ``adapter``'s target once, honouring ``calibration.controls``
    and the caller's own ``authorized`` gesture.

    Cached: a second call for the same spec+scope (``spec_key``) returns the
    recorded result without launching the target again — callers (``scan``,
    ``validate``, ``gate``, ``ablate``, the testkit) each call this once on
    their own path, and a long-lived process re-running the same target finds
    the same result.

    Whether the controls are allowed to run real writes is decided from
    ``adapter._spec.calibration_controls`` and ``authorized``, never from
    ``allow_writes`` directly:

    * ``"skip"`` never runs, regardless of ``authorized``.
    * ``"auto"`` (the default) runs only when ``authorized`` is True AND the
      target's transport is ``"stdio"`` — a remote (``sse``/``http``) target
      needs the explicit ``"allow"`` opt-in.
    * ``"allow"`` runs whenever ``authorized`` is True, on any transport.

    ``authorized`` is not re-derived here: every caller reaches this function
    only after its own ``--authorize`` gate (or, for the testkit, the
    ``MYLONITE_LIVE_TARGET=1`` opt-in an emitted test's skip guard already
    checked) has already passed — this parameter exists so that guarantee is
    still enforced defensively, at the one place that can make real writes,
    rather than assumed.

    :func:`calibrate` itself lets a failure to launch the target or list its
    tools propagate; this wrapper catches that instead of crashing the caller,
    and records a not-calibrated result so a broken target isn't relaunched on
    every subsequent call either.
    """
    spec = adapter._spec
    scope = adapter._scope
    cached = lookup(spec, scope)
    if cached is not None:
        return cached

    allow = authorized and _controls_permit_writes(spec)
    try:
        result = await calibrate(adapter, allow_writes=allow)
    except Exception as exc:
        result = CalibrationResult(
            spec_key=spec_key(spec, scope),
            status=STATUS_FAILED,
            reason_code=INC_POSITIVE_FAILED,
            detail=f"could not launch the target to calibrate it: {type(exc).__name__}: {exc}",
            tools=(),
            seed_control=SeedControl(
                SEED_NOT_RUN,
                INC_SEED_NOT_RUN,
                "the target could not be launched to run the seed control",
            ),
        )
        record(result)
    return result


def _controls_permit_writes(spec: target_registry.TargetSpec) -> bool:
    """Whether ``spec.calibration_controls`` allows real writes, independent
    of ``authorized`` (the caller ANDs the two together)."""
    controls = spec.calibration_controls
    if controls == "skip":
        return False
    if controls == "allow":
        return True
    # "auto": authorized stdio targets only.
    return spec.transport == "stdio"


def _new_token() -> str:
    return f"{TOKEN_PREFIX}{secrets.token_hex(6)}"


def _quote(content: Any) -> str:
    return redact(_truncate_result(content, _DETAIL_QUOTE_CHARS))


def _changed(before: str, after: str, marker: str) -> bool:
    """The effect probe's "new" rule: the marker count grew, or with no marker, any change."""
    if marker:
        return after.count(marker) > before.count(marker)
    return after != before


def _fill_required_strings(tool: ToolSpec, args: dict[str, Any], value: str) -> dict[str, Any]:
    """``args`` with each missing required top-level string param set to ``value``."""
    schema: dict[str, Any] = tool.json_schema if isinstance(tool.json_schema, dict) else {}
    raw_props = schema.get("properties")
    props: dict[str, Any] = raw_props if isinstance(raw_props, dict) else {}
    raw_required = schema.get("required")
    required: list[Any] = raw_required if isinstance(raw_required, list) else []
    out = dict(args)
    for name in required:
        prop = props.get(name)
        if name not in out and isinstance(prop, dict) and prop.get("type") == "string":
            out[name] = value
    return out


def _is_destructive(tool: ToolSpec, spec: target_registry.TargetSpec) -> bool:
    declared = spec.control_config.destructive_tools if spec.control_config else ()
    annotations = tool.annotations or {}
    return (
        tool.name in declared
        or annotations.get("destructiveHint") is True
        or hint_matches(tool.name, _DESTRUCTIVE_HINTS)
    )


def _candidate_tools(
    specs: list[ToolSpec], spec: target_registry.TargetSpec, verify_tool: str
) -> list[tuple[ToolSpec, dict[str, Any]]]:
    """Consequential, non-destructive tools with a content slot, at most five.

    Each comes with its ``args_template``, ``{payload}`` at the content slot.
    """
    by_name = {t.name: t for t in specs}
    declared = (
        frozenset(spec.control_config.consequential_tools)
        if spec.control_config is not None and spec.control_config.consequential_tools
        else None
    )
    out: list[tuple[ToolSpec, dict[str, Any]]] = []
    for name, _reason in consequential_tool_names(specs, declared=declared):
        tool = by_name[name]
        if name == verify_tool or _is_destructive(tool, spec):
            continue
        slot = _content_slot_template(tool)
        if slot is None:
            continue
        out.append((tool, slot[1]))
        if len(out) == MAX_CANDIDATE_TOOLS:
            break
    return out


async def _probe_controls(
    adapter: MCPSessionAdapterBase, session: ClientSession, specs: list[ToolSpec]
) -> tuple[str, str | None, str, tuple[ToolControl, ...]]:
    """The schema check and the negative and positive controls for the effect probe."""
    spec = adapter._spec
    scope = adapter._scope
    probe = spec.effect_probe
    if probe is None or not probe.verify_tool:
        return STATUS_NO_PROBE, None, "the target declares no effect_probe verify_tool", ()
    by_name = {t.name: t for t in specs}
    verify = by_name.get(probe.verify_tool)
    if verify is None:
        return (
            STATUS_FAILED,
            INC_POSITIVE_FAILED,
            f"verify_tool {probe.verify_tool!r} is not among the server's tools",
            (),
        )

    token = _new_token()
    verify_args = _render_seed_args(probe.verify_args_template, token, scope)
    errors = validate_args(verify.json_schema, verify_args)
    if errors:
        return (
            STATUS_FAILED,
            INC_SCHEMA,
            f"verify_args_template fails {probe.verify_tool!r}'s inputSchema: {errors[0]}",
            (),
        )

    candidates = _candidate_tools(specs, spec, probe.verify_tool)
    if not candidates:
        return (
            STATUS_FAILED,
            INC_POSITIVE_FAILED,
            "no consequential tool with a content argument to write a control record through",
            (),
        )

    controls: list[ToolControl] = []
    for tool, template in candidates:
        control = await _control_one_tool(adapter, session, probe, tool, template, token)
        controls.append(control)
        token = _new_token()
        # A negative-control failure or a failed read is about the probe, not the
        # tool, so trying further tools would only repeat it.
        if control.reason_code == INC_NEGATIVE_FAILED or control.is_read_failure:
            break

    if any(c.status == TOOL_CERTIFIED for c in controls) and not any(
        c.reason_code == INC_NEGATIVE_FAILED for c in controls
    ):
        certified = ", ".join(c.tool for c in controls if c.status == TOOL_CERTIFIED)
        return STATUS_CERTIFIED, None, f"certified through {certified}", tuple(controls)
    first = next(
        (c for c in controls if c.reason_code == INC_NEGATIVE_FAILED),
        next(c for c in controls if c.status == TOOL_FAILED),
    )
    return STATUS_FAILED, first.reason_code, f"{first.tool}: {first.detail}", tuple(controls)


def _read_failed(probe: target_registry.EffectProbeSpec) -> str:
    return f"the verify read {probe.verify_tool!r} raised or timed out"


async def _control_one_tool(
    adapter: MCPSessionAdapterBase,
    session: ClientSession,
    probe: target_registry.EffectProbeSpec,
    tool: ToolSpec,
    template: dict[str, Any],
    token: str,
) -> ToolControl:
    """Negative then positive control through ``tool``, using ``token``.

    The control record carries the token, plus the probe's rendered marker when
    the marker does not already contain the token, so the probe's own rule can
    see it.
    """
    scope = adapter._scope
    marker = _render_seed_args(probe.expect_marker or "", token, scope)
    value = token if not marker or token in marker else f"{token} {marker}"
    write_args = _fill_required_strings(tool, _render_seed_args(template, value, scope), token)
    errors = validate_args(tool.json_schema, write_args)
    if errors:
        return ToolControl(
            tool.name,
            TOOL_FAILED,
            INC_SCHEMA,
            f"the control write fails {tool.name!r}'s inputSchema: {errors[0]}",
        )

    def failed(code: str, detail: str, *, is_read_failure: bool = False) -> ToolControl:
        return ToolControl(tool.name, TOOL_FAILED, code, detail, is_read_failure=is_read_failure)

    read_failed = _read_failed(probe)

    # Negative control: nothing is written between these two reads.
    before = await adapter._probe_verify_content(session, probe, token)
    after = await adapter._probe_verify_content(session, probe, token)
    if before is None or after is None:
        return failed(INC_POSITIVE_FAILED, read_failed, is_read_failure=True)
    if _changed(before, after, marker):
        return failed(
            INC_NEGATIVE_FAILED,
            "the verify output changed between two reads with nothing written",
        )

    # Positive control: one write carrying the token.
    try:
        result = await adapter._bounded(session.call_tool(tool.name, write_args))
    except Exception as exc:
        return failed(INC_POSITIVE_FAILED, f"the control write raised {type(exc).__name__}")
    if getattr(result, "isError", False):
        return failed(
            INC_POSITIVE_FAILED,
            f"the control write returned an error: {_quote(getattr(result, 'content', ''))}",
        )
    written = await adapter._probe_verify_content(session, probe, token)
    if written is None:
        return failed(INC_POSITIVE_FAILED, read_failed, is_read_failure=True)
    before_write, after_write = after.lower(), written.lower()
    for deferral in probe.deferred_markers:
        needle = deferral.lower()
        if needle and after_write.count(needle) > before_write.count(needle):
            return failed(INC_POSITIVE_FAILED, f"the control write was deferred ({deferral!r})")
    if not (_changed(after, written, marker) and written.count(token) > after.count(token)):
        return failed(
            INC_POSITIVE_FAILED,
            f"{probe.verify_tool!r} did not show the control record written through {tool.name!r}",
        )
    return ToolControl(tool.name, TOOL_CERTIFIED, None, "negative and positive controls passed")


def _recall_candidates(
    specs: list[ToolSpec], spec: target_registry.TargetSpec, arm: target_registry.SeedArmSpec
) -> list[ToolSpec]:
    """Tools that may read planted content back, best first, at most three.

    Declared ``read_tool_names`` come first, then tools inferred by name and
    schema. The effect probe's verify tool comes last, so a store with its own
    recall tool is exercised through that tool.
    """
    seed_tool = arm.tool
    by_name = {t.name: t for t in specs}
    verify = spec.effect_probe.verify_tool if spec.effect_probe else None
    names: list[str] = [
        n
        for n in (spec.control_config.read_tool_names if spec.control_config else ())
        if n in by_name and n != seed_tool
    ]
    remaining = [t for t in specs if t.name not in (seed_tool, verify, *names)]
    while remaining:
        inferred = _classify_tools(remaining).retrieve_tool
        if inferred is None:
            break
        names.append(inferred)
        remaining = [t for t in remaining if t.name != inferred]
    if (
        verify in by_name
        and verify not in names
        and _classify_tools([by_name[verify]]).retrieve_tool is not None
    ):
        names.append(verify)
    return [by_name[n] for n in names[:MAX_RECALL_TOOLS]]


async def _seed_control(
    adapter: MCPSessionAdapterBase, session: ClientSession, specs: list[ToolSpec]
) -> SeedControl:
    """Plant a token through the seed_arm, then recall it."""
    spec = adapter._spec
    arm = spec.seed_arm
    if arm is None:
        return SeedControl(SEED_NOT_DECLARED, None, "the target declares no seed_arm")
    recalls = _recall_candidates(specs, spec, arm)
    if not recalls:
        return SeedControl(
            SEED_NOT_RUN, INC_SEED_NOT_RUN, "no tool could be inferred to recall planted content"
        )
    try:
        return await _plant_and_recall(adapter, session, arm, specs, recalls)
    except SeedArmUnavailable as exc:
        return SeedControl(SEED_FAILED, INC_SEED_FAILED, exc.reason)


async def _plant_and_recall(
    adapter: MCPSessionAdapterBase,
    session: ClientSession,
    arm: target_registry.SeedArmSpec,
    specs: list[ToolSpec],
    recalls: list[ToolSpec],
) -> SeedControl:
    """Raises ``SeedArmUnavailable`` when the plant fails or no recall returns it."""
    scope = adapter._scope
    by_name = {t.name: t for t in specs}
    plant_tool = by_name.get(arm.tool)
    if plant_tool is None:
        raise SeedArmUnavailable(f"seed_arm tool {arm.tool!r} is not among the server's tools")

    token = _new_token()
    body = f"Mylonite calibration record {token}."
    errors = validate_args(
        plant_tool.json_schema, _render_seed_args(arm.args_template, body, scope)
    )
    if errors:
        return SeedControl(
            SEED_FAILED,
            INC_SCHEMA,
            f"seed_arm args_template fails {arm.tool!r}'s inputSchema: {errors[0]}",
        )
    calls: list[tuple[ToolSpec, dict[str, Any]]] = []
    schema_errors: list[str] = []
    for recall in recalls:
        args = _fill_required_strings(recall, {}, token)
        errors = validate_args(recall.json_schema, args)
        if errors:
            schema_errors.append(
                f"the recall call fails {recall.name!r}'s inputSchema: {errors[0]}"
            )
        else:
            calls.append((recall, args))
    if not calls:
        return SeedControl(SEED_FAILED, INC_SCHEMA, schema_errors[0])

    try:
        await adapter._run_seed_arm(session, arm, body, [])
    except SeedArmUnavailable:
        raise
    except Exception as exc:
        raise SeedArmUnavailable(f"seed_arm plant call raised {type(exc).__name__}") from exc

    problems: list[str] = []
    for recall, args in calls:
        try:
            result = await adapter._bounded(session.call_tool(recall.name, args))
        except Exception as exc:
            problems.append(f"{recall.name!r} raised {type(exc).__name__}")
            continue
        content = str(getattr(result, "content", "") or "")
        if getattr(result, "isError", False):
            problems.append(f"{recall.name!r} returned an error: {_quote(content)}")
        elif token in content:
            return SeedControl(SEED_PASSED, None, "planted and recalled", recall.name)
        else:
            problems.append(f"{recall.name!r} did not return it")
    raise SeedArmUnavailable(
        f"the record planted through {arm.tool!r} was not recalled: " + "; ".join(problems)
    )
