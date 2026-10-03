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
* **Readback control (#324).** On a memory-style store the verify read selects
  the record the ``seed_arm`` writes (a knowledge-graph entity, a fixed key),
  so no consequential tool's write can show up in it. When no consequential
  tool passed, and the probe neither changed on its own nor failed to read,
  the probe is checked on that record instead, in this order: two baseline
  reads (no change between them), the plant (the seed control's own plant
  when it ran, so one record serves both), a positive read that must show
  the planted token, a second read that must not grow and must still show
  it, then a read that sends a never-planted token in the verify template's
  argument slot and must answer with a non-empty, non-error result that
  lacks it (an error, an empty result or a raised call fails). When the
  seed control has no recall tool and so never plants, this control plants
  the record itself through ``seed_arm``. Passing it gives ``confirm_only``, never
  ``certified``: the probe can confirm a planted record appears, but it
  cannot clear a call that changed nothing, because the plant only proves it
  sees writes to the one record it reads. The result is not calibrated, and
  the consequential tools' failure code stays on it.

The controls are real writes, so :func:`calibrate` makes no call at all unless
the caller passes ``allow_writes=True``; the result is then ``MYL-INC-002``.
Each control write leaves a record carrying its ``myl-cal-`` token behind.

Only "create" effects are calibrated: destructive tools (delete, overwrite,
transfer and the like) are never written to.

Results live in a process-level registry keyed by :func:`spec_key`, so an
adapter rebuilt for another run of the same target and launch (validate, gate,
ablate, the testkit) finds the same result. The launch is part of the key: a
probe proven against the default launch says nothing about a vulnerable twin
started with a different command or environment.
``target_registry.clear_runtime_targets()`` does not clear the registry;
:func:`clear_calibrations` does.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final

from jsonschema.exceptions import SchemaError
from jsonschema.validators import validator_for

from mylonite._redaction import redact
from mylonite.contracts import ToolSpec
from mylonite.plugins._mcp import target_registry
from mylonite.plugins._mcp._session_adapter import (
    _render_seed_args,
    _result_readback_text,
    _serialise_tools,
    _truncate_result,
)
from mylonite.plugins._mcp.never_call import never_call_names
from mylonite.plugins._mcp.server_shim import MCPSessionAsServerLike
from mylonite.scan._types import SeedArmUnavailable
from mylonite.scan.class_verdict import CalibrationSummary
from mylonite.scan.control_shim import _DESTRUCTIVE_HINTS, consequential_tool_names
from mylonite.scan.predicate_primitives import count_deferral_word
from mylonite.scan.tool_classifier import hint_matches
from mylonite.scan.tool_roles import (
    _ID_PARAM_HINTS,
    _classify_tools,
    _concrete_spec,
    _content_slot_template,
    _schema_type_kinds,
)

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
#: No consequential tool passed, but the readback control did: the probe can
#: confirm a planted record appears; it cannot clear a call that changed
#: nothing. Not calibrated: every consumer reads it like ``failed``.
STATUS_CONFIRM_ONLY: Final = "confirm_only"

SEED_PASSED: Final = "passed"
SEED_FAILED: Final = "failed"
SEED_NOT_RUN: Final = "not_run"
SEED_NOT_DECLARED: Final = "not_declared"

TOOL_CERTIFIED: Final = "certified"
TOOL_FAILED: Final = "failed"
#: The readback control passed through the ``seed_arm`` tool. Never counted in
#: ``certified_tools``: the plant wrote to the record the verify read selects,
#: so it shows nothing about where another write through that tool lands.
TOOL_READBACK: Final = "readback"

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
        """True only when the probe passed both controls through at least one
        consequential tool. ``confirm_only`` is not calibrated."""
        return self.status == STATUS_CERTIFIED

    @property
    def certified_tools(self) -> tuple[str, ...]:
        """The tools whose writes the probe was shown to see (readback excluded)."""
        return tuple(t.tool for t in self.tools if t.status == TOOL_CERTIFIED)


# --- the registry ---------------------------------------------------------------

_REGISTRY: dict[str, CalibrationResult] = {}


def launch_of(adapter: Any) -> dict[str, Any]:
    """The launch an adapter starts its target with, for :func:`spec_key`.

    Read defensively: ``None`` for a launch knob the adapter does not set,
    which :func:`spec_key` reads as the target's default launch.
    """
    return {
        "command": getattr(adapter, "_launch_command", None),
        "args": getattr(adapter, "_launch_args", None),
        "env": getattr(adapter, "_launch_env", None),
    }


def _launch_material(
    spec: target_registry.TargetSpec, scope: str | None, launch: Mapping[str, Any] | None
) -> dict[str, Any]:
    """The launch, normalised so the default launch always reads the same way."""
    launch = launch or {}
    args = launch.get("args")
    env = launch.get("env") or {}
    return {
        "command": launch.get("command") or spec.command,
        "args": list(args) if args is not None else spec.render_args(scope),
        # Only what differs from the target's own env: a vulnerable_launch or
        # control_env toggle. Folded into the digest, never stored or printed.
        "env_overrides": sorted(
            (key, str(value)) for key, value in env.items() if spec.extra_env.get(key) != value
        ),
    }


def spec_key(
    spec: target_registry.TargetSpec,
    scope: str | None,
    launch: Mapping[str, Any] | None = None,
) -> str:
    """A stable digest of everything about a target that calibration depends on.

    ``launch`` is :func:`launch_of` an adapter; ``None`` is the default launch.
    The target's own env and header values are left out (they may carry
    secrets); their names are kept. The timeout is left out: it bounds the run
    but changes nothing the run proves.
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
        "launch": _launch_material(spec, scope, launch),
    }
    blob = json.dumps(material, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def record(result: CalibrationResult) -> None:
    """Store ``result`` under its spec key, replacing any earlier one."""
    _REGISTRY[result.spec_key] = result


def lookup(
    spec: target_registry.TargetSpec,
    scope: str | None,
    launch: Mapping[str, Any] | None = None,
) -> CalibrationResult | None:
    """The recorded result for this target and launch, or ``None`` if it was never calibrated."""
    return _REGISTRY.get(spec_key(spec, scope, launch))


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


def summary_for(
    spec: target_registry.TargetSpec,
    scope: str | None,
    launch: Mapping[str, Any] | None = None,
) -> CalibrationSummary | None:
    """The calibration summary for this target, as a scan reports it.

    The recorded result when calibration ran. When it did not (controls set to
    ``skip``, or never authorized) but the target declares an effect probe or a
    seed arm, that is reported as not calibrated (``MYL-INC-002``), never as
    nothing. ``None`` for a target with nothing to calibrate.
    """
    recorded = lookup(spec, scope, launch)
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
    key = spec_key(spec, scope, launch_of(adapter))
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

    async with adapter._guarded_session(
        extra_env=adapter._effective_env(),
        command=adapter._launch_command,
        args=adapter._launch_args,
    ) as session:
        shim = MCPSessionAsServerLike(
            session, page_timeout_s=adapter._mcp_read_timeout.total_seconds()
        )
        specs = _serialise_tools(await adapter._bounded(shim.list_tools()))
        status, code, detail, tools, eligible = await _probe_controls(adapter, session, specs)
        readback: _Readback | None = None
        if (
            eligible
            and spec.effect_probe is not None
            and spec.seed_arm is not None
            and _readback_usable(specs, spec)
        ):
            readback = await _readback_baseline(adapter, session, spec.effect_probe, spec.seed_arm)
        seed = await _seed_control(adapter, session, specs, readback=readback)
        if readback is not None:
            control = await _readback_finish(adapter, session, readback, specs)
            tools = (*tools, control)
            if control.status == TOOL_READBACK:
                # Not calibrated, and ``code`` is kept: no consequential tool's
                # write was shown, so the probe may never clear a call.
                status = STATUS_CONFIRM_ONLY
                detail = (
                    "the probe can confirm a planted record appears; it cannot clear a call "
                    f"that changed nothing (the record planted through {control.tool!r} "
                    f"showed up, but {detail})"
                )

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
    launch = launch_of(adapter)
    cached = lookup(spec, scope, launch)
    if cached is not None:
        return cached

    allow = authorized and _controls_permit_writes(spec)
    try:
        result = await calibrate(adapter, allow_writes=allow)
    except Exception as exc:
        # The target never started, so no control ran: not calibrated, and
        # nothing about the probe's wiring is to blame.
        seed = (
            SeedControl(
                SEED_NOT_RUN,
                INC_NOT_CALIBRATED,
                "the target could not be launched to run the seed control",
            )
            if spec.seed_arm is not None
            else SeedControl(SEED_NOT_DECLARED, None, "the target declares no seed_arm")
        )
        result = CalibrationResult(
            spec_key=spec_key(spec, scope, launch),
            status=STATUS_FAILED,
            reason_code=INC_NOT_CALIBRATED,
            detail=(
                "could not launch the target to calibrate it: "
                f"{type(exc).__name__}: {redact(str(exc))}"
            ),
            tools=(),
            seed_control=seed,
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


def _fill_required_args(tool: ToolSpec, args: dict[str, Any], value: str) -> dict[str, Any] | None:
    """``args`` with each missing required top-level param filled in, or
    ``None`` when a required param has no schema-valid value to fill.

    A missing required STRING param gets ``value`` (the control's own
    token), so the call still carries what the probe looks for. A missing
    required integer/number param gets ``0``, boolean gets ``False`` —
    ``"type"`` is resolved through a nullable-type list and ``anyOf``/
    ``oneOf`` first (:func:`mylonite.scan.tool_roles._concrete_spec`), so a
    union- or nullable-typed required param (the same Go/Pydantic schema
    idioms the content-slot walker now unwraps, #324) still resolves to a
    fillable primitive when one of its branches is one — this is what makes
    mcp-redis's two-required-argument ``expire(name, expire_seconds)`` a
    usable control candidate instead of a guaranteed schema failure.

    A required param of any other shape (array, object, or one with no
    concrete primitive branch at all) returns ``None`` for the WHOLE call:
    the caller must then skip this tool rather than send a call with that
    param missing or guessed — never an invalid call.

    An id-shaped NON-STRING required param (its name is a whole
    ``_ID_PARAM_HINTS`` token — ``chat_id``, ``parentId``, a bare
    ``key``/``ref``/``handle``) also returns ``None`` for the whole call,
    whatever its type: a string fill uses ``value`` (the control's own
    per-run token), which can never collide with a real record, but a bare
    ``0``/``False`` filled into an integer or boolean id CAN BE a real,
    often root or default, resource (``parent_id: 0``, ``chat_id: 0``) —
    calibration would then call a consequential tool against a resource the
    operator never scoped (#324 review I3).
    """
    schema: dict[str, Any] = tool.json_schema if isinstance(tool.json_schema, dict) else {}
    raw_props = schema.get("properties")
    props: dict[str, Any] = raw_props if isinstance(raw_props, dict) else {}
    raw_required = schema.get("required")
    required: list[Any] = raw_required if isinstance(raw_required, list) else []
    out = dict(args)
    for name in required:
        if name in out:
            continue
        kinds = _schema_type_kinds(_concrete_spec(props.get(name)))
        if "string" in kinds:
            out[name] = value
        elif hint_matches(name, _ID_PARAM_HINTS):
            return None
        elif "integer" in kinds or "number" in kinds:
            out[name] = 0
        elif "boolean" in kinds:
            out[name] = False
        else:
            return None
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
    # A never_call tool is never written through, not even by a calibration
    # control; the guarded session would refuse it anyway.
    never = frozenset(never_call_names(spec.control_config))
    out: list[tuple[ToolSpec, dict[str, Any]]] = []
    for name, _reason in consequential_tool_names(specs, declared=declared):
        tool = by_name[name]
        if name == verify_tool or name in never or _is_destructive(tool, spec):
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
) -> tuple[str, str | None, str, tuple[ToolControl, ...], bool]:
    """The schema check and the negative and positive controls for the effect probe.

    The last item says whether the readback control may still be tried: only
    when the probe's own read is valid and stable, and no consequential tool
    passed (none existed, or each one's write failed or did not show).
    """
    spec = adapter._spec
    scope = adapter._scope
    probe = spec.effect_probe
    if probe is None or not probe.verify_tool:
        return STATUS_NO_PROBE, None, "the target declares no effect_probe verify_tool", (), False
    by_name = {t.name: t for t in specs}
    verify = by_name.get(probe.verify_tool)
    if verify is None:
        return (
            STATUS_FAILED,
            INC_POSITIVE_FAILED,
            f"verify_tool {probe.verify_tool!r} is not among the server's tools",
            (),
            False,
        )

    if _mentions_payload(probe.verify_args_template):
        # An attempt renders {payload} as its whole attack text, calibration as
        # its own short token. A read that finds the token proves nothing about
        # the read an attempt makes, so the probe can never be certified.
        return (
            STATUS_FAILED,
            INC_POSITIVE_FAILED,
            "verify_args_template uses {payload}, which an attempt fills with its whole "
            "attack text, so calibration cannot prove the read an attempt makes; select "
            "the record by a fixed value instead",
            (),
            False,
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
            False,
        )

    candidates = _candidate_tools(specs, spec, probe.verify_tool)
    if not candidates:
        return (
            STATUS_FAILED,
            INC_POSITIVE_FAILED,
            "no consequential tool with a content argument to write a control record through",
            (),
            True,
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
        return STATUS_CERTIFIED, None, f"certified through {certified}", tuple(controls), False
    first = next(
        (c for c in controls if c.reason_code == INC_NEGATIVE_FAILED),
        next(c for c in controls if c.status == TOOL_FAILED),
    )
    eligible = not any(c.reason_code == INC_NEGATIVE_FAILED or c.is_read_failure for c in controls)
    return (
        STATUS_FAILED,
        first.reason_code,
        f"{first.tool}: {first.detail}",
        tuple(controls),
        eligible,
    )


def _mentions_payload(template: Any) -> bool:
    """Whether ``{payload}`` appears in any string leaf of ``template``."""
    if isinstance(template, str):
        return "{payload}" in template
    if isinstance(template, dict):
        return any(_mentions_payload(v) for v in template.values())
    if isinstance(template, (list, tuple)):
        return any(_mentions_payload(v) for v in template)
    return False


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
    write_args = _fill_required_args(tool, _render_seed_args(template, value, scope), token)
    if write_args is None:
        return ToolControl(
            tool.name,
            TOOL_FAILED,
            INC_SCHEMA,
            f"{tool.name!r} has a required argument with no schema-valid value to fill",
        )
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
    for deferral in probe.deferred_markers:
        if count_deferral_word(written, deferral) > count_deferral_word(after, deferral):
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
    never = frozenset(never_call_names(spec.control_config))
    return [by_name[n] for n in names if n not in never][:MAX_RECALL_TOOLS]


async def _seed_control(
    adapter: MCPSessionAdapterBase,
    session: ClientSession,
    specs: list[ToolSpec],
    *,
    readback: _Readback | None = None,
) -> SeedControl:
    """Plant a token through the seed_arm, then recall it.

    With a ``readback`` whose baseline passed, the plant carries the readback
    control's token and body, so the one record serves both controls: a
    store that ignores a second write under the same name (server-memory's
    ``create_entities``) would otherwise make one of them fail.
    """
    spec = adapter._spec
    arm = spec.seed_arm
    if arm is None:
        return SeedControl(SEED_NOT_DECLARED, None, "the target declares no seed_arm")
    recalls = _recall_candidates(specs, spec, arm)
    if not recalls:
        return SeedControl(
            SEED_NOT_RUN, INC_SEED_NOT_RUN, "no tool could be inferred to recall planted content"
        )
    shared = readback if readback is not None and readback.failure is None else None
    try:
        return await _plant_and_recall(adapter, session, arm, specs, recalls, shared=shared)
    except SeedArmUnavailable as exc:
        return SeedControl(SEED_FAILED, INC_SEED_FAILED, exc.reason)


async def _plant_and_recall(
    adapter: MCPSessionAdapterBase,
    session: ClientSession,
    arm: target_registry.SeedArmSpec,
    specs: list[ToolSpec],
    recalls: list[ToolSpec],
    *,
    shared: _Readback | None = None,
) -> SeedControl:
    """Raises ``SeedArmUnavailable`` when the plant fails or no recall returns it.

    ``shared`` (a readback control waiting on this plant) supplies the token
    and body, and is told whether the plant call went through.
    """
    scope = adapter._scope
    by_name = {t.name: t for t in specs}
    plant_tool = by_name.get(arm.tool)
    if plant_tool is None:
        raise SeedArmUnavailable(f"seed_arm tool {arm.tool!r} is not among the server's tools")

    token = shared.token if shared is not None else _new_token()
    body = shared.body if shared is not None else _plant_body(token, "")
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
        args = _fill_required_args(recall, {}, token)
        if args is None:
            schema_errors.append(
                f"{recall.name!r} has a required argument with no schema-valid value to fill"
            )
            continue
        errors = validate_args(recall.json_schema, args)
        if errors:
            schema_errors.append(
                f"the recall call fails {recall.name!r}'s inputSchema: {errors[0]}"
            )
        else:
            calls.append((recall, args))
    if not calls:
        return SeedControl(SEED_FAILED, INC_SCHEMA, schema_errors[0])

    # Baseline: read each recall candidate with the SAME args BEFORE anything
    # is planted. Every required argument was just filled with the token
    # itself, so a recall tool whose reply echoes its own query (a common
    # shape for a typed `structuredContent` result) would otherwise read
    # "recalled" with nothing actually stored (#324 review I2). Requiring the
    # token's count to GROW after the plant -- mirroring the positive
    # control's own before/after/written reads -- catches that: an echo's
    # count is identical before and after; a real recall's is not.
    #
    # A baseline read that raises proves NOTHING about this tool's post-plant
    # count: defaulting it to zero (as an earlier version of this fix did)
    # made the baseline easiest, not hardest, to beat -- a transient baseline
    # failure (timeout, rate limit) next to a post-plant call that merely
    # echoes the token once would then read `1 > 0` as recalled, the exact
    # I2 echo bug re-opened through a different door (#324 re-review). A tool
    # whose baseline failed is excluded from the recall check entirely: it
    # can never yield SEED_PASSED this run, whatever its post-plant reply
    # says.
    baselines: dict[str, str] = {}
    problems: list[str] = []
    for recall, args in calls:
        try:
            baseline_result = await adapter._bounded(session.call_tool(recall.name, args))
        except Exception as exc:
            problems.append(
                f"{recall.name!r}'s baseline read raised {type(exc).__name__}, so it cannot "
                "confirm a recall this run"
            )
            continue
        baselines[recall.name] = _result_readback_text(baseline_result)

    if shared is not None:
        shared.plant_attempted = True
    try:
        await adapter._run_seed_arm(session, arm, body, [])
    except SeedArmUnavailable as exc:
        if shared is not None:
            shared.plant_error = exc.reason
        raise
    except Exception as exc:
        if shared is not None:
            shared.plant_error = f"seed_arm plant call raised {type(exc).__name__}"
        raise SeedArmUnavailable(f"seed_arm plant call raised {type(exc).__name__}") from exc
    if shared is not None:
        shared.planted = True

    for recall, args in calls:
        if recall.name not in baselines:
            # Its baseline read already failed above; the problem is recorded.
            continue
        try:
            result = await adapter._bounded(session.call_tool(recall.name, args))
        except Exception as exc:
            problems.append(f"{recall.name!r} raised {type(exc).__name__}")
            continue
        content = _result_readback_text(result)
        if getattr(result, "isError", False):
            problems.append(f"{recall.name!r} returned an error: {_quote(content)}")
            continue
        before = baselines[recall.name]
        if content.count(token) > before.count(token):
            return SeedControl(SEED_PASSED, None, "planted and recalled", recall.name)
        problems.append(f"{recall.name!r} did not return it")
    raise SeedArmUnavailable(
        f"the record planted through {arm.tool!r} was not recalled: " + "; ".join(problems)
    )


# --- the readback control (#324) ---------------------------------------------------


def _plant_body(token: str, marker: str) -> str:
    """The text a calibration plant writes: the token, plus the probe's marker
    when the marker does not already carry the token."""
    if marker and token not in marker:
        return f"Mylonite calibration record {token} {marker}."
    return f"Mylonite calibration record {token}."


@dataclass
class _Readback:
    """One readback control in progress, shared with the seed control's plant."""

    probe: target_registry.EffectProbeSpec
    arm: target_registry.SeedArmSpec
    token: str
    marker: str
    body: str
    #: The second baseline read, which the positive read is compared against.
    after: str = ""
    #: Set when the baseline itself failed; the control ends with it.
    failure: ToolControl | None = None
    #: The seed control tried the plant (so this control must not plant again).
    plant_attempted: bool = False
    #: The seed control's plant call went through.
    planted: bool = False
    plant_error: str = ""


def _readback_usable(specs: list[ToolSpec], spec: target_registry.TargetSpec) -> bool:
    """Whether the seed_arm can carry a readback control at all."""
    arm = spec.seed_arm
    if arm is None or spec.effect_probe is None:
        return False
    tool = next((t for t in specs if t.name == arm.tool), None)
    if tool is None or tool.name in frozenset(never_call_names(spec.control_config)):
        return False
    return not _is_destructive(tool, spec)


def _readback_failed(
    rb: _Readback, code: str, detail: str, *, is_read_failure: bool = False
) -> ToolControl:
    return ToolControl(rb.arm.tool, TOOL_FAILED, code, detail, is_read_failure=is_read_failure)


async def _readback_baseline(
    adapter: MCPSessionAdapterBase,
    session: ClientSession,
    probe: target_registry.EffectProbeSpec,
    arm: target_registry.SeedArmSpec,
) -> _Readback:
    """Two verify reads with nothing written between them, before the plant."""
    token = _new_token()
    marker = _render_seed_args(probe.expect_marker or "", token, adapter._scope)
    rb = _Readback(probe, arm, token, marker, _plant_body(token, marker))
    before = await adapter._probe_verify_content(session, probe, token)
    after = await adapter._probe_verify_content(session, probe, token)
    if before is None or after is None:
        rb.failure = _readback_failed(
            rb, INC_POSITIVE_FAILED, _read_failed(probe), is_read_failure=True
        )
    elif _changed(before, after, marker):
        rb.failure = _readback_failed(
            rb,
            INC_NEGATIVE_FAILED,
            "the verify output changed between two reads with nothing written",
        )
    else:
        rb.after = after
    return rb


async def _readback_finish(
    adapter: MCPSessionAdapterBase, session: ClientSession, rb: _Readback, specs: list[ToolSpec]
) -> ToolControl:
    """The plant (unless the seed control made it), the positive read, a
    second read that must not grow and must still show the record, then the
    discrimination read (:func:`_discrimination_read`)."""
    if rb.failure is not None:
        return rb.failure
    probe = rb.probe
    read_failed = _read_failed(probe)
    if rb.plant_attempted and not rb.planted:
        return _readback_failed(
            rb, INC_POSITIVE_FAILED, f"the plant did not go through: {rb.plant_error}"
        )
    if not rb.planted:
        # The seed control never reached its plant (no recall tool, or no valid
        # recall call), so this control plants the record itself.
        plant_tool = next((t for t in specs if t.name == rb.arm.tool), None)
        rendered = _render_seed_args(rb.arm.args_template, rb.body, adapter._scope)
        errors = validate_args(plant_tool.json_schema if plant_tool else None, rendered)
        if errors:
            return _readback_failed(
                rb,
                INC_SCHEMA,
                f"seed_arm args_template fails {rb.arm.tool!r}'s inputSchema: {errors[0]}",
            )
        try:
            await adapter._run_seed_arm(session, rb.arm, rb.body, [])
        except SeedArmUnavailable as exc:
            return _readback_failed(
                rb, INC_POSITIVE_FAILED, f"the plant did not go through: {exc.reason}"
            )
        except Exception as exc:
            return _readback_failed(
                rb, INC_POSITIVE_FAILED, f"the plant call raised {type(exc).__name__}"
            )

    written = await adapter._probe_verify_content(session, probe, rb.token)
    if written is None:
        return _readback_failed(rb, INC_POSITIVE_FAILED, read_failed, is_read_failure=True)
    for deferral in probe.deferred_markers:
        if count_deferral_word(written, deferral) > count_deferral_word(rb.after, deferral):
            return _readback_failed(
                rb, INC_POSITIVE_FAILED, f"the plant was deferred ({deferral!r})"
            )
    if not (
        _changed(rb.after, written, rb.marker)
        and written.count(rb.token) > rb.after.count(rb.token)
    ):
        return _readback_failed(
            rb,
            INC_POSITIVE_FAILED,
            f"{probe.verify_tool!r} did not show the record planted through {rb.arm.tool!r}",
        )

    # Stability after the plant: nothing is written, the output does not grow,
    # and the planted record is still there. An error or empty read
    # (``_probe_verify_content`` maps ``isError`` to "") loses the token, so it
    # fails here rather than reading as "no change".
    still = await adapter._probe_verify_content(session, probe, rb.token)
    if still is None:
        return _readback_failed(rb, INC_POSITIVE_FAILED, read_failed, is_read_failure=True)
    if _changed(written, still, rb.marker):
        return _readback_failed(
            rb,
            INC_NEGATIVE_FAILED,
            "the verify output changed after the plant with nothing written",
        )
    if still.count(rb.token) < written.count(rb.token):
        return _readback_failed(
            rb,
            INC_POSITIVE_FAILED,
            f"{probe.verify_tool!r} no longer showed the planted record on a second read",
        )
    return await _discrimination_read(adapter, session, rb)


def _with_string_leaves(value: Any, replacement: str) -> tuple[Any, int]:
    """``value`` with every string leaf replaced, and how many were replaced."""
    if isinstance(value, str):
        return replacement, 1
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        count = 0
        for key, item in value.items():
            out[key], n = _with_string_leaves(item, replacement)
            count += n
        return out, count
    if isinstance(value, (list, tuple)):
        items = [_with_string_leaves(item, replacement) for item in value]
        return [i for i, _ in items], sum(n for _, n in items)
    return value, 0


async def _discrimination_read(
    adapter: MCPSessionAdapterBase, session: ClientSession, rb: _Readback
) -> ToolControl:
    """Send a never-planted token to the server through the verify read.

    The token goes in the same argument slot the positive read selects its
    record by (every string leaf of the rendered ``verify_args_template``).
    The read discriminates only when the call succeeds and returns a
    non-empty, non-error result that lacks the token. An error, an empty
    result or a raised call proves nothing, so it is never read as "absent";
    an echo of the token means the read cannot tell a planted record from
    its own query.
    """
    probe = rb.probe
    unplanted = _new_token()
    rendered = _render_seed_args(probe.verify_args_template, unplanted, adapter._scope)
    args, slots = _with_string_leaves(rendered, unplanted)
    if not slots:
        return _readback_failed(
            rb,
            INC_POSITIVE_FAILED,
            f"{probe.verify_tool!r}'s verify_args_template has no argument to send a "
            "never-planted token through, so the read was not shown to discriminate",
        )
    verify = probe.verify_tool or ""
    not_shown = "so the read was not shown to discriminate"
    try:
        result = await adapter._bounded(session.call_tool(verify, args))
    except Exception as exc:
        return _readback_failed(
            rb,
            INC_POSITIVE_FAILED,
            f"the read with a never-planted token raised {type(exc).__name__}, {not_shown}",
            is_read_failure=True,
        )
    text = _result_readback_text(result)
    if getattr(result, "isError", False):
        return _readback_failed(
            rb,
            INC_POSITIVE_FAILED,
            f"the read with a never-planted token returned an error, {not_shown}",
        )
    if not text.strip():
        return _readback_failed(
            rb,
            INC_POSITIVE_FAILED,
            f"the read with a never-planted token returned nothing, {not_shown}",
        )
    if unplanted in text:
        return _readback_failed(
            rb,
            INC_NEGATIVE_FAILED,
            "the read with a never-planted token echoed that token back, so it cannot "
            "tell a planted record from its own query",
        )
    return ToolControl(
        rb.arm.tool,
        TOOL_READBACK,
        None,
        "the planted record appeared, stayed, and a read for a never-planted token "
        "answered without it",
    )
