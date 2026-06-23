"""Declarative custom-MCP-target spec (``--target-file target.yaml``).

The headline value proposition — "test *your* AI app" — needs an on-ramp for an
MCP server that isn't one of the three bundled families. A ``TargetFile`` is the
declarative form: one YAML (or a set of ``mcp:custom`` CLI flags) declares how to
launch the server, which weakness classes it exposes, and how to plant poisoned
content for indirect-injection seeds. ``build_target_spec`` turns it into a
``target_registry.TargetSpec`` that ``register_target`` makes resolvable, so the
generic ``MCPStdioAdapter`` can drive it exactly like a bundled target.

See ``docs`` and ``SECURITY.md`` for the ``--authorize`` rules and the
bring-your-own-stdio-target footguns.

Windows SQLite footgun (#18): if your target's ``env`` points at a SQLite DB by
URL, note that ``sqlite:////c/Users/...`` (4 slashes) and
``sqlite:///C:/Users/...`` (3 slashes) open *different* databases on Windows —
a silent way to scan an empty DB and conclude (wrongly) that the agent is clean.
Prefer an absolute path and verify the target actually opened it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, model_validator

from mylonite.plugins._mcp.target_registry import (
    ControlConfig,
    EffectProbeSpec,
    InvalidTargetScope,
    LaunchOverride,
    SeedArmSpec,
    TargetSpec,
)

_WEAKNESS_CLASSES = frozenset({"W1", "W2", "W3", "W4"})

_DEFAULT_CUSTOM_PROMPT = (
    "You are a helpful assistant with access to the connected tools. Use them "
    "whenever the user's request requires them. Be concise."
)


class TargetFile(BaseModel):
    """Declarative description of a custom MCP stdio target."""

    model_config = ConfigDict(extra="forbid")

    family: str
    # Transport. Default "stdio" launches ``command``/``args`` as a subprocess.
    # "sse"/"http" connect to a remote MCP server at ``url`` (``command`` is then
    # optional/ignored; ``headers`` may carry auth and are never logged).
    transport: Literal["stdio", "sse", "http"] = "stdio"
    command: str = ""
    args: list[str] = []
    env: dict[str, str] = {}
    url: str | None = None
    headers: dict[str, str] = {}
    scope: str | None = None
    requires_scope: bool = False
    system_prompt: str | None = None
    system_prompt_file: Path | None = None
    primary_tools: list[str] = []
    weakness_classes: list[str] = []
    seed_arm: SeedArmSpec | None = None
    effect_probe: EffectProbeSpec | None = None
    control_config: ControlConfig | None = None
    # Server-layer twin launch: how to start a genuinely UNGUARDED variant of
    # this server (vulnerable_launch) and/or per-control env toggles that disable
    # a single server-layer guard (control_env). Optional; omitting both keeps
    # today's behaviour. See docs/quarry.md and SECURITY.md (--authorize gate).
    vulnerable_launch: LaunchOverride | None = None
    control_env: dict[str, dict[str, str]] = {}

    @model_validator(mode="after")
    def _check(self) -> TargetFile:
        if self.system_prompt is not None and self.system_prompt_file is not None:
            msg = "set at most one of system_prompt / system_prompt_file"
            raise ValueError(msg)
        if self.transport == "stdio":
            if not self.command:
                raise ValueError("a stdio target requires a 'command' to launch the MCP server")
            if self.url is not None:
                raise ValueError("'url' is only valid for transport: sse|http")
        else:  # sse | http — remote
            if not self.url:
                raise ValueError(f"transport {self.transport!r} requires a 'url'")
        if self.family in {"filesystem", "fetch", "github"}:
            msg = f"family {self.family!r} is reserved for a bundled target; choose another name"
            raise ValueError(msg)
        bad = sorted(set(self.control_env) - _WEAKNESS_CLASSES)
        if bad:
            msg = (
                f"control_env keys must be weakness classes {sorted(_WEAKNESS_CLASSES)}; "
                f"got unknown key(s): {bad}"
            )
            raise ValueError(msg)
        return self


def _resolved_prompt(tf: TargetFile) -> str:
    if tf.system_prompt is not None:
        return tf.system_prompt
    if tf.system_prompt_file is not None:
        return Path(tf.system_prompt_file).read_text(encoding="utf-8")
    return _DEFAULT_CUSTOM_PROMPT


def build_target_spec(tf: TargetFile) -> TargetSpec:
    """Turn a ``TargetFile`` into a registrable ``TargetSpec``.

    Custom targets pass all args explicitly (``args_with_scope=False``); the
    scope, if any, is a free-form label used only for the ``--authorize`` match
    and the ``{scope}`` seed-arm placeholder.
    """
    requires_scope = tf.requires_scope

    def _validate_scope(scope: str | None) -> None:
        if requires_scope and not (scope and scope.strip()):
            raise InvalidTargetScope(
                f"custom target {tf.family!r} declares requires_scope; pass a non-empty scope"
            )

    return TargetSpec(
        family=tf.family,
        command=tf.command,
        args_template=tuple(tf.args),
        scope_validator=_validate_scope,
        default_system_prompt=_resolved_prompt(tf),
        requires_scope=requires_scope,
        args_with_scope=False,
        primary_tools=tuple(tf.primary_tools),
        extra_env=dict(tf.env),
        weakness_classes=tuple(tf.weakness_classes),
        seed_arm=tf.seed_arm,
        effect_probe=tf.effect_probe,
        control_config=tf.control_config,
        vulnerable_launch=tf.vulnerable_launch,
        control_env={k: dict(v) for k, v in tf.control_env.items()},
        transport=tf.transport,
        url=tf.url,
        headers=dict(tf.headers),
    )


def load_target_file(path: Path) -> TargetFile:
    """Parse a YAML target file into a validated ``TargetFile``."""
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        msg = f"target file {path} must contain a YAML mapping at the top level"
        raise ValueError(msg)
    return TargetFile.model_validate(data)


def dump_target_file(tf: TargetFile) -> str:
    """Serialise a ``TargetFile`` back to YAML.

    Used to persist an *inline* ``mcp:custom`` target (assembled from CLI flags,
    with no source YAML on disk) next to its scan as ``target.yaml`` — so
    ``generate`` and ``validate`` can re-resolve the exact same target without the
    operator re-passing every flag. ``exclude_defaults`` keeps the file minimal and
    re-loadable: it round-trips back through ``load_target_file`` to an equal model.
    """
    data = tf.model_dump(mode="json", exclude_defaults=True)
    return yaml.safe_dump(data, sort_keys=True, default_flow_style=False)


def payload_placement_warnings(tf: TargetFile) -> list[str]:
    """Non-fatal warnings about where the ``{payload}`` placeholder is planted (R7).

    Mylonite plants a NATURAL-LANGUAGE payload (the customiser returns a bare
    ``body`` string) at a BARE string leaf. Two anti-patterns defeat that:

    * ``{payload}`` embedded inside a JSON/structured string (e.g.
      ``body: '{"text": "{payload}"}'``) — the plant is no longer natural language
      and may not be ingested as untrusted content.
    * no ``{payload}`` anywhere in ``args_template`` — nothing gets planted, so an
      indirect-injection seed would silently deliver an empty attack.
    """
    warnings: list[str] = []
    if tf.seed_arm is None:
        return warnings

    found = [False]

    def _walk(node: object, path: str) -> None:
        if isinstance(node, str):
            if "{payload}" in node:
                found[0] = True
                stripped = node.strip()
                if stripped != "{payload}" and stripped[:1] in "{[":
                    warnings.append(
                        f"seed_arm.args_template{path}: '{{payload}}' looks embedded in a "
                        "JSON/structured string. Mylonite plants a natural-language payload "
                        "at a BARE string leaf — make the whole field value '{payload}' (e.g. "
                        'body: "{payload}"), not nested serialized JSON.'
                    )
        elif isinstance(node, dict):
            for key, value in node.items():
                _walk(value, f"{path}.{key}")
        elif isinstance(node, list):
            for i, value in enumerate(node):
                _walk(value, f"{path}[{i}]")

    _walk(tf.seed_arm.args_template, "")
    if not found[0]:
        warnings.append(
            "seed_arm.args_template has no '{payload}' placeholder — an indirect-injection "
            "seed would plant nothing. Put '{payload}' at the field that holds untrusted content."
        )
    return warnings


# Weakness classes delivered ONLY by planting a poisoned note (the seeds use
# setup="seed_note"). Without a ``seed_arm`` the payload cannot be planted, so
# every such seed skips and a vulnerable target wrongly reads as clean — the most
# dangerous silent footgun. W1/W3/W4 also have non-indirect (direct) variants, so
# only the indirect-only classes are hard blockers here.
_INDIRECT_ONLY_WEAKNESS_CLASSES: frozenset[str] = frozenset({"W2"})


def validate_for_scan(tf: TargetFile, *, allow_no_seed_arm: bool = False) -> list[str]:
    """BLOCKING pre-flight errors for a scan (distinct from the non-fatal
    ``payload_placement_warnings``).

    Returns a list of human-readable error strings; an empty list means the
    target is safe to scan. The caller is expected to print these and exit
    non-zero so a misconfigured target never produces a misleading "clean" scan.

    Currently enforces one rule: declaring an indirect-injection-only weakness
    class (e.g. W2) with no ``seed_arm`` is a hard error, because those seeds
    would silently skip. ``allow_no_seed_arm=True`` downgrades it to allowed (the
    seeds then report NOT TESTED, which the summary surfaces loudly).
    """
    errors: list[str] = []
    indirect = sorted(set(tf.weakness_classes) & _INDIRECT_ONLY_WEAKNESS_CLASSES)
    if indirect and tf.seed_arm is None and not allow_no_seed_arm:
        errors.append(
            f"weakness class(es) {', '.join(indirect)} are indirect-injection only and need a "
            "seed_arm to plant the poisoned content, but the target declares none. Those seeds "
            "would skip and a vulnerable target would wrongly read as clean. Add a seed_arm to "
            "the target file (see docs/targets), or pass --allow-no-seed-arm to scan anyway "
            "(those seeds will be reported NOT TESTED, not clean)."
        )
    return errors


# Weakness classes whose finding turns on a real SIDE EFFECT materialising — a
# message actually sent (W4), a URL actually fetched (W3). Whether that effect
# happened can only be confirmed by probing the target's OWN state; it is invisible
# in the transcript. Without an effect_probe a real target under-detects these.
_EFFECTFUL_WEAKNESS_CLASSES: frozenset[str] = frozenset({"W3", "W4"})


def effect_probe_warnings(tf: TargetFile) -> list[str]:
    """Non-fatal warnings: side-effecting weaknesses (W3/W4) need an ``effect_probe``.

    A W3 (egress/SSRF) or W4 (unconfirmed consequential action) finding turns on
    whether a real side effect MATERIALISED. On the bundled reference target that
    lands in adapter-private metadata the deterministic predicates read; a REAL MCP
    target does not surface it, so without an ``effect_probe`` (which queries the
    target's own state) the effect cannot be confirmed and the seed silently
    under-detects — a vulnerable target can read as clean.

    Distinct from the W2 hard block in :func:`validate_for_scan`: W3/W4 also have
    direct (non-indirect) variants and still exercise the surface, so this is a
    WARNING (the scan proceeds; those seeds report NOT TESTED FOR EFFECT), not an
    error. ``mylonite init-target`` auto-suggests an ``effect_probe`` candidate from
    the tool surface.
    """
    warnings: list[str] = []
    effectful = sorted(set(tf.weakness_classes) & _EFFECTFUL_WEAKNESS_CLASSES)
    if effectful and tf.effect_probe is None:
        warnings.append(
            f"weakness class(es) {', '.join(effectful)} cause a real side effect "
            "(a send/fetch/write) whose occurrence can only be confirmed by an "
            "effect_probe that queries the target's own state. None is declared, so "
            "those seeds cannot confirm the effect on a real target and a side-effecting "
            "attack may read as clean. Add an effect_probe to the target file "
            "(see docs/target-file; `mylonite init-target` suggests one) for end-to-end "
            "damage confirmation."
        )
    return warnings


def needs_seed_arm_autowire(tf: TargetFile) -> bool:
    """True when the target declares an indirect-injection-only weakness (W2) but no
    ``seed_arm`` — the case M3 auto-wires from the tool surface so a real app needs
    near-zero config instead of a hard pre-flight block."""
    return tf.seed_arm is None and bool(set(tf.weakness_classes) & _INDIRECT_ONLY_WEAKNESS_CLASSES)


def infer_seed_arm(tools: list[Any]) -> tuple[SeedArmSpec | None, str]:
    """Derive a ``seed_arm`` (how to plant untrusted content) from the tool surface.

    Reuses the deterministic tool-role heuristics (``_classify_tools``). Only returns
    a seed_arm when a NO-id recall path exists, so the planted payload is *guaranteed*
    to be surfaced back to the planner — avoiding the "plants but never lands" trap (a
    store whose only readback needs the new record's id the planner never learns). The
    caller prints the note; the operator can override the inferred value in the file.
    """
    from mylonite.scan.tool_roles import _classify_tools

    roles = _classify_tools(tools)
    if roles.seed_arm_tool and roles.seed_arm_param and roles.retrieve_tool:
        spec = SeedArmSpec(
            tool=roles.seed_arm_tool,
            args_template={roles.seed_arm_param: "{payload}"},
        )
        note = (
            f"inferred seed_arm: {roles.seed_arm_tool}({roles.seed_arm_param}='{{payload}}') "
            f"with recall via {roles.retrieve_tool!r} — override in the target file if wrong."
        )
        return spec, note
    if roles.seed_arm_tool:
        return None, (
            f"found a content-storing tool ({roles.seed_arm_tool!r}) but NO id-free recall path: "
            "an auto-wired plant could not be delivered back to the planner. Declare a seed_arm "
            "(+ matching drive) in the target file."
        )
    return None, (
        "no content-storing tool found on the target's surface — declare a seed_arm in the "
        "target file to test indirect injection (W2)."
    )
