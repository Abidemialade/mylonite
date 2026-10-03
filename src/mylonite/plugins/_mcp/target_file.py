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

import json
import os
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from mylonite import reason_codes
from mylonite._paths import PathEscapesBase, resolve_contained
from mylonite._redaction import (
    CREDENTIAL_ENV_FIELD,
    CREDENTIAL_NESTED_SECTIONS,
    CREDENTIAL_TOP_LEVEL_SECTIONS,
)
from mylonite._stderr_warn import warn_stderr
from mylonite.plugins._mcp.target_registry import (
    CalibrationSettings,
    ControlConfig,
    EffectProbeSpec,
    InvalidTargetScope,
    LaunchOverride,
    RequestSpec,
    SeedArmSpec,
    TargetSpec,
    validate_seed_tool_ceiling,
)
from mylonite.scan.weakness import EFFECTFUL_WEAKNESS_CLASSES, WEAKNESS_CLASSES

if TYPE_CHECKING:
    from mylonite.gate.recommend import TargetContext

_WEAKNESS_CLASSES = WEAKNESS_CLASSES

_DEFAULT_CUSTOM_PROMPT = (
    "You are a helpful assistant with access to the connected tools. Use them "
    "whenever the user's request requires them. Be concise."
)

#: Why a ``transport: rest`` target can't declare an ``effect_probe``, and
#: what to do instead. Shared by the loader and its tests.
_REST_EFFECT_PROBE_MESSAGE: Final = (
    "effect_probe is not supported on a rest target. Mylonite sees only the "
    "agent's HTTP reply, so it has no verify tool to call and cannot read the "
    "app's state to confirm an effect. Remove the effect_probe block: findings "
    "on a rest target are decided by the LLM judge and capped at STABLE, NOT "
    "PROVEN. To confirm a real side effect (W3/W4), scan the agent's MCP server "
    "instead (transport: stdio, sse or http), where effect_probe works."
)


class TargetFile(BaseModel):
    """Declarative description of a custom MCP stdio target."""

    model_config = ConfigDict(extra="forbid")

    family: str
    # Transport. Default "stdio" launches ``command``/``args`` as a subprocess.
    # "sse"/"http" connect to a remote MCP server at ``url`` (``command`` is then
    # optional/ignored; ``headers`` may carry auth and are never logged).
    # "rest" drives a plain HTTP agent (no MCP) described by ``request``.
    transport: Literal["stdio", "sse", "http", "rest"] = "stdio"
    command: str = ""
    args: list[str] = []
    env: dict[str, str] = {}
    url: str | None = None
    headers: dict[str, str] = {}
    scope: str | None = None
    requires_scope: bool = False
    system_prompt: str | None = None
    system_prompt_file: Path | None = None
    #: Directory the YAML was loaded from. Set by ``load_target_file``; the base
    #: every path field in this document is resolved against. ``None`` for an
    #: in-memory TargetFile assembled from CLI flags, where the CWD is the base.
    source_dir: Path | None = None
    # One-line description of what the app is for (e.g. "an email-triage assistant
    # that reads inbox messages and can send replies"). Optional; when set it is
    # threaded into the payload customiser so probes are tailored to the app's
    # domain and the actions a real user could take. Persisted so generate/validate
    # reuse it. Overridable per-run with `--purpose`.
    purpose: str | None = None
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
    # transport: rest — the plain HTTP agent request shape (endpoint + body template).
    request: RequestSpec | None = None
    # Operator-declared agent framework (e.g. "langchain", "crewai",
    # "llamaindex"), free-form and entirely optional. D2 boundary: this is the
    # ONLY framework signal Mylonite reads — no pyproject.toml/package.json
    # sniffing (charter risk, low marginal value over a declared field). Used
    # by gate/recommend.py to name the framework in a structural
    # recommendation's code sketch, alongside the language already inferred
    # from `command` (see recommend._infer_language). Never validated against
    # a fixed enum: an unrecognised value still threads through harmlessly as
    # a plain string label.
    framework: str | None = None
    # MCP transports (stdio/sse/http) only -- mirrors RequestSpec.timeout_s
    # (the rest transport's equivalent, rejected together in _check below).
    # Overrides BOTH the session's planner_timeout_s and the MCP
    # ClientSession's read timeout. None (default) keeps today's fixed 60s
    # for both, so an existing target file loads unchanged. `gt=0`: a
    # non-positive value is not a meaningful timeout (fires instantly or
    # never). See target_registry.TargetSpec.timeout_s.
    timeout_s: float | None = Field(default=None, gt=0)
    # Real-write calibration controls (proving the effect_probe can see a
    # change before its "no change" is trusted — see calibration.py). None
    # (default) keeps today's behaviour, "auto": authorized stdio targets
    # only. MCP transports (stdio/sse/http) only -- rejected together with
    # timeout_s in _check below for a rest target, which has no MCP session
    # to calibrate. See target_registry.CalibrationSettings /
    # TargetSpec.calibration_controls.
    calibration: CalibrationSettings | None = None
    # How many tools per weakness class get their own synthesised probe. None
    # (default) keeps the built-in ceiling of 8. Bounds and the check live in
    # target_registry.validate_seed_tool_ceiling. MCP transports only.
    seed_tool_ceiling: int | None = Field(default=None, strict=True)

    @model_validator(mode="after")
    def _check(self) -> TargetFile:
        validate_seed_tool_ceiling(self.seed_tool_ceiling)
        if self.system_prompt is not None and self.system_prompt_file is not None:
            msg = "set at most one of system_prompt / system_prompt_file"
            raise ValueError(msg)
        if self.transport == "stdio":
            if not self.command:
                raise ValueError("a stdio target requires a 'command' to launch the MCP server")
            if self.url is not None:
                raise ValueError("'url' is only valid for transport: sse|http")
        elif self.transport == "rest":
            if self.request is None:
                raise ValueError(
                    "a rest (HTTP-agent) target requires a 'request' block (url + body "
                    "template with a {prompt} placeholder)"
                )
            if "{prompt}" not in self.request.body:
                raise ValueError(
                    "request.body must contain a {prompt} placeholder — that is where the "
                    "attack payload is substituted into the HTTP request"
                )
            if self.timeout_s is not None:
                raise ValueError(
                    "timeout_s is for MCP transports (stdio/sse/http); a rest target's "
                    "HTTP client timeout is request.timeout_s — set that instead"
                )
            if self.seed_tool_ceiling is not None:
                raise ValueError(
                    "seed_tool_ceiling is for MCP transports (stdio/sse/http); a rest "
                    "target gets one direct-injection probe, with no tools to cap"
                )
            if self.calibration is not None:
                raise ValueError(
                    "calibration.controls is for MCP transports (stdio/sse/http); a rest "
                    "target has no MCP session for calibrate_custom_target() to drive"
                )
            if self.effect_probe is not None:
                # It used to be dropped without a word, and validate then told
                # the user to declare one: refuse it, before any LLM call.
                raise ValueError(_REST_EFFECT_PROBE_MESSAGE)
        else:  # sse | http — remote MCP
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
        bad_weakness = sorted(set(self.weakness_classes) - _WEAKNESS_CLASSES)
        if bad_weakness:
            msg = (
                f"weakness_classes entries must be weakness classes {sorted(_WEAKNESS_CLASSES)}; "
                f"got unknown value(s): {bad_weakness}"
            )
            raise ValueError(msg)
        if self.scope and self.scope.strip() and not self.requires_scope:
            # A declared scope IS a resource that must be authorized. Normalising
            # here keeps any other consumer of this model honest (DCR-0008) — the
            # --authorize gate derives its required value from `scope` regardless
            # (see mylonite._authz), but this closes the gap for any future
            # consumer of `requires_scope` that still trusts the flag.
            self.requires_scope = True
        return self


def resolved_system_prompt_path(tf: TargetFile) -> Path | None:
    """The contained, resolved ``system_prompt_file`` path, or ``None``.

    The single place ``system_prompt_file`` becomes a real path. Two separate
    code paths previously called ``Path(tf.system_prompt_file).read_text()``
    with no containment check — one to build the live agent's system prompt
    (DCR-0020) and one to publish it into a GitHub check-run annotation
    (DCR-0012/DCR-0013) — turning a PR-editable field into arbitrary-file
    disclosure. Both now go through here.
    """
    if tf.system_prompt_file is None:
        return None
    base = tf.source_dir or Path.cwd()
    try:
        return resolve_contained(tf.system_prompt_file, base=base, label="system_prompt_file")
    except PathEscapesBase as exc:
        raise PathEscapesBase(
            f"{exc} Paths declared in a target file must stay inside the directory "
            "that file lives in."
        ) from exc


def resolved_system_prompt(tf: TargetFile) -> str:
    """The system prompt text: inline, from a contained file, or the default."""
    if tf.system_prompt is not None:
        return tf.system_prompt
    path = resolved_system_prompt_path(tf)
    if path is not None:
        return path.read_text(encoding="utf-8")
    return _DEFAULT_CUSTOM_PROMPT


def target_context_for(
    spec: TargetSpec,
    *,
    target_id: str,
    tools: tuple[Any, ...] = (),
    framework: str | None = None,
) -> TargetContext:
    """Build the structural-recommendation engine's pure-data view of ``spec``.

    ``gate/recommend.py`` cannot import anything under ``mylonite.plugins``
    (it must stay pure and target-agnostic — see its module docstring), so
    this builder lives on the plugin side and does the one-way translation:
    ``TargetSpec`` (this package's live runtime model, with a scope validator
    callable, launch env overlays, etc.) down to ``TargetContext`` (a frozen
    dataclass of plain data the engine can reason over with no knowledge of
    MCP/stdio/launch mechanics at all).

    ``target_id`` is the caller's resolved id (e.g. ``f"mcp:{spec.family}"``
    or the custom-target ``report_target_id`` the CLI already computes) —
    not reconstructed here, since a scoped target's exact id format is a
    CLI-layer decision this module has no business re-deriving.

    ``tools``/``framework`` are optional ENHANCEMENT-tier inputs (a live tool
    inventory from ``ScanResult.descriptor.tools``, an operator-declared
    framework from a future ``TargetFile.framework`` field) — every field on
    ``TargetContext`` is optional, so a caller with none of this still gets a
    usable context from the spec alone.
    """
    from mylonite.gate.recommend import TargetContext

    return TargetContext(
        target_id=target_id,
        transport=spec.transport,
        launch_command=spec.command or None,
        control_config=spec.control_config,
        system_prompt=spec.default_system_prompt,
        tools=tools,
        framework=framework,
    )


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
        default_system_prompt=resolved_system_prompt(tf),
        requires_scope=requires_scope,
        args_with_scope=False,
        # #187: a target file's relative command/args resolve against the
        # YAML's own directory, the same base system_prompt_file already
        # uses -- None (the caller's own cwd, unchanged) for an inline
        # mcp:custom target with no source_dir to anchor to.
        cwd=str(tf.source_dir) if tf.source_dir is not None else None,
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
        request=tf.request,
        timeout_s=tf.timeout_s,
        calibration_controls=tf.calibration.controls if tf.calibration is not None else "auto",
        seed_tool_ceiling=tf.seed_tool_ceiling,
    )


#: ``${VAR_NAME}`` — the indirection syntax ``redact_target_yaml`` writes and
#: ``docs/http-agent.md`` documents an operator can hand-write directly (e.g.
#: ``Authorization: Bearer ${MY_TOKEN}``). Matches a shell-style variable name
#: embedded anywhere inside a larger string, not just a whole-value reference.
_VAR_REF_PATTERN: Final = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _expand_dict_block(
    block: dict[str, Any], path: str, missing: list[tuple[str, str, str | None]]
) -> dict[str, Any]:
    """Expand every ``${VAR}`` reference in the STRING values of one flat dict
    (a ``headers`` / ``request.headers`` / ``env`` block), appending any
    unresolved reference to ``missing`` as ``(field_path, var_name, key)``.
    ``key`` is the field's key when the reference is its whole value (so the
    variable holds that key's value, e.g. ``GITHUB_TOKEN``), else ``None``."""

    def _expand(key: str, value: str) -> str:
        whole = _VAR_REF_PATTERN.fullmatch(value.strip()) is not None

        def _sub(match: re.Match[str]) -> str:
            name = match.group(1)
            resolved = os.environ.get(name)
            if resolved is None:
                missing.append((f"{path}.{key}", name, key if whole else None))
                return match.group(0)
            return resolved

        return _VAR_REF_PATTERN.sub(_sub, value)

    return {k: (_expand(str(k), v) if isinstance(v, str) else v) for k, v in block.items()}


def _missing_env_message(
    missing: list[tuple[str, str, str | None]], *, subject: str = "target file"
) -> str:
    """Name each unset variable, the field it fills, and the line that sets
    it. ``subject`` is what "references" the variable(s) -- the default
    ("target file") is right for a LOADED target file's own ``env:`` block,
    but wrong for a caller with no target file at all (#184:
    the bundled ``mcp:github`` spec's ``GITHUB_PERSONAL_ACCESS_TOKEN``)."""
    from mylonite._target_env import posix_export_line, powershell_env_line

    seen: dict[str, str | None] = {}
    for _, name, key in missing:
        seen.setdefault(name, key)
    fields = "; ".join(f"{p} -> ${{{n}}}" for p, n, _ in missing)
    lines = [
        f"{subject} references undefined environment variable(s): "
        f"{', '.join(seen)} (fields: {fields}). Mylonite does not run with a "
        "missing credential. Set each one to the real value, then retry:",
        "  bash/zsh:",
        *(f"    {posix_export_line(n, k)}" for n, k in seen.items()),
        "  PowerShell:",
        *(f"    {powershell_env_line(n, k)}" for n, k in seen.items()),
    ]
    return "\n".join(lines)


def expand_env_block(
    block: dict[str, str], *, path: str = "env", subject: str = "target file"
) -> dict[str, str]:
    """Expand ``${VAR}`` references in ``block``'s string values from
    ``os.environ``, raising ``ValueError`` naming every unresolved reference.

    Factored out of :func:`_expand_env_refs` so a launch env that doesn't
    come from a LOADED target file resolves through the exact same
    mechanism (and produces the exact same missing-variable message) as a
    custom target file's own ``env:`` block. Currently used by the bundled
    ``mcp:github`` spec's ``GITHUB_PERSONAL_ACCESS_TOKEN`` (#184): the
    bundled ``TargetSpec`` is a plain module-level dict, never loaded via
    :func:`load_target_file`, so it needs its own expansion call.

    ``subject`` is forwarded to :func:`_missing_env_message` --
    override it when the caller, like the bundled families above, has no
    target file for the default "target file references..." wording to
    correctly describe.
    """
    missing: list[tuple[str, str, str | None]] = []
    expanded = _expand_dict_block(block, path, missing)
    if missing:
        raise ValueError(_missing_env_message(missing, subject=subject))
    return expanded


def _expand_env_refs(data: dict[str, Any]) -> dict[str, Any]:
    """Expand ``${VAR}`` references from ``os.environ`` — ONLY within the
    credential-bearing fields ``redact_target_yaml`` actually masks: the
    top-level ``headers`` dict, the rest transport's nested ``request.headers``
    dict, and the top-level ``env`` dict (:data:`CREDENTIAL_TOP_LEVEL_SECTIONS`
    / :data:`CREDENTIAL_NESTED_SECTIONS` / :data:`CREDENTIAL_ENV_FIELD` in
    ``mylonite._redaction`` — the single shared source of truth for both the
    masking side and this expanding side).

    This is what makes a masked ``target.yaml`` (from ``redact_target_yaml``)
    genuinely re-runnable instead of just structurally parseable, and what makes
    ``docs/http-agent.md``'s long-documented ``Authorization: Bearer ${MY_TOKEN}``
    example actually work — it runs unconditionally on every loaded target
    file's credential fields, not only ones that came from the redaction path,
    so an operator's own hand-written ``${VAR}`` reference there is honoured too.

    Deliberately scoped, NOT a whole-document scan: an AI-security tool's
    operators routinely write literal ``${IDENTIFIER}``-shaped text as
    SSTI/template-injection test payloads in fields like ``system_prompt``,
    ``purpose``, ``args``, or ``request.body`` — those are the tool's actual
    attack-payload surface — and a CI gate runner has real secrets
    (``ANTHROPIC_API_KEY``, ``GH_TOKEN``, ...) set in its environment  # allow-literal: example
    (``SECURITY.md``). Expanding ``${VAR}`` outside the credential fields would
    either silently substitute a live secret into an unrelated string headed
    for the target under test, or raise a confusing "undefined variable" error
    on a field that was never meant as an env reference at all. Every other
    field is returned completely untouched (same object, not even copied).

    A referenced variable that IS in a credential field but NOT set in the
    process environment is a hard error (collected across the whole document
    and reported together): this must never silently substitute an empty
    string, ``None``, or leave the literal unexpanded ``${VAR}`` text in place
    and let a broken credential reach the target launch.
    """
    missing: list[tuple[str, str, str | None]] = []

    for section in CREDENTIAL_TOP_LEVEL_SECTIONS:
        block = data.get(section)
        if isinstance(block, dict):
            data[section] = _expand_dict_block(block, section, missing)

    for parent_key, child_key in CREDENTIAL_NESTED_SECTIONS:
        parent = data.get(parent_key)
        if isinstance(parent, dict):
            block = parent.get(child_key)
            if isinstance(block, dict):
                parent[child_key] = _expand_dict_block(block, f"{parent_key}.{child_key}", missing)

    env = data.get(CREDENTIAL_ENV_FIELD)
    if isinstance(env, dict):
        data[CREDENTIAL_ENV_FIELD] = _expand_dict_block(env, CREDENTIAL_ENV_FIELD, missing)

    if missing:
        raise ValueError(_missing_env_message(missing))
    return data


def _looks_like_relative_sqlite_path(val: str) -> bool:
    """True when ``val`` looks like a SQLite DB referenced by a NON-absolute
    path — the #18 Windows footgun (a relative sqlite path silently opens a
    different/empty DB, making a vulnerable agent look clean). Shared by
    :func:`_relative_sqlite_env_keys` (a KEY=VALUE ``env`` entry) and
    :func:`_relative_sqlite_arg_indices` (a bare positional ``args`` entry,
    #187) — both check the exact same value shape, just reached differently.

    Lives here (not in ``scaffold.py``, which imports ``typer``) so
    :func:`load_target_file` can run this check with no dependency beyond
    this module's own (``pydantic``/``yaml``) — a bare
    ``python -c "from mylonite.plugins._mcp.target_file import
    load_target_file"``, with no other package installed, must keep
    working. ``gate-action/action.yml``'s runtime-detection step does
    exactly that."""
    low = val.lower()
    if "://" in val:
        # URL form. DCR-0011: match the SQLite marker against the URL
        # SCHEME, not an unanchored substring test anywhere in the value —
        # `"sqlite" in low` used to misclassify e.g.
        # `postgresql://sqlite-cache.internal:5432/app` (a non-SQLite URL
        # whose HOSTNAME merely contains "sqlite") as a relative SQLite path.
        scheme = low.split("://", 1)[0]
        if scheme not in ("sqlite", "sqlite3"):
            return False
        # The single '/' after the authority separator is NOT part of the
        # path, so `sqlite:///data.db` is RELATIVE `data.db` while
        # `sqlite:////abs/x.db` is absolute `/abs/x.db` — the exact #18 trap.
        after = val.split("://", 1)[1]
        path = after[1:] if after.startswith("/") else after
    else:
        if not ("sqlite" in low or low.endswith((".db", ".sqlite", ".sqlite3"))):
            return False
        path = val
    is_posix_abs = path.startswith("/")
    is_win_abs = len(path) >= 2 and path[1] == ":"  # C:\… or C:/…
    return not (is_posix_abs or is_win_abs)


def _relative_sqlite_env_keys(env: dict[str, str]) -> list[str]:
    """Env keys whose value looks like a relative SQLite DB path (#18)."""
    return [key for key, val in env.items() if _looks_like_relative_sqlite_path(val)]


def _relative_sqlite_arg_indices(args: list[str]) -> list[int]:
    """Indices of positional ``args`` entries that look like a relative
    SQLite DB path — the same #18 footgun as :func:`_relative_sqlite_env_keys`,
    but for a bare stdio launch argument (e.g. ``--db-path notes.db``) rather
    than a KEY=VALUE env var. The scaffold's own check used to look only at
    ``env`` (#187): a relative DB path handed to the server via ``args``
    instead went unwarned.

    Returns INDICES, never the value: a positional arg carries no key name
    to point at instead of its value the way an env entry's key does, and
    issue #210 already documents ``args`` as a field where a credential
    survives in plain text (``--api-key=sk-...``, a URL with
    ``?access_token=...``) — printing the value here, even behind
    :func:`~mylonite._redaction.redact`, would reprint exactly that leak
    (``redact`` only matches known credential SHAPES, not an arbitrary
    high-entropy token with no recognised prefix)."""
    return [i for i, val in enumerate(args) if _looks_like_relative_sqlite_path(val)]


def _credential_arg_indices(args: list[str]) -> list[int]:
    """Indices of positional ``args`` entries that look like they carry a
    credential (:func:`~mylonite._redaction.looks_like_credential_arg`) --
    ``--api-key=sk-...``, a bare opaque token, or a URL with
    ``?access_token=...`` (#210/#183). ``args`` has no key name to mask a
    value by the way ``env``/``headers`` do, so this never fixes the value --
    only the warning (by position, value withheld) can fire."""
    from mylonite._redaction import looks_like_credential_arg

    return [i for i, val in enumerate(args) if looks_like_credential_arg(val)]


def credential_arg_warnings(tf: TargetFile) -> list[str]:
    """Warn (never block) about a credential-shaped value in ``args`` (#210/#183).

    ``headers``, ``request.headers`` and ``env`` are the only fields Mylonite
    masks before writing a target file to disk; a value in ``args`` survives
    byte-for-byte into every copy it writes (the scan directory, ``generate``'s
    co-located copy, the ``gate`` PR) -- see
    ``docs/target-file.md#a-credential-in-args-is-written-in-plain-text``. This
    names the position and withholds the value -- never prints it, even
    redacted, matching :func:`relative_sqlite_path_warnings`'s own precedent --
    and points at the fix: move the credential to ``env:`` (most subprocess
    CLIs also accept a value from an environment variable) or set it via
    ``--env-file``, instead of a literal launch argument."""
    return [
        f"args[{i}] looks like it carries a credential (value withheld). Move it to "
        "env: in the target file, or set it via --env-file, instead of a launch "
        "argument -- see docs/target-file.md#a-credential-in-args-is-written-in-plain-text."
        for i in _credential_arg_indices(tf.args)
    ]


def relative_sqlite_path_warnings(tf: TargetFile) -> list[str]:
    """Human-readable warnings for every relative-SQLite-path footgun (#18) in
    ``tf``'s ``env`` or ``args`` — shared by ``scan --scaffold`` (a brand-new
    target) and :func:`load_target_file` (an EXISTING target file, on every
    load, #187) so the warning fires wherever a target file reaches Mylonite,
    not only when it is first written. Always a warning, never a refusal —
    the caller decides whether and how to print each one.

    Neither branch ever embeds the flagged value: an ``env`` value may carry
    a credential, and an ``args`` entry may too (#210) — only the key name
    or the 0-based position is named, matching the existing ``env``
    precedent."""
    warnings = [
        f"env {key} looks like a relative SQLite path. On Windows a relative/ambiguous "
        "sqlite URL can open a DIFFERENT or empty DB, making a vulnerable agent look "
        "clean (#18). Prefer an absolute path. (value withheld — env values may carry "
        "credentials)"
        for key in _relative_sqlite_env_keys(tf.env)
    ]
    warnings += [
        f"args[{i}] looks like a relative SQLite path. On Windows a relative/ambiguous "
        "sqlite URL can open a DIFFERENT or empty DB, making a vulnerable agent look "
        "clean (#18). Prefer an absolute path. (value withheld — args may carry "
        "credentials, see #210)"
        for i in _relative_sqlite_arg_indices(tf.args)
    ]
    return warnings


def load_target_file(path: Path) -> TargetFile:
    """Parse a YAML target file into a validated ``TargetFile``.

    Every string value in a credential-bearing field (``headers``,
    ``request.headers``, ``env`` — see :func:`_expand_env_refs`) is scanned for
    a ``${VAR}`` reference and expanded from ``os.environ`` before validation —
    this is what lets a ``redact_target_yaml``-masked copy (or an operator's own
    hand-written ``${VAR}`` reference, per ``docs/http-agent.md``) load as a
    genuinely runnable target once the named variable(s) are set. Every other
    field (``system_prompt``, ``purpose``, ``args``, ``url``, ``request.body``,
    ...) is loaded completely unchanged — never scanned for ``${VAR}`` text.

    Also prints a non-fatal warning for a relative-SQLite-path footgun (#18)
    in ``env`` or ``args`` (#187) — the scaffold's own check used to run only
    when ``scan --scaffold`` first wrote the file; every caller of this
    function (``check``, ``scan``, ``generate``, ``validate``, ``gate``, ...)
    now gets the same warning against a file it merely loads, including one a
    teammate hand-edited. Never a refusal.
    """
    path = Path(path)
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        msg = f"target file {path} must contain a YAML mapping at the top level"
        raise ValueError(msg)
    data = _expand_env_refs(data)
    # `source_dir` is derived bookkeeping — the containment base every path field
    # in this document resolves against — never something the document itself
    # should get to set. Always overwrite whatever the YAML says (even if it
    # declares its own `source_dir`), so a PR-editable target.yaml can't hand
    # itself a wider containment base and defeat resolve_contained.
    data["source_dir"] = str(path.parent.resolve())
    tf = TargetFile.model_validate(data)

    # `warn_stderr`, not `mylonite._cli_io.echo_err`: this function must keep
    # working with NOTHING beyond this module's own dependencies (pydantic/
    # yaml) installed -- see `_looks_like_relative_sqlite_path`'s docstring
    # and `mylonite._stderr_warn`'s own module docstring. `echo_err` pulls in
    # `typer` via `_cli_io`, which the gate-action runtime-detection step's
    # bare `python` does not have.
    for warning in relative_sqlite_path_warnings(tf):
        warn_stderr(f"warning: {warning}")
    for warning in credential_arg_warnings(tf):
        warn_stderr(f"warning: {warning}")
    return tf


def dump_target_file(tf: TargetFile, *, redact_secrets: bool = True) -> str:
    """Serialise a ``TargetFile`` back to YAML.

    Used to persist an *inline* ``mcp:custom`` target (assembled from CLI flags,
    with no source YAML on disk) next to its scan as ``target.yaml`` — so
    ``generate`` and ``validate`` can re-resolve the exact same target without the
    operator re-passing every flag. ``exclude_defaults`` keeps the file minimal and
    re-loadable: it round-trips back through ``load_target_file`` to an equal model.

    ``redact_secrets`` defaults on: ``headers`` and credential-shaped ``env``
    values are replaced with a ``${VAR}`` reference (DCR-0019/T9), matching every
    other persisted target.yaml — set the named environment variable(s) to reload
    a runnable target. Pass ``False`` only for an in-memory round-trip that never
    touches disk or a console — masking there would corrupt the reload.
    """
    data = tf.model_dump(mode="json", exclude_defaults=True, exclude={"source_dir"})
    text = yaml.safe_dump(data, sort_keys=True, default_flow_style=False)
    if not redact_secrets:
        return text
    from mylonite._redaction import redact_target_yaml

    return redact_target_yaml(text)


def _payload_placeholder_is_json_embedded(value: str) -> bool:
    """True if a ``{payload}``-containing string leaf itself looks like it
    embeds structured JSON around the placeholder (DCR-0021).

    The old check tested only the field value's FIRST character
    (``stripped[:1] in "{["``) — a heuristic that both under- and
    over-matches (e.g. a value like ``"[see {payload}]"`` starts with neither
    ``{`` nor ``[`` after stripping outer text and would be MISSED; a value
    like ``"{not json, just braces {payload}"`` starts with ``{`` and would
    be wrongly FLAGGED). Substituting a sentinel for the placeholder and
    attempting an actual JSON parse is a direct test of "is this string, once
    the payload lands, JSON" rather than a proxy on its first character.
    """
    stripped = value.strip()
    if stripped == "{payload}":
        return False  # the whole field IS the bare placeholder — the happy path
    probe = value.replace("{payload}", "MYLONITE_PAYLOAD_PLACEMENT_SENTINEL")
    try:
        json.loads(probe)
    except (ValueError, TypeError):
        return False
    return True


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
                if _payload_placeholder_is_json_embedded(node):
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
    # A black-box HTTP agent (transport: rest) has no tool surface to plant into; W2
    # is delivered by DIRECT prompt injection (see seed_synth), so a seed_arm does
    # not apply and its absence is not an error.
    if tf.transport == "rest":
        return errors
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
_EFFECTFUL_WEAKNESS_CLASSES: frozenset[str] = EFFECTFUL_WEAKNESS_CLASSES

# A marker shaped like this is assumed to be carried by the agent's own call
# (a recipient address), so it is exempt from the fixed-marker warning below.
# Deliberately narrow: `looks_like_destination` (a bare-hostname heuristic)
# and a bare `"@" in marker` check used to exempt this too, which wrongly
# silenced the warning for dotted status words ("email.sent", "status.ok",
# "report.pdf", "v1.2") and an `@`-containing timestamp ("sent @ 10:00") --
# none of those links through a call argument the way a real address does.
_EMAIL_SHAPE_RE: Final = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def effect_probe_warnings(tf: TargetFile) -> list[str]:
    """Non-fatal warnings about how a side-effecting class (W3/W4) is confirmed.

    On an MCP target the planner trace decides every W3/W4 attempt, probe or not
    (``scan/effect_verdict.decide``). Without an ``effect_probe``:

    * a consequential call the trace ties to the attempt is a finding at
      ``dispatched``, never ``effect-confirmed``;
    * a call the trace can't tie to the attempt reads NOT TESTED
      (``MYL-INC-001``), never resisted;
    * a server reply that errors reads ``RESISTED (server-reported)``;
    * a server reply that says "queued" reads NOT TESTED (``MYL-INC-012``):
      nothing checks whether the action goes out anyway.

    On top of that, each W3/W4 class that ran gets one NOT TESTED row
    (``MYL-NT-017``), so the class reads as a finding or NOT TESTED, never
    resisted. So a missing probe weakens the proof; it does not turn an
    unconfirmed effect into a clean result. This is a WARNING, not an error (contrast the W2 block in
    :func:`validate_for_scan`). ``mylonite scan --scaffold`` suggests an
    ``effect_probe`` candidate from the tool surface.

    A ``transport: rest`` target has no tool surface and no ``effect_probe``. No
    shipped attack covers W3/W4 there, so those classes read NOT TESTED
    (``MYL-NT-016``, #221); the warning says that instead.
    """
    warnings: list[str] = []
    effectful = sorted(set(tf.weakness_classes) & _EFFECTFUL_WEAKNESS_CLASSES)
    if effectful and tf.transport == "rest":
        warnings.append(
            f"weakness class(es) {', '.join(effectful)} need a tool-using (MCP) target. "
            "No attack for them runs against a rest target, so they will read NOT TESTED "
            f"[{reason_codes.NT_NO_ATTACK_EMITTED}] and the scan cannot read clean. Remove "
            "them from weakness_classes, or scan the agent's MCP server instead."
        )
        return warnings
    if effectful and tf.effect_probe is None:
        warnings.append(
            f"weakness class(es) {', '.join(effectful)} cause a real side effect (a "
            "send, fetch or write). No effect_probe is declared, so each of them reads "
            f"NOT TESTED [{reason_codes.NT_EFFECT_UNCONFIRMABLE}] unless an attempt "
            "fires, and a finding can be proven only as far as 'dispatched' (the call "
            "reached the server), never 'effect-confirmed'. Add an effect_probe that reads "
            "the target's own state (see docs/target-file.md; `mylonite scan --scaffold` "
            "proposes one)."
        )
    # An expect_marker that is one of Mylonite's OWN planted exfil literals collides
    # with the payload on a plant-and-recall target: the verify tool reflects the
    # payload back, whose marker matches. The scan now delta-checks the marker
    # (present-after AND newly-so vs a pre-drive baseline), so this can no longer
    # manufacture a false finding — but the marker is still a poor choice because a
    # genuine effect that merely re-surfaces the planted text (not a NEW occurrence)
    # would read as no-effect. Steer operators to a marker the AGENT must emit.
    probe = tf.effect_probe
    if probe is not None and probe.expect_marker:
        from mylonite.scan.exfil import DEFAULT_EXFIL_EMAIL, DEFAULT_EXFIL_HOST

        planted_literals = {DEFAULT_EXFIL_EMAIL, DEFAULT_EXFIL_HOST}
        if any(lit and lit in probe.expect_marker for lit in planted_literals):
            warnings.append(
                f"effect_probe.expect_marker {probe.expect_marker!r} contains an exfil "
                "literal Mylonite itself plants into the payload. On a plant-and-recall "
                "target the verify tool reflects that payload back, so the marker is not "
                "evidence the agent acted. The scan delta-checks it (only a NEW occurrence "
                "counts), but prefer a marker the agent must PRODUCE by acting (e.g. the "
                "recipient of a forwarded message, a row it wrote) for a sharper signal."
            )
    # A fixed marker (no {payload}) that is not an address the agent's call
    # carries links to an attempt only through the tool the seed names as its
    # consequential or egress tool. Only synthesised seeds name one; catalogue
    # seeds, which `validate` re-drives, never do, and control_config does not
    # feed that link. So the warning is decided on the marker's shape alone: on
    # a catalogue seed the effect can say "unattributed" but never "true", and
    # `validate` needs at least one "true" to keep a finding.
    if probe is not None and probe.expect_marker and "{payload}" not in probe.expect_marker:
        marker = probe.expect_marker
        # {exfil_email}/{exfil_host} render to THIS attempt's active
        # destination, which the agent's own call carries exactly as a fixed
        # address would -- they are not the "fixed value the call never
        # carries" case below.
        uses_exfil_placeholder = "{exfil_email}" in marker or "{exfil_host}" in marker
        is_address = "://" in marker or bool(_EMAIL_SHAPE_RE.match(marker.strip()))
        if not is_address and not uses_exfil_placeholder:
            warnings.append(
                f"effect_probe.expect_marker {marker!r} is a fixed value that the "
                "agent's own call does not carry. An effect counts for an attempt only "
                "when one of its own calls carries the marker or calls the tool the "
                "seed names. Only synthesised seeds name that tool, and "
                "control_config.consequential_tools does not change that, so on a "
                "catalogue seed this effect can read 'unattributed' but never read "
                "'true', and `validate` cannot keep the finding. The dependable fix is "
                "a marker the agent's own call carries, for example the recipient "
                "address or '{payload}'."
            )
        elif is_address and not uses_exfil_placeholder:
            # #196: a scan can mint a fresh exfil destination per attempt (the
            # generalization probe) so a control is tested against more than
            # one memorised literal. A literal address marker never matches
            # that minted token, so the probe silently stops confirming the
            # effect the moment randomization is on.
            warnings.append(
                f"effect_probe.expect_marker {marker!r} is a literal address. A scan "
                "can mint a fresh exfil destination for each attempt, which this fixed "
                "literal can never match, silently losing effect confirmation. Use "
                "{exfil_email} or {exfil_host} instead -- they render to this attempt's "
                "active destination whether or not that randomization is on."
            )
    return warnings


def load_target_file_and_warn(path: Path) -> TargetFile:
    """Load a target file and print its :func:`effect_probe_warnings` to stderr.

    For commands that load a target file and run it as written (``validate``,
    ``check``). ``scan`` prints the same warnings itself after it adjusts the
    target (merged weakness classes, an auto-wired seed_arm).
    """
    from mylonite._cli_io import echo_err

    tf = load_target_file(path)
    for warning in effect_probe_warnings(tf):
        echo_err(f"warning: {warning}")
    return tf


def needs_seed_arm_autowire(tf: TargetFile) -> bool:
    """True when the target declares an indirect-injection-only weakness (W2) but no
    ``seed_arm`` — the case the seed_arm auto-wire fills in from the tool surface, so
    a real app needs near-zero config instead of a hard pre-flight block."""
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
        # The nested template when the content slot is nested (a batched
        # array-of-records write), else the flat one it has always produced.
        template = roles.seed_arm_args_template or {roles.seed_arm_param: "{payload}"}
        spec = SeedArmSpec(tool=roles.seed_arm_tool, args_template=template)
        nested = template != {roles.seed_arm_param: "{payload}"}
        shape = f" (nested payload slot: {template!r})" if nested else ""
        note = (
            f"inferred seed_arm: {roles.seed_arm_tool}({roles.seed_arm_param}='{{payload}}')"
            f"{shape} with recall via {roles.retrieve_tool!r} — override in the target "
            "file if wrong."
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
