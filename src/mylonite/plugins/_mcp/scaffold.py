"""Target-file scaffolding: turn a discovered tool surface into a starter
``target.yaml`` (the ``mylonite scan --scaffold`` domain).

Extracted from ``cli.py`` (issue #91) so the CLI stays a thin composition root
and this target-file domain logic lives with the rest of the target-file code
(``target_file`` / ``target_registry``). ``cli`` re-exports these for its scan
command and for tests. Heavy dependencies (``TargetFile``, ``build_target_spec``,
``build_mcp_adapter``, redaction/authz helpers) are imported function-locally,
exactly as they were in ``cli``.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
from pathlib import Path
from typing import Any

import typer
import yaml
from pydantic import ValidationError

from mylonite._cli_io import echo, echo_err, echo_exc
from mylonite.exit_codes import EXIT_CONFIG
from mylonite.plugins._mcp import target_registry

# Re-exported here (not defined here): `load_target_file` must run this
# check on every load, from a module (`target_file.py`) with no `typer`
# dependency -- unlike this one. `cli.py`'s existing import of
# `_relative_sqlite_env_keys` FROM THIS MODULE, and this module's own
# `_scaffold_target_file` below, both keep working unchanged (#187).
from mylonite.plugins._mcp.target_file import (
    _relative_sqlite_arg_values as _relative_sqlite_arg_values,
)
from mylonite.plugins._mcp.target_file import (
    _relative_sqlite_env_keys as _relative_sqlite_env_keys,
)
from mylonite.plugins._mcp.target_file import (
    relative_sqlite_path_warnings as relative_sqlite_path_warnings,
)
from mylonite.scan.tool_roles import ReadbackChoice, _classify_tools, _ToolRoles


class _OutputNotWritable(Exception):
    """Raised by :func:`_check_output_writable` -- a clear, one-line reason the
    ``--scaffold`` output path cannot be used, caught at the call site and
    turned into an ``EXIT_CONFIG`` exit before anything expensive happens."""


def _check_output_writable(output: Path) -> None:
    """Fail fast and clearly if ``output`` cannot be written, *before* the
    caller does anything expensive (launching the target MCP server -- S14).

    Checks, in order: the path is not an existing directory; its parent
    directory exists or can be created; a real probe file can be written in
    that directory (catches permission errors a mere existence check misses).
    """
    if output.exists() and output.is_dir():
        raise _OutputNotWritable(f"{output} is a directory, not a file.")

    parent = output.parent
    try:
        parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise _OutputNotWritable(f"cannot create directory {parent}: {exc}") from exc

    probe = parent / f".mylonite-scaffold-writecheck-{os.getpid()}.tmp"
    try:
        probe.write_text("", encoding="utf-8")
    except OSError as exc:
        raise _OutputNotWritable(f"{output} is not writable: {exc}") from exc
    finally:
        with contextlib.suppress(OSError):
            probe.unlink()


def _atomic_write_text(path: Path, text: str) -> None:
    """Write ``text`` to ``path`` atomically (S15): write a temp file beside
    ``path``, then rename it into place with ``Path.replace`` (``os.replace``
    under the hood). A crash or interruption mid-write leaves the temp file
    orphaned (best-effort cleaned up below) and any pre-existing ``path``
    untouched -- never a truncated ``path``.
    """
    tmp = path.with_name(f".{path.name}.mylonite-tmp-{os.getpid()}")
    try:
        tmp.write_text(text, encoding="utf-8")
        tmp.replace(path)
    except BaseException:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise


def _suggest_weakness_classes(tools: list[Any]) -> list[str]:
    """Heuristic weakness-class HINTS from a target's live tool surface.

    These are SUGGESTIONS for the operator to confirm/edit - never authoritative.
    Grounded in the bundled W1-W4 taxonomy and derived from the tool *schemas*
    (param shapes) first, with the tool name/description as a fallback hint only
    (no English keyword is load-bearing for a verdict — that lives in the scan's
    structural signals and the operator-declared effect probe).

    * W1 (tool-description instruction smuggling) + W2 (indirect injection):
      baseline for any tool-using agent that ingests external content.
    * W3 (SSRF / unrestricted egress): a tool taking a URL/endpoint-shaped input.
    * W4 (unconfirmed consequential action): a tool that mutates external state.

    #181b: the raw keyword-blob hints above are then gated through
    ``control_shim.coverable_weakness_classes`` — the SAME coverability
    check ``mylonite check``'s own suggestion line uses, so the two can't
    drift — which itself uses ``scan.seeds.seed_coverage``, the engine's own
    seed selection. This is what stops the scaffold writing a class the
    engine could never cover for this exact surface: that used to hand a
    fresh ``mylonite scan --scaffold`` user a target.yaml that immediately
    hit the pre-flight refusal on first run. The coverability check assumes
    the seed_arm THIS scaffold is about to suggest (a detected plant/recall
    pair) gets declared, so a genuine W2 candidate is never wrongly dropped
    just because the operator hasn't pasted the seed_arm block in yet.
    """
    suggestions: set[str] = set()
    if tools:
        suggestions.update({"W1", "W2"})
    egress_hints = ("url", "uri", "endpoint", "fetch", "http", "request", "webhook")
    action_hints = (
        "send",
        "email",
        "post",
        "create",
        "delete",
        "write",
        "execute",
        "pay",
        "transfer",
        "purchase",
        "publish",
        "update",
        "remove",
        "issue",
        "commit",
    )
    for t in tools:
        blob = f"{getattr(t, 'name', '')} {getattr(t, 'description', '')}".lower()
        schema_text = str(getattr(t, "json_schema", "")).lower()
        if any(k in blob or k in schema_text for k in egress_hints):
            suggestions.add("W3")
        if any(k in blob for k in action_hints):
            suggestions.add("W4")
    if not suggestions:
        return []

    from mylonite.scan.control_shim import coverable_weakness_classes

    return coverable_weakness_classes(suggestions, tools)


def _target_file_from_flags(
    *,
    command: str | None,
    args: list[str] | None,
    env: list[str] | None,
    scope: str | None,
    system_prompt: str | None,
    system_prompt_file: Path | None,
    primary_tools: list[str] | None,
    weakness_classes: list[str] | None,
) -> Any:
    """Assemble a ``TargetFile`` (family='custom') from ``mcp:custom`` CLI flags."""

    from mylonite.plugins._mcp.target_file import TargetFile

    if not command:
        echo_err("mcp:custom requires --command (the MCP server launch command).")
        raise typer.Exit(code=EXIT_CONFIG)
    env_map: dict[str, str] = {}
    for item in env or []:
        if "=" not in item:
            echo_err(f"--env must be KEY=VALUE; got {item!r}.")
            raise typer.Exit(code=EXIT_CONFIG)
        key, _, value = item.partition("=")
        env_map[key] = value
    try:
        return TargetFile(
            family="custom",
            command=command,
            args=list(args or []),
            env=env_map,
            scope=scope,
            requires_scope=scope is not None,
            system_prompt=system_prompt,
            system_prompt_file=system_prompt_file,
            primary_tools=list(primary_tools or []),
            weakness_classes=list(weakness_classes or []),
        )
    except ValidationError as exc:
        echo_exc("invalid custom target", exc)
        raise typer.Exit(code=EXIT_CONFIG) from exc


def _rebase_relative_path(path: Path, *, output: Path) -> Path:
    """Re-express ``path`` so it resolves to the same file once ``output`` is
    later loaded (#187).

    ``--system-prompt-file`` is typed relative to the CURRENT directory, like
    every other relative CLI argument — but ``load_target_file`` resolves
    every path field in a target YAML against THAT FILE'S OWN directory
    (``TargetFile.source_dir``), not the directory ``--scaffold`` ran from.
    Writing the flag's value verbatim into the scaffolded file breaks the
    moment ``--scaffold`` writes to a different directory than the one the
    caller is in. Re-base it onto ``output``'s own directory instead, so the
    written file and the loader agree:

    - an already-absolute ``path`` is returned unchanged;
    - a ``path`` under ``output``'s directory becomes a plain relative path
      (no ``..``);
    - otherwise ``path`` is returned as an absolute path — a ``..``-climbing
      relative value would fail the loader's containment check (see
      ``resolved_system_prompt_path``), so that is never written.
    """
    if path.is_absolute():
        return path
    abs_path = (Path.cwd() / path).resolve()
    output_dir = output.resolve().parent
    rel = os.path.relpath(abs_path, output_dir)
    if rel.startswith(".."):
        return abs_path
    return Path(rel)


def _verify_args_stub(tool: Any) -> dict[str, Any]:
    """A minimal args dict satisfying ``tool``'s required top-level properties.

    Each required property gets a type-appropriate placeholder (a string,
    ``0``, ``False``, ``[]`` or ``{}``) — enough to satisfy JSON Schema
    ``type`` validation, not a real value; the operator still edits it to the
    target's actual shape. The point is only that the emitted
    ``verify_args_template`` is never ``{}`` against a verify tool that
    requires arguments (#217): an empty dict against e.g. ``read_text_file``
    (which requires ``path``) makes the verify call itself error, so the
    effect probe never gets a chance to confirm anything.
    """
    schema = getattr(tool, "json_schema", None)
    if not isinstance(schema, dict):
        return {}
    props = schema.get("properties")
    props = props if isinstance(props, dict) else {}
    required = schema.get("required")
    required = required if isinstance(required, list) else []

    def _stub(prop_schema: Any) -> Any:
        prop_type = prop_schema.get("type") if isinstance(prop_schema, dict) else None
        if prop_type in ("integer", "number"):
            return 0
        if prop_type == "boolean":
            return False
        if prop_type == "array":
            return []
        if prop_type == "object":
            return {}
        return "<value>"

    return {name: _stub(props.get(name)) for name in required if isinstance(name, str)}


def _render_target_scaffold(
    *,
    tf: Any,
    tool_names: list[str],
    suggested_weaknesses: list[str],
    system_prompt_file: Path | None,
    roles: _ToolRoles | None = None,
    tools: list[Any] | None = None,
    readback: ReadbackChoice | bool | None = True,
) -> str:
    """Render a ``target.yaml`` that runs as written.

    When ``roles`` is supplied, a ``seed_arm`` the scan's auto-wire would infer
    and an ``effect_probe`` on a no-argument readback tool are written live,
    each tagged ``# auto-detected``; a candidate that still needs a human value
    stays commented (see ``_render_seed_arm_block`` and
    ``_render_effect_probe_block``). ``tools`` (the same list ``roles`` was classified from) drives
    two things that must never diverge from what a live scan would do: the
    "consequential tools detected" hint (``control_shim.consequential_tool_names``
    — the SAME classifier the runtime W4 control and ``mylonite check`` use, so
    this hint can't disagree with what actually gets gated, #217 cause 3) and the
    verify tool's required-argument stub (see ``_verify_args_stub``).
    """

    from mylonite._redaction import redact_env
    from mylonite.scan.control_shim import consequential_tool_names

    roles = roles or _ToolRoles(None, None, None, None, [])
    tools = tools or []
    consequential_tools = [name for name, _reason in consequential_tool_names(tools)]

    def _yaml_list(items: list[str]) -> str:
        return yaml.safe_dump(items, default_flow_style=True).strip()

    args_line = _yaml_list(list(tf.args)) if tf.args else "[]"
    env_block = ""
    if tf.env:
        # Dump as a proper YAML mapping so values with ':' (e.g. sqlite URLs) are
        # quoted/escaped correctly — never hand-roll per-value scalars. A credential-
        # shaped --env value (e.g. a live GITHUB_TOKEN) must not reach the scaffold
        # file on disk in cleartext — same leak class as the scan/generate/gate
        # target.yaml writes, just a fourth, earlier origination path (DCR-0006).
        env_block = yaml.safe_dump({"env": redact_env(dict(tf.env))}, default_flow_style=False)
    prompt_line = (
        f"system_prompt_file: {system_prompt_file}\n"
        if system_prompt_file is not None
        else '# system_prompt_file: prompt.txt   # or set system_prompt: "..." inline\n'
    )
    scope_line = f"scope: {tf.scope}\n" if tf.scope is not None else "# scope: my-scope\n"

    # The seed_arm and effect_probe blocks. A block the scan can use as written
    # goes in live, tagged `# auto-detected: <why>`; anything that still needs a
    # human value stays commented with the candidate filled in.
    from mylonite.scan.tool_roles import effect_readback

    # ``readback=True`` (the default) means "detect it from ``tools``"; tests
    # pass a ReadbackChoice (or None) to pin one.
    chosen = effect_readback(tools) if readback is True else readback
    seed_arm_block = _render_seed_arm_block(roles, tools)
    effect_block = _render_effect_probe_block(
        readback=chosen if isinstance(chosen, ReadbackChoice) else None,
        tools=tools,
        effectful=sorted({"W3", "W4"} & set(suggested_weaknesses)),
    )
    from mylonite.scan.tool_inventory import inventory_comment_lines, tool_inventory

    # Every tool with its role and that role's source, from the same inventory
    # `mylonite check` prints. Comments only: the scan reads nothing from it.
    inventory_block = (
        "\n" + "\n".join(inventory_comment_lines(tool_inventory(tools))) + "\n" if tools else ""
    )
    sink_hint = (
        f"# Consequential-action tools detected (W4 candidates): {', '.join(consequential_tools)}.\n"
        if consequential_tools
        else ""
    )
    return f"""\
# Mylonite custom-target scaffold — generated by `mylonite scan --scaffold`.
# Blocks tagged `# auto-detected` are live: the scan uses them as written.
# Review them, and edit anything that does not match your server.
family: {tf.family}
command: {tf.command}
args: {args_line}
{env_block}{scope_line}{prompt_line}
# Discovered tools: {", ".join(tool_names) or "(none)"}.
# primary_tools: recorded for documentation; nothing reads it yet (see docs/target-file.md).
# Use weakness_classes to control what gets tested.
primary_tools: {_yaml_list(tool_names) if tool_names else "[]"}
{inventory_block}
# Weakness classes this target exposes (only classes this surface can be tested for):
#   W1 tool-description instruction smuggling · W2 indirect injection
#   W3 unrestricted egress / SSRF · W4 unconfirmed consequential action
weakness_classes: {_yaml_list(suggested_weaknesses) if suggested_weaknesses else "[]"}

# How to plant untrusted content for indirect-injection (W2) seeds. {{payload}}
# is replaced per attempt with a natural-language payload. It goes at the tool's
# free-text content slot — a bare string leaf for a simple tool, or a nested
# array/object slot for a batched-record tool (matching the tool's own schema;
# do NOT flatten it to a string).
{seed_arm_block}
# How to CONFIRM the damage materialised end-to-end (the effect probe). After the
# attack, the scan re-reads the target's state and checks the side effect is new.
{sink_hint}{effect_block}"""


def _render_seed_arm_block(roles: _ToolRoles, tools: list[Any]) -> str:
    """The seed_arm block: live when the scan's own auto-wire
    (:func:`~mylonite.plugins._mcp.target_file.infer_seed_arm`) infers one from
    ``tools``, commented otherwise, so the scaffold never writes a seed_arm the
    scan would not."""
    from mylonite.plugins._mcp.target_file import infer_seed_arm

    # One source for the block AND its comment: infer_seed_arm classifies
    # ``tools`` with _classify_tools, so read the recall tool from the same
    # classification rather than from the caller's ``roles``.
    spec = infer_seed_arm(tools)[0] if tools else None
    if tools:
        roles = _classify_tools(tools)
    sa_param = roles.seed_arm_param or "body"
    template = (
        dict(spec.args_template)
        if spec is not None
        else roles.seed_arm_args_template or {sa_param: "{payload}"}
    )
    nested = template != {sa_param: "{payload}"}
    placement = "# args_template places {payload} at this tool's content slot " + (
        "(a nested array-of-records slot, auto-detected)." if nested else "(a bare string leaf)."
    )
    id_help = (
        "#   id_key: id         # the field in the store tool's RESULT holding the new record's\n"
        "#                      # handle (look for: id, uuid, note_id, key, _id). ONLY needed when\n"
        "#                      # recall requires that id; a list/search-style recall does not.\n"
        "#                      # Alternatives: id_pattern (a regex) or id_from: first_int.\n"
    )
    if spec is not None:
        live = yaml.safe_dump(
            {"seed_arm": {"tool": spec.tool, "args_template": template}}, sort_keys=False
        )
        return (
            f"# auto-detected: {spec.tool} stores content and "
            f"{roles.retrieve_tool} surfaces it without an id.\n"
            "# This is the seed_arm a scan would wire on its own; confirm or edit it.\n"
            f"{placement}\n{live}{id_help}"
        )
    if roles.seed_arm_tool is not None:
        status = (
            f"# CANDIDATE: {roles.seed_arm_tool} stores content, but no id-free retrieval "
            "tool was detected, so a\n# planted payload may never be read back: the agent "
            "never learns a new record's id.\n# Left commented, and W2 is not suggested "
            "above for that reason. Declare a seed_arm\n# by hand if your server can "
            "recall what it stores."
        )
    else:
        status = "# (no content-storing tool auto-detected — fill in the tool that ingests content)"
    tool = roles.seed_arm_tool or "<tool that stores/accepts untrusted content>"
    args = "\n".join(
        f"#     {line}" for line in yaml.safe_dump(template, sort_keys=False).splitlines()
    )
    return (
        f"{status}\n{placement}\n# seed_arm:\n#   tool: {tool}\n#   args_template:\n"
        f"{args}\n{id_help}"
    )


def _render_effect_probe_block(
    *, readback: ReadbackChoice | None, tools: list[Any], effectful: list[str]
) -> str:
    """The effect_probe block.

    Live only when the file lists W3 or W4 and ``readback`` (from
    :func:`~mylonite.scan.tool_roles.effect_readback`) is safe, tied to a
    consequential tool, and takes no required argument. It declares no
    ``expect_marker`` (any new change a linked call made counts) and no
    deferral words, so a reply that says "queued" stays inconclusive
    (``MYL-INC-012``). Anything else is a commented hint, and with no probe in
    the file the scan reads each W3/W4 class NOT TESTED (``MYL-NT-017``)
    unless an attempt fires.
    """
    from mylonite import reason_codes

    by_name = {getattr(t, "name", ""): t for t in tools}
    verify_obj = by_name.get(readback.tool) if readback is not None else None
    # The verify tool's own required top-level args, stubbed to a type-valid
    # placeholder — never the bare `{}` that used to make the verify call
    # error against a tool like `read_text_file` (requires `path`).
    verify_args = _verify_args_stub(verify_obj) if verify_obj is not None else {}
    verify_args_line = (
        yaml.safe_dump(verify_args, default_flow_style=True).strip() if verify_args else "{}"
    )
    classes = "/".join(effectful)
    optional = (
        '#   expect_marker: "{exfil_email}"  # optional: "{exfil_email}" for a send (W4),\n'
        '#                                   # "{exfil_host}" for a fetch (W3). Ties the\n'
        "#                                   # effect to this attempt's own destination.\n"
        '#   deferred_markers: ["held for approval"]  # words that mark a HELD item in the\n'
        "#                                   # readback. Leave unset unless you know them.\n"
    )
    if effectful and readback is not None and readback.tied and not verify_args:
        live = yaml.safe_dump(
            {"effect_probe": {"verify_tool": readback.tool, "verify_args_template": {}}},
            sort_keys=False,
        )
        return (
            f"# auto-detected: {readback.tool} reads back what this server's consequential "
            f"tools change.\n# Confirm it shows what a {classes} attack would change. With "
            "no expect_marker, any new\n# change a call from this attempt made counts as the "
            "effect. A reply that says it queued\n# the action reads NOT TESTED "
            f"[{reason_codes.INC_UNCHECKED_DEFERRAL}], never resisted.\n"
            "# Calibration: before trusting this probe, the first scan calls up to five of "
            "this server's\n# consequential tools for real (never one marked destructive), "
            "with myl-cal- marker values,\n# to prove the probe sees a change. Add "
            '`calibration: {controls: skip}` to turn that off;\n# a probe\'s "no change" '
            f"then never clears a call [MYL-INC-002]. "
            "See docs/target-file.md.\n"
            "# Attempts on a target with an effect_probe run one at a time.\n"
            f"{live}{optional}"
        )
    unconfirmable = (
        f"# effect unconfirmable: with no effect_probe in this file, each {classes} class "
        f"reads NOT TESTED\n# [{reason_codes.NT_EFFECT_UNCONFIRMABLE}] unless an attempt "
        "fires.\n"
        if effectful
        else ""
    )
    if readback is None:
        status = (
            f"{unconfirmable}# No tool on this server is safe to read its state back "
            "(a whole-word read name, no write\n# or destructive annotation, not "
            "consequential). Point an effect_probe at one if it exists."
        )
    elif not readback.tied:
        status = (
            f"{unconfirmable}# CANDIDATE verify_tool: {readback.tool}. It reads state "
            "back, but nothing ties it to a\n# consequential tool, so it may not show the "
            "effect. Check it does, then uncomment."
        )
    else:
        status = (
            f"{unconfirmable}# CANDIDATE verify_tool (auto-detected): {readback.tool}. "
            "It needs arguments: fill in each\n# <value> with what the attack would "
            "change, then uncomment."
        )
    verify_tool = readback.tool if readback is not None else "<tool that reports the side effect>"
    return (
        f"{status}\n# effect_probe:\n#   verify_tool: {verify_tool}\n"
        f"#   verify_args_template: {verify_args_line}\n{optional}"
    )


def _scaffold_target_file(
    *,
    output: Path,
    command: str | None,
    arg: list[str] | None,
    env: list[str] | None,
    scope: str | None,
    system_prompt: str | None,
    system_prompt_file: Path | None,
    model: str | None,
    force: bool,
) -> None:
    """Implement ``scan --scaffold``: launch the MCP server, list its tools, and
    write a commented ``target.yaml`` starter (NO LLM call, no attack).

    Introspects the live tool surface and writes a starter with SUGGESTED
    ``weakness_classes`` / ``primary_tools`` and a ``seed_arm`` + ``effect_probe``
    template for the operator to fill in. The suggestions are hints grounded in
    the bundled OWASP-LLM/ASI taxonomy — the operator owns the
    consequential-capability + effect-probe declarations, so they review and edit
    before scanning.
    """

    from mylonite.plugins._mcp.factory import build_mcp_adapter
    from mylonite.plugins._mcp.target_file import build_target_spec

    if not command:
        echo_err("--scaffold needs --command (the MCP server launch command).")
        raise typer.Exit(code=EXIT_CONFIG)

    if output.exists() and not force:
        echo_err(f"{output} already exists — pass --force to overwrite.")
        raise typer.Exit(code=EXIT_CONFIG)

    try:
        _check_output_writable(output)
    except _OutputNotWritable as exc:
        echo_err(str(exc))
        raise typer.Exit(code=EXIT_CONFIG) from exc

    tf = _target_file_from_flags(
        command=command,
        args=arg,
        env=env,
        scope=scope,
        system_prompt=system_prompt,
        system_prompt_file=system_prompt_file,
        primary_tools=None,
        weakness_classes=None,
    )

    try:
        spec = build_target_spec(tf)
    except Exception as exc:
        echo_exc("invalid target flags", exc)
        raise typer.Exit(code=EXIT_CONFIG) from exc

    target_registry.clear_runtime_targets()
    target_registry.register_target(spec)
    # --scaffold makes no LLM call (introspection/describe() only), so `model`
    # stays whatever the caller passed -- possibly None -- rather than
    # defaulting to one.
    adapter = build_mcp_adapter(family=spec.family, scope=tf.scope, model=model)

    echo_err(f"launching {command!r} to introspect its tools (no LLM call)…")
    try:
        descriptor = asyncio.run(adapter.describe())
    except Exception as exc:
        echo_exc("could not launch / introspect the MCP server", exc)
        echo_err("check --command/--arg/--env and that the server speaks MCP over stdio.")
        raise typer.Exit(code=EXIT_CONFIG) from exc

    tools = list(descriptor.tools)
    tool_names = [t.name for t in tools]
    suggested_weaknesses = _suggest_weakness_classes(tools)
    roles = _classify_tools(tools)

    # #18/#187 footgun: warn (do not block) on a relative SQLite DB path in
    # either `env` or `args`.
    for warning in relative_sqlite_path_warnings(tf):
        echo_err(f"warning: {warning}")

    # #187: write `system_prompt_file` re-based onto the SCAFFOLDED file's own
    # directory, not the (possibly different) directory `--scaffold` ran from
    # -- the base `load_target_file` will resolve it against later.
    written_system_prompt_file = (
        _rebase_relative_path(system_prompt_file, output=output)
        if system_prompt_file is not None
        else None
    )
    if written_system_prompt_file is not None:
        from mylonite._paths import PathEscapesBase, resolve_contained

        try:
            resolve_contained(
                written_system_prompt_file,
                base=output.resolve().parent,
                label="system_prompt_file",
            )
        except PathEscapesBase:
            # No representation of this path can load: `system_prompt_file`
            # must stay inside the target file's own directory (see
            # resolved_system_prompt_path). Warn now, at scaffold time,
            # instead of leaving the operator to discover it only when a
            # later `scan`/`check` fails to load the file.
            echo_err(
                f"warning: --system-prompt-file {system_prompt_file} is outside "
                f"{output.resolve().parent}, the directory the scaffolded file will live "
                "in. A target file's system_prompt_file must stay inside that directory; "
                "move the prompt file there, or pass --system-prompt inline instead."
            )

    yaml_text = _render_target_scaffold(
        tf=tf,
        tool_names=tool_names,
        suggested_weaknesses=suggested_weaknesses,
        system_prompt_file=written_system_prompt_file,
        roles=roles,
        tools=tools,
    )

    # Round-trip-validate the scaffold we are about to write so it never lands broken.
    from mylonite.plugins._mcp.target_file import TargetFile

    try:
        written = TargetFile.model_validate(yaml.safe_load(yaml_text))
    except Exception as exc:  # pragma: no cover - defensive; the scaffold is fixed-shape
        echo_exc("internal error: scaffolded YAML failed validation", exc)
        raise typer.Exit(code=EXIT_CONFIG) from exc

    _atomic_write_text(output, yaml_text)
    echo(f"wrote {output} — {len(tool_names)} tools discovered.")
    echo_err(
        f"  weakness_classes {suggested_weaknesses or '[]'}: the classes this surface "
        "can be tested for."
    )
    from mylonite.scan.tool_inventory import tool_inventory, unknown_tools

    unknown = unknown_tools(tool_inventory(tools))
    echo_err(
        "  tool inventory: every tool is listed in the file with its role and where the "
        "role came from."
        + (
            f" {len(unknown)} have an unknown role and are treated as consequential: "
            f"{', '.join(unknown)}."
            if unknown
            else ""
        )
    )
    # Describe what was WRITTEN (the round-tripped file), so these lines can
    # never disagree with the file or with what the scan then does.
    needs_hand_edit = False
    if written.seed_arm is not None:
        echo_err(
            f"  seed_arm: auto-detected and written live: {written.seed_arm.tool} plants "
            f"content, {roles.retrieve_tool} recalls it."
        )
    elif roles.seed_arm_tool is not None:
        echo_err(
            f"  seed_arm: {roles.seed_arm_tool} stores content, but no id-free retrieval tool "
            "was found to read it back. The agent never learns a new record's id, so a store "
            "whose only readback needs that id cannot deliver a planted payload. The block is "
            "left commented and W2 is not suggested."
        )
    effectful = sorted({"W3", "W4"} & set(written.weakness_classes))
    classes = "/".join(effectful)
    from mylonite import reason_codes
    from mylonite.scan.tool_roles import effect_readback

    readback = effect_readback(tools)
    if written.effect_probe is not None:
        echo_err(
            f"  effect_probe: auto-detected and written live: {written.effect_probe.verify_tool} "
            f"reads back what the consequential tools change. Check it shows what a {classes} "
            "attack would change. The first scan calibrates it by calling those tools for "
            "real (calibration: {controls: skip} turns that off; see docs/target-file.md)."
        )
    elif effectful:
        needs_hand_edit = readback is not None
        why = (
            f"candidate {readback.tool} needs arguments"
            if readback is not None and readback.tied
            else f"candidate {readback.tool} is not tied to a consequential tool"
            if readback is not None
            else "no tool on this server is safe to read its state back"
        )
        echo_err(
            f"  effect_probe: none written live ({why}). Until one is declared, the "
            f"{classes} effect is unconfirmable: those classes read NOT TESTED "
            f"[{reason_codes.NT_EFFECT_UNCONFIRMABLE}] unless an attempt fires."
        )
    from mylonite._authz import required_authorization
    from mylonite._target_env import echo_env_notice

    echo_env_notice(yaml_text, output)
    run = (
        f"`mylonite scan --target-file {output} "
        f"--authorize {required_authorization(family=spec.family, scope=tf.scope)}`"
    )
    if needs_hand_edit:
        echo_err(f"  next: fill in the commented effect_probe, then run {run}.")
    else:
        echo_err(f"  next: review the auto-detected blocks, then run {run}.")


_RESERVED_FAMILIES = frozenset({"filesystem", "fetch", "github", "target", "app"})


def _redact_credential_shaped_json_body(body: str) -> str:
    """Mask any JSON string leaf that looks like a live credential (DCR-0002).

    Best-effort: only touches ``body`` when it parses as JSON (the common
    case — the default/most rest-body templates are simple JSON objects) and
    only rewrites it when something was actually masked, so a non-JSON or
    already-clean body is returned byte-for-byte unchanged (never reformatted
    for no reason). Uses the same :func:`~mylonite._redaction.looks_like_api_key`
    heuristic as :func:`mylonite._redaction.redact_url_query` — the
    ``{prompt}`` placeholder itself is far too short to ever match it.
    """
    import json

    from mylonite._redaction import REDACTION_PLACEHOLDER, looks_like_api_key

    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return body

    def _walk(value: object) -> object:
        if isinstance(value, str):
            return REDACTION_PLACEHOLDER if looks_like_api_key(value) else value
        if isinstance(value, dict):
            return {k: _walk(v) for k, v in value.items()}
        if isinstance(value, list):
            return [_walk(v) for v in value]
        return value

    masked = _walk(data)
    if masked == data:
        return body
    return json.dumps(masked)


def _scaffold_rest_target_file(
    *,
    output: Path,
    rest_url: str,
    rest_body: str | None,
    rest_response_path: str | None,
    force: bool,
) -> None:
    """Implement ``scan --scaffold --rest-url``: write a RUNNABLE HTTP-agent target.

    A plain HTTP agent has nothing to introspect, so (unlike the MCP scaffold) this
    writes a complete, ready-to-scan ``target.yaml`` for the endpoint — no hand-editing
    required. See docs/http-agent.md.
    """
    from mylonite.plugins._mcp.target_file import TargetFile, dump_target_file
    from mylonite.plugins._mcp.target_registry import RequestSpec

    if output.exists() and not force:
        echo_err(f"{output} already exists — pass --force to overwrite.")
        raise typer.Exit(code=EXIT_CONFIG)

    try:
        _check_output_writable(output)
    except _OutputNotWritable as exc:
        echo_err(str(exc))
        raise typer.Exit(code=EXIT_CONFIG) from exc

    body = rest_body or '{"prompt": "{prompt}"}'
    if "{prompt}" not in body:
        echo_err("--rest-body must contain a {prompt} placeholder.")
        raise typer.Exit(code=EXIT_CONFIG)

    import re

    stem = re.sub(r"[^a-z0-9]+", "-", output.stem.lower()).strip("-") or "http-agent"
    family = "http-agent" if stem in _RESERVED_FAMILIES else stem

    # This TargetFile is only ever serialised to disk below — no live request is
    # made from this scaffold path — so redacting rest_url/rest_body BEFORE
    # construction is safe and closes the credential-in-URL leak (DCR-0002)
    # at the source, on top of dump_target_file's own generic redaction pass.
    from mylonite._redaction import redact_url_query

    safe_url = redact_url_query(rest_url)
    safe_body = _redact_credential_shaped_json_body(body)

    try:
        tf = TargetFile(
            family=family,
            transport="rest",
            weakness_classes=["W2"],
            request=RequestSpec(url=safe_url, body=safe_body, response_path=rest_response_path),
        )
    except Exception as exc:
        echo_exc("invalid rest target", exc)
        raise typer.Exit(code=EXIT_CONFIG) from exc

    header = (
        "# Mylonite HTTP-agent target — generated by `mylonite scan --scaffold ... --rest-url`.\n"
        "# A black-box HTTP agent is tested for prompt-injection / goal-hijack (W2), judged\n"
        "# on the reply. This file is runnable as-is; edit the request block to match your\n"
        "# endpoint (auth goes in request.headers — never logged). See docs/http-agent.md.\n\n"
    )
    from mylonite._target_env import echo_env_notice

    text = header + dump_target_file(tf)
    _atomic_write_text(output, text)
    echo(f"wrote runnable HTTP-agent target -> {output}")
    echo_env_notice(text, output)
    echo_err(f"next: mylonite scan --target-file {output} --authorize {family}")
