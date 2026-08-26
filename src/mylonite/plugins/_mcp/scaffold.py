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
from pathlib import Path
from typing import Any

import typer
import yaml
from pydantic import ValidationError

from mylonite._cli_io import echo, echo_err, echo_exc
from mylonite.exit_codes import EXIT_CONFIG
from mylonite.plugins._mcp import target_registry
from mylonite.scan.tool_roles import _classify_tools, _ToolRoles


def _relative_sqlite_env_keys(env: dict[str, str]) -> list[str]:
    """Env keys whose value looks like a SQLite DB referenced by a NON-absolute
    path — the #18 Windows footgun (a relative sqlite path silently opens a
    different/empty DB, making a vulnerable agent look clean)."""
    flagged: list[str] = []
    for key, val in env.items():
        low = val.lower()
        if "://" in val:
            # URL form. DCR-0011: match the SQLite marker against the URL
            # SCHEME, not an unanchored substring test anywhere in the value —
            # `"sqlite" in low` used to misclassify e.g.
            # `postgresql://sqlite-cache.internal:5432/app` (a non-SQLite URL
            # whose HOSTNAME merely contains "sqlite") as a relative SQLite path.
            scheme = low.split("://", 1)[0]
            if scheme not in ("sqlite", "sqlite3"):
                continue
            # The single '/' after the authority separator is NOT part of the
            # path, so `sqlite:///data.db` is RELATIVE `data.db` while
            # `sqlite:////abs/x.db` is absolute `/abs/x.db` — the exact #18 trap.
            after = val.split("://", 1)[1]
            path = after[1:] if after.startswith("/") else after
        else:
            if not ("sqlite" in low or low.endswith((".db", ".sqlite", ".sqlite3"))):
                continue
            path = val
        is_posix_abs = path.startswith("/")
        is_win_abs = len(path) >= 2 and path[1] == ":"  # C:\… or C:/…
        if not (is_posix_abs or is_win_abs):
            flagged.append(key)
    return flagged


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
    return sorted(suggestions)


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


def _render_target_scaffold(
    *,
    tf: Any,
    tool_names: list[str],
    suggested_weaknesses: list[str],
    system_prompt_file: Path | None,
    roles: _ToolRoles | None = None,
) -> str:
    """Render a commented, ready-to-edit ``target.yaml`` starter.

    When ``roles`` is supplied, the ``seed_arm`` and ``effect_probe`` blocks are
    pre-filled with concrete candidates auto-detected from the tool schemas
    (still commented — the operator confirms and uncomments), instead of blank
    placeholders.
    """

    from mylonite._redaction import redact_env

    roles = roles or _ToolRoles(None, None, None, None, [])

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

    # Pre-fill seed_arm/effect_probe from the detected roles (commented — confirm
    # then uncomment). Concrete tool + param names beat blank placeholders.
    sa_tool = roles.seed_arm_tool or "<tool that stores/accepts untrusted content>"
    sa_param = roles.seed_arm_param or "body"
    if roles.seed_arm_tool is not None and roles.retrieve_tool is not None:
        sa_status = (
            f"# CANDIDATE (auto-detected): {roles.seed_arm_tool} stores content; "
            f"{roles.retrieve_tool} surfaces it without an id."
        )
    elif roles.seed_arm_tool is not None:
        sa_status = (
            f"# CANDIDATE (auto-detected): {roles.seed_arm_tool} — WARNING: no id-free retrieval "
            "tool detected, so the planted poison may never be readable back (save_note trap)."
        )
    else:
        sa_status = (
            "# (no content-storing tool auto-detected — fill in the tool that ingests content)"
        )
    # The args_template to suggest: the NESTED template the auto-wire path
    # (tool_roles._content_slot_template) computes for a batched array-of-records
    # write, else the flat single-string form. The scaffold used to hard-code the
    # flat `{param: "{payload}"}` even for a tool whose content slot is nested
    # (server-memory's create_entities), producing a template the server's own
    # schema rejects — and a comment insisting on a "BARE string leaf" that is
    # impossible for such a tool. Reuse exactly what the live scan would infer.
    import yaml as _yaml

    _template = getattr(roles, "seed_arm_args_template", None) or {sa_param: "{payload}"}
    _nested = _template != {sa_param: "{payload}"}
    sa_args_block = "\n".join(
        f"#     {line}" for line in _yaml.safe_dump(_template, sort_keys=False).splitlines()
    )
    sa_placement_note = "# args_template below places {payload} at this tool's content slot " + (
        "(a nested array-of-records slot, auto-detected)." if _nested else "(a bare string leaf)."
    )
    verify_tool = roles.verify_tool or "<tool that reports the side effect>"
    ep_status = (
        f"# CANDIDATE verify_tool (auto-detected): {roles.verify_tool}."
        if roles.verify_tool is not None
        else "# (no side-effect-reporting tool auto-detected — point this at one)"
    )
    sink_hint = (
        f"# Consequential-action tools detected (W4 candidates): {', '.join(roles.sink_tools)}.\n"
        if roles.sink_tools
        else ""
    )
    return f"""\
# Mylonite custom-target scaffold — generated by `mylonite scan --scaffold`.
# Review and EDIT before scanning: the suggestions below are hints, not gospel.
family: {tf.family}
command: {tf.command}
args: {args_line}
{env_block}{scope_line}{prompt_line}
# Discovered tools: {", ".join(tool_names) or "(none)"}.
# primary_tools narrows seed selection to your consequential tools (optional).
primary_tools: {_yaml_list(tool_names) if tool_names else "[]"}

# Weakness classes this target exposes (SUGGESTED — confirm/edit):
#   W1 tool-description instruction smuggling · W2 indirect injection
#   W3 unrestricted egress / SSRF · W4 unconfirmed consequential action
weakness_classes: {_yaml_list(suggested_weaknesses) if suggested_weaknesses else "[]"}

# How to plant untrusted content for indirect-injection (W2) seeds. {{payload}}
# is replaced per attempt with a natural-language payload. It goes at the tool's
# free-text content slot — a bare string leaf for a simple tool, or a nested
# array/object slot for a batched-record tool (shown below, matching the tool's
# own schema; do NOT flatten it to a string).
{sa_status}
{sa_placement_note}
# seed_arm:
#   tool: {sa_tool}
#   args_template:
{sa_args_block}
#   id_key: id           # the field in the store tool's RESULT holding the new record's
#                        # handle (look for: id, uuid, note_id, key, _id). ONLY needed when
#                        # recall requires that id; a list/search-style recall does not.
#                        # Alternatives: id_pattern (a regex) or id_from: first_int.

# How to CONFIRM the damage materialised end-to-end (the effect probe). After the
# attack, re-query the target and check the damaging side effect is present.
{ep_status}
{sink_hint}# effect_probe:
#   verify_tool: {verify_tool}
#   verify_args_template: {{}}
#   expect_marker: "<a string proving the effect, e.g. the attacker recipient>"
#   deferred_markers: ["queued for approval", "pending review"]  # mark a DEFENDED result
"""


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
    adapter = build_mcp_adapter(
        family=spec.family, scope=tf.scope, model=model or "claude-haiku-4-5-20251001"
    )

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

    # #18 footgun: warn (do not block) on a relative SQLite DB path.
    for key in _relative_sqlite_env_keys(tf.env):
        echo_err(
            f"warning: env {key} looks like a relative SQLite path. "
            "On Windows a relative/ambiguous sqlite URL can open a DIFFERENT or empty "
            "DB, making a vulnerable agent look clean (#18). Prefer an absolute path. "
            "(value withheld — env values may carry credentials)"
        )

    yaml_text = _render_target_scaffold(
        tf=tf,
        tool_names=tool_names,
        suggested_weaknesses=suggested_weaknesses,
        system_prompt_file=system_prompt_file,
        roles=roles,
    )

    # Round-trip-validate the scaffold we are about to write so it never lands broken.
    from mylonite.plugins._mcp.target_file import TargetFile

    try:
        TargetFile.model_validate(yaml.safe_load(yaml_text))
    except Exception as exc:  # pragma: no cover - defensive; the scaffold is fixed-shape
        echo_exc("internal error: scaffolded YAML failed validation", exc)
        raise typer.Exit(code=EXIT_CONFIG) from exc

    output.write_text(yaml_text, encoding="utf-8")
    echo(f"wrote {output} — {len(tool_names)} tools discovered.")
    echo_err(
        "  suggested weakness_classes "
        f"{suggested_weaknesses or '[]'} (hints — confirm/edit before scanning)."
    )
    if roles.seed_arm_tool is not None:
        echo_err(
            f"  seed_arm candidate: {roles.seed_arm_tool}(...{roles.seed_arm_param}='{{payload}}') "
            f"+ retrieval via {roles.retrieve_tool!r}."
            if roles.retrieve_tool is not None
            else (
                f"  seed_arm candidate: {roles.seed_arm_tool} — but NO id-free retrieval tool was "
                "found to surface what it stores. The planner never learns a new record's id, so a "
                "store whose only readback needs that id (the save_note/read_note trap) will never "
                "deliver the poison. Confirm a list/recall/search-style tool exists, or expect those "
                "seeds to report NOT TESTED."
            )
        )
    elif "W2" in suggested_weaknesses:
        echo_err(
            "  no obvious content-storing tool found for the seed_arm — fill it in by hand "
            "(the tool that ingests untrusted content), or W2 seeds will report NOT TESTED."
        )
    from mylonite._authz import required_authorization

    echo_err(
        "  next: fill in the seed_arm (how to plant untrusted content) and the "
        "effect_probe (how to confirm damage), then run "
        f"`mylonite scan --target-file {output} "
        f"--authorize {required_authorization(family=spec.family, scope=tf.scope)}`."
    )
