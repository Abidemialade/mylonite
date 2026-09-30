"""The `mylonite check` command: static structural pre-check of a target.

Extracted out of ``cli.py`` (#91/#197 follow-up) to keep the composition
root thin. See ``tests/test_cli_size.py``.

``_discover_run_config`` is imported lazily, inside the function body,
because it still lives in ``mylonite.cli`` and ``cli.py`` imports this
module at load time to register the command -- a module-level import here
would be a circular import.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.markup import escape as rich_escape
from rich.table import Table

from mylonite._cli_io import (
    _exit_if_missing_target_file,
    console_print,
    echo,
    echo_err,
    echo_exc,
)
from mylonite.exit_codes import EXIT_CONFIG, EXIT_FINDINGS, EXIT_SUCCESS
from mylonite.plugins.cli_targets import _build_adapter_for_reference
from mylonite.scan.control_shim import _check_description_pins, _has_approval_sibling
from mylonite.scan.tool_classifier import destination_tools
from mylonite.scan.tool_roles import content_processor_tools, instruction_bearing_tools

_console = Console()


def check(
    target: Annotated[
        str | None,
        typer.Argument(help="`reference:vulnerable` / `reference:guarded`, or use --target-file."),
    ] = None,
    target_file: Annotated[
        Path | None,
        typer.Option("--target-file", help="Custom-target YAML: the app to check."),
    ] = None,
    enforce: Annotated[
        bool,
        typer.Option(
            "--enforce",
            help=(
                "Exit 1 on substantive W1-W4 structural findings, instead of reporting "
                "and exiting 0. The 'unpinned descriptions' advisory (which fires on "
                "every tool of every server on first contact) does NOT gate, so this is "
                "adoptable as a CI stage from day one."
            ),
        ),
    ] = False,
    run_config_path: Annotated[
        Path | None,
        typer.Option(
            "--config",
            help=(
                "A declarative mylonite.yaml run config. Fills --target-file when you "
                "omit it; auto-discovered from ./mylonite.yaml when present; an explicit "
                "flag always wins."
            ),
        ),
    ] = None,
) -> None:
    """Static structural pre-check of a target's tool surface: no LLM, no API key, no spend.

    Connects to the target ONCE (`describe()` — exactly what `scan --scaffold`
    already does) and reports structural exposure from the tool schemas alone:
    consequential tools with no approval-shaped sibling, descriptions that
    steer the agent, tools taking an apparent network destination, content-
    processing tools that could carry an indirect-injection payload, unpinned
    tool descriptions (rug-pull exposure), and which weakness classes the
    surface suggests. Every finding is a HINT to confirm, never a verdict —
    the differential oracle (`scan`/`gate`) is what proves an attack actually
    lands. Belongs in CI stage 1, next to lint: cheap enough to run on every
    push, unlike the live stages that spend LLM budget.
    """
    from mylonite.cli import _discover_run_config
    from mylonite.plugins._mcp import target_registry
    from mylonite.plugins._mcp.factory import build_mcp_adapter
    from mylonite.plugins._mcp.target_file import build_target_spec, load_target_file_and_warn
    from mylonite.report.render import trifecta_lines
    from mylonite.scan.control_shim import (
        consequential_tool_names,
        coverable_weakness_classes,
        outbound_tool_names,
        trifecta_legs,
        untrusted_content_tool_names,
        unwired_tool_names,
    )

    _config_path, rc = _discover_run_config(run_config_path, command="check")
    if target_file is None and rc is not None:
        target_file = rc.target_file

    # The bundled reference app needs no target file, so `check` is runnable with
    # nothing configured and no key -- the second step of the zero-key path after
    # `mylonite demo`, and the one a reader points at their own server next.
    tf = None
    if target is not None and target.startswith("reference:"):
        adapter = _build_adapter_for_reference(target, "claude-haiku-4-5-20251001")
    else:
        if target_file is None:
            echo_err(
                "pass `reference:vulnerable`, or --target-file (or set target_file: in "
                "mylonite.yaml). See `mylonite scan --scaffold` to create one."
            )
            raise typer.Exit(code=EXIT_CONFIG)
        try:
            tf = load_target_file_and_warn(target_file)
            spec = build_target_spec(tf)
        except Exception as exc:
            _exit_if_missing_target_file(exc, target_file)
            echo_exc(f"could not load {target_file}", exc)
            raise typer.Exit(code=EXIT_CONFIG) from exc
        target_registry.clear_runtime_targets()
        target_registry.register_target(spec)
        adapter = build_mcp_adapter(
            family=spec.family, scope=tf.scope, model="claude-haiku-4-5-20251001"
        )

    echo_err(f"connecting to {target_file or target} to introspect its tools (no LLM call)…")
    try:
        descriptor = asyncio.run(adapter.describe())
    except Exception as exc:
        echo_exc("could not connect to / introspect the target", exc)
        raise typer.Exit(code=EXIT_CONFIG) from exc

    tools = list(descriptor.tools)
    if not tools:
        echo_err("target exposed no tools — nothing to check.")
        raise typer.Exit(code=EXIT_SUCCESS)

    # None on the reference route (no target file): every `cc`-derived value
    # below already treats a missing control_config as "nothing declared".
    cc = tf.control_config if tf is not None else None
    declared_consequential = (
        frozenset(cc.consequential_tools) if cc and cc.consequential_tools else None
    )
    sinks = consequential_tool_names(tools, declared=declared_consequential)
    unapproved_sinks = [
        (name, reason) for name, reason in sinks if not _has_approval_sibling(tools, name)
    ]

    egress = destination_tools(tools)
    declared_egress = set(cc.egress_tools) if cc else set()
    egress_names = {name for name, _param, _reason in egress}
    for name in sorted(declared_egress - egress_names):
        egress.append((name, "(declared)", "declared"))

    steering = instruction_bearing_tools(tools)
    processors = content_processor_tools(tools)
    unpinned = _check_description_pins(tools, cc)
    # #181c: a misspelled/stale wiring name silently never fires at scan time.
    wiring_issues = unwired_tool_names(tf, tools)
    # Derived from THIS command's own findings above (never disagrees with the
    # table), not scan --scaffold's separate, wider keyword heuristic. #181b:
    # then gated through the same coverability check `scan` itself applies,
    # so this line never suggests a class `scan` would then refuse to run.
    suggested_set = {"W1", "W2"}  # baseline: any tool-using agent risks smuggling/injection
    if egress:
        suggested_set.add("W3")
    if unapproved_sinks:
        suggested_set.add("W4")
    suggested = coverable_weakness_classes(suggested_set, tools)

    findings = 0
    table = Table(title=f"Structural check — {len(tools)} tools discovered")
    table.add_column("Check")
    table.add_column("Detail")
    table.add_column("Confidence")

    if unapproved_sinks:
        findings += len(unapproved_sinks)
        for name, reason in unapproved_sinks:
            table.add_row(
                "Consequential action, no approval step (W4)",
                rich_escape(name),
                reason,
            )
    if steering:
        findings += len(steering)
        for name, excerpt in steering:
            table.add_row(
                "Description steers the agent (W1)",
                rich_escape(f"{name}: {excerpt!r}"),
                "pattern match",
            )
    if egress:
        findings += len(egress)
        for name, param, reason in egress:
            table.add_row(
                "Tool takes a network destination (W3)",
                rich_escape(f"{name}({param})"),
                reason,
            )
    if processors:
        findings += len(processors)
        for name, param in processors:
            table.add_row(
                "Content-processing tool, possible injection sink (W2)",
                rich_escape(f"{name}({param})"),
                "name hint",
            )
    if unpinned:
        # Counted per-tool (len(unpinned)), matching every other check above
        # -- this row summarises N tools in a single line, but "findings" is
        # the total number of individual tool-level issues, not the number
        # of check CATEGORIES that fired; a single "+1" here would silently
        # undercount relative to a target with many unpinned descriptions.
        findings += len(unpinned)
        table.add_row(
            "Unpinned tool descriptions (rug-pull exposure)",
            rich_escape(f"{len(unpinned)} tool(s) — see below for digests to pin"),
            "not pinned",
        )
    if wiring_issues:
        # Unlike "unpinned descriptions", this gates --enforce: a name with no real tool is a defect.
        findings += len(wiring_issues)
        for field, name in wiring_issues:
            table.add_row(
                "Target-file wiring names a tool not on the server",
                rich_escape(f"{field}: {name!r}"),
                "not on the described tool surface",
            )

    if findings == 0:
        echo("no structural exposure found on this tool surface.")
    else:
        console_print(_console, table)
        if unpinned:
            echo_err("description_pins to add under control_config:")
            for name, digest in unpinned:
                echo_err(f"  {name}: {digest}")
        echo_err(f"suggested weakness_classes {suggested or '[]'} (hints — confirm/edit).")

    # Advisory, like the unpinned-descriptions row: it never counts toward --enforce.
    legs = trifecta_legs(
        untrusted_content=[n for n, _ in untrusted_content_tool_names(tools)]
        + [n for n, _ in processors],
        external_communication=[name for name, _param, _reason in egress]
        + outbound_tool_names(tools, declared=frozenset(declared_egress)),
        private_tools=tuple(cc.private_tools) if cc else (),
        private_markers=tuple(cc.private_markers) if cc else (),
    )
    for line in trifecta_lines(legs):
        echo_err(line)

    echo(f"{findings} structural finding(s) across {len(tools)} tool(s).")
    # The "Unpinned tool descriptions" row fires on EVERY tool of EVERY
    # target on first contact (nothing is pinned yet), so counting it toward the
    # --enforce exit made `check --enforce` red for everyone — unusable as the
    # documented CI stage-1. It is advisory (a suggestion to pin, not a defect),
    # so it is EXCLUDED from the enforce gate while still shown in the table.
    # --enforce fails only on substantive W1-W4 structural findings.
    gating_findings = findings - len(unpinned)
    if enforce and gating_findings > 0:
        raise typer.Exit(code=EXIT_FINDINGS)
    raise typer.Exit(code=EXIT_SUCCESS)
