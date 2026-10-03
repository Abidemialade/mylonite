"""The pre-spend run plan for ``scan``, ``validate`` and ``gate``.

A live run drives the user's own tools, and some of those take real actions.
Before the first live call, these commands print what the run is about to do:
the model, where the agent's system prompt comes from, which consequential
tools the run may drive, and the target's ``control_config.never_call`` list.
A last line says to run against a test instance.

Everything here reads what the run already knows: the target file, the
adapter's cached tool listing, or the finding's recorded calls. The only
contact with the target is one tool listing (no tool call, no LLM call) when
nothing has listed the tools yet.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from typing import Any, Final

from mylonite._cli_io import echo_err

TEST_INSTANCE_LINE: Final = "Run against a test instance, never production."

DEFAULT_PROMPT_WARNING: Final = (
    "warning: no system prompt declared, so the agent runs under Mylonite's generic "
    "default prompt. Results depend heavily on the prompt, and some weaknesses only "
    "show under your app's real one. Declare it with system_prompt: or "
    "system_prompt_file: in the target file (or --system-prompt / --system-prompt-file)."
)

#: How long the plan waits for a tool listing before falling back to the
#: declared lists.
_DESCRIBE_TIMEOUT_S: Final = 20.0


def models_line(planner: str, customiser: str, judge: str) -> str:
    """One line naming the model, or each role's model when they differ."""
    if planner == customiser == judge:
        return f"Model: {planner} (planner, customiser and judge)"
    return f"Models: planner {planner}, customiser {customiser}, judge {judge}"


def prompt_source(target_file: Any | None, target_id: str) -> tuple[str, str | None]:
    """Where the agent's system prompt comes from, and a warning when it's the default."""
    if target_file is not None:
        if getattr(target_file, "transport", None) == "rest":
            return "set by your app (a rest target runs its own agent)", None
        if getattr(target_file, "system_prompt", None) is not None:
            return "declared inline in the target file (system_prompt)", None
        prompt_file = getattr(target_file, "system_prompt_file", None)
        if prompt_file is not None:
            return f"declared in {prompt_file} (system_prompt_file)", None
        return "Mylonite's generic default (none declared)", DEFAULT_PROMPT_WARNING
    if target_id.startswith("reference:"):
        return "the practice app's built-in prompt", None
    return "Mylonite's built-in prompt for this bundled server", None


def _control_config(target_file: Any | None, adapter: Any | None) -> Any | None:
    if target_file is not None:
        return getattr(target_file, "control_config", None)
    spec = getattr(adapter, "_spec", None)
    return getattr(spec, "control_config", None)


def _never_call(control_config: Any | None) -> tuple[str, ...]:
    from mylonite.plugins._mcp.never_call import never_call_names

    return never_call_names(control_config)


def _declared_drivable(control_config: Any | None) -> list[str]:
    if control_config is None:
        return []
    return list(
        dict.fromkeys(
            [*control_config.consequential_tools, *control_config.egress_tools],
        )
    )


def _from_inventory(tools: Sequence[Any], control_config: Any | None) -> list[str]:
    from mylonite.scan.tool_inventory import tool_inventory

    return [
        entry.name
        for entry in tool_inventory(tools, control_config=control_config)
        if entry.consequential or any(role.role == "egress" for role in entry.roles)
    ]


def _listed_tools(adapter: Any) -> Sequence[Any] | None:
    """The adapter's tool listing: the cached one, else one fresh listing."""
    cached = getattr(adapter, "_last_descriptor", None)
    if cached is not None:
        return list(cached.tools)
    describe = getattr(adapter, "describe", None)
    if describe is None:
        return None
    try:
        descriptor = asyncio.run(asyncio.wait_for(describe(), timeout=_DESCRIBE_TIMEOUT_S))
    except Exception:
        return None
    return list(descriptor.tools)


def drivable_tools(
    *,
    target_file: Any | None,
    target_id: str,
    adapter: Any | None = None,
    recorded_tools: Sequence[str] | None = None,
) -> str:
    """The consequential tools this run may drive, as one plain phrase."""
    if target_id.startswith("reference:"):
        return "none (the practice app runs inside Mylonite and takes no real action)"
    if target_file is not None and getattr(target_file, "transport", None) == "rest":
        return "your app's own (a rest target calls its tools itself)"
    cc = _control_config(target_file, adapter)
    never = set(_never_call(cc))
    names: list[str] | None = None
    source = ""
    if recorded_tools is not None:
        declared = _declared_drivable(cc)
        if declared:
            names, source = declared, " (declared in control_config)"
        else:
            names = list(dict.fromkeys(recorded_tools))
            source = " (the calls the recorded finding made)"
    elif adapter is not None:
        tools = _listed_tools(adapter)
        if tools is not None:
            names = _from_inventory(tools, cc)
        else:
            declared = _declared_drivable(cc)
            if declared:
                names, source = declared, " (declared; the tool list could not be read)"
    if names is None:
        return "unknown until the tools are listed; run `mylonite check` to see them"
    drive = [n for n in names if n not in never]
    if not drive:
        return "none" + source
    return ", ".join(drive) + source


def run_plan_lines(
    *,
    planner: str,
    customiser: str,
    judge: str,
    target_file: Any | None,
    target_id: str,
    adapter: Any | None = None,
    recorded_tools: Sequence[str] | None = None,
) -> list[str]:
    """The plan block, one string per printed line."""
    prompt, warning = prompt_source(target_file, target_id)
    never = _never_call(_control_config(target_file, adapter))
    lines = [
        "Run plan (nothing has been sent yet):",
        f"  {models_line(planner, customiser, judge)}",
        f"  System prompt: {prompt}",
        "  Consequential tools this run may drive: "
        + drivable_tools(
            target_file=target_file,
            target_id=target_id,
            adapter=adapter,
            recorded_tools=recorded_tools,
        ),
        "  never_call (blocked before the server): "
        + (", ".join(never) if never else "none declared"),
        TEST_INSTANCE_LINE,
    ]
    if warning is not None:
        lines.append(warning)
    return lines


def print_run_plan(
    *,
    planner: str,
    customiser: str,
    judge: str,
    target_file: Any | None,
    target_id: str,
    adapter: Any | None = None,
    recorded_tools: Sequence[str] | None = None,
) -> None:
    """Print the plan block to stderr, before the first live call."""
    for line in run_plan_lines(
        planner=planner,
        customiser=customiser,
        judge=judge,
        target_file=target_file,
        target_id=target_id,
        adapter=adapter,
        recorded_tools=recorded_tools,
    ):
        echo_err(line)
