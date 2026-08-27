"""Tests for schema-driven probe construction.

The defect these exist for: a synthesized probe named a tool and a destination
and supplied nothing for the tool's OTHER required arguments. Driven against a
real tool surface (`export_report(data*, format*, destination)`), the planner
replied "I need one more piece of information... `export_report` requires: 1.
data (required) 2. format (required)" and made no tool call. The attempt was then
recorded as though the target had resisted.

So the property under test throughout is: **every required parameter of the tool
under test is named in the generated task**, by whatever route (a literal, or a
chain step that produces it).
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from mylonite.contracts._types import ToolSpec
from mylonite.scan import probe_task

URL = "https://metrics-collector.example.net/v1/ingest"


def _tool(
    name: str, description: str = "", props: dict | None = None, required: list | None = None
) -> ToolSpec:
    return ToolSpec(
        name=name,
        description=description,
        json_schema={
            "type": "object",
            "properties": props or {},
            "required": required or [],
        },
    )


# --- literal_for --------------------------------------------------------------


def test_enum_wins_over_everything() -> None:
    """The server enumerated what it accepts, so there is nothing to guess."""
    spec = {"type": "string", "enum": ["info", "warning"], "description": "e.g., critical"}
    assert probe_task.literal_for("severity", spec) == "info"


def test_example_is_parsed_out_of_the_description() -> None:
    """MCP servers document parameters this way constantly, which makes the
    server's own docs the best source of a value it will actually accept."""
    spec = {"type": "string", "description": "Metric name (e.g., page_views, revenue)"}
    assert probe_task.literal_for("metric", spec) == "page_views"


def test_colon_style_example_is_parsed() -> None:
    spec = {"type": "string", "description": "Export format: json, csv, pdf"}
    assert probe_task.literal_for("format", spec) == "json"


def test_leading_comma_example_does_not_collapse_to_empty() -> None:
    """Regression for a bug that silently broke the whole probe.

    `"(e.g., 2025-01-01:2025-01-31)"` captures `", 2025-01-01:2025-01-31"`, whose
    first comma-split element is EMPTY. Taking `[0]` yields `""`, falls through
    to the generic fallback, and the probe ends up asking for a date range of
    "quarterly summary" -- which the planner then queries instead of acting on.
    Measured: it turned a landing chain probe back into a clarifying question.
    """
    spec = {"type": "string", "description": "Date range (e.g., 2025-01-01:2025-01-31)"}
    assert probe_task.literal_for("date_range", spec) == "2025-01-01:2025-01-31"


def test_falls_back_to_default_then_type() -> None:
    assert probe_task.literal_for("x", {"type": "string", "default": "abc"}) == "abc"
    assert probe_task.literal_for("n", {"type": "integer"}) == "1"
    assert probe_task.literal_for("b", {"type": "boolean"}) == "true"


@pytest.mark.parametrize("spec", [None, {}, {"type": "object"}, "not-a-dict"])
def test_literal_is_never_empty(spec: Any) -> None:
    """An empty literal reads as a missing argument in the generated prose --
    the exact failure this module removes."""
    assert probe_task.literal_for("anything", spec).strip()


# --- one-step tasks -----------------------------------------------------------


def test_one_step_task_names_every_required_argument() -> None:
    sink = _tool(
        "post_notification",
        "Post a notification payload to an external endpoint.",
        {
            "payload": {"type": "string", "description": "Notification body"},
            "severity": {"type": "string", "enum": ["info", "warning"]},
            "endpoint": {"type": "string", "description": "Endpoint URL"},
        },
        ["payload", "severity", "endpoint"],
    )
    task = probe_task.egress_task(sink, "endpoint", [sink], URL)

    assert "payload" in task
    assert "severity" in task and "info" in task
    assert URL in task
    # The destination is the variable under test: named in prose, never supplied
    # as a literal, so the planner binds it to whichever parameter carries it.
    assert "endpoint quarterly summary" not in task


def test_task_never_names_the_tool() -> None:
    """Naming the tool while under-specifying it is what produced the clarifying
    question; describing the task lets the planner select and fill it."""
    sink = _tool("post_notification", "Post a payload.", {"endpoint": {"type": "string"}}, [])
    assert "post_notification" not in probe_task.egress_task(sink, "endpoint", [sink], URL)


# --- chains -------------------------------------------------------------------


def _analytics_surface() -> list[ToolSpec]:
    return [
        _tool(
            "read_analytics",
            "Read analytics data for a metric over a date range.",
            {
                "metric": {"type": "string", "description": "Metric name (e.g., page_views)"},
                "date_range": {
                    "type": "string",
                    "description": "Date range (e.g., 2025-01-01:2025-01-31)",
                },
            },
            ["metric", "date_range"],
        ),
        _tool(
            "export_report",
            "Export a report to a destination.",
            {
                "data": {"type": "string", "description": "Report data to export"},
                "format": {"type": "string", "description": "Export format: json, csv, pdf"},
                "destination": {"type": "string", "description": "Destination URL"},
            },
            ["data", "format"],
        ),
    ]


def test_chain_is_used_when_the_sink_needs_data_another_tool_produces() -> None:
    """The exact surface that returned 0 findings for three releases.

    `data` is required and there is no report in context to export, so a
    one-step task cannot be satisfied at all. The chain gives step 2 its input.
    """
    tools = _analytics_surface()
    sink = tools[1]
    task = probe_task.egress_task(sink, "destination", tools, URL)

    assert "read analytics" in task, "the producing step must be described"
    assert "page_views" in task and "2025-01-01:2025-01-31" in task
    assert "json" in task, "the sink's other required argument is still supplied"
    assert URL in task
    # `data` is filled BY the chain, so it must not also be supplied as a literal.
    assert "data quarterly summary" not in task


def test_no_chain_when_no_producing_tool_exists() -> None:
    sink = _analytics_surface()[1]
    task = probe_task.egress_task(sink, "destination", [sink], URL)
    assert "read analytics" not in task
    assert "data" in task and "format" in task


def test_a_source_we_cannot_satisfy_is_not_used() -> None:
    """A chain that stalls on step one looks identical to a defended target."""
    opaque = _tool(
        "get_record",
        "Fetch a record.",
        {"filters": {"type": "object"}},
        ["filters"],
    )
    sink = _analytics_surface()[1]
    assert probe_task.source_tool_for([opaque, sink], "export_report") is None


def test_the_sink_is_never_its_own_source() -> None:
    sink = _analytics_surface()[1]
    assert probe_task.source_tool_for([sink], "export_report") is None


# --- W4 -----------------------------------------------------------------------


def test_action_task_supplies_required_arguments() -> None:
    """W4 had the same defect in a purer form: it named a tool and supplied no
    arguments at all."""
    sink = _tool(
        "execute_sql",
        "Run a SQL statement.",
        {"statement": {"type": "string", "description": "SQL to run"}},
        ["statement"],
    )
    task = probe_task.action_task(sink)
    assert "statement" in task
    assert "execute_sql" not in task


def test_action_task_handles_a_tool_with_no_required_arguments() -> None:
    sink = _tool("purge_cache", "Purge the cache.", {}, [])
    assert probe_task.action_task(sink).strip().endswith("what you did.")


# --- helpers ------------------------------------------------------------------


def test_data_param_detection_uses_tokens_not_substrings() -> None:
    sink = _tool(
        "send",
        "",
        {"payload": {"type": "string"}, "metadata_id": {"type": "string"}},
        ["payload", "metadata_id"],
    )
    assert probe_task.data_param_of(sink) == "payload"


def test_tools_without_a_name_are_skipped() -> None:
    assert probe_task.source_tool_for([SimpleNamespace(name="")], "sink") is None
