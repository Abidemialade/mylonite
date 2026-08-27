"""Tests for the fail-closed tool classification shared by the boundary controls."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from mylonite.scan.tool_classifier import (
    _FILENAME_SUFFIXES,
    _is_reportable_destination,
    classify,
    destination_tools,
    looks_like_destination,
    url_values,
)


class _FakeTool:
    def __init__(self, name: str, json_schema: dict) -> None:
        self.name = name
        self.json_schema = json_schema


# -- looks_like_destination -----------------------------------------------------


def test_looks_like_destination_accepts_a_full_url() -> None:
    assert looks_like_destination("http://attacker.example/exfil")


def test_looks_like_destination_accepts_a_scheme_less_hostname() -> None:
    # DCR-0032: `web_fetch(host="attacker.example")` has no "://".
    assert looks_like_destination("attacker.example")


def test_looks_like_destination_accepts_a_hostname_with_path_or_port() -> None:
    assert looks_like_destination("attacker.example/exfil")
    assert looks_like_destination("attacker.example:8080")


def test_looks_like_destination_accepts_an_ip_literal() -> None:
    assert looks_like_destination("127.0.0.1")
    assert looks_like_destination("10.0.0.5")


def test_looks_like_destination_accepts_bare_localhost() -> None:
    # localhost is the single most common allowlist entry and has no dot.
    assert looks_like_destination("localhost")
    assert looks_like_destination("LOCALHOST")
    assert looks_like_destination("localhost:8080")


def test_looks_like_destination_rejects_a_plain_identifier() -> None:
    # A note id / free-text argument is not a destination just because it's a string.
    assert not looks_like_destination("1")
    assert not looks_like_destination("note-42")
    assert not looks_like_destination("hello world")


def test_looks_like_destination_rejects_non_strings() -> None:
    assert not looks_like_destination(42)
    assert not looks_like_destination(None)
    assert not looks_like_destination(["http://x.example"])


# -- url_values -------------------------------------------------------------------


def test_url_values_finds_a_scheme_less_bare_hostname_argument() -> None:
    # DCR-0032: the old extractor returned None for a scheme-less value, and
    # None short-circuited the allowlist to pass-through.
    assert url_values({"host": "attacker.example"}) == ["attacker.example"]


def test_url_values_walks_list_valued_arguments() -> None:
    found = url_values({"targets": ["http://attacker.example/exfil", "not-a-url"]})
    assert found == ["http://attacker.example/exfil"]


def test_url_values_walks_nested_dict_arguments() -> None:
    found = url_values({"request": {"headers": {}, "url": "http://attacker.example"}})
    assert found == ["http://attacker.example"]


def test_url_values_ignores_non_destination_arguments() -> None:
    assert url_values({"note_id": "1", "title": "hello world"}) == []


def test_url_values_returns_every_match_not_just_the_first() -> None:
    found = url_values({"primary": "http://a.example", "backup": "http://b.example"})
    assert found == ["http://a.example", "http://b.example"]


# -- classify ---------------------------------------------------------------------


def test_classify_declared_list_is_authoritative_true() -> None:
    matched, reason = classify("anything", declared=frozenset({"anything"}), hints=())
    assert matched is True
    assert reason == "declared"


def test_classify_declared_list_is_authoritative_false() -> None:
    # Even a name that matches a hint is exempted by a declared list that omits it.
    matched, reason = classify("web_fetch", declared=frozenset({"other_tool"}), hints=("fetch",))
    assert matched is False
    assert reason == "declared"


def test_classify_name_hint_matches() -> None:
    matched, reason = classify("web_fetch", declared=None, hints=("fetch",))
    assert matched is True
    assert reason == "name hint"


def test_classify_fail_closed_default_when_no_hint_matches() -> None:
    # DCR-0033/0034/0035: an unrecognised name is guarded, not passed through.
    matched, reason = classify("visit_page", declared=None, hints=("fetch", "http"))
    assert matched is True
    assert reason == "fail-closed default"


# -- destination_tools -----------------------------------------------------------


def test_destination_tools_matches_on_schema_default_over_name_hint() -> None:
    tools = [
        _FakeTool(
            "notify", {"properties": {"target": {"type": "string", "default": "attacker.example"}}}
        )
    ]
    found = destination_tools(tools)
    assert found == [("notify", "target", "schema default")]


def test_destination_tools_matches_on_param_name_hint() -> None:
    tools = [_FakeTool("web_fetch", {"properties": {"url": {"type": "string"}}})]
    found = destination_tools(tools)
    assert found == [("web_fetch", "url", "name hint")]


def test_destination_tools_matches_on_tool_name_hint_with_no_matching_param() -> None:
    tools = [_FakeTool("web_fetch", {"properties": {"query": {"type": "string"}}})]
    found = destination_tools(tools)
    assert found == [("web_fetch", "(unspecified)", "name hint")]


def test_destination_tools_is_silent_for_a_tool_with_no_destination_signal() -> None:
    """A discovery report, not a fail-closed gate: no signal means no finding."""
    tools = [_FakeTool("read_note", {"properties": {"note_id": {"type": "string"}}})]
    assert destination_tools(tools) == []


def test_destination_tools_ignores_non_string_params() -> None:
    tools = [_FakeTool("configure", {"properties": {"url": {"type": "integer"}}})]
    assert destination_tools(tools) == []


def test_uniform_default_annotations_detected_and_neutralized() -> None:
    """An SDK that stamps the SAME default annotation block on every
    tool (mcp-go's destructiveHint=true/openWorldHint=true) is not making
    declarations. Detect the uniform block and clear it so classification falls
    back to name/structure rather than flagging read-only tools as sinks."""
    from mylonite.contracts._types import ToolSpec
    from mylonite.scan.tool_classifier import (
        neutralize_uniform_default_annotations,
        uniform_default_annotations,
    )

    default = {"readOnlyHint": False, "destructiveHint": True, "openWorldHint": True}
    go_tools = [
        ToolSpec(name="read_analytics", description="read", annotations=dict(default)),
        ToolSpec(name="list_notes", description="list", annotations=dict(default)),
        ToolSpec(name="get_weather", description="weather", annotations=dict(default)),
    ]
    assert uniform_default_annotations(go_tools) is True
    cleared = neutralize_uniform_default_annotations(go_tools)
    assert all(t.annotations is None for t in cleared)


def test_meaningful_per_tool_annotations_are_untouched() -> None:
    """A server that annotates meaningfully (per-tool variety) must NOT be
    neutralized — the TypeScript case."""
    from mylonite.contracts._types import ToolSpec
    from mylonite.scan.tool_classifier import (
        neutralize_uniform_default_annotations,
        uniform_default_annotations,
    )

    ts_tools = [
        ToolSpec(name="read_file", description="r", annotations={"readOnlyHint": True}),
        ToolSpec(name="write_file", description="w", annotations={"destructiveHint": True}),
    ]
    assert uniform_default_annotations(ts_tools) is False
    kept = neutralize_uniform_default_annotations(ts_tools)
    assert kept[0].annotations == {"readOnlyHint": True}


# -- destination_tools: the shapes measured on real servers ----------------------
#
# These are not hypotheticals. The first two are the exact tool signatures of a
# live MCP server whose `export_report` tool was independently proven to accept
# an arbitrary external destination with no allowlist and no auth; `check`
# reported no network surface for it, and because `seed_synth._egress_candidates`
# delegates here, no W3 seed was synthesised either. The third is the
# mirror-image false positive observed on the reference "everything" server.


def test_destination_tools_matches_a_param_named_destination() -> None:
    """`destination` is not in the hint list at all, so exact equality missed it."""
    tools = [
        _FakeTool(
            "export_report",
            {
                "properties": {
                    "data": {"type": "string"},
                    "destination": {"type": "string", "description": "Destination URL"},
                    "format": {"type": "string"},
                }
            },
        )
    ]
    assert destination_tools(tools) == [("export_report", "destination", "name hint")]


def test_destination_tools_matches_a_compound_param_name() -> None:
    """`webhook_url` equals neither "webhook" nor "url"; it tokenises to both."""
    tools = [
        _FakeTool(
            "schedule_report",
            {
                "properties": {
                    "frequency": {"type": "string"},
                    "metric": {"type": "string"},
                    "webhook_url": {"type": "string"},
                }
            },
        )
    ]
    assert destination_tools(tools) == [("schedule_report", "webhook_url", "name hint")]


def test_destination_tools_matches_camel_case_param_name() -> None:
    tools = [_FakeTool("notify", {"properties": {"callbackUrl": {"type": "string"}}})]
    assert destination_tools(tools) == [("notify", "callbackUrl", "name hint")]


def test_destination_tools_does_not_report_a_filename_as_a_host() -> None:
    """A dotted filename in a schema default is not a network destination.

    `_HOSTNAME_RE` matches any dotted alphanumeric string, which is the right
    calibration for the live refusal path and the wrong one for a static report.
    """
    tools = [
        _FakeTool(
            "gzip_file",
            {
                "properties": {
                    "name": {"type": "string", "default": "README.md.gz"},
                    "outputType": {"type": "string", "default": "resourceLink"},
                }
            },
        )
    ]
    assert destination_tools(tools) == []


def test_destination_tools_still_reports_a_real_url_default() -> None:
    """The filename guard must not suppress a genuine destination."""
    tools = [
        _FakeTool(
            "gzip_file",
            {
                "properties": {
                    "name": {"type": "string", "default": "README.md.gz"},
                    "data": {
                        "type": "string",
                        "default": "https://raw.example.com/main/README.md",
                    },
                }
            },
        )
    ]
    assert destination_tools(tools) == [("gzip_file", "data", "schema default")]


def test_destination_tools_reports_an_ip_literal_default() -> None:
    tools = [
        _FakeTool("ping", {"properties": {"target": {"type": "string", "default": "10.0.0.5"}}})
    ]
    assert destination_tools(tools) == [("ping", "target", "schema default")]


def test_destination_tools_does_not_regress_on_an_unrelated_dotted_id() -> None:
    tools = [_FakeTool("get_record", {"properties": {"record_id": {"type": "string"}}})]
    assert destination_tools(tools) == []


# ---------------------------------------------------------------------------
# Regressions introduced by 0.8.3's egress-detection widening.
#
# 0.8.3 switched `destination_tools` to token matching and added
# `destination`/`dest`/`callback` to the hint list, which fixed a real false
# negative (a live server exposing `export_report(destination=...)` reported no
# network surface at all). It also created two new false-positive classes on the
# report path, both of them common shapes rather than exotic ones.
# ---------------------------------------------------------------------------


def _tool(name: str, description: str, props: dict[str, Any]) -> SimpleNamespace:
    return SimpleNamespace(name=name, description=description, json_schema={"properties": props})


def test_filesystem_dest_is_not_reported_as_a_network_destination() -> None:
    """`copy_file(src, dest)` is the commonest signature on a filesystem server.

    `dest` there is a PATH. Reporting it as egress surface puts a W3 row on a
    server that cannot egress, and — because `seed_synth._egress_candidates`
    delegates here — spends the scan budget synthesising a probe with nowhere
    to send anything.
    """
    tool = _tool(
        "copy_file",
        "Copy a file to a new location on disk.",
        {"src": {"type": "string"}, "dest": {"type": "string"}},
    )
    assert destination_tools([tool]) == []


def test_move_file_destination_is_not_reported() -> None:
    tool = _tool(
        "move_file",
        "Move or rename a file.",
        {"source": {"type": "string"}, "destination": {"type": "string"}},
    )
    assert destination_tools([tool]) == []


def test_reference_shaped_param_is_not_a_destination() -> None:
    """`destination_id` is a key into an address book, not an address."""
    tool = _tool("send_message", "Send a message.", {"destination_id": {"type": "string"}})
    assert destination_tools([tool]) == []


def test_export_report_destination_is_still_reported() -> None:
    """The true positive the 0.8.3 widening existed for must survive the fix.

    Confirmed live: this tool accepts an arbitrary external destination with no
    allowlist and no auth. Corroborated twice over — the verb exports, and the
    description names an https default.
    """
    tool = _tool(
        "export_report",
        "Export a report to a destination. Default destination: "
        "https://analytics-collector.internal/api/v2/ingest",
        {"data": {"type": "string"}, "destination": {"type": "string"}},
    )
    assert destination_tools([tool]) == [("export_report", "destination", "name hint")]


def test_weak_hint_corroborated_by_schema_format_alone() -> None:
    """A tool with a neutral name still reports when the schema says `format: uri`."""
    tool = _tool(
        "store_record",
        "Store a record.",
        {"destination": {"type": "string", "format": "uri"}},
    )
    assert destination_tools([tool]) == [("store_record", "destination", "name hint")]


def test_strong_hints_still_match_on_the_name_alone() -> None:
    """`webhook_url` needs no corroboration — it is unambiguous."""
    tool = _tool("schedule_report", "Schedule a report.", {"webhook_url": {"type": "string"}})
    assert destination_tools([tool]) == [("schedule_report", "webhook_url", "name hint")]


@pytest.mark.parametrize("host", ["notify.md", "deploy.py", "assets.zip"])
def test_cctld_lookalikes_are_not_suppressed_as_filenames(host: str) -> None:
    """`.md`, `.py` and `.zip` are real TLDs (Moldova, Paraguay, a Google gTLD).

    Suppressing them treated a genuine destination as a document and dropped it
    from the report entirely — a false negative on the discovery path, which is
    the worse direction for a tool whose job is to find egress surface.
    """
    assert _is_reportable_destination(host) is True


@pytest.mark.parametrize("sample", ["README.md.gz", "config.json", "report.log", "notes.txt"])
def test_genuine_filenames_are_still_suppressed(sample: str) -> None:
    """The case the suffix list was added for still holds.

    `README.md.gz` suppresses on `.gz`, which is not a TLD — so dropping the
    TLD-colliding entries did not reintroduce the false positive.
    """
    assert _is_reportable_destination(sample) is False


def test_every_filename_suffix_avoids_a_known_tld_collision() -> None:
    """Guards the rule itself, not just today's list.

    Any future addition to `_FILENAME_SUFFIXES` that is also a TLD silently
    reintroduces this class of false negative, and nothing else would catch it.
    """
    known_tlds = {".md", ".py", ".zip", ".sh", ".app", ".dev", ".pl", ".it", ".ai", ".io"}
    collisions = sorted(set(_FILENAME_SUFFIXES) & known_tlds)
    assert not collisions, f"these suffixes are real TLDs: {collisions}"
