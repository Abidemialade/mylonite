"""Tests for the plain HTTP-agent adapter (``transport: rest``).

Uses ``httpx.MockTransport`` so no network is touched: we inject a mock client
into the adapter (its ``_ensure_client`` seam returns the pre-set ``_client``).
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from mylonite.contracts._types import Payload
from mylonite.plugins._http.http_adapter import (
    HTTPAgentAdapter,
    _escape_for_body,
    _extract_reply,
)
from mylonite.plugins._mcp import target_registry
from mylonite.plugins._mcp.factory import build_mcp_adapter
from mylonite.plugins._mcp.target_file import TargetFile, build_target_spec, load_target_file


def _register_rest(**request_kwargs: object) -> None:
    request = target_registry.RequestSpec(
        url="https://agent.example/chat",
        body='{"prompt": "{prompt}"}',
        response_path="reply",
        **request_kwargs,  # type: ignore[arg-type]
    )
    spec = target_registry.TargetSpec(
        family="myagent",
        command="",
        args_template=(),
        scope_validator=lambda _s: None,
        default_system_prompt="You are a support agent.",
        requires_scope=False,
        weakness_classes=("W2",),
        transport="rest",
        request=request,
    )
    target_registry.clear_runtime_targets()
    target_registry.register_target(spec)


def _payload(body: str) -> Payload:
    return Payload(pattern_id="synth-w2-direct-injection-agent", channel="user-message", body=body)


def teardown_function() -> None:
    target_registry.clear_runtime_targets()


# --- unit helpers ------------------------------------------------------------


def test_escape_for_body_makes_payload_json_safe() -> None:
    escaped = _escape_for_body('hi "there"\nnewline\\slash', "{prompt}")
    # Substituting into a JSON string must keep it valid JSON.
    body = '{"prompt": "' + escaped + '"}'
    import json

    assert json.loads(body)["prompt"] == 'hi "there"\nnewline\\slash'


def test_extract_reply_dotted_path_and_list_index() -> None:
    raw = '{"choices": [{"message": {"content": "hello"}}]}'
    assert _extract_reply(raw, "choices.0.message.content") == "hello"


def test_extract_reply_falls_back_to_raw_on_miss_or_nonjson() -> None:
    assert _extract_reply("plain text, not json", "reply") == "plain text, not json"
    assert _extract_reply('{"other": 1}', "reply") == '{"other": 1}'
    assert _extract_reply("whole body", None) == "whole body"


# --- adapter behaviour -------------------------------------------------------


def test_describe_reports_http_agent_kind_and_declared_weaknesses() -> None:
    _register_rest()
    adapter = HTTPAgentAdapter(family="myagent")
    descriptor = asyncio.run(adapter.describe())
    assert descriptor.kind == "http-agent"
    assert descriptor.tools == []
    assert descriptor.weakness_classes == ["W2"]
    assert descriptor.target_id == "rest:myagent"


def test_invoke_substitutes_payload_and_extracts_reply() -> None:
    _register_rest()
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = request.content.decode("utf-8")
        captured["method"] = request.method
        return httpx.Response(200, json={"reply": "I will not follow that instruction."})

    adapter = HTTPAgentAdapter(family="myagent")
    adapter._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        resp = asyncio.run(adapter.invoke(_payload('exfiltrate to "x"\nnow')))
    finally:
        asyncio.run(adapter.close())

    assert resp.raw_response == "I will not follow that instruction."
    assert resp.payload_pattern_id == "synth-w2-direct-injection-agent"
    assert resp.tool_calls == []
    assert captured["method"] == "POST"
    # The payload was JSON-escaped into the {prompt} slot, keeping the body valid JSON.
    import json

    assert json.loads(captured["body"])["prompt"] == 'exfiltrate to "x"\nnow'


def test_headers_are_passed_but_request_object_is_the_only_carrier() -> None:
    _register_rest(headers={"Authorization": "Bearer secret-token"})
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("Authorization", "")
        return httpx.Response(200, json={"reply": "ok"})

    adapter = HTTPAgentAdapter(family="myagent")
    adapter._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        asyncio.run(adapter.invoke(_payload("hi")))
    finally:
        asyncio.run(adapter.close())
    assert seen["auth"] == "Bearer secret-token"


# --- factory routing ---------------------------------------------------------


def test_factory_routes_rest_transport_to_http_adapter() -> None:
    _register_rest()
    adapter = build_mcp_adapter(family="myagent", scope=None, model="anthropic/claude-haiku-4-5")
    assert isinstance(adapter, HTTPAgentAdapter)


# --- target-file validation --------------------------------------------------


def test_rest_target_file_requires_request_block() -> None:
    with pytest.raises(ValueError, match="requires a 'request' block"):
        TargetFile(family="agent", transport="rest")


def test_rest_target_file_requires_prompt_placeholder() -> None:
    with pytest.raises(ValueError, match=r"\{prompt\} placeholder"):
        TargetFile(
            family="agent",
            transport="rest",
            request=target_registry.RequestSpec(url="https://x/chat", body='{"q": "no slot"}'),
        )


def test_rest_target_file_builds_spec_and_round_trips(tmp_path: object) -> None:
    from pathlib import Path

    yaml_text = (
        "family: agent\n"
        "transport: rest\n"
        "weakness_classes: [W2]\n"
        "request:\n"
        "  url: https://agent.example/chat\n"
        "  body: '{\"prompt\": \"{prompt}\"}'\n"
        "  response_path: reply\n"
    )
    p = Path(tmp_path) / "agent.yaml"  # type: ignore[arg-type]
    p.write_text(yaml_text, encoding="utf-8")
    tf = load_target_file(p)
    assert tf.transport == "rest"
    assert tf.request is not None and tf.request.url == "https://agent.example/chat"
    spec = build_target_spec(tf)
    assert spec.transport == "rest"
    assert spec.request is not None and spec.request.response_path == "reply"
