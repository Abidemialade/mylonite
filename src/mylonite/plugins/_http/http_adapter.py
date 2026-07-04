"""Adapter for a plain HTTP agent (``transport: rest``).

A black-box HTTP agent takes a prompt in an HTTP request and returns a reply in
the response — no MCP, no tool surface. The operator declares the request shape
once in the target file's ``request`` block (endpoint, method, headers, a body
template with a ``{prompt}`` placeholder, and a ``response_path`` into the JSON
reply). This adapter substitutes the attack payload into that template, POSTs it,
and returns the agent's reply as the :class:`AdapterResponse` the judge reasons
over.

Because a black-box agent exposes no ``tools/list``, the applicable attacks are
the prompt-injection / goal-hijack class judged on the reply text (see
``seed_synth`` — a tool-less target gets a direct-injection probe). Tool-poisoning
(W1) and effect-based egress/action (W3/W4) need a tool surface / side-effect
probe a black box can't provide.

``request.headers`` may carry an API key / bearer token and are NEVER logged.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from mylonite.contracts._types import AdapterResponse, Payload, TargetDescriptor
from mylonite.contracts.target_adapter import AsyncTargetAdapterBase
from mylonite.plugins._mcp import target_registry


def _escape_for_body(text: str, body: str) -> str:
    """Return ``text`` safe to substitute into the ``{prompt}`` slot of ``body``.

    The default (and typical LLM-API) body is JSON, so the payload must be
    JSON-string-escaped (quotes, backslashes, newlines) to keep the body valid.
    We escape whenever the body parses as JSON *after* a trial substitution would
    otherwise break it — practically: JSON-escape unless the template is clearly
    not JSON (contains ``{prompt}`` at a non-JSON position). Keeping it simple and
    robust: always JSON-escape (``json.dumps`` then strip the surrounding quotes).
    """
    return json.dumps(text)[1:-1]


def _extract_reply(raw: str, response_path: str | None) -> str:
    """Pull the agent's reply out of the HTTP response body.

    ``response_path`` is a dotted path into the JSON body (integer segments index
    into lists), e.g. ``choices.0.message.content``. When it is ``None``, or the
    body isn't JSON, or the path misses, we fall back to the whole raw body so the
    judge still has something to reason over rather than an empty string.
    """
    if not response_path:
        return raw
    try:
        node: Any = json.loads(raw)
    except (ValueError, TypeError):
        return raw
    for segment in response_path.split("."):
        try:
            if isinstance(node, list):
                node = node[int(segment)]
            elif isinstance(node, dict):
                node = node[segment]
            else:
                return raw
        except (KeyError, IndexError, ValueError):
            return raw
    return node if isinstance(node, str) else json.dumps(node)


class HTTPAgentAdapter(AsyncTargetAdapterBase):
    """Async adapter for a plain HTTP agent (``transport: rest``).

    Constructed like the MCP adapters — ``family``/``scope`` resolve the
    already-registered :class:`TargetSpec`; MCP-only kwargs (``model``,
    ``controls``, launch overrides) are accepted and ignored, so the same factory
    call site works for every transport. Implements the single-shot ``invoke``
    path only (no ``AttackSession``): the scan engine falls back to ``invoke`` for
    a black-box target, which is exactly the direct-injection channel a tool-less
    HTTP agent supports.
    """

    def __init__(self, *, family: str, scope: str | None = None, **_ignored: Any) -> None:
        spec = target_registry.resolve_target(family, scope)
        if spec.request is None:
            raise ValueError(
                f"target {family!r} has transport 'rest' but no 'request' block — "
                "declare the HTTP request shape (url + body template) in the target file"
            )
        self._family = family
        self._spec = spec
        self._request = spec.request
        self._client: httpx.AsyncClient | None = None

    def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._request.timeout_s)
        return self._client

    async def describe(self) -> TargetDescriptor:
        return TargetDescriptor(
            target_id=f"rest:{self._family}",
            kind="http-agent",
            system_prompt=self._spec.default_system_prompt,
            tools=[],
            data_sources=[],
            notes="Plain HTTP agent (transport: rest); black-box, no tool surface.",
            weakness_classes=list(self._spec.weakness_classes),
        )

    async def invoke(self, payload: Payload) -> AdapterResponse:
        req = self._request
        body = req.body.replace("{prompt}", _escape_for_body(payload.body, req.body))
        client = self._ensure_client()
        response = await client.request(
            req.method.upper(),
            req.url,
            headers=req.headers or None,
            content=body.encode("utf-8"),
        )
        reply = _extract_reply(response.text, req.response_path)
        return AdapterResponse(
            payload_pattern_id=payload.pattern_id,
            raw_response=reply,
            tool_calls=[],
            metadata={"http_status": str(response.status_code)},
        )

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None
