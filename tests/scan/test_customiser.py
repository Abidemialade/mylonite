"""PayloadCustomiser tests with LiteLLM mocked."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from mylonite.contracts._types import ComplianceTags, TargetDescriptor, ToolSpec
from mylonite.scan.customiser import PayloadCustomiser
from mylonite.scan.seeds import SeedPattern


def _stub_response(text: str) -> SimpleNamespace:
    return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=text))])


def _seed() -> SeedPattern:
    return SeedPattern(
        pattern_id="test-seed",
        weakness="W2",
        channel="tool-result",
        seed_body="ORIGINAL SEED BODY",
        setup="seed_note",
        drive="read_note_for_summary",
        predicate="send_email_to_attacker",
        applicable_targets=["kitchen-sink"],
        compliance=ComplianceTags(owasp_llm=["LLM01"], owasp_asi=["ASI01"]),
    )


def _descriptor() -> TargetDescriptor:
    return TargetDescriptor(
        target_id="test-target",
        kind="mcp",
        system_prompt="You are a helpful agent.",
        tools=[ToolSpec(name="read_note", description="read by id", json_schema={})],
    )


@pytest.mark.asyncio
async def test_customise_returns_payload_with_required_metadata() -> None:
    async def stub(**_: Any) -> SimpleNamespace:
        return _stub_response('{"body": "REFINED BODY"}')

    cust = PayloadCustomiser(model="stub", completion_fn=stub)
    payload = await cust.customise(_seed(), _descriptor())
    assert payload.pattern_id == "test-seed"
    assert payload.channel == "tool-result"
    assert payload.body == "REFINED BODY"
    assert payload.metadata["seed_id"] == "test-seed"
    assert payload.metadata["weakness"] == "W2"
    assert payload.metadata["predicate"] == "send_email_to_attacker"
    assert payload.metadata["setup"] == "seed_note"
    assert payload.metadata["drive"] == "read_note_for_summary"
    assert "customiser" not in payload.metadata  # fallback marker absent


@pytest.mark.asyncio
async def test_customise_falls_back_on_invalid_json() -> None:
    async def stub(**_: Any) -> SimpleNamespace:
        return _stub_response("not json at all")

    cust = PayloadCustomiser(model="stub", completion_fn=stub)
    payload = await cust.customise(_seed(), _descriptor())
    assert payload.body == "ORIGINAL SEED BODY"
    assert payload.metadata["customiser"] == "fallback"


@pytest.mark.asyncio
async def test_customise_falls_back_when_llm_raises() -> None:
    async def stub(**_: Any) -> SimpleNamespace:
        raise RuntimeError("provider down")

    cust = PayloadCustomiser(model="stub", completion_fn=stub)
    payload = await cust.customise(_seed(), _descriptor())
    assert payload.body == "ORIGINAL SEED BODY"
    assert payload.metadata["customiser"] == "fallback"


@pytest.mark.asyncio
async def test_customise_falls_back_when_body_key_missing() -> None:
    async def stub(**_: Any) -> SimpleNamespace:
        return _stub_response('{"wrong_key": "thing"}')

    cust = PayloadCustomiser(model="stub", completion_fn=stub)
    payload = await cust.customise(_seed(), _descriptor())
    assert payload.body == "ORIGINAL SEED BODY"
    assert payload.metadata["customiser"] == "fallback"
