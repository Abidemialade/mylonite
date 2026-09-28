"""#181d: a failed seed_arm PLANT call must be named as a plant failure,
not misreported as "payload not delivered".

Before this fix, ``_run_seed_arm`` ignored ``result.isError`` on the plant
call: a target whose seed-arm tool refused (bad args, a full store, a
permission error) still "planted" successfully as far as the adapter was
concerned. The recall step then naturally found nothing, and the attempt was
reported as ``skipped_payload_not_delivered`` with the generic reason "the
planted payload was never retrieved by the planner" — true, but not the real
cause, and not actionable (an operator would go check the DRIVE/recall
wiring, when the actual defect was the PLANT call itself).
"""

from __future__ import annotations

from typing import Any

import pytest

from mylonite.plugins._mcp.stdio_adapter import MCPStdioAdapter
from mylonite.plugins._mcp.target_registry import SeedArmSpec
from mylonite.scan._types import SeedArmUnavailable


class _Result:
    def __init__(self, *, content: str, is_error: bool) -> None:
        self.content = content
        self.isError = is_error


class _FakeSession:
    def __init__(self, result: _Result) -> None:
        self._result = result
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> _Result:
        self.calls.append((name, dict(arguments)))
        return self._result


@pytest.mark.asyncio
async def test_seed_arm_plant_call_error_raises_seed_arm_unavailable() -> None:
    adapter = MCPStdioAdapter(family="fetch", scope=None)
    arm = SeedArmSpec(tool="remember", args_template={"content": "{payload}"})
    session = _FakeSession(_Result(content="quota exceeded: too many notes", is_error=True))

    with pytest.raises(SeedArmUnavailable) as excinfo:
        await adapter._run_seed_arm(session, arm, "the payload body", [])

    reason = excinfo.value.reason
    assert "seed_arm plant call failed" in reason
    assert "quota exceeded" in reason
    assert "payload not delivered" not in reason


@pytest.mark.asyncio
async def test_seed_arm_plant_call_error_reason_is_redacted_and_capped() -> None:
    """The error content is target-controlled text: redact it (the same helper
    every other adapter-side error message uses) and cap it, mirroring
    ``_truncate_result``'s treatment of other target-controlled strings."""
    adapter = MCPStdioAdapter(family="fetch", scope=None)
    arm = SeedArmSpec(tool="remember", args_template={"content": "{payload}"})
    secret = "sk-ant-" + "f" * 40  # pragma: allowlist secret — a fake, all-f test fixture
    long_error = f"call failed, key={secret} " + ("x" * 1000)
    session = _FakeSession(_Result(content=long_error, is_error=True))

    with pytest.raises(SeedArmUnavailable) as excinfo:
        await adapter._run_seed_arm(session, arm, "the payload body", [])

    reason = excinfo.value.reason
    assert secret not in reason
    assert len(reason) < 400, "the error content must be capped, not embedded verbatim"


@pytest.mark.asyncio
async def test_seed_arm_plant_call_ok_is_unaffected() -> None:
    """The happy path (isError=False) is unchanged: no exception, and the
    result content still feeds the existing id_key/id_pattern/id_from logic."""
    adapter = MCPStdioAdapter(family="fetch", scope=None)
    arm = SeedArmSpec(tool="remember", args_template={"content": "{payload}"})
    session = _FakeSession(_Result(content="stored", is_error=False))

    handle = await adapter._run_seed_arm(session, arm, "the payload body", [])

    assert handle is None  # no id_key/id_pattern/id_from declared on this arm
    assert session.calls == [("remember", {"content": "the payload body"})]
