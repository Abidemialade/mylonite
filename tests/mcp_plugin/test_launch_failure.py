"""A failed launch must be reported as a launch failure, and must name the command.

Two defects, one symptom. ``_classify_failure`` had no ``FileNotFoundError``
branch, so a missing launch binary fell through to ``"planner_exception"`` and
the run told the operator their planner had broken. And the classification it
computed was written to ``attempt_metadata["reason"]``, which nothing reads --
``ScanEngine`` reads only ``attempt_metadata["exception"]`` -- so reclassifying
alone would have changed nothing the operator ever sees.
"""

from __future__ import annotations

from typing import Any

import pytest

from mylonite.contracts import Payload
from mylonite.plugins._mcp._session_adapter import MCPSessionAdapterBase
from mylonite.plugins._mcp.stdio_adapter import MCPStdioAdapter
from mylonite.scan._types import AdapterInvocationSkipped


class _MissingBinarySessionCM:
    """What an MCP stdio launch of a non-existent command actually raises."""

    async def __aenter__(self) -> Any:
        raise FileNotFoundError(2, "The system cannot find the file specified")

    async def __aexit__(self, *exc_info: object) -> bool:
        return False


def test_missing_launch_binary_is_classified_as_a_launch_failure() -> None:
    assert MCPSessionAdapterBase._classify_failure(FileNotFoundError()) == "launch_failure"


def test_a_planner_exception_is_still_classified_as_one() -> None:
    """The new branch must not swallow the genuine planner-error case."""
    assert MCPSessionAdapterBase._classify_failure(ValueError("boom")) == "planner_exception"


@pytest.mark.asyncio
async def test_launch_failure_reason_names_the_cause_and_the_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The operator must be able to see WHAT failed and WHICH command failed.

    ``_describe_data_sources()`` already formats exactly the string needed
    (``MCP stdio: <command> <args>``); the error path simply never used it.
    """
    adapter = MCPStdioAdapter(family="fetch", scope=None)
    monkeypatch.setattr(adapter, "_session", lambda **_: _MissingBinarySessionCM())

    payload = Payload(pattern_id="p", channel="tool-result", body="x")

    with pytest.raises(AdapterInvocationSkipped) as excinfo:
        await adapter.invoke(payload)

    reason = excinfo.value.reason
    # named as a launch failure, not as a planner failure
    assert "launch_failure" in reason
    assert "planner" not in reason.lower()
    # ...and it says which command could not be launched
    assert adapter._spec.command in reason
    # the classification is also carried in the metadata the engine persists
    assert excinfo.value.attempt_metadata["reason"] == "launch_failure"


@pytest.mark.asyncio
async def test_launch_failure_does_not_leak_a_credential_from_the_launch_args(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Naming the command must not print the operator's credentials.

    A target's `args:` routinely carry a secret as a CLI flag (the common MCP
    shape `npx some-server --api-key=...`), which is why the gate redacts
    target.yaml before committing it (DCR-0019). The remote adapter's own
    `_describe_data_sources` is deliberately host-only for the same reason --
    "never the full URL with query/credentials/userinfo". The stdio one returns
    the command and args verbatim, so the string must be redacted before it is
    spliced into a message that lands in ScanAttempt.verdict_reason and, from
    there, in scan_report.json and a committed gate branch.
    """
    secret = "sk-ant-" + "f" * 40  # pragma: allowlist secret — a fake, all-f test fixture
    adapter = MCPStdioAdapter(family="fetch", scope=None)
    monkeypatch.setattr(adapter, "_session", lambda **_: _MissingBinarySessionCM())
    monkeypatch.setattr(
        adapter,
        "_describe_data_sources",
        lambda: [f"MCP stdio: npx some-mcp-server --api-key={secret}"],
    )

    with pytest.raises(AdapterInvocationSkipped) as excinfo:
        await adapter.invoke(Payload(pattern_id="p", channel="tool-result", body="x"))

    reason = excinfo.value.reason
    assert secret not in reason
    # ...while the part that answers "which command?" survives.
    assert "npx some-mcp-server" in reason
