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
from mylonite.scan._types import AdapterDescribeFailed, AdapterInvocationSkipped


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


def _custom_stdio_adapter(
    args: list[str], monkeypatch: pytest.MonkeyPatch, *, family: str = "custom-launch-secret"
) -> MCPStdioAdapter:
    """A custom stdio target with the given ``args:``, wired to fail its launch."""
    from mylonite.plugins._mcp import target_registry
    from mylonite.plugins._mcp.target_file import TargetFile, build_target_spec

    target_registry.clear_runtime_targets()
    tf = TargetFile(family=family, command="python", args=args)
    target_registry.register_target(build_target_spec(tf))
    adapter = MCPStdioAdapter(family=family, scope=None)
    monkeypatch.setattr(adapter, "_session", lambda **_: _MissingBinarySessionCM())
    return adapter


@pytest.mark.asyncio
async def test_launch_failure_does_not_leak_a_credential_from_the_launch_args(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Naming the command must not print the operator's credentials.

    A target's `args:` routinely carry a secret as a CLI flag (the common MCP
    shape `npx some-server --api-key=...`), which is why the gate redacts
    target.yaml before committing it (DCR-0019). The remote adapter's own
    `_describe_data_sources` is deliberately host-only for the same reason --
    "never the full URL with query/credentials/userinfo". The stdio launch-
    failure message never prints an arg value at all (#195 review finding --
    see `MCPStdioAdapter._launch_failure_summary`): only the executable and
    an argument count reach `ScanAttempt.verdict_reason` and, from there,
    `scan_report.json` and a committed gate branch.
    """
    secret = "sk-ant-" + "f" * 40  # pragma: allowlist secret — a fake, all-f test fixture
    try:
        adapter = _custom_stdio_adapter(["some-mcp-server", f"--api-key={secret}"], monkeypatch)

        with pytest.raises(AdapterInvocationSkipped) as excinfo:
            await adapter.invoke(Payload(pattern_id="p", channel="tool-result", body="x"))

        reason = excinfo.value.reason
        assert secret not in reason
        assert "some-mcp-server" not in reason  # no arg text at all, not even a bare name
        # ...while the part that answers "which command?" survives.
        assert "python" in reason
    finally:
        from mylonite.plugins._mcp import target_registry

        target_registry.clear_runtime_targets()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "args",
    [
        pytest.param(["--password", "hunter2verylongfakepassword"], id="two-argv-items"),
        pytest.param(["--password=hunter2verylongfakepassword"], id="equals-joined"),
    ],
)
async def test_launch_failure_withholds_a_credential_with_no_provider_shape(
    args: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """#195 review finding: `redact()` only catches a `key=value`/`key: value`
    shape or a provider-shaped token (`sk-…`, `AKIA…`, ...) -- a credential
    passed as TWO separate argv items (no separator at all) with an
    unremarkable value slips through `redact()` untouched; even the
    `=`-joined form has no provider-recognisable shape here. Both the
    pre-existing `invoke()` launch-failure path and the new `describe()` one
    must withhold it on both forms, because neither relies on `redact()`
    catching the value -- neither ever prints an arg value at all.
    """
    fake_value = "hunter2verylongfakepassword"  # pragma: allowlist secret
    adapter = _custom_stdio_adapter(args, monkeypatch)
    try:
        with pytest.raises(AdapterInvocationSkipped) as invoke_excinfo:
            await adapter.invoke(Payload(pattern_id="p", channel="tool-result", body="x"))
        invoke_reason = invoke_excinfo.value.reason
        assert fake_value not in invoke_reason
        assert "--password" not in invoke_reason

        with pytest.raises(AdapterDescribeFailed) as describe_excinfo:
            await adapter.describe()
        describe_message = str(describe_excinfo.value)
        assert fake_value not in describe_message
        assert "--password" not in describe_message
    finally:
        from mylonite.plugins._mcp import target_registry

        target_registry.clear_runtime_targets()
