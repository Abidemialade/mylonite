"""Tests for ``build_adapter_for_spec`` / ``LaunchIntent`` (T10).

``build_mcp_adapter`` (the pre-existing low-level entry point) takes a bare
``family`` string plus raw constructor kwargs — a caller wanting a target's
unguarded twin must compute and pass the launch triple itself, and nothing
stops it from forgetting. ``build_adapter_for_spec`` closes that hole: it takes
an already-resolved ``TargetSpec`` plus a ``LaunchIntent`` and ALWAYS
recomputes the launch triple from ``spec`` + ``intent`` — a caller cannot pass
a raw ``launch_env`` and cannot skip it.
"""

from __future__ import annotations

from typing import Any

import pytest

from mylonite.plugins._http.http_adapter import HTTPAgentAdapter
from mylonite.plugins._mcp import target_registry
from mylonite.plugins._mcp.factory import LaunchIntent, build_adapter_for_spec
from mylonite.plugins._mcp.remote_adapter import MCPRemoteAdapter
from mylonite.plugins._mcp.stdio_adapter import MCPStdioAdapter
from mylonite.plugins._mcp.target_file import LaunchOverride, TargetFile, build_target_spec


@pytest.fixture(autouse=True)
def _clean_registry() -> Any:
    yield
    target_registry.clear_runtime_targets()


def _register_stdio(
    family: str = "twin-app",
    *,
    vulnerable_launch: LaunchOverride | None = None,
    control_env: dict[str, dict[str, str]] | None = None,
) -> target_registry.TargetSpec:
    target_registry.clear_runtime_targets()
    tf = TargetFile(
        family=family,
        command="echo",
        args=["default"],
        env={"BASE": "1"},
        weakness_classes=["W4"],
        vulnerable_launch=vulnerable_launch,
        control_env=control_env or {},
    )
    spec = build_target_spec(tf)
    target_registry.register_target(spec)
    return spec


def test_dispatches_stdio_by_default() -> None:
    spec = _register_stdio()
    adapter = build_adapter_for_spec(spec, scope=None, model="m")
    assert isinstance(adapter, MCPStdioAdapter)


def test_dispatches_sse_remote() -> None:
    target_registry.clear_runtime_targets()
    tf = TargetFile(
        family="remote-twin",
        transport="sse",
        url="https://target.example/mcp",
        weakness_classes=["W4"],
    )
    spec = build_target_spec(tf)
    target_registry.register_target(spec)
    adapter = build_adapter_for_spec(spec, scope=None, model="m")
    assert isinstance(adapter, MCPRemoteAdapter)


def test_dispatches_rest_http_agent() -> None:
    target_registry.clear_runtime_targets()
    tf = TargetFile(
        family="rest-twin",
        transport="rest",
        request=target_registry.RequestSpec(
            url="https://agent.example/chat", body='{"prompt": "{prompt}"}'
        ),
        weakness_classes=["W4"],
    )
    spec = build_target_spec(tf)
    target_registry.register_target(spec)
    adapter = build_adapter_for_spec(spec, scope=None, model="m")
    assert isinstance(adapter, HTTPAgentAdapter)


def test_default_intent_is_the_plain_launch() -> None:
    """No ``intent`` == byte-for-byte today's default launch (base extra_env,
    default command/args) — the safe, backward-compatible default. The launch
    triple is always explicitly resolved now (never left implicit), so this
    checks the RESOLVED values match the spec's plain default launch."""
    spec = _register_stdio()
    adapter = build_adapter_for_spec(spec, scope=None, model="m")
    assert isinstance(adapter, MCPStdioAdapter)
    assert adapter._launch_env == {"BASE": "1"}
    assert adapter._launch_command == "echo"
    assert adapter._launch_args == ["default"]


def test_vulnerable_intent_swaps_the_launch_triple() -> None:
    """``LaunchIntent(vulnerable=True)`` must thread the target's declared
    ``vulnerable_launch`` override through to the constructed adapter — this is
    the property that makes it structurally impossible to build a "raw" twin
    that silently launches the guarded default instead."""
    spec = _register_stdio(
        vulnerable_launch=LaunchOverride(
            command="raw-echo", args=["--unsafe"], env={"GUARD": "off"}
        )
    )
    adapter = build_adapter_for_spec(
        spec, scope=None, model="m", intent=LaunchIntent(vulnerable=True)
    )
    assert isinstance(adapter, MCPStdioAdapter)
    assert adapter._launch_command == "raw-echo"
    assert adapter._launch_args == ["--unsafe"]
    assert adapter._launch_env == {"BASE": "1", "GUARD": "off"}


def test_disable_controls_threads_server_layer_toggle() -> None:
    spec = _register_stdio(control_env={"W4": {"W4_GUARD": "off"}})
    adapter = build_adapter_for_spec(
        spec, scope=None, model="m", intent=LaunchIntent(disable_controls=("W4",))
    )
    assert isinstance(adapter, MCPStdioAdapter)
    assert adapter._launch_env == {"BASE": "1", "W4_GUARD": "off"}


def test_rest_transport_ignores_launch_triple_but_honours_input_frame() -> None:
    target_registry.clear_runtime_targets()
    tf = TargetFile(
        family="rest-twin2",
        transport="rest",
        request=target_registry.RequestSpec(
            url="https://agent.example/chat", body='{"prompt": "{prompt}"}'
        ),
        weakness_classes=["W4"],
    )
    spec = build_target_spec(tf)
    target_registry.register_target(spec)
    adapter = build_adapter_for_spec(
        spec, scope=None, model="m", intent=LaunchIntent(input_frame=True)
    )
    assert isinstance(adapter, HTTPAgentAdapter)
    assert adapter._input_frame is True
