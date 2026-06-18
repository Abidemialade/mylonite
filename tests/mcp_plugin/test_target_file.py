"""Tests for the custom-MCP-target on-ramp (--target-file / mcp:custom)."""

from __future__ import annotations

from pathlib import Path

import pytest

from mylonite.plugins._mcp import target_registry
from mylonite.plugins._mcp.target_file import (
    TargetFile,
    build_target_spec,
    load_target_file,
    payload_placement_warnings,
)
from mylonite.plugins._mcp.target_registry import InvalidTargetScope, SeedArmSpec


@pytest.fixture(autouse=True)
def _clean_runtime() -> None:
    target_registry.clear_runtime_targets()
    yield
    target_registry.clear_runtime_targets()


def _tf(**over: object) -> TargetFile:
    base: dict[str, object] = {"family": "triagent", "command": "python", "args": ["-m", "srv"]}
    base.update(over)
    return TargetFile(**base)  # type: ignore[arg-type]


def test_target_file_rejects_unknown_keys() -> None:
    with pytest.raises(Exception):  # noqa: B017 — pydantic ValidationError (extra=forbid)
        TargetFile(family="x", command="c", bogus=1)  # type: ignore[call-arg]


def test_target_file_rejects_reserved_family() -> None:
    with pytest.raises(ValueError, match="reserved"):
        _tf(family="filesystem")


def test_target_file_carries_control_config() -> None:
    from mylonite.plugins._mcp.target_registry import ControlConfig

    tf = _tf(
        weakness_classes=["W3"],
        control_config=ControlConfig(
            egress_tools=("web_fetch",),
            egress_url_param="url",
            consequential_tools=("send_email",),
        ),
    )
    spec = build_target_spec(tf)
    assert spec.control_config is not None
    assert spec.control_config.egress_tools == ("web_fetch",)
    assert spec.control_config.egress_url_param == "url"
    assert spec.control_config.consequential_tools == ("send_email",)


def test_target_file_control_config_round_trips_yaml(tmp_path: Path) -> None:
    from mylonite.plugins._mcp.target_file import dump_target_file

    tf = _tf(control_config={"egress_tools": ["web_fetch"], "egress_url_param": "url"})
    p = tmp_path / "t.yaml"
    p.write_text(dump_target_file(tf), encoding="utf-8")
    reloaded = load_target_file(p)
    assert reloaded.control_config is not None
    assert reloaded.control_config.egress_tools == ("web_fetch",)
    assert reloaded.control_config.egress_url_param == "url"


def test_target_file_rejects_both_prompt_sources() -> None:
    with pytest.raises(ValueError, match="at most one"):
        _tf(system_prompt="a", system_prompt_file=Path("p.txt"))


def test_build_target_spec_shape() -> None:
    tf = _tf(
        env={"DB": "x"},
        scope="s",
        requires_scope=True,
        primary_tools=["remember", "send_email"],
        weakness_classes=["W2", "W4"],
        seed_arm=SeedArmSpec(tool="remember", args_template={"content": "{payload}"}),
    )
    spec = build_target_spec(tf)
    assert spec.family == "triagent"
    assert spec.command == "python"
    assert spec.args_template == ("-m", "srv")
    assert spec.args_with_scope is False
    assert spec.extra_env == {"DB": "x"}
    assert spec.weakness_classes == ("W2", "W4")
    assert spec.seed_arm is not None and spec.seed_arm.tool == "remember"
    assert spec.requires_scope is True


def test_build_target_spec_scope_validator_enforces_requires_scope() -> None:
    spec = build_target_spec(_tf(requires_scope=True))
    with pytest.raises(InvalidTargetScope):
        spec.scope_validator(None)
    spec.scope_validator("ok")  # non-empty passes


def test_register_and_resolve_round_trip() -> None:
    spec = build_target_spec(_tf())
    target_registry.register_target(spec)
    assert target_registry.resolve_target("triagent", None) is spec
    assert "triagent" in target_registry.known_families()


def test_register_cannot_shadow_bundled_family() -> None:
    # build_target_spec would already reject reserved names; guard the registry too.
    from dataclasses import replace

    spec = replace(build_target_spec(_tf()), family="github")
    with pytest.raises(ValueError, match="bundled"):
        target_registry.register_target(spec)


def test_load_target_file_from_yaml(tmp_path: Path) -> None:
    p = tmp_path / "t.yaml"
    p.write_text(
        "family: triagent\n"
        "command: python\n"
        "args: [-m, srv]\n"
        "weakness_classes: [W2, W4]\n"
        "seed_arm:\n"
        "  tool: remember\n"
        "  args_template: {content: '{payload}'}\n",
        encoding="utf-8",
    )
    tf = load_target_file(p)
    assert tf.family == "triagent"
    assert tf.weakness_classes == ["W2", "W4"]
    assert tf.seed_arm is not None and tf.seed_arm.tool == "remember"


# --- R7: natural-language payload-placement warnings ------------------------


def test_payload_warnings_clean_for_bare_leaf() -> None:
    """A {payload} at a bare string leaf is the happy path — no warnings."""
    tf = _tf(seed_arm=SeedArmSpec(tool="remember", args_template={"content": "{payload}"}))
    assert payload_placement_warnings(tf) == []


def test_payload_warnings_flag_json_nested_placeholder() -> None:
    """{payload} embedded in a JSON-object string is flagged (not natural language)."""
    tf = _tf(
        seed_arm=SeedArmSpec(tool="remember", args_template={"content": '{"text": "{payload}"}'})
    )
    warnings = payload_placement_warnings(tf)
    assert any("BARE string leaf" in w for w in warnings)


def test_payload_warnings_flag_missing_placeholder() -> None:
    """No {payload} anywhere → the plant would deliver nothing; flagged."""
    tf = _tf(seed_arm=SeedArmSpec(tool="remember", args_template={"content": "static text"}))
    warnings = payload_placement_warnings(tf)
    assert any("no '{payload}' placeholder" in w for w in warnings)


def test_payload_warnings_none_without_seed_arm() -> None:
    """A target with no seed_arm has nothing to plant — no warnings."""
    assert payload_placement_warnings(_tf()) == []
