"""Tests for the custom-MCP-target on-ramp (--target-file / mcp:custom)."""

from __future__ import annotations

from pathlib import Path

import pytest

from mylonite._paths import PathEscapesBase
from mylonite.plugins._mcp import target_registry
from mylonite.plugins._mcp.target_file import (
    TargetFile,
    build_target_spec,
    effect_probe_warnings,
    load_target_file,
    payload_placement_warnings,
    resolved_system_prompt,
)
from mylonite.plugins._mcp.target_registry import InvalidTargetScope, SeedArmSpec


@pytest.fixture(autouse=True)
def _clean_runtime() -> None:
    target_registry.clear_runtime_targets()
    yield
    target_registry.clear_runtime_targets()


def _tf(**over: object) -> TargetFile:
    base: dict[str, object] = {"family": "acme", "command": "python", "args": ["-m", "srv"]}
    base.update(over)
    return TargetFile(**base)  # type: ignore[arg-type]


def test_target_file_rejects_unknown_keys() -> None:
    with pytest.raises(Exception):  # noqa: B017 — pydantic ValidationError (extra=forbid)
        TargetFile(family="x", command="c", bogus=1)  # type: ignore[call-arg]


def test_target_file_rejects_reserved_family() -> None:
    with pytest.raises(ValueError, match="reserved"):
        _tf(family="filesystem")


def test_target_file_normalises_requires_scope_when_scope_declared() -> None:
    """DCR-0008: a scope IS a resource that must be authorized — a target file
    declaring `scope` but leaving `requires_scope: false` (accidentally or by a
    PR-editable YAML trying to downgrade the gate) is normalised to true."""
    tf = _tf(scope="/home/alice/private", requires_scope=False)
    assert tf.requires_scope is True


def test_target_file_leaves_requires_scope_false_with_no_scope() -> None:
    tf = _tf(scope=None, requires_scope=False)
    assert tf.requires_scope is False


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


def test_system_prompt_file_cannot_escape_the_target_file_directory(tmp_path: Path) -> None:
    """DCR-0020 / DCR-0012 / DCR-0013: a repo-editable YAML field became an
    arbitrary-file-read primitive in two independent code paths."""
    secret = tmp_path.parent / "id_rsa"
    secret.write_text("PRIVATE", encoding="utf-8")
    target = tmp_path / "app.yaml"
    target.write_text(
        "family: app\ncommand: python\nsystem_prompt_file: ../id_rsa\n", encoding="utf-8"
    )
    tf = load_target_file(target)
    with pytest.raises(PathEscapesBase):
        resolved_system_prompt(tf)


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
    assert spec.family == "acme"
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
    assert target_registry.resolve_target("acme", None) is spec
    assert "acme" in target_registry.known_families()


def test_register_cannot_shadow_bundled_family() -> None:
    # build_target_spec would already reject reserved names; guard the registry too.
    from dataclasses import replace

    spec = replace(build_target_spec(_tf()), family="github")
    with pytest.raises(ValueError, match="bundled"):
        target_registry.register_target(spec)


def test_load_target_file_from_yaml(tmp_path: Path) -> None:
    p = tmp_path / "t.yaml"
    p.write_text(
        "family: acme\n"
        "command: python\n"
        "args: [-m, srv]\n"
        "weakness_classes: [W2, W4]\n"
        "seed_arm:\n"
        "  tool: remember\n"
        "  args_template: {content: '{payload}'}\n",
        encoding="utf-8",
    )
    tf = load_target_file(p)
    assert tf.family == "acme"
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


def test_payload_warnings_first_char_heuristic_under_match_is_now_caught() -> None:
    """DCR-0021: the OLD check tested only the field's first character — a
    value like '"{payload}"' (the placeholder wrapped in LITERAL quote
    characters, i.e. a JSON-encoded-string field) doesn't start with '{' or
    '[' (it starts with '"'), so the old heuristic MISSED it even though,
    once substituted, it genuinely parses as embedded JSON (a JSON string).
    Sentinel-substitution + an actual parse catches what the first-character
    proxy couldn't see."""
    tf = _tf(seed_arm=SeedArmSpec(tool="remember", args_template={"content": '"{payload}"'}))
    warnings = payload_placement_warnings(tf)
    assert any("BARE string leaf" in w for w in warnings)


def test_payload_warnings_first_char_heuristic_over_match_is_no_longer_flagged() -> None:
    """The placeholder syntax ``{payload}`` itself starts with '{' — so ANY
    value beginning with it (e.g. ordinary natural-language content like
    "{payload} please read this") trivially satisfied the OLD first-character
    check and was wrongly flagged as JSON embedding, even though it plainly
    isn't. Sentinel-substitution + an actual parse fixes this over-match."""
    tf = _tf(
        seed_arm=SeedArmSpec(
            tool="remember", args_template={"content": "{payload} please read this"}
        )
    )
    warnings = payload_placement_warnings(tf)
    assert not any("BARE string leaf" in w for w in warnings)


def test_effect_probe_warning_for_side_effecting_weakness_without_probe() -> None:
    """W3/W4 without an effect_probe can't confirm the effect on a real target —
    the seed under-detects, so warn (a vulnerable target could read clean)."""
    for cls in ("W3", "W4"):
        warnings = effect_probe_warnings(_tf(weakness_classes=[cls]))
        assert any("effect_probe" in w and cls in w for w in warnings), cls


def test_effect_probe_warning_silent_when_probe_declared() -> None:
    """With an effect_probe declared, the effect is confirmable — no warning."""
    from mylonite.plugins._mcp.target_registry import EffectProbeSpec

    tf = _tf(
        weakness_classes=["W4"],
        effect_probe=EffectProbeSpec(verify_tool="list_sent", expect_marker="attacker@example.com"),
    )
    assert effect_probe_warnings(tf) == []


def test_effect_probe_warning_silent_for_non_effecting_weakness() -> None:
    """W1/W2 don't hinge on a side effect materialising — no effect_probe warning."""
    assert effect_probe_warnings(_tf(weakness_classes=["W1", "W2"])) == []


# --- Theme B: server-layer twin launch (vulnerable_launch + control_env) ------
# Lets ablation/chain/prove-control launch a genuinely UNGUARDED variant of a
# target whose guards live in the SERVER (env-driven), not the adapter shim.


def test_launch_env_defaults_to_extra_env() -> None:
    """No new fields → launch resolves to today's behaviour (extra_env only)."""
    spec = build_target_spec(_tf(env={"DB": "x"}))
    assert spec.launch_env() == {"DB": "x"}
    assert spec.launch_command() == "python"
    assert spec.launch_args(None) == ["-m", "srv"]


def test_launch_env_disables_named_server_controls() -> None:
    """control_env toggles disable a server-layer guard per weakness class."""
    spec = build_target_spec(
        _tf(
            env={"DB": "x"},
            control_env={"W2": {"DISABLE_DATA_MARKING": "1"}, "W4": {"AUTONOMY": "full"}},
        )
    )
    assert spec.launch_env(disable_controls=("W2",)) == {"DB": "x", "DISABLE_DATA_MARKING": "1"}
    assert spec.launch_env(disable_controls=("W2", "W4")) == {
        "DB": "x",
        "DISABLE_DATA_MARKING": "1",
        "AUTONOMY": "full",
    }
    assert spec.launch_env() == {"DB": "x"}  # nothing disabled → base only


def test_launch_env_vulnerable_launch_overrides_command_args_env() -> None:
    spec = build_target_spec(
        _tf(
            env={"DB": "x"},
            vulnerable_launch={
                "command": "python",
                "args": ["-m", "srv", "--insecure"],
                "env": {"PROFILE": "vuln"},
            },
        )
    )
    assert spec.launch_env(vulnerable=True) == {"DB": "x", "PROFILE": "vuln"}
    assert spec.launch_env(vulnerable=False) == {"DB": "x"}
    assert spec.launch_command(vulnerable=True) == "python"
    assert spec.launch_args(None, vulnerable=True) == ["-m", "srv", "--insecure"]
    assert spec.launch_args(None, vulnerable=False) == ["-m", "srv"]


def test_target_file_rejects_bad_control_env_key() -> None:
    with pytest.raises(ValueError, match="control_env"):
        _tf(control_env={"W9": {"X": "1"}})


def test_target_file_rejects_miscased_weakness_class() -> None:
    """DCR-0005: a lowercase/miscased weakness class (e.g. 'w2' instead of 'W2')
    must be rejected at load time, not silently pass validation and then fail to
    match `_INDIRECT_ONLY_WEAKNESS_CLASSES` in a case-sensitive set intersection —
    which would let a seed-less W2 target skip the hard pre-flight block and read
    as clean."""
    with pytest.raises(ValueError, match="weakness_classes"):
        _tf(weakness_classes=["w2"])


@pytest.mark.parametrize("cls", ["W1", "W2", "W3", "W4"])
def test_target_file_accepts_valid_weakness_classes(cls: str) -> None:
    tf = _tf(weakness_classes=[cls])
    assert tf.weakness_classes == [cls]


def test_target_file_server_layer_fields_round_trip(tmp_path: Path) -> None:
    from mylonite.plugins._mcp.target_file import dump_target_file

    tf = _tf(
        control_env={"W2": {"DISABLE_MARKING": "1"}},
        vulnerable_launch={"env": {"PROFILE": "vuln"}},
    )
    p = tmp_path / "t.yaml"
    p.write_text(dump_target_file(tf), encoding="utf-8")
    reloaded = load_target_file(p)
    assert reloaded.control_env == {"W2": {"DISABLE_MARKING": "1"}}
    assert reloaded.vulnerable_launch is not None
    assert reloaded.vulnerable_launch.env == {"PROFILE": "vuln"}


def test_build_target_spec_carries_server_layer_fields() -> None:
    spec = build_target_spec(
        _tf(
            control_env={"W4": {"AUTONOMY": "full"}},
            vulnerable_launch={"command": "python", "args": ["-m", "srv", "--raw"]},
        )
    )
    assert spec.control_env == {"W4": {"AUTONOMY": "full"}}
    assert spec.vulnerable_launch is not None
    assert spec.vulnerable_launch.command == "python"
    assert spec.vulnerable_launch.args == ["-m", "srv", "--raw"]


def test_target_context_for_translates_spec_to_pure_data() -> None:
    """PR2: target_context_for is the one-way TargetSpec -> TargetContext
    translation gate/recommend.py needs but cannot import plugins to build
    itself (see that function's docstring for why the import direction only
    goes this way)."""
    from mylonite.gate.recommend import TargetContext
    from mylonite.plugins._mcp.target_file import target_context_for
    from mylonite.plugins._mcp.target_registry import ControlConfig

    cfg = ControlConfig(egress_tools=("web_fetch",))
    spec = build_target_spec(_tf(control_config=cfg))
    ctx = target_context_for(spec, target_id="mcp:acme", framework="langchain")
    assert isinstance(ctx, TargetContext)
    assert ctx.target_id == "mcp:acme"
    assert ctx.transport == "stdio"
    assert ctx.launch_command == "python"
    assert ctx.control_config is cfg
    assert ctx.framework == "langchain"
    assert ctx.tools == ()


def test_target_file_framework_defaults_to_none_and_round_trips(tmp_path: Path) -> None:
    """PR10: `framework:` is optional, free-form, and never validated against a
    fixed enum -- an unrecognised value still round-trips as a plain string."""
    from mylonite.plugins._mcp.target_file import dump_target_file

    default = _tf()
    assert default.framework is None
    assert "framework" not in dump_target_file(default)

    tf = _tf(framework="langchain")
    dumped = dump_target_file(tf)
    assert "framework: langchain" in dumped
    p = tmp_path / "target.yaml"
    p.write_text(dumped, encoding="utf-8")
    reloaded = load_target_file(p)
    assert reloaded.framework == "langchain"


def test_target_file_with_no_new_fields_is_byte_identical_round_trip(tmp_path: Path) -> None:
    """Backward-compat: a target file that declares neither new field round-trips
    unchanged (the optional fields are omitted on dump via exclude_defaults).

    Compares excluding ``source_dir``: that field is bookkeeping set by
    ``load_target_file`` (the containment base for path fields in the document),
    never part of the persisted YAML, so it legitimately differs between an
    in-memory ``TargetFile`` (``source_dir=None``) and one loaded from ``p``
    (``source_dir=p.parent``).
    """
    from mylonite.plugins._mcp.target_file import dump_target_file

    tf = _tf(weakness_classes=["W2"])
    dumped = dump_target_file(tf)
    assert "control_env" not in dumped
    assert "vulnerable_launch" not in dumped
    assert "source_dir" not in dumped
    p = tmp_path / "t.yaml"
    p.write_text(dumped, encoding="utf-8")
    reloaded = load_target_file(p)
    assert reloaded.model_dump(exclude={"source_dir"}) == tf.model_dump(exclude={"source_dir"})


# --- M3: auto-wire seed_arm from the tool surface ---------------------------


def _toolspec(name: str, props: dict, required: list | None = None):
    from mylonite.contracts._types import ToolSpec

    return ToolSpec(
        name=name,
        description=name,
        json_schema={"type": "object", "properties": props, "required": required or []},
    )


def test_infer_seed_arm_when_store_and_recall_present() -> None:
    from mylonite.plugins._mcp.target_file import infer_seed_arm

    tools = [
        _toolspec("remember", {"content": {"type": "string"}}),
        _toolspec("recall", {}),  # no-id recall path → delivery guaranteed
    ]
    spec, note = infer_seed_arm(tools)
    assert spec is not None
    assert spec.tool == "remember"
    assert spec.args_template == {"content": "{payload}"}
    assert "inferred seed_arm" in note


def test_infer_seed_arm_none_when_no_id_free_recall() -> None:
    from mylonite.plugins._mcp.target_file import infer_seed_arm

    tools = [
        _toolspec("save_note", {"content": {"type": "string"}}),
        _toolspec("read_note", {"note_id": {"type": "string"}}, required=["note_id"]),
    ]
    spec, note = infer_seed_arm(tools)
    assert spec is None
    assert "id-free recall" in note.lower()


def test_infer_seed_arm_none_when_no_store_tool() -> None:
    from mylonite.plugins._mcp.target_file import infer_seed_arm

    spec, note = infer_seed_arm([_toolspec("list_files", {"path": {"type": "string"}})])
    assert spec is None
    assert "no content-storing tool" in note.lower()


def test_needs_seed_arm_autowire() -> None:
    from mylonite.plugins._mcp.target_file import needs_seed_arm_autowire

    assert needs_seed_arm_autowire(_tf(weakness_classes=["W2"])) is True  # W2, no seed_arm
    assert needs_seed_arm_autowire(_tf(weakness_classes=["W4"])) is False  # not indirect-only
    assert (
        needs_seed_arm_autowire(
            _tf(weakness_classes=["W2"], seed_arm=SeedArmSpec(tool="x", args_template={}))
        )
        is False  # already declared
    )
