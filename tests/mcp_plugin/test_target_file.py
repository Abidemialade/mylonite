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
from mylonite.plugins._mcp.target_registry import (
    CalibrationSettings,
    InvalidTargetScope,
    RequestSpec,
    SeedArmSpec,
)


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


def test_build_target_spec_cwd_defaults_to_none_for_inline_target() -> None:
    """#187: an in-memory TargetFile (assembled from `--command`/`--arg` CLI
    flags, no source YAML) has no `source_dir` to anchor to, so the spec's
    `cwd` stays None -- the caller's own working directory is unaffected."""
    spec = build_target_spec(_tf())
    assert spec.cwd is None


def test_build_target_spec_cwd_is_the_loaded_files_directory(tmp_path: Path) -> None:
    """#187: a LOADED target file's relative command/args must resolve
    against the YAML's own directory, the same base `system_prompt_file`
    already uses -- `build_target_spec` threads `TargetFile.source_dir`
    through as `TargetSpec.cwd`."""
    target = tmp_path / "app.yaml"
    target.write_text("family: acme\ncommand: python\nargs: [server.py]\n", encoding="utf-8")
    tf = load_target_file(target)
    spec = build_target_spec(tf)
    assert spec.cwd == str(tmp_path.resolve())


def test_target_file_timeout_s_defaults_to_none() -> None:
    """#186/#216: optional, mirrors RequestSpec.timeout_s -- an existing
    target file with no timeout_s must load unchanged (None -> today's
    fixed 60s planner/read timeout)."""
    assert _tf().timeout_s is None


def test_target_file_timeout_s_round_trips_through_yaml(tmp_path: Path) -> None:
    target = tmp_path / "t.yaml"
    target.write_text(
        "family: acme\ncommand: python\nargs: [-m, srv]\ntimeout_s: 90\n", encoding="utf-8"
    )
    tf = load_target_file(target)
    assert tf.timeout_s == 90.0


def test_build_target_spec_carries_timeout_s() -> None:
    spec = build_target_spec(_tf(timeout_s=45.0))
    assert spec.timeout_s == 45.0


def test_build_target_spec_timeout_s_defaults_to_none() -> None:
    spec = build_target_spec(_tf())
    assert spec.timeout_s is None


def test_target_file_rejects_a_non_positive_timeout_s() -> None:
    """timeout_s must be > 0 -- 0 or a negative value is not a
    meaningful timeout and would either fire instantly or never."""
    with pytest.raises(Exception, match="timeout_s"):
        _tf(timeout_s=0)
    with pytest.raises(Exception, match="timeout_s"):
        _tf(timeout_s=-5)


def test_target_file_rejects_timeout_s_on_a_rest_transport() -> None:
    """timeout_s is the MCP-transport (stdio/sse/http) knob --
    a rest target has its own request.timeout_s. Declaring both is
    confusing (which one applies?), so the top-level field is rejected
    outright on transport: rest, pointing at the right one."""
    with pytest.raises(ValueError, match=r"request\.timeout_s"):
        _tf(
            transport="rest",
            command="",
            request=RequestSpec(url="https://agent.example/chat", body='{"prompt": "{prompt}"}'),
            timeout_s=30,
        )


def test_target_file_calibration_defaults_to_none() -> None:
    """No calibration block declared -- build_target_spec falls back to "auto"."""
    assert _tf().calibration is None


def test_target_file_calibration_controls_round_trips_through_yaml(tmp_path: Path) -> None:
    target = tmp_path / "t.yaml"
    target.write_text(
        "family: acme\ncommand: python\nargs: [-m, srv]\ncalibration:\n  controls: allow\n",
        encoding="utf-8",
    )
    tf = load_target_file(target)
    assert tf.calibration is not None
    assert tf.calibration.controls == "allow"


def test_build_target_spec_carries_calibration_controls() -> None:
    spec = build_target_spec(_tf(calibration=CalibrationSettings(controls="skip")))
    assert spec.calibration_controls == "skip"


def test_build_target_spec_calibration_controls_defaults_to_auto() -> None:
    spec = build_target_spec(_tf())
    assert spec.calibration_controls == "auto"


def test_target_file_rejects_an_unknown_calibration_controls_value() -> None:
    with pytest.raises(Exception):  # noqa: B017 — pydantic ValidationError
        _tf(calibration={"controls": "sometimes"})


def test_target_file_rejects_calibration_on_a_rest_transport() -> None:
    """calibration.controls is the MCP-transport knob -- a rest target has no
    MCP session to calibrate, so it is rejected outright, mirroring timeout_s."""
    with pytest.raises(ValueError, match="calibration"):
        _tf(
            transport="rest",
            command="",
            request=RequestSpec(url="https://agent.example/chat", body='{"prompt": "{prompt}"}'),
            calibration=CalibrationSettings(controls="allow"),
        )


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


def test_load_target_file_warns_on_relative_sqlite_path_in_env(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """#18/#187: the relative-SQLite-path footgun used to warn only when
    `scan --scaffold` first wrote the file. Loading an EXISTING target file
    (e.g. one a teammate hand-edited) must warn too."""
    p = tmp_path / "t.yaml"
    p.write_text(
        "family: acme\ncommand: python\nenv: {DB_URL: 'sqlite:///data.db'}\n",
        encoding="utf-8",
    )
    load_target_file(p)
    assert "relative SQLite path" in capsys.readouterr().err


def test_load_target_file_warns_on_relative_sqlite_path_in_args(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """#187: the footgun check used to look only at `env`; a relative DB path
    handed to the server via a positional `args` entry must warn too."""
    p = tmp_path / "t.yaml"
    p.write_text(
        "family: acme\ncommand: python\nargs: ['--db', 'notes.db']\n",
        encoding="utf-8",
    )
    load_target_file(p)
    assert "relative SQLite path" in capsys.readouterr().err


def test_load_target_file_never_prints_a_credential_shaped_arg_value(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Critical fix (review round 1): the `args` warning must withhold the
    flagged value exactly like the `env` warning already does -- a
    credential-shaped token with no recognised prefix sails straight past
    `redact()`'s shape-based patterns. Names the position instead."""
    token = "session_7f3a9c2b1e4d6f8a0b2c4d6e8f0a2b4c.sqlite3"
    p = tmp_path / "t.yaml"
    p.write_text(
        f"family: acme\ncommand: python\nargs: ['--cache-db', '{token}']\n",
        encoding="utf-8",
    )
    load_target_file(p)
    err = capsys.readouterr().err
    assert "relative SQLite path" in err
    assert "args[1]" in err
    assert token not in err


def test_load_target_file_silent_with_no_relative_sqlite_path(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    p = tmp_path / "t.yaml"
    p.write_text("family: acme\ncommand: python\nargs: [server.py]\n", encoding="utf-8")
    load_target_file(p)
    assert "relative SQLite path" not in capsys.readouterr().err


# --- #210/#183: a credential-shaped `args` entry warns, never prints it -----


def test_load_target_file_warns_on_credential_shaped_arg(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`args` has no key name to mask a value by (unlike `env`/`headers`), so
    a credential handed to the server as a literal launch argument
    (`--api-key=sk-live-...`) survives in every copy Mylonite writes. Warn,
    naming the position, and withhold the value."""
    fake_key = "sk-live-abcdefghijklmnopqrstuvwxyz"  # pragma: allowlist secret
    p = tmp_path / "t.yaml"
    p.write_text(
        f"family: acme\ncommand: python\nargs: ['--api-key={fake_key}']\n",
        encoding="utf-8",
    )
    load_target_file(p)
    err = capsys.readouterr().err
    assert "credential" in err
    assert "args[0]" in err
    assert fake_key not in err
    assert "env" in err  # points at the fix


def test_load_target_file_warns_on_bare_opaque_token_arg(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    fake_token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"  # pragma: allowlist secret
    p = tmp_path / "t.yaml"
    p.write_text(
        f"family: acme\ncommand: python\nargs: ['server.py', '{fake_token}']\n",
        encoding="utf-8",
    )
    load_target_file(p)
    err = capsys.readouterr().err
    assert "args[1]" in err
    assert fake_token not in err


def test_load_target_file_silent_with_no_credential_shaped_arg(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    p = tmp_path / "t.yaml"
    p.write_text(
        "family: acme\ncommand: python\nargs: [server.py, --port, '8080']\n", encoding="utf-8"
    )
    load_target_file(p)
    assert "carries a credential" not in capsys.readouterr().err


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
    """With an effect_probe declared, the effect is confirmable — no missing-probe
    warning. Uses {exfil_email}: a marker the agent must PRODUCE (not one Mylonite
    plants), so the exfil-literal collision advisory stays silent, and it already
    is the randomization-safe marker shape, so the literal-address advisory (#196)
    stays silent too."""
    from mylonite.plugins._mcp.target_registry import EffectProbeSpec

    tf = _tf(
        weakness_classes=["W4"],
        # A recipient the agent's own call carries, so the fixed-marker warning
        # stays silent too.
        effect_probe=EffectProbeSpec(verify_tool="list_sent", expect_marker="{exfil_email}"),
    )
    assert effect_probe_warnings(tf) == []


def test_effect_probe_warns_when_marker_is_a_planted_exfil_literal() -> None:
    """An expect_marker containing an exfil literal Mylonite itself plants is a
    collision hazard on a plant-and-recall target — warn, and name the marker."""
    from mylonite.plugins._mcp.target_registry import EffectProbeSpec

    tf = _tf(
        weakness_classes=["W4"],
        effect_probe=EffectProbeSpec(
            verify_tool="read_graph", expect_marker="attacker@example.com"
        ),
    )
    warnings = effect_probe_warnings(tf)
    assert any("attacker@example.com" in w and "reflects" in w for w in warnings), warnings


def _status_word_warnings(marker: str, **over: object) -> list[str]:
    from mylonite.plugins._mcp.target_registry import EffectProbeSpec

    tf = _tf(
        weakness_classes=["W4"],
        effect_probe=EffectProbeSpec(verify_tool="list_outbox", expect_marker=marker),
        **over,
    )
    return [w for w in effect_probe_warnings(tf) if "never read 'true'" in w]


def test_effect_probe_warns_on_a_fixed_marker_the_agent_does_not_carry() -> None:
    """A fixed status word the agent's call does not carry links only when the
    seed names the tool, and only synthesised seeds do. On a catalogue seed the
    effect can read 'unattributed' but never 'true', so `validate` cannot keep
    the finding. The dependable fix is a marker the agent's own call carries."""
    warnings = _status_word_warnings("status=sent")
    assert len(warnings) == 1, warnings
    assert "'status=sent'" in warnings[0]
    assert "synthesised" in warnings[0]
    assert "recipient" in warnings[0]
    assert warnings[0].isascii()


def test_effect_probe_fixed_marker_warning_silent_when_marker_uses_payload() -> None:
    assert _status_word_warnings("sent: {payload}") == []


def test_effect_probe_fixed_marker_warning_fires_even_when_consequential_tool_declared() -> None:
    """A declared consequential tool never reaches a catalogue seed's link, so
    it does not make the marker work there and must not silence the warning."""
    from mylonite.plugins._mcp.target_registry import ControlConfig

    cc = ControlConfig(consequential_tools=("send_email",))
    warnings = _status_word_warnings("status=sent", control_config=cc)
    assert len(warnings) == 1, warnings
    assert "consequential_tools" in warnings[0]


def test_effect_probe_fixed_marker_warning_fires_even_when_egress_tool_declared() -> None:
    from mylonite.plugins._mcp.target_registry import ControlConfig

    cc = ControlConfig(egress_tools=("web_fetch",))
    assert len(_status_word_warnings("status=fetched", control_config=cc)) == 1


@pytest.mark.parametrize("marker", ["ops@example.com", "https://collector.example.net/x"])
def test_effect_probe_fixed_marker_warning_silent_for_an_address(marker: str) -> None:
    """A recipient or destination is what the agent's own call carries, so it
    links through that call's arguments: the fix the warning recommends."""
    assert _status_word_warnings(marker) == []


@pytest.mark.parametrize("marker", ["ops@example.com", "https://collector.example.net/x"])
def test_effect_probe_warns_a_literal_address_cannot_match_a_randomized_one(
    marker: str,
) -> None:
    """#196: a scan can mint a fresh exfil destination per attempt, which a fixed
    literal address can never match -- steer the operator to {exfil_email}/{exfil_host}."""
    from mylonite.plugins._mcp.target_registry import EffectProbeSpec

    tf = _tf(
        weakness_classes=["W4"],
        effect_probe=EffectProbeSpec(verify_tool="list_outbox", expect_marker=marker),
    )
    warnings = [w for w in effect_probe_warnings(tf) if "{exfil_email}" in w or "{exfil_host}" in w]
    assert len(warnings) == 1, warnings
    assert marker in warnings[0]


@pytest.mark.parametrize("marker", ["{exfil_email}", "{exfil_host}", "sent to {exfil_email}"])
def test_effect_probe_exfil_placeholder_marker_warns_neither_way(marker: str) -> None:
    """{exfil_email}/{exfil_host} render to THIS attempt's active destination, so
    they are neither "fixed and uncarried" nor "a literal that can't be randomized"."""
    from mylonite.plugins._mcp.target_registry import EffectProbeSpec

    tf = _tf(
        weakness_classes=["W4"],
        effect_probe=EffectProbeSpec(verify_tool="list_outbox", expect_marker=marker),
    )
    assert effect_probe_warnings(tf) == []


@pytest.mark.parametrize(
    "marker", ["email.sent", "status.ok", "report.pdf", "v1.2", "sent @ 10:00"]
)
def test_effect_probe_fixed_marker_warning_fires_for_a_status_word_not_an_address(
    marker: str,
) -> None:
    """A dotted or `@`-containing status word is not an email or a URL, so the
    address exemption must not swallow it: the marker still can't be tied to
    an attempt through the agent's own call. Before the exemption was tightened to
    a real email shape (`x@y.z`) or `://`, `looks_like_destination`'s bare-host
    heuristic and the bare `"@" in marker` check wrongly exempted all five."""
    assert len(_status_word_warnings(marker)) == 1


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


# --- auto-wire seed_arm from the tool surface -------------------------------


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


def test_expand_env_block_subject_customises_the_missing_var_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """expand_env_block's default subject ("target file") is
    right for a LOADED target file's own env: block, but wrong for a
    caller with no target file at all (the bundled mcp:github spec) --
    the subject must be overridable per call."""
    from mylonite.plugins._mcp.target_file import expand_env_block

    monkeypatch.delenv("NOT_A_REAL_VAR_XYZ", raising=False)
    with pytest.raises(ValueError, match="the bundled mcp:github target") as excinfo:
        expand_env_block(
            {"TOKEN": "${NOT_A_REAL_VAR_XYZ}"}, subject="the bundled mcp:github target"
        )
    assert "target file references" not in str(excinfo.value)


def test_expand_env_block_default_subject_stays_target_file() -> None:
    from mylonite.plugins._mcp.target_file import expand_env_block

    with pytest.raises(ValueError, match="target file references"):
        expand_env_block({"TOKEN": "${NOT_A_REAL_VAR_XYZ}"})


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


def _rest_with_probe_yaml() -> str:
    return (
        "family: my-agent\n"
        "transport: rest\n"
        "weakness_classes: [W2]\n"
        "request:\n"
        "  url: https://agent.example/chat\n"
        '  body: \'{"prompt": "{prompt}"}\'\n'
        "effect_probe:\n"
        "  verify_tool: list_outbox\n"
        "  expect_marker: '{exfil_email}'\n"
    )


def test_target_file_rejects_an_effect_probe_on_a_rest_transport() -> None:
    """A rest target only returns the agent's reply, so nothing can run a verify
    tool against its state. The field used to be dropped without a word; it is
    now refused with one message that says why and what to do instead."""
    from mylonite.plugins._mcp.target_registry import EffectProbeSpec

    with pytest.raises(ValueError, match="effect_probe is not supported on a rest target") as info:
        _tf(
            transport="rest",
            command="",
            request=RequestSpec(url="https://agent.example/chat", body='{"prompt": "{prompt}"}'),
            effect_probe=EffectProbeSpec(verify_tool="list_outbox"),
        )
    message = str(info.value)
    assert "Remove the effect_probe block" in message
    assert "MCP server" in message


def test_load_target_file_rejects_an_effect_probe_on_a_rest_transport(tmp_path: Path) -> None:
    target = tmp_path / "agent.yaml"
    target.write_text(_rest_with_probe_yaml(), encoding="utf-8")
    with pytest.raises(ValueError, match="effect_probe is not supported on a rest target"):
        load_target_file(target)


def test_a_rest_target_without_an_effect_probe_still_loads(tmp_path: Path) -> None:
    target = tmp_path / "agent.yaml"
    target.write_text(_rest_with_probe_yaml().split("effect_probe:")[0], encoding="utf-8")
    assert load_target_file(target).effect_probe is None


# --- seed_tool_ceiling -------------------------------------------------------


def test_seed_tool_ceiling_defaults_to_none() -> None:
    """An existing target file loads unchanged and keeps the built-in ceiling."""
    assert _tf().seed_tool_ceiling is None
    assert build_target_spec(_tf()).seed_tool_ceiling is None


def test_seed_tool_ceiling_round_trips_through_yaml_into_the_spec(tmp_path: Path) -> None:
    target = tmp_path / "t.yaml"
    target.write_text(
        "family: acme\ncommand: python\nargs: [-m, srv]\nseed_tool_ceiling: 20\n",
        encoding="utf-8",
    )
    tf = load_target_file(target)
    assert tf.seed_tool_ceiling == 20
    assert build_target_spec(tf).seed_tool_ceiling == 20


@pytest.mark.parametrize("value", [2, 51, 0, -1])
def test_seed_tool_ceiling_out_of_bounds_is_rejected(value: int) -> None:
    with pytest.raises(ValueError, match="seed_tool_ceiling must be between 3 and 50"):
        _tf(seed_tool_ceiling=value)


@pytest.mark.parametrize("value", [True, 8.5, "12"])
def test_seed_tool_ceiling_must_be_a_whole_number(value: object) -> None:
    with pytest.raises(ValueError, match="seed_tool_ceiling"):
        _tf(seed_tool_ceiling=value)


@pytest.mark.parametrize("value", [3, 50])
def test_seed_tool_ceiling_bounds_are_inclusive(value: int) -> None:
    assert _tf(seed_tool_ceiling=value).seed_tool_ceiling == value


def test_a_target_spec_checks_its_own_seed_tool_ceiling() -> None:
    """A spec built in code, not from a file, gets the same check."""
    spec = build_target_spec(_tf())
    with pytest.raises(ValueError, match="seed_tool_ceiling"):
        type(spec)(**{**spec.__dict__, "seed_tool_ceiling": 99})


def test_seed_tool_ceiling_is_rejected_on_a_rest_transport() -> None:
    with pytest.raises(ValueError, match="seed_tool_ceiling is for MCP transports"):
        _tf(
            transport="rest",
            command="",
            request=RequestSpec(url="https://agent.example/chat", body='{"p": "{prompt}"}'),
            seed_tool_ceiling=12,
        )


# --- Mylonite's own credentials in a remote target file's headers -------------

_FAKE_VALUE = "fake-value-not-a-real-secret"  # pragma: allowlist secret


def _remote_yaml(transport: str, field: str, name: str) -> str:
    """A minimal target file whose ``field`` header references ``${name}``."""
    if field == "headers":
        url = "" if transport == "rest" else "url: https://app.example.com/mcp\n"
        req = (
            'request:\n  url: https://agent.example.com/chat\n  body: \'{"p": "{prompt}"}\'\n'
            if transport == "rest"
            else ""
        )
        return (
            f"family: acme\ntransport: {transport}\n{url}{req}"
            f"headers:\n  Authorization: Bearer ${{{name}}}\n"
        )
    return (
        "family: acme\ntransport: rest\nrequest:\n  url: https://agent.example.com/chat\n"
        '  body: \'{"p": "{prompt}"}\'\n'
        f"  headers:\n    Authorization: Bearer ${{{name}}}\n"
    )


_FIXED_RESERVED = (
    "MYLONITE_API_KEY",
    "MYLONITE_LLM_KEY",
    "MYLONITE_LLM_HEADERS",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "ACTIONS_RUNTIME_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
)


def _reserved_names() -> list[str]:
    """Built independently of the module under test: every provider
    credential in the registry plus Mylonite's and CI's own tokens."""
    from mylonite.providers.registry import PROVIDERS

    names = set(_FIXED_RESERVED)
    for info in PROVIDERS.values():
        names.update(info.key_env)
        for alt in info.key_env_alternatives:
            names.update(alt)
    return sorted(names)


@pytest.mark.parametrize("name", _reserved_names())
@pytest.mark.parametrize(
    ("transport", "field"),
    [("sse", "headers"), ("http", "headers"), ("rest", "headers"), ("rest", "request.headers")],
)
def test_remote_target_refuses_mylonites_own_credential_in_headers(
    name: str,
    transport: str,
    field: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A shared remote target file must not be able to send one of
    Mylonite's own credentials to its URL. The error names the variable and
    the alias fix, and never prints the value."""
    monkeypatch.setenv(name, _FAKE_VALUE)
    path = tmp_path / "target.yaml"
    path.write_text(_remote_yaml(transport, field, name), encoding="utf-8")

    with pytest.raises(ValueError) as excinfo:
        load_target_file(path)
    msg = str(excinfo.value)
    assert f"${{{name}}}" in msg
    assert field in msg
    assert "export MY_TOKEN=" in msg
    assert "${MY_TOKEN}" in msg
    assert _FAKE_VALUE not in msg
    captured = capsys.readouterr()
    assert _FAKE_VALUE not in captured.err + captured.out


def test_reserved_credential_check_ignores_case(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Windows reads env names case-insensitively, so ``${gh_token}`` would
    resolve GH_TOKEN there; refuse it on every platform."""
    monkeypatch.setenv("gh_token", _FAKE_VALUE)
    path = tmp_path / "target.yaml"
    path.write_text(_remote_yaml("sse", "headers", "gh_token"), encoding="utf-8")
    with pytest.raises(ValueError, match=r"\$\{gh_token\}"):
        load_target_file(path)


def test_stdio_target_with_a_reserved_header_reference_still_loads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A stdio target sends no headers anywhere, so the check does not apply."""
    monkeypatch.setenv("GH_TOKEN", _FAKE_VALUE)
    path = tmp_path / "target.yaml"
    path.write_text(
        "family: acme\ncommand: python\nheaders:\n  Authorization: Bearer ${GH_TOKEN}\n"
        "env:\n  GITHUB_TOKEN: ${GH_TOKEN}\n",
        encoding="utf-8",
    )
    tf = load_target_file(path)
    assert tf.headers["Authorization"] == f"Bearer {_FAKE_VALUE}"
    assert tf.env["GITHUB_TOKEN"] == _FAKE_VALUE
    assert "target file sends" not in capsys.readouterr().err


def test_remote_target_env_block_with_a_reserved_name_is_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only headers are checked; a remote target's ``env`` block is not sent."""
    monkeypatch.setenv("GH_TOKEN", _FAKE_VALUE)
    path = tmp_path / "target.yaml"
    path.write_text(
        "family: acme\ntransport: sse\nurl: https://app.example.com/mcp\n"
        "env:\n  GITHUB_TOKEN: ${GH_TOKEN}\n",
        encoding="utf-8",
    )
    assert load_target_file(path).env["GITHUB_TOKEN"] == _FAKE_VALUE


@pytest.mark.parametrize(
    ("transport", "field", "host"),
    [
        ("sse", "headers", "app.example.com"),
        ("http", "headers", "app.example.com"),
        ("rest", "request.headers", "agent.example.com"),
    ],
)
def test_remote_target_names_each_header_variable_and_its_host(
    transport: str,
    field: str,
    host: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The documented ``${MY_TOKEN}`` pattern keeps working and prints a
    notice naming the variable and the host it goes to (never the value)."""
    monkeypatch.setenv("MY_TOKEN", _FAKE_VALUE)
    path = tmp_path / "target.yaml"
    path.write_text(_remote_yaml(transport, field, "MY_TOKEN"), encoding="utf-8")

    tf = load_target_file(path)
    headers = tf.headers if field == "headers" else tf.request.headers  # type: ignore[union-attr]
    assert headers["Authorization"] == f"Bearer {_FAKE_VALUE}"
    err = capsys.readouterr().err
    assert f"target file sends $MY_TOKEN to {host}" in err
    assert _FAKE_VALUE not in err


def test_reserved_set_covers_every_provider_credential() -> None:
    """Guard: a provider added to the registry is reserved automatically."""
    from mylonite.plugins._mcp.target_file import RESERVED_CREDENTIAL_ENV_VARS

    assert set(_reserved_names()) <= RESERVED_CREDENTIAL_ENV_VARS
