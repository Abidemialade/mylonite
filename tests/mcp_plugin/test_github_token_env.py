"""``mcp:github``'s ``GITHUB_PERSONAL_ACCESS_TOKEN`` (#184).

The bundled ``github`` ``TargetSpec`` declares an ``extra_env`` entry pointing
at ``${GITHUB_PERSONAL_ACCESS_TOKEN}`` -- the same ``${VAR}`` expansion
mechanism a custom target file's own ``env:`` block already uses (see
``plugins/_mcp/target_file.py``'s ``_expand_dict_block``/``expand_env_block``).
Before this, the bundled spec had no ``extra_env`` at all: the stdio env
allowlist (``_INHERITED_ENV_KEYS``) deliberately withholds secrets, and
``--env`` only applies to ``mcp:custom`` -- so a spawned ``mcp:github`` server
never received a token no matter what the operator set.
"""

from __future__ import annotations

import pytest

from mylonite.plugins._mcp.stdio_adapter import GitHubMCPAdapter
from mylonite.plugins._mcp.target_registry import BUNDLED_TARGETS


def test_bundled_github_spec_declares_the_token_env_ref() -> None:
    assert BUNDLED_TARGETS["github"].extra_env == {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "${GITHUB_PERSONAL_ACCESS_TOKEN}"
    }


def test_github_effective_env_resolves_the_token_from_the_parent_shell(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "GITHUB_PERSONAL_ACCESS_TOKEN", "ghp_realvalue123"
    )  # pragma: allowlist secret
    adapter = GitHubMCPAdapter(scope="myhandle/myrepo")
    assert adapter._effective_env() == {"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_realvalue123"}


def test_github_effective_env_raises_a_named_error_when_the_token_is_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GITHUB_PERSONAL_ACCESS_TOKEN", raising=False)
    adapter = GitHubMCPAdapter(scope="myhandle/myrepo")
    with pytest.raises(ValueError, match="GITHUB_PERSONAL_ACCESS_TOKEN"):
        adapter._effective_env()


def test_github_missing_token_message_does_not_say_target_file(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fix round 1: the bundled mcp:github family has no target file at all
    -- the generic custom-target-file wording ("target file references
    undefined environment variable(s)...") is actively wrong here."""
    monkeypatch.delenv("GITHUB_PERSONAL_ACCESS_TOKEN", raising=False)
    adapter = GitHubMCPAdapter(scope="myhandle/myrepo")
    with pytest.raises(ValueError) as excinfo:
        adapter._effective_env()
    assert "target file" not in str(excinfo.value).lower()


def test_a_caller_supplied_launch_env_is_also_expanded(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fix round 1: ``launch_env`` is NOT always concrete -- every real caller
    that constructs one (``factory.build_adapter_for_spec``, the ONLY path
    gate's re-drive twin and ablation both go through) builds it from
    ``TargetSpec.launch_env()``, which is just ``dict(self.extra_env)`` --
    still carrying the SAME unexpanded ``${VAR}`` template the base
    (non-launch_env) branch already expands. The previous "launch_env is
    already concrete" assumption was wrong and left gate's guarded/raw twin
    receiving the literal string ``${GITHUB_PERSONAL_ACCESS_TOKEN}``."""
    monkeypatch.setenv(
        "GITHUB_PERSONAL_ACCESS_TOKEN", "ghp_realvalue123"
    )  # pragma: allowlist secret
    adapter = GitHubMCPAdapter(scope="myhandle/myrepo", planner_timeout_s=5.0)
    adapter._launch_env = {"GITHUB_PERSONAL_ACCESS_TOKEN": "${GITHUB_PERSONAL_ACCESS_TOKEN}"}
    assert adapter._effective_env() == {"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_realvalue123"}


def test_a_caller_supplied_launch_env_still_raises_when_unresolvable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GITHUB_PERSONAL_ACCESS_TOKEN", raising=False)
    adapter = GitHubMCPAdapter(scope="myhandle/myrepo", planner_timeout_s=5.0)
    adapter._launch_env = {"GITHUB_PERSONAL_ACCESS_TOKEN": "${GITHUB_PERSONAL_ACCESS_TOKEN}"}
    with pytest.raises(ValueError, match="GITHUB_PERSONAL_ACCESS_TOKEN"):
        adapter._effective_env()


def test_build_adapter_for_spec_github_twin_resolves_the_real_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#184 fix round 1: the exact repro -- ``build_adapter_for_spec(resolve_
    target('github', 'o/r'), ...)._effective_env()`` used to return the
    literal ``${GITHUB_PERSONAL_ACCESS_TOKEN}`` because gate/wiring.py builds
    both re-drive twins through ``build_adapter_for_spec``, which always
    passes ``launch_env=spec.launch_env(...)`` -- the SAME unexpanded
    template, not a caller-supplied concrete value."""
    from mylonite.plugins._mcp import target_registry
    from mylonite.plugins._mcp.factory import build_adapter_for_spec

    monkeypatch.setenv(
        "GITHUB_PERSONAL_ACCESS_TOKEN", "ghp_realvalue123"
    )  # pragma: allowlist secret
    spec = target_registry.resolve_target("github", "o/r")
    adapter = build_adapter_for_spec(spec, scope="o/r", model="m")
    assert adapter._effective_env() == {"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_realvalue123"}


def test_gate_re_drive_twin_raw_and_guarded_both_resolve_the_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Simulates gate/wiring.py's ``_factory``/``_guarded`` closures (~362/370):
    both the raw and the boundary-guarded twin are built through
    ``build_adapter_for_spec`` with a ``LaunchIntent`` -- neither must ever
    see the unexpanded template."""
    from mylonite.plugins._mcp import target_registry
    from mylonite.plugins._mcp.factory import LaunchIntent, build_adapter_for_spec

    monkeypatch.setenv(
        "GITHUB_PERSONAL_ACCESS_TOKEN", "ghp_realvalue123"
    )  # pragma: allowlist secret
    spec = target_registry.resolve_target("github", "o/r")

    raw = build_adapter_for_spec(spec, scope="o/r", model="m", intent=LaunchIntent())
    assert raw._effective_env() == {"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_realvalue123"}

    guarded = build_adapter_for_spec(
        spec, scope="o/r", model="m", intent=LaunchIntent(disable_controls=())
    )
    assert guarded._effective_env() == {"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_realvalue123"}
