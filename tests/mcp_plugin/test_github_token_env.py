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


def test_a_caller_supplied_launch_env_is_not_expanded(monkeypatch: pytest.MonkeyPatch) -> None:
    """``launch_env`` (ablation / --prove-control) already holds CONCRETE
    values, never a ``${VAR}`` template -- it must pass through unexpanded,
    including when it happens to contain a literal ``${...}``-shaped string
    (an attacker-controlled payload, say)."""
    monkeypatch.delenv("GITHUB_PERSONAL_ACCESS_TOKEN", raising=False)
    adapter = GitHubMCPAdapter(scope="myhandle/myrepo", planner_timeout_s=5.0)
    adapter._launch_env = {"GITHUB_PERSONAL_ACCESS_TOKEN": "${NOT_A_REAL_VAR}"}
    assert adapter._effective_env() == {"GITHUB_PERSONAL_ACCESS_TOKEN": "${NOT_A_REAL_VAR}"}
