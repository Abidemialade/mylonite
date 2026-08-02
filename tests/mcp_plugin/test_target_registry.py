"""Unit tests for the bundled MCP target registry."""

from __future__ import annotations

from pathlib import Path

import pytest

from mylonite.plugins._mcp.target_registry import (
    BUNDLED_TARGETS,
    InvalidTargetScope,
    UnknownTargetFamily,
    _validate_filesystem_scope,
    resolve_target,
)


def test_bundled_targets_contains_expected_families() -> None:
    assert set(BUNDLED_TARGETS) == {"filesystem", "fetch", "github"}


def test_resolve_filesystem_accepts_absolute_path(tmp_path: Path) -> None:
    spec = resolve_target("filesystem", str(tmp_path))
    assert spec.family == "filesystem"
    assert spec.command == "npx"
    assert spec.requires_scope is True
    assert "read_file" in spec.primary_tools


def test_resolve_filesystem_rejects_empty_scope() -> None:
    with pytest.raises(InvalidTargetScope, match=r"absolute path|sandbox path"):
        resolve_target("filesystem", "")


def test_resolve_filesystem_rejects_relative_path() -> None:
    with pytest.raises(InvalidTargetScope, match="absolute path"):
        resolve_target("filesystem", "relative/path")


@pytest.mark.parametrize("scope", ["/", "C:\\", "/tmp/sandbox/../../etc"])
def test_validate_filesystem_scope_rejects_root_and_traversal(scope: str) -> None:
    """DCR-0017: absolute-shape was the only check, so `/` collapsed the sandbox
    to the whole disk and the target's read_file/write_file reached anything."""
    with pytest.raises(InvalidTargetScope):
        _validate_filesystem_scope(scope)


def test_resolve_fetch_accepts_none_scope() -> None:
    spec = resolve_target("fetch", None)
    assert spec.family == "fetch"
    assert spec.requires_scope is False


def test_resolve_fetch_accepts_label_scope() -> None:
    spec = resolve_target("fetch", "any-label")
    assert spec.family == "fetch"


def test_resolve_fetch_rejects_whitespace_only_scope() -> None:
    with pytest.raises(InvalidTargetScope, match="non-empty"):
        resolve_target("fetch", "   ")


def test_resolve_github_accepts_owner_repo() -> None:
    spec = resolve_target("github", "myhandle/test-repo")
    assert spec.family == "github"
    assert spec.requires_scope is True
    assert "create_issue" in spec.primary_tools


def test_resolve_github_rejects_missing_slash() -> None:
    with pytest.raises(InvalidTargetScope, match="owner/repo"):
        resolve_target("github", "not-a-repo")


def test_resolve_github_rejects_extra_slashes() -> None:
    with pytest.raises(InvalidTargetScope, match="owner/repo"):
        resolve_target("github", "owner/repo/extra")


def test_resolve_unknown_family_raises_typed_error() -> None:
    with pytest.raises(UnknownTargetFamily, match="unknown MCP target family"):
        resolve_target("nosuch", "scope")


def test_render_args_appends_scope_for_filesystem(tmp_path: Path) -> None:
    spec = BUNDLED_TARGETS["filesystem"]
    args = spec.render_args(str(tmp_path))
    assert args == ["-y", "@modelcontextprotocol/server-filesystem", str(tmp_path)]


def test_render_args_omits_scope_for_fetch() -> None:
    spec = BUNDLED_TARGETS["fetch"]
    args = spec.render_args(None)
    assert args == ["mcp-server-fetch"]


def test_render_args_omits_scope_for_github_uses_env_var_pattern() -> None:
    """github MCP server reads owner/repo via env var, not CLI args."""
    spec = BUNDLED_TARGETS["github"]
    args = spec.render_args("myhandle/repo")
    assert args == ["-y", "@modelcontextprotocol/server-github"]
