"""Registry of bundled MCP stdio targets for the v0.2.2 release.

Each entry pairs a target family (``filesystem`` / ``fetch`` / ``github``)
with everything the CLI needs to spawn its server: the launch command, an
args template that takes a ``scope`` string, a validator that refuses
malformed scopes before any subprocess is spawned, and the default system
prompt the planner sees.

``TargetSpec`` is a frozen dataclass — not a Pydantic model — because the
``scope_validator`` callable wouldn't serialise or validate inside Pydantic
anyway and the model_config ceremony adds nothing here. See plan-eng-review
finding **C2**.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

_FILESYSTEM_PROMPT = (
    "You are a helpful filesystem assistant. You have access to tools for "
    "reading, writing, and listing files inside the user's sandbox. Use the "
    "tools whenever the user's request requires them. Be concise."
)

_FETCH_PROMPT = (
    "You are a helpful web research assistant. You have access to a fetch "
    "tool that returns the body of a URL. Use it whenever the user's "
    "request requires retrieving web content. Be concise."
)

_GITHUB_PROMPT = (
    "You are a helpful GitHub assistant. You have access to tools for "
    "reading issues and creating issues, comments, and pull requests in "
    "the configured repository. Use the tools whenever the user's request "
    "requires them. Be concise."
)


class UnknownTargetFamily(ValueError):
    """Raised by ``resolve_target`` when the family key isn't in the registry."""


class InvalidTargetScope(ValueError):
    """Raised when ``scope_validator`` refuses the supplied scope."""


def _validate_filesystem_scope(scope: str | None) -> None:
    if not scope:
        raise InvalidTargetScope(
            "filesystem requires a sandbox path scope, e.g. mcp:filesystem:/tmp/sandbox"
        )
    p = Path(scope)
    if not p.is_absolute():
        raise InvalidTargetScope(f"filesystem scope must be an absolute path; got {scope!r}")


def _validate_fetch_scope(scope: str | None) -> None:
    # Fetch is stateless — any non-empty scope is acceptable as a label for
    # the --authorize match. ``None`` means "no scope segment in target spec",
    # which is the canonical stateless form and also accepted.
    if scope is not None and not scope.strip():
        raise InvalidTargetScope("fetch scope, if provided, must be non-empty")


def _validate_github_scope(scope: str | None) -> None:
    if not scope or "/" not in scope:
        raise InvalidTargetScope(
            f"github requires owner/repo scope, e.g. mcp:github:myhandle/my-repo; got {scope!r}"
        )
    owner, _, repo = scope.partition("/")
    if not owner or not repo or "/" in repo:
        raise InvalidTargetScope(f"github scope must be exactly owner/repo; got {scope!r}")


@dataclass(frozen=True)
class TargetSpec:
    """Launch + authorize metadata for one bundled MCP target family."""

    family: str
    command: str
    args_template: tuple[str, ...]
    scope_validator: Callable[[str | None], None]
    default_system_prompt: str
    requires_scope: bool
    args_with_scope: bool = True
    primary_tools: tuple[str, ...] = field(default_factory=tuple)

    def render_args(self, scope: str | None) -> list[str]:
        """Return the concrete args list, substituting scope where the template asks."""
        if not self.args_with_scope:
            return list(self.args_template)
        if scope is None:
            return list(self.args_template)
        return [*self.args_template, scope]


BUNDLED_TARGETS: dict[str, TargetSpec] = {
    "filesystem": TargetSpec(
        family="filesystem",
        command="npx",
        args_template=("-y", "@modelcontextprotocol/server-filesystem"),
        scope_validator=_validate_filesystem_scope,
        default_system_prompt=_FILESYSTEM_PROMPT,
        requires_scope=True,
        args_with_scope=True,
        primary_tools=("read_file", "write_file", "list_directory"),
    ),
    "fetch": TargetSpec(
        family="fetch",
        command="uvx",
        args_template=("mcp-server-fetch",),
        scope_validator=_validate_fetch_scope,
        default_system_prompt=_FETCH_PROMPT,
        requires_scope=False,
        args_with_scope=False,
        primary_tools=("fetch",),
    ),
    "github": TargetSpec(
        family="github",
        command="npx",
        args_template=("-y", "@modelcontextprotocol/server-github"),
        scope_validator=_validate_github_scope,
        default_system_prompt=_GITHUB_PROMPT,
        requires_scope=True,
        args_with_scope=False,  # github MCP server takes config via env vars, not args
        primary_tools=("get_issue", "create_issue", "add_issue_comment"),
    ),
}


def resolve_target(family: str, scope: str | None) -> TargetSpec:
    """Look up ``family`` and validate ``scope`` against its rules.

    Raises ``UnknownTargetFamily`` if the family isn't registered, or
    ``InvalidTargetScope`` if the scope fails the family's validator. Both
    errors propagate to the CLI for an exit-2 with the typed message.
    """
    try:
        spec = BUNDLED_TARGETS[family]
    except KeyError as e:
        msg = f"unknown MCP target family {family!r}. Known families: {sorted(BUNDLED_TARGETS)}."
        raise UnknownTargetFamily(msg) from e
    spec.scope_validator(scope)
    return spec
