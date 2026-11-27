"""Compare a coding agent's real GitHub grant with an owner-approved intent file."""

from mylonite.access.compare import Finding, compare_grant, escalation_findings
from mylonite.access.github_client import GitHubClient, GitHubError
from mylonite.access.grants import (
    Grant,
    GrantError,
    Level,
    NotTested,
    RepoGrant,
    read_app_grant,
    read_classic_token_grant,
)
from mylonite.access.intent import (
    ControlsIntent,
    EscalationIntent,
    Identity,
    Intent,
    IntentError,
    RepoIntent,
    load_intent,
    require_approved,
)

__all__ = [
    "ControlsIntent",
    "EscalationIntent",
    "Finding",
    "GitHubClient",
    "GitHubError",
    "Grant",
    "GrantError",
    "Identity",
    "Intent",
    "IntentError",
    "Level",
    "NotTested",
    "RepoGrant",
    "RepoIntent",
    "compare_grant",
    "escalation_findings",
    "load_intent",
    "read_app_grant",
    "read_classic_token_grant",
    "require_approved",
]
