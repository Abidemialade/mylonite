"""Compare a coding agent's real GitHub grant with an owner-approved intent file."""

from mylonite.access.compare import Finding, compare_grant, escalation_findings
from mylonite.access.drill import (
    ArmResult,
    DrillResult,
    mint_app_jwt,
    not_tested_drill,
    run_revocation_drill,
)
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
from mylonite.access.report import (
    AccessReport,
    build_report,
    exit_code,
    input_digest,
    to_json,
    to_markdown,
)

__all__ = [
    "AccessReport",
    "ArmResult",
    "ControlsIntent",
    "DrillResult",
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
    "build_report",
    "compare_grant",
    "escalation_findings",
    "exit_code",
    "input_digest",
    "load_intent",
    "mint_app_jwt",
    "not_tested_drill",
    "read_app_grant",
    "read_classic_token_grant",
    "require_approved",
    "run_revocation_drill",
    "to_json",
    "to_markdown",
]
