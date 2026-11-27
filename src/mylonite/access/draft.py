"""Draft an unapproved intent file from an agent's current grant.

The draft mirrors what the agent holds today so an owner can remove what it
should not have, then approve it. It is never approved: ``approved_by`` is
empty and ``approved_on`` is absent. Both escalation fields are written as
``forbidden`` whatever the grant holds, so a draft never approves an
escalation path by default.

The YAML is written by hand in a fixed order with sorted lists. Every
GitHub-sourced string goes through :func:`_q`, which emits a JSON string
(valid YAML double-quoted scalar, control characters escaped), so a hostile
repository name cannot add keys or comments to the file.
"""

from __future__ import annotations

import json

from mylonite.access.grants import Grant

_HEADER = (
    "# Drafted from the current grant. Remove what the agent should not have, "
    "then fill in approved_by and approved_on."
)
_ADMIN_NOTE = "  # the grant is admin, which is higher than write"
_NONE_NOTE = "  # the grant gives no contents access"
_NOTES = {"admin": _ADMIN_NOTE, "none": _NONE_NOTE}


def _q(text: str) -> str:
    """A string as a quoted YAML scalar that cannot break out of its line."""
    return json.dumps(text, ensure_ascii=True)


def draft_intent_yaml(grant: Grant, organisation: str) -> str:
    """The text of an unapproved intent file that mirrors ``grant``."""
    lines = [
        _HEADER,
        "intent_version: 0",
        'approved_by: ""',
        f"organisation: {_q(organisation)}",
        "environment: test",
        "identity:",
        f"  kind: {grant.identity_kind}",
    ]
    if grant.identity_kind == "github_app":
        lines.append(f"  app_slug: {_q(grant.identity_label)}")

    # A repository the grant reaches with no contents access is written as
    # read, the lowest level an intent can hold, so an approved, unchanged
    # draft does not report it as not intended.
    repos = sorted(grant.repos, key=lambda r: r.name)
    if repos:
        lines.append("repositories:")
        for repo in repos:
            access = "write" if repo.level in ("write", "admin") else "read"
            note = _NOTES.get(repo.level, "")
            lines.append(f"  - name: {_q(repo.name)}")
            lines.append(f"    access: {access}{note}")
    else:
        lines.append("repositories: []")

    if grant.identity_kind == "github_app":
        perms = sorted(
            (k, v) for k, v in grant.permissions.items() if v in ("read", "write", "admin")
        )
        if perms:
            lines.append("permissions:")
            for key, value in perms:
                level = "read" if value == "read" else "write"
                note = _ADMIN_NOTE if value == "admin" else ""
                lines.append(f"  {_q(key)}: {level}{note}")
    else:
        scopes = sorted(set(grant.scopes))
        if scopes:
            lines.append("scopes:")
            lines.extend(f"  - {_q(scope)}" for scope in scopes)
        else:
            lines.append("scopes: []")

    lines += [
        "escalation:",
        "  workflow_write: forbidden",
        "  branch_rule_bypass: forbidden",
        "controls:",
        "  revocation: expected",
    ]
    return "\n".join(lines) + "\n"
