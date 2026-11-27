"""The intent file: what an owner approved a coding agent to hold on GitHub."""

from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, ValidationError, model_validator


class IntentError(ValueError):
    """The intent file cannot be used. The message is one line."""


class Identity(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["github_app", "classic_token"]
    app_slug: str | None = None


class RepoIntent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    access: Literal["read", "write"]


class EscalationIntent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    workflow_write: Literal["forbidden", "allowed"] = "forbidden"
    branch_rule_bypass: Literal["forbidden", "allowed"] = "forbidden"


class ControlsIntent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    revocation: Literal["expected", "not_expected"] = "expected"


class Intent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    intent_version: Literal[0]
    approved_by: str
    approved_on: date | None = None
    organisation: str
    environment: Literal["test"]
    identity: Identity
    repositories: list[RepoIntent]
    permissions: dict[str, Literal["read", "write"]] = {}
    scopes: list[str] = []
    escalation: EscalationIntent = EscalationIntent()
    controls: ControlsIntent = ControlsIntent()

    @model_validator(mode="after")
    def _check_consistency(self) -> Intent:
        prefix = self.organisation + "/"
        for repo in self.repositories:
            if not repo.name.startswith(prefix):
                raise ValueError(
                    f"repository {repo.name} is outside the organisation {self.organisation}"
                )
        if self.identity.kind == "github_app" and not self.identity.app_slug:
            raise ValueError("identity.app_slug is required when kind is github_app")
        return self


def _one_line(text: str) -> str:
    return " ".join(text.split())


def load_intent(path: Path) -> Intent:
    """Read and validate an intent file. Raises IntentError with a one-line message."""
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise IntentError(f"cannot read intent file {path}: {exc.strerror or exc}") from exc
    except UnicodeDecodeError:
        raise IntentError(f"intent file {path} is not valid UTF-8 text") from None
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise IntentError(f"intent file {path} is not valid YAML: {_one_line(str(exc))}") from exc
    if not isinstance(data, dict):
        raise IntentError(f"intent file {path} must be a mapping of fields")
    try:
        return Intent.model_validate(data)
    except ValidationError as exc:
        parts = []
        for err in exc.errors():
            loc = ".".join(str(p) for p in err["loc"]) or "intent"
            parts.append(f"{loc}: {err['msg']}")
        raise IntentError(f"intent file {path} is invalid: " + "; ".join(parts)) from exc


def require_approved(intent: Intent) -> None:
    """Refuse an intent that no owner has approved."""
    if not intent.approved_by.strip() or intent.approved_on is None:
        raise IntentError("intent file is not approved: set approved_by and approved_on")
