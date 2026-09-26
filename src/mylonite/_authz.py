"""The one authorization gate for every command that live-drives a real target.

Mylonite reproduces working exploits, so ``SECURITY.md`` requires the operator
to NAME the resource they are authorizing. That rule used to be implemented
three times: ``scan`` and ``gate`` shared one check that derived its branch
from a flag (``requires_scope``) living INSIDE the document being authorized
(DCR-0008), ``ablate`` only checked that *something* was passed, and
``validate`` implemented it zero times (DCR-0009).

The required token is derived from the TARGET's data, never from a
self-asserted flag: a target file declaring ``scope: /home/alice/private``
must have that scope authorized even if it also (accidentally or otherwise)
sets ``requires_scope: false``.
"""

from __future__ import annotations

from pathlib import Path

__all__ = [
    "AuthorizationRefused",
    "authorize_fix",
    "authorize_hint",
    "bundled_authorize_value",
    "check_authorization",
    "required_authorization",
]


class AuthorizationRefused(ValueError):
    """Raised when ``--authorize`` does not name the target being driven."""


def required_authorization(*, family: str, scope: str | None) -> str:
    """The exact ``--authorize`` value this target requires.

    Derived from data, not from ``requires_scope``: a target that NAMES a scope
    must have that scope authorized. Trusting the flag let a target file declare
    ``scope: /home/alice/private`` with ``requires_scope: false`` and be
    authorized by typing the guessable literal ``custom`` (DCR-0008).
    """
    if scope and scope.strip():
        return scope.strip()
    return family


def check_authorization(
    *, family: str, scope: str | None, authorize: str | None, command: str
) -> None:
    """Raise :class:`AuthorizationRefused` unless ``authorize`` names the target."""
    required = required_authorization(family=family, scope=scope)
    if authorize is not None and authorize.strip() == required:
        return
    kind = "scope" if (scope and scope.strip()) else "family name"
    msg = (
        f"mylonite {command} live-drives {family!r} and sends real attack payloads "
        f"to it. --authorize must equal the {kind} for {family!r} ({required!r}); "
        f"got {authorize!r}. See SECURITY.md."
    )
    raise AuthorizationRefused(msg)


def authorize_fix(value: str) -> str:
    """The one wording for "name the fix" wherever a caller must pass ``--authorize``.

    Capitalised: every call site interpolates this straight after a sentence
    that already ends in a full stop (typically "... See SECURITY.md."), so
    this reads as its own sentence, not a dangling clause. ``authorize_hint``
    and the two bundled-target call sites in ``cli.py`` all route through this
    one function so the wording cannot drift between them.
    """
    return f"Pass --authorize {value}."


def authorize_hint(target_file: Path) -> str | None:
    """The ``--authorize`` fix sentence for a custom target file, or ``None``.

    Uses the same chain as the scaffold's "next:" line (load the file, build
    its spec, derive the required value), so the hint cannot drift from the
    check that later enforces it. Returns ``None`` when the file is missing or
    does not load: the caller reports that case on its own.
    """
    # Imported lazily: the target-file loader pulls in pydantic/yaml and the
    # MCP registry, which the authorization rule itself does not need.
    from mylonite.plugins._mcp.target_file import build_target_spec, load_target_file

    try:
        tf = load_target_file(target_file)
        spec = build_target_spec(tf)
    except Exception:
        return None
    return authorize_fix(required_authorization(family=spec.family, scope=tf.scope))


def bundled_authorize_value(target: str) -> str:
    """The ``--authorize`` value a bundled ``mcp:<family>[:<scope>]`` target needs.

    Mirrors the check in ``cli._build_adapter_for_mcp``: a family that requires
    a scope is authorized by that scope, every other family by its name. A
    scope-requiring family given without a scope yields ``"<scope>"``, since no
    value can authorize it until a scope is named.
    """
    from mylonite.plugins._mcp.target_registry import BUNDLED_TARGETS

    parts = target.split(":", 2)
    family = parts[1] if len(parts) > 1 else target
    scope = parts[2] if len(parts) == 3 else None
    spec = BUNDLED_TARGETS.get(family)
    if spec is not None and not spec.requires_scope:
        return family
    if scope:
        return scope
    return "<scope>" if spec is not None else family
