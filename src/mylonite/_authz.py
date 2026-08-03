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

__all__ = ["AuthorizationRefused", "check_authorization", "required_authorization"]


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
