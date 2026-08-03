"""The one authorization gate: required_authorization/check_authorization.

DCR-0008: a target file that declares a ``scope`` but leaves
``requires_scope: false`` must still require that scope to be authorized —
the required token is derived from the declared scope (data), never trusted
from the self-asserted ``requires_scope`` flag living inside the very
document being authorized.
"""

from __future__ import annotations

import pytest

from mylonite._authz import AuthorizationRefused, check_authorization, required_authorization


def test_scope_wins_over_family_even_when_requires_scope_is_false() -> None:
    """DCR-0008: a YAML setting `scope` but leaving `requires_scope: false`
    downgraded the gate to matching the guessable literal family name."""
    assert required_authorization(family="custom", scope="/home/alice/private") == (
        "/home/alice/private"
    )


def test_required_authorization_falls_back_to_family_when_no_scope() -> None:
    assert required_authorization(family="fetch", scope=None) == "fetch"


def test_required_authorization_treats_blank_scope_as_absent() -> None:
    assert required_authorization(family="fetch", scope="   ") == "fetch"


def test_refuses_family_name_when_a_scope_is_declared() -> None:
    with pytest.raises(AuthorizationRefused) as exc:
        check_authorization(
            family="custom", scope="/home/alice/private", authorize="custom", command="scan"
        )
    assert "/home/alice/private" in str(exc.value)


def test_accepts_matching_scope() -> None:
    check_authorization(
        family="custom",
        scope="/home/alice/private",
        authorize="/home/alice/private",
        command="scan",
    )


def test_stateless_target_authorizes_by_family() -> None:
    check_authorization(family="fetch", scope=None, authorize="fetch", command="scan")


def test_stateless_target_refuses_wrong_authorize() -> None:
    with pytest.raises(AuthorizationRefused) as exc:
        check_authorization(family="fetch", scope=None, authorize="wrong", command="scan")
    assert "fetch" in str(exc.value)


def test_refuses_missing_authorize() -> None:
    with pytest.raises(AuthorizationRefused):
        check_authorization(family="fetch", scope=None, authorize=None, command="scan")


def test_error_names_the_command() -> None:
    with pytest.raises(AuthorizationRefused) as exc:
        check_authorization(family="fetch", scope=None, authorize=None, command="validate")
    assert "validate" in str(exc.value)
