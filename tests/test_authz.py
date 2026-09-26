"""The one authorization gate: required_authorization/check_authorization.

DCR-0008: a target file that declares a ``scope`` but leaves
``requires_scope: false`` must still require that scope to be authorized —
the required token is derived from the declared scope (data), never trusted
from the self-asserted ``requires_scope`` flag living inside the very
document being authorized.
"""

from __future__ import annotations

from pathlib import Path

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


# --- authorize_hint / bundled_authorize_value (0.10.2 / M02) ---


def test_authorize_hint_names_the_scope(tmp_path: Path) -> None:
    from mylonite._authz import authorize_hint

    p = tmp_path / "t.yaml"
    p.write_text("family: acme\nscope: my-app\ncommand: python\nargs: []\n", encoding="utf-8")
    assert authorize_hint(p) == "Pass --authorize my-app."


def test_authorize_hint_falls_back_to_family(tmp_path: Path) -> None:
    from mylonite._authz import authorize_hint

    p = tmp_path / "t.yaml"
    p.write_text("family: acme\ncommand: python\nargs: []\n", encoding="utf-8")
    assert authorize_hint(p) == "Pass --authorize acme."


def test_authorize_hint_is_none_for_missing_or_invalid_file(tmp_path: Path) -> None:
    from mylonite._authz import authorize_hint

    assert authorize_hint(tmp_path / "missing.yaml") is None
    bad = tmp_path / "bad.yaml"
    bad.write_text("not: [valid\n", encoding="utf-8")
    assert authorize_hint(bad) is None
    wrong_shape = tmp_path / "shape.yaml"
    wrong_shape.write_text("family: acme\n", encoding="utf-8")
    assert authorize_hint(wrong_shape) is None


@pytest.mark.parametrize(
    "target,expected",
    [
        ("mcp:filesystem:/tmp/sandbox", "/tmp/sandbox"),
        ("mcp:github:octo/repo", "octo/repo"),
        ("mcp:fetch", "fetch"),
        # fetch does not require a scope, so a label still authorizes by family,
        # exactly as _build_adapter_for_mcp checks it.
        ("mcp:fetch:label", "fetch"),
        ("mcp:filesystem", "<scope>"),
    ],
)
def test_bundled_authorize_value(target: str, expected: str) -> None:
    from mylonite._authz import bundled_authorize_value

    assert bundled_authorize_value(target) == expected


# --- authorize_fix: the one wording, shared by authorize_hint and cli.py's two
# bundled-target inline call sites (0.10.2 / M02 controller polish) ---


def test_authorize_fix_is_capitalised_and_ends_with_a_full_stop() -> None:
    from mylonite._authz import authorize_fix

    assert authorize_fix("my-app") == "Pass --authorize my-app."


def test_authorize_hint_routes_through_authorize_fix(tmp_path: Path) -> None:
    from mylonite._authz import authorize_fix, authorize_hint

    p = tmp_path / "t.yaml"
    p.write_text("family: acme\nscope: my-app\ncommand: python\nargs: []\n", encoding="utf-8")
    assert authorize_hint(p) == authorize_fix("my-app")


@pytest.mark.parametrize(
    "target,expected",
    [
        ("mcp:filesystem:/tmp/sandbox", "Pass --authorize /tmp/sandbox."),
        ("mcp:fetch", "Pass --authorize fetch."),
        # No --authorize value alone can authorize a scope-requiring family with
        # no scope: the fix is the whole command form.
        ("mcp:filesystem", "Name a scope: mcp:filesystem:<scope> --authorize <scope>."),
        ("mcp:github", "Name a scope: mcp:github:<scope> --authorize <scope>."),
    ],
)
def test_bundled_authorize_fix(target: str, expected: str) -> None:
    from mylonite._authz import bundled_authorize_fix

    assert bundled_authorize_fix(target) == expected
