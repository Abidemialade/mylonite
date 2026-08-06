"""Tests for :mod:`mylonite.scan.exec_context` -- T12's ``ExecContext``.

Covers the two load-bearing properties: the allowlist (:meth:`to_metadata`
never emits anything outside :data:`ALLOWED_METADATA_KEYS`, in particular
nothing credential-shaped) and the round-trip (:meth:`from_metadata` recovers
what :meth:`to_metadata` wrote, and returns ``None`` when the required
``provider``/``model`` pair is absent).
"""

from __future__ import annotations

from mylonite.scan.exec_context import ALLOWED_METADATA_KEYS, METADATA_PREFIX, ExecContext


def test_to_metadata_is_a_closed_allowlist() -> None:
    """Every key ``to_metadata()`` can ever emit is namespaced + pre-declared.

    Constructs an ``ExecContext`` with every field populated (the maximal
    case) and asserts the resulting metadata dict's keys are EXACTLY the
    declared allowlist -- nothing more, nothing less, and every one under
    ``mylonite.exec.``.
    """
    ctx = ExecContext(
        provider="anthropic",
        model="claude-sonnet-4-5",
        planner_model="claude-haiku-4-5",
        customiser_model="claude-haiku-4-5",
        judge_model="claude-opus-4-5",
        target_file="target.yaml",
        mylonite_version="0.7.8",
    )
    metadata = ctx.to_metadata()
    assert set(metadata.keys()) == ALLOWED_METADATA_KEYS
    assert all(key.startswith(METADATA_PREFIX) for key in metadata)


def test_to_metadata_never_carries_credential_shaped_values() -> None:
    """Nothing shaped like a credential/env-var value ever appears.

    ``ExecContext`` has no field for a secret (no ``api_key_env_var``, no
    ``api_base``) -- this test enumerates the exact allowed keys (mirroring
    the plan's fallback for "if your dataclass has no such field") AND scans
    every emitted value for a credential-shaped token, so a future field added
    to the dataclass without updating ``to_metadata()`` cannot silently leak a
    secret through this allowlist.
    """
    ctx = ExecContext(
        provider="openai",
        model="gpt-4.1-mini",
        planner_model="sk-live-should-never-appear-here",
        target_file="../target.yaml",
    )
    metadata = ctx.to_metadata()
    # Only the allowlisted keys, never more.
    assert set(metadata.keys()) <= ALLOWED_METADATA_KEYS
    # No key resembling a secret/env-var name made it in.
    for key in metadata:
        lowered = key.lower()
        assert "key" not in lowered
        assert "secret" not in lowered
        assert "token" not in lowered
        assert "credential" not in lowered


def test_to_metadata_omits_unset_optional_fields() -> None:
    """Only the two required fields render when the optional ones are None."""
    ctx = ExecContext(provider="anthropic", model="claude-haiku-4-5")
    metadata = ctx.to_metadata()
    assert metadata == {
        f"{METADATA_PREFIX}provider": "anthropic",
        f"{METADATA_PREFIX}model": "claude-haiku-4-5",
    }


def test_from_metadata_round_trips() -> None:
    ctx = ExecContext(
        provider="anthropic",
        model="claude-sonnet-4-5",
        planner_model="claude-haiku-4-5",
        mylonite_version="0.7.8",
    )
    restored = ExecContext.from_metadata(ctx.to_metadata())
    assert restored == ctx


def test_from_metadata_returns_none_when_absent() -> None:
    """No ``mylonite.exec.*`` keys at all -> None, not a context of blank strings."""
    assert ExecContext.from_metadata({}) is None
    assert ExecContext.from_metadata({"seed_id": "x", "weakness": "W2"}) is None


def test_from_metadata_returns_none_when_only_partially_present() -> None:
    """Model without provider (or vice versa) is not a usable context."""
    assert ExecContext.from_metadata({f"{METADATA_PREFIX}model": "claude-haiku-4-5"}) is None
    assert ExecContext.from_metadata({f"{METADATA_PREFIX}provider": "anthropic"}) is None
