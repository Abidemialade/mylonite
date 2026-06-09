"""Plugin loader version-compatibility checks."""

from __future__ import annotations

import pytest

from mylonite.contracts.attack_module import (
    CONTRACT_VERSION as ATTACK_CONTRACT_VERSION,
)
from mylonite.contracts.target_adapter import (
    CONTRACT_VERSION as ADAPTER_CONTRACT_VERSION,
)
from mylonite.plugins.registry import (
    VersionIncompatibleError,
    _check_compat,
    _parse_semver,
    discover,
)


class _FuturePlugin:
    contract_version = "999.0.0"

    def attack_metadata(self) -> object: ...

    def generate_payloads(self, target: object) -> object: ...


class _MissingVersionPlugin:
    def attack_metadata(self) -> object: ...

    def generate_payloads(self, target: object) -> object: ...


def test_parse_semver() -> None:
    assert _parse_semver("0.1.0") == (0, 1, 0)
    assert _parse_semver("12.3.4") == (12, 3, 4)


def test_parse_semver_rejects_two_part() -> None:
    with pytest.raises(ValueError, match=r"major\.minor\.patch"):
        _parse_semver("0.1")


def test_compat_rejects_major_mismatch() -> None:
    with pytest.raises(VersionIncompatibleError, match="major=0"):
        _check_compat(
            "mylonite.attack_modules",
            ATTACK_CONTRACT_VERSION,
            _FuturePlugin(),
            "future_test",
        )


def test_compat_rejects_missing_version() -> None:
    with pytest.raises(VersionIncompatibleError, match="missing 'contract_version'"):
        _check_compat(
            "mylonite.attack_modules",
            ATTACK_CONTRACT_VERSION,
            _MissingVersionPlugin(),
            "noversion_test",
        )


def test_compat_accepts_matching_major() -> None:
    class _OK:
        contract_version = ADAPTER_CONTRACT_VERSION

    # Should not raise.
    _check_compat(
        "mylonite.target_adapters",
        ADAPTER_CONTRACT_VERSION,
        _OK(),
        "ok_test",
    )


def test_discover_returns_reference_plugins() -> None:
    attacks = discover("mylonite.attack_modules")
    assert len(attacks) >= 1
    assert any(type(p).__name__ == "ReferenceAttackModule" for p in attacks)
