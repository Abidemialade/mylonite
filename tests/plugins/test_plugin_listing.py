"""`mylonite plugins` and resilient discovery (issue #90).

The four non-attack extension-contract groups were never discovered at runtime,
so `discover_all()` was dead and a misregistered plugin in one of them went
unnoticed. `mylonite plugins` now exercises discovery + version-gating for all
five groups, and `discover()` skips (rather than crashes on) a plugin that does
not meet the no-arg instantiation contract.
"""

from __future__ import annotations

from typing import Any

import pytest
from typer.testing import CliRunner

from mylonite.cli import app
from mylonite.plugins import registry
from mylonite.plugins.registry import discover

runner = CliRunner()

_ALL_GROUPS = (
    "mylonite.attack_modules",
    "mylonite.target_adapters",
    "mylonite.test_generators",
    "mylonite.validators",
    "mylonite.compliance_mappers",
)


def test_plugins_command_lists_every_group() -> None:
    result = runner.invoke(app, ["plugins"])
    assert result.exit_code == 0, result.output
    for group in _ALL_GROUPS:
        assert group in result.output


def test_plugins_command_reports_registered_reference_impls() -> None:
    result = runner.invoke(app, ["plugins"])
    # A representative reference implementation from a non-attack group proves the
    # other four groups are now discovered, not just attack modules.
    assert "DifferentialValidator" in result.output
    assert "ReferenceComplianceMapper" in result.output


def test_discover_is_resilient_to_non_no_arg_plugins() -> None:
    # The target-adapter group registers adapters that require a `family` kwarg
    # (they are reached through the factory, not the no-arg registry). Discovery
    # must skip those rather than raise, still returning the ones that do meet
    # the contract.
    adapters = discover("mylonite.target_adapters")
    names = {type(a).__name__ for a in adapters}
    assert "HTTPAgentAdapter" not in names  # requires args -> skipped
    assert names  # but the no-arg reference adapters still load


# --- listing must not report the product's own adapters as broken ------------


def test_plugins_lists_adapters_that_require_construction_config() -> None:
    """`mylonite plugins` lists what is INSTALLED; it need not construct it.

    Three of the target adapters Mylonite ships take a required argument -- they
    are built by the target-file factory for a named server family, not
    discovered ready-made. Because the listing used `discover_all`, which
    instantiates, those three were skipped with a WARNING and a clean install
    reported half the product's own adapters as broken.
    """
    result = runner.invoke(app, ["plugins"])
    assert result.exit_code == 0, result.output
    for name in ("FilesystemMCPAdapter", "GitHubMCPAdapter"):
        assert name in result.output, f"{name} should be listed, not skipped"


def test_plugins_output_carries_no_skip_warning() -> None:
    result = runner.invoke(app, ["plugins"])
    assert "not instantiable" not in result.output
    assert "skipping plugin" not in result.output


def test_plugins_marks_config_requiring_adapters_as_such() -> None:
    """Needing construction config is a property of the contract, not a fault."""
    result = runner.invoke(app, ["plugins"])
    assert "configured per target" in result.output


def test_describe_reads_the_version_without_constructing() -> None:
    from mylonite.plugins.registry import describe

    infos = describe("mylonite.target_adapters")
    assert infos, "expected registered target adapters"
    by_name = {i.class_name: i for i in infos}
    # A no-arg adapter and a config-requiring one are both described, and both
    # carry a real contract version read off the class.
    assert by_name["InProcessVulnerableReferenceAdapter"].needs_config is False
    assert by_name["FilesystemMCPAdapter"].needs_config is True
    assert all(i.contract_version != "?" for i in infos)


def test_describe_all_covers_every_group() -> None:
    from mylonite.plugins.registry import describe_all

    described = describe_all()
    assert set(described) == set(_ALL_GROUPS)
    assert described["mylonite.validators"], "expected the bundled validators"


# ---------------------------------------------------------------------------
# One incompatible plugin must not take out the whole listing.
#
# `describe()` used to run the compat check as a raising call, so a single
# third-party plugin declaring a mismatched major version made `mylonite
# plugins` exit with nothing printed -- while `scan`, which goes through
# `discover()`, only warned and carried on. The user sees a listing command
# claim total breakage about a working install.
# ---------------------------------------------------------------------------


class _MismatchedAttackModule:
    contract_version = "99.0.0"


def _fake_entry_points(monkeypatch: pytest.MonkeyPatch, group_name: str, name: str) -> None:
    real = registry.entry_points

    class _EP:
        def __init__(self) -> None:
            self.name = name

        def load(self) -> type:
            return _MismatchedAttackModule

    def _patched(*, group: str) -> list[Any]:
        existing = list(real(group=group))
        return [*existing, _EP()] if group == group_name else existing

    monkeypatch.setattr(registry, "entry_points", _patched)


def test_describe_reports_an_incompatible_plugin_instead_of_raising(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_entry_points(monkeypatch, "mylonite.attack_modules", "wrong_major")

    infos = registry.describe("mylonite.attack_modules")

    bad = [i for i in infos if i.entry_point == "wrong_major"]
    assert len(bad) == 1, "the incompatible plugin must still be listed"
    assert bad[0].incompatible, "it must be marked, not silently listed as healthy"
    assert "99.0.0" in bad[0].incompatible
    # The point of the change: the compatible plugins are still there.
    assert [i for i in infos if not i.incompatible], "the rest of the group must survive"


def test_plugins_command_lists_everything_then_exits_nonzero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both halves of the contract, in one command.

    The listing is the product of the command and must be printed; the non-zero
    exit is the signal that something needs attention. Aborting before printing
    gave the signal and destroyed the product.
    """
    _fake_entry_points(monkeypatch, "mylonite.attack_modules", "wrong_major")

    result = CliRunner().invoke(app, ["plugins"])

    assert result.exit_code != 0
    assert "INCOMPATIBLE" in result.output
    assert "_MismatchedAttackModule" in result.output
    # ...and the healthy plugins were still listed alongside it.
    assert "mylonite.target_adapters:" in result.output
    assert result.output.count("  - ") > 1
