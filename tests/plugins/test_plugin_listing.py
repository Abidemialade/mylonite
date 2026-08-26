"""`mylonite plugins` and resilient discovery (issue #90).

The four non-attack extension-contract groups were never discovered at runtime,
so `discover_all()` was dead and a misregistered plugin in one of them went
unnoticed. `mylonite plugins` now exercises discovery + version-gating for all
five groups, and `discover()` skips (rather than crashes on) a plugin that does
not meet the no-arg instantiation contract.
"""

from __future__ import annotations

from typer.testing import CliRunner

from mylonite.cli import app
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
