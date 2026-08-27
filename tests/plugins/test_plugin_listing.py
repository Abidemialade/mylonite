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
