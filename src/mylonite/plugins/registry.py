"""Plugin discovery via standard PyPI entry points.

Five groups, one per extension contract. The five groups and the contract
versions they expose are read from the contract modules so the registry
never drifts out of sync with the contracts themselves.

Compatibility rule (also documented in CONTRIBUTING.md):

* Plugin's declared ``contract_version`` major MUST equal the host's major.
  Otherwise the plugin is refused at load time, with a clear error message.
* Minor mismatches are logged at WARNING but the plugin is loaded.
* Patch differences are ignored.
"""

from __future__ import annotations

import logging
from importlib.metadata import EntryPoint, entry_points
from typing import Any, Literal, get_args

from mylonite.contracts import (
    attack_module,
    compliance_mapper,
    target_adapter,
    test_generator,
    validator,
)

logger = logging.getLogger(__name__)

PluginGroup = Literal[
    "mylonite.attack_modules",
    "mylonite.target_adapters",
    "mylonite.test_generators",
    "mylonite.validators",
    "mylonite.compliance_mappers",
]

_GROUP_VERSIONS: dict[str, str] = {
    "mylonite.attack_modules": attack_module.CONTRACT_VERSION,
    "mylonite.target_adapters": target_adapter.CONTRACT_VERSION,
    "mylonite.test_generators": test_generator.CONTRACT_VERSION,
    "mylonite.validators": validator.CONTRACT_VERSION,
    "mylonite.compliance_mappers": compliance_mapper.CONTRACT_VERSION,
}


class VersionIncompatibleError(RuntimeError):
    """Raised when a discovered plugin is incompatible with the host contract."""


def _parse_semver(version: str) -> tuple[int, int, int]:
    parts = version.split(".")
    if len(parts) != 3:
        msg = f"contract_version must be 'major.minor.patch', got {version!r}"
        raise ValueError(msg)
    try:
        return (int(parts[0]), int(parts[1]), int(parts[2]))
    except ValueError as exc:
        msg = f"contract_version components must be integers, got {version!r}"
        raise ValueError(msg) from exc


def _check_compat(group: str, host_version: str, plugin: object, ep_name: str) -> None:
    plugin_version = getattr(plugin, "contract_version", None)
    if plugin_version is None:
        msg = f"Plugin {ep_name!r} in group {group!r} is missing 'contract_version'."
        raise VersionIncompatibleError(msg)
    host_major, host_minor, _ = _parse_semver(host_version)
    plugin_major, plugin_minor, _ = _parse_semver(plugin_version)
    if plugin_major != host_major:
        msg = (
            f"Plugin {ep_name!r} declares contract_version={plugin_version} "
            f"in group {group!r}; host expects major={host_major} (current "
            f"contract version {host_version}). Refusing to load."
        )
        raise VersionIncompatibleError(msg)
    if plugin_minor > host_minor:
        logger.warning(
            "Plugin %r declares contract_version=%s, newer than host's %s. "
            "Loading anyway; some optional behavior may be unavailable.",
            ep_name,
            plugin_version,
            host_version,
        )


def discover(group: PluginGroup) -> list[Any]:
    """Discover and instantiate plugins for ``group``.

    Each plugin is a class (registered as an entry point pointing at the
    class itself); the registry instantiates them with no arguments. Plugins
    that need configuration should accept it lazily via the contract's
    methods, not via ``__init__``, to keep discovery side-effect free.

    A plugin that cannot be instantiated with no arguments (i.e. does not meet
    that contract) is **skipped with a WARNING** rather than crashing discovery
    -- one misregistered plugin must not take out an unrelated group. This is
    how ``mylonite plugins`` can enumerate every group even though some target
    adapters are reached through the target-file / factory path and expect
    construction arguments, not the no-arg registry.
    """
    if group not in _GROUP_VERSIONS:
        valid = ", ".join(sorted(_GROUP_VERSIONS))
        msg = f"Unknown plugin group {group!r}. Valid groups: {valid}"
        raise ValueError(msg)
    host_version = _GROUP_VERSIONS[group]
    eps: list[EntryPoint] = list(entry_points(group=group))
    loaded: list[Any] = []
    for ep in eps:
        cls = ep.load()
        try:
            instance = cls()
        except TypeError:
            # A missing required __init__ argument is the precise no-arg-contract
            # violation. Catch only TypeError so a genuine bug in a plugin's
            # __init__ (NameError, a config-load failure, ...) still surfaces
            # loudly instead of being silently skipped.
            logger.warning(
                "skipping plugin %r in group %s: not instantiable with no arguments "
                "(discovery requires config to flow via the contract's methods, not "
                "__init__)",
                ep.name,
                group,
            )
            continue
        _check_compat(group, host_version, instance, ep.name)
        loaded.append(instance)
    return loaded


def discover_all() -> dict[str, list[Any]]:
    """Discover plugins for every known group."""
    return {group: discover(group) for group in get_args(PluginGroup)}
