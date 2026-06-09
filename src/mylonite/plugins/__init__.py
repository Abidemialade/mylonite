"""Plugin discovery and registration for the five extension points."""

from __future__ import annotations

from mylonite.plugins.registry import (
    PluginGroup,
    VersionIncompatibleError,
    discover,
    discover_all,
)

__all__ = [
    "PluginGroup",
    "VersionIncompatibleError",
    "discover",
    "discover_all",
]
