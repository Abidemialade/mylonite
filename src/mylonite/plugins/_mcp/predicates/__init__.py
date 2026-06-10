"""Per-target predicate modules for the v0.2.2 bundled MCP stdio targets.

Each module here is imported for its ``@predicate(...)`` side effects.
The parent package's ``__init__.py`` does the eager import; this package
init stays empty so re-importing one module doesn't drag the others in.
"""
