"""Stdio entry point: the VULNERABLE kitchen-sink server as a real MCP server.

Console script ``mcp-kitchen-sink-vulnerable`` (see ``pyproject.toml``) and
``python -m mcp_kitchen_sink.stdio_vulnerable`` both run this. Speaks the MCP
wire protocol over stdin/stdout until the peer closes the pipe — this is a
genuinely launchable ``command``/``args`` target for a ``mylonite``
``target.yaml`` (``examples/target.yaml`` in the repo root points at it).

Delegates every tool call to ``server_vulnerable.VulnerableKitchenSinkServer``
via ``_stdio_common.build_app`` — the seeded weaknesses (W1-W4, see
``server_vulnerable.py``) are unmodified.
"""

from __future__ import annotations

from mcp_kitchen_sink._stdio_common import run


def main() -> None:
    run("vulnerable")


if __name__ == "__main__":
    main()
