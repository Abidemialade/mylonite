"""Stdio entry point: the GUARDED kitchen-sink server as a real MCP server.

Console script ``mcp-kitchen-sink-guarded`` (see ``pyproject.toml``) and
``python -m mcp_kitchen_sink.stdio_guarded`` both run this. Speaks the MCP
wire protocol over stdin/stdout until the peer closes the pipe — the "PASS"
side of the differential oracle, launchable as a real ``command``/``args``
target for a ``mylonite`` ``target.yaml``.

Delegates every tool call to ``server_guarded.GuardedKitchenSinkServer`` via
``_stdio_common.build_app`` — the mitigations (M1-M4, see
``server_guarded.py``) are unmodified.
"""

from __future__ import annotations

from mcp_kitchen_sink._stdio_common import run


def main() -> None:
    run("guarded")


if __name__ == "__main__":
    main()
