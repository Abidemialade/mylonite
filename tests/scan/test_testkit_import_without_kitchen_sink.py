"""Importing testkit / generate must NOT require the reference target (P3).

`mcp_kitchen_sink` is a separately-installed package. Importing `mylonite.testkit`
(which `mylonite generate` does) must work without it — the reference adapter's
kitchen-sink imports are lazy. We prove it in a subprocess that blocks the import.
"""

from __future__ import annotations

import subprocess
import sys

_SNIPPET = """
import sys, importlib.abc
class _Block(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path, target=None):
        if name == "mcp_kitchen_sink" or name.startswith("mcp_kitchen_sink."):
            raise ImportError("mcp_kitchen_sink blocked for this test")
        return None
sys.meta_path.insert(0, _Block())

import mylonite.testkit
import mylonite.scan.wiring
from mylonite.cli import app  # generate command imports must resolve too
assert hasattr(mylonite.testkit, "load_exploit")
assert "mcp_kitchen_sink" not in sys.modules, "reference target leaked into import"
print("OK")
"""


def test_testkit_and_generate_import_without_reference_target() -> None:
    result = subprocess.run(
        [sys.executable, "-c", _SNIPPET],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "OK" in result.stdout
