"""Live end-to-end scan + generate against the real OSS fetch MCP server (G2).

Gated behind ``MYLONITE_LIVE_E2E=1`` and a present ``uvx`` (mirrors
``tests/integration/test_scan_mcp_fetch_live.py``). When enabled, it:

1. runs ``mylonite scan mcp:fetch --authorize fetch`` against the real
   ``mcp-server-fetch`` (spawned via ``uvx``), asserting a finding lands as an
   ``exploit_*.json`` artefact; then
2. runs ``mylonite generate`` against that scan output, asserting a regression
   test file is emitted.

This is the gated proof behind the docs' claim that the demo flow works on a
*real* target, not just the bundled reference twins. It SKIPS in normal CI — no
key, no subprocess, no network. Kept deliberately minimal.

Run with:

    pip install uv mcp-server-fetch
    MYLONITE_LIVE_E2E=1 ANTHROPIC_API_KEY=… pytest tests/e2e/test_real_target_generate_live.py -v
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("MYLONITE_LIVE_E2E") != "1",
    reason="Live e2e gated behind MYLONITE_LIVE_E2E=1",
)


def _run_cli(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    """Invoke the mylonite CLI as a subprocess, returning the completed process."""
    return subprocess.run(
        [sys.executable, "-m", "mylonite", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=300,
    )


def test_live_scan_then_generate_mcp_fetch(tmp_path: Path) -> None:
    if shutil.which("uvx") is None:
        pytest.skip("uvx not available — install uv (https://github.com/astral-sh/uv)")
    if not os.environ.get("ANTHROPIC_API_KEY"):
        pytest.skip("ANTHROPIC_API_KEY not set — required for the live LLM call")

    output_dir = tmp_path / "scans"
    scan = _run_cli(
        [
            "scan",
            "mcp:fetch",
            "--authorize",
            "fetch",
            "--output-dir",
            str(output_dir),
        ],
        cwd=tmp_path,
    )
    assert scan.returncode == 0, f"scan failed:\n{scan.stdout}\n{scan.stderr}"

    exploits = list(output_dir.rglob("exploit_*.json"))
    assert exploits, f"no exploit artefact found under {output_dir}:\n{scan.stdout}"

    scan_dir = exploits[0].parent
    out_dir = tmp_path / "generated"
    generate = _run_cli(
        ["generate", str(scan_dir), "--out", str(out_dir)],
        cwd=tmp_path,
    )
    assert generate.returncode == 0, f"generate failed:\n{generate.stdout}\n{generate.stderr}"

    tests = list(out_dir.rglob("test_security_*.py"))
    assert tests, f"no generated test found under {out_dir}:\n{generate.stdout}"
