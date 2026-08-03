"""``verification/fetch.py`` swallowed-exception tests — hermetic (no network).

DCR-0001/0002: ``_enable_truststore`` and ``fetch_agentdojo_runs`` used to
swallow every exception with a bare ``except Exception: pass``/``continue``,
so a truststore import failure or a proxy/TLS error was completely
undiagnosable (it looked identical to "everything is fine"). Both must now
log the exception instead of discarding it silently.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

from verification import fetch


def test_enable_truststore_logs_instead_of_swallowing(monkeypatch, caplog) -> None:
    fake_truststore = types.ModuleType("truststore")

    def _boom() -> None:
        raise RuntimeError("truststore inject failed")

    fake_truststore.inject_into_ssl = _boom  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "truststore", fake_truststore)

    with caplog.at_level("DEBUG", logger="verification.fetch"):
        fetch._enable_truststore()  # must not raise — best-effort

    assert any("truststore" in r.message.lower() for r in caplog.records)


def test_fetch_agentdojo_runs_logs_instead_of_swallowing_per_url_errors(
    monkeypatch, tmp_path: Path, caplog
) -> None:
    def _boom_urlopen(url, *a, **kw):
        raise OSError("connection refused")

    monkeypatch.setattr(fetch.urllib.request, "urlopen", _boom_urlopen)
    monkeypatch.setattr(fetch, "_enable_truststore", lambda: None)
    # Shrink the grid so the test doesn't log dozens of lines.
    monkeypatch.setattr(fetch, "_AGENTDOJO_USER_TASKS", range(1))
    monkeypatch.setattr(fetch, "_AGENTDOJO_INJECTION_TASKS", range(1))

    with caplog.at_level("DEBUG", logger="verification.fetch"):
        out = fetch.fetch_agentdojo_runs(dest_dir=tmp_path)

    assert out == []  # every combo failed — sparse grid, non-fatal
    assert any("connection refused" in r.message.lower() for r in caplog.records)
