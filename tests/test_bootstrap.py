"""Tests for the shared process-environment bootstrap (``mylonite._bootstrap``)
and the package-level litellm cost-map default (``mylonite/__init__.py``).

These cover the "the CLI sets up the environment but the library path doesn't"
gap: truststore injection must be reusable from the testkit, and the import-time
litellm cost-map fetch must be disabled before any submodule imports litellm.
"""

from __future__ import annotations

import subprocess
import sys
from types import ModuleType
from typing import Any

import pytest

from mylonite._bootstrap import enable_truststore


def _install_fake_truststore(monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    """Put a fake ``truststore`` module on sys.modules; return a call counter."""
    calls = {"inject": 0}
    fake = ModuleType("truststore")

    def _inject() -> None:
        calls["inject"] += 1

    fake.inject_into_ssl = _inject  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "truststore", fake)
    return calls


def test_enable_truststore_injects_when_available(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MYLONITE_NO_TRUSTSTORE", raising=False)
    calls = _install_fake_truststore(monkeypatch)
    assert enable_truststore() is True
    assert calls["inject"] == 1


def test_enable_truststore_opt_out(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MYLONITE_NO_TRUSTSTORE", "1")
    calls = _install_fake_truststore(monkeypatch)
    assert enable_truststore() is False
    assert calls["inject"] == 0  # never even imported


def test_enable_truststore_absent_is_silent_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MYLONITE_NO_TRUSTSTORE", raising=False)

    # Force the import to fail.
    real_import = (
        __builtins__["__import__"] if isinstance(__builtins__, dict) else __builtins__.__import__
    )

    def _no_truststore(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "truststore":
            raise ModuleNotFoundError("No module named 'truststore'")
        return real_import(name, *args, **kwargs)

    monkeypatch.delitem(sys.modules, "truststore", raising=False)
    monkeypatch.setattr("builtins.__import__", _no_truststore)
    assert enable_truststore() is False  # best-effort, no raise


def test_cost_map_default_set_at_package_import(monkeypatch: pytest.MonkeyPatch) -> None:
    """Importing mylonite sets LITELLM_LOCAL_MODEL_COST_MAP=True when unset.

    Runs in a subprocess because the package is already imported in this session,
    so the module-level setdefault has already run here.
    """
    code = "import os; os.environ.pop('LITELLM_LOCAL_MODEL_COST_MAP', None); import mylonite; print(os.environ.get('LITELLM_LOCAL_MODEL_COST_MAP'))"
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "True"


def test_cost_map_default_does_not_override_user(monkeypatch: pytest.MonkeyPatch) -> None:
    """A user who set LITELLM_LOCAL_MODEL_COST_MAP keeps their value (setdefault)."""
    code = "import os; os.environ['LITELLM_LOCAL_MODEL_COST_MAP']='False'; import mylonite; print(os.environ['LITELLM_LOCAL_MODEL_COST_MAP'])"
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "False"
