"""The keyless gate path must not load LiteLLM.

A committed gate test imports ``mylonite.testkit`` and replays fixtures; it never
calls a model. LiteLLM takes several seconds to import, so loading it there made
every gate run, in users' CI and in this suite's subprocess tests, pay for a
client it never used. Each check runs in a fresh interpreter so no other test's
imports can have loaded LiteLLM first.
"""

from __future__ import annotations

import subprocess
import sys

import pytest


@pytest.mark.parametrize(
    "module",
    ["mylonite.testkit", "mylonite.scan._llm", "mylonite.scan.diagnostics"],
)
def test_importing_the_gate_path_does_not_load_litellm(module: str) -> None:
    code = (
        f"import sys\nimport {module}\nassert 'litellm' not in sys.modules, '{module} loaded it'\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_a_provider_error_is_still_classified_once_litellm_is_loaded() -> None:
    import litellm

    from mylonite.scan.diagnostics import classify_provider_error

    # The lazy lookup must still recognise LiteLLM's exception types once a
    # real call has loaded the module.
    exc = litellm.AuthenticationError(message="bad key", llm_provider="anthropic", model="m")
    assert classify_provider_error(exc, provider="anthropic").category == "auth"
