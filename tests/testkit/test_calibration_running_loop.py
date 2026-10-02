"""The testkit's calibration step works from inside a running event loop.

``assert_target_resists`` and ``assert_control_holds`` calibrate the target's
effect probe before re-driving it. A caller that already runs an event loop
(an async test, a notebook) must not get ``RuntimeError: asyncio.run() cannot
be called from a running event loop`` from that step.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from tests.testkit.test_bounded_redrive import _exploit

from mylonite import testkit
from mylonite.plugins._mcp import calibration

_TARGET_YAML = """\
family: myapp-loop
command: echo
args: []
weakness_classes:
  - W4
effect_probe:
  verify_tool: check_sent
  expect_marker: ops@example.com
"""


@pytest.mark.asyncio
async def test_assert_target_resists_calibrates_inside_a_running_loop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "target.yaml"
    target.write_text(_TARGET_YAML, encoding="utf-8")
    calibrated: list[bool] = []

    async def _fake_calibrate(adapter: Any, *, authorized: bool) -> Any:
        calibrated.append(authorized)
        return None

    monkeypatch.setattr(calibration, "calibrate_custom_target", _fake_calibrate)
    monkeypatch.setattr(testkit, "_run_target_scan", lambda **kwargs: object())
    # TK-1 gives `assert_target_resists` a context-accurate `_assert_from_result`
    # call (extra keyword-only args naming the real target), so the double must
    # accept and ignore them too.
    monkeypatch.setattr(testkit, "_assert_from_result", lambda *args, **kwargs: None)

    testkit.assert_target_resists(
        _exploit(), target_file=target, model="stub-model", provider="anthropic"
    )
    assert calibrated == [True]
