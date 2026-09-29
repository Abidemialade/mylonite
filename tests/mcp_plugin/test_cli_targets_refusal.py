"""#181b: the pre-flight refusal, and its --allow-no-seed-arm exemption.

Unit-level (not through the full CLI): a fake adapter stands in for the
live ``describe()`` call, so these pin the refusal's own decision logic
directly — see ``tests/test_cli.py`` for the CLI-integration coverage
(exit codes, --dry-run downgrade, before-the-LLM-check ordering).
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
import typer

from mylonite.contracts import TargetDescriptor, ToolSpec
from mylonite.plugins.cli_targets import refuse_uncoverable_weakness_classes


class _FakeAdapter:
    def __init__(self, descriptor: TargetDescriptor) -> None:
        self._descriptor = descriptor

    async def describe(self) -> TargetDescriptor:
        return self._descriptor


def _descriptor(**kw: Any) -> TargetDescriptor:
    return TargetDescriptor(target_id="mcp:acme", kind="mcp", **kw)


def test_refuses_when_a_declared_class_has_zero_seeds() -> None:
    tf = SimpleNamespace(weakness_classes=["W3"])
    adapter = _FakeAdapter(
        _descriptor(weakness_classes=["W3"], tools=[ToolSpec(name="x", description="d")])
    )
    with pytest.raises(typer.Exit) as excinfo:
        refuse_uncoverable_weakness_classes(tf, adapter)
    assert excinfo.value.exit_code == 2


def test_no_op_when_every_declared_class_has_a_seed() -> None:
    tf = SimpleNamespace(weakness_classes=["W4"])
    adapter = _FakeAdapter(
        _descriptor(
            weakness_classes=["W4"], tools=[ToolSpec(name="send_email", description="send")]
        )
    )
    refuse_uncoverable_weakness_classes(tf, adapter)  # must not raise


def test_no_op_when_the_target_declares_no_weakness_classes() -> None:
    """The legacy family-mapping targets (empty weakness_classes) never go
    through descriptor-driven selection at all — describe() must not even
    be called (a bundled reference/mcp: target has no live adapter to spare
    calling describe() twice for)."""
    tf = SimpleNamespace(weakness_classes=[])

    class _ExplodingAdapter:
        async def describe(self) -> TargetDescriptor:
            raise AssertionError("describe() must not be called when weakness_classes is empty")

    refuse_uncoverable_weakness_classes(tf, _ExplodingAdapter())


def test_allow_no_seed_arm_exempts_w2_but_not_other_uncoverable_classes() -> None:
    """W2 (indirect-injection-only) is exempted, matching the operator's
    explicit --allow-no-seed-arm opt-in; an unrelated uncoverable W3 still
    refuses."""
    tf = SimpleNamespace(weakness_classes=["W2", "W3"])
    adapter = _FakeAdapter(
        _descriptor(
            weakness_classes=["W2", "W3"],
            tools=[ToolSpec(name="get_status", description="read-only")],
        )
    )
    with pytest.raises(typer.Exit) as excinfo:
        refuse_uncoverable_weakness_classes(tf, adapter, allow_no_seed_arm=True)
    assert excinfo.value.exit_code == 2


def test_allow_no_seed_arm_with_only_w2_uncoverable_does_not_refuse() -> None:
    tf = SimpleNamespace(weakness_classes=["W2", "W4"])
    adapter = _FakeAdapter(
        _descriptor(
            weakness_classes=["W2", "W4"],
            tools=[ToolSpec(name="send_email", description="send")],
        )
    )
    refuse_uncoverable_weakness_classes(tf, adapter, allow_no_seed_arm=True)  # must not raise


def test_dry_run_downgrades_to_a_warning_and_does_not_raise(
    capsys: pytest.CaptureFixture[str],
) -> None:
    tf = SimpleNamespace(weakness_classes=["W3"])
    adapter = _FakeAdapter(
        _descriptor(weakness_classes=["W3"], tools=[ToolSpec(name="x", description="d")])
    )
    refuse_uncoverable_weakness_classes(tf, adapter, dry_run=True)  # must not raise
    err = capsys.readouterr().err
    assert "warning:" in err
    assert "W3" in err


def test_describe_failure_fails_closed_with_a_named_message(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A describe that raises must not skip the refusal: the declared class
    would then run zero attempts and the scan could read as clean."""
    tf = SimpleNamespace(weakness_classes=["W3"])

    class _FailingAdapter:
        async def describe(self) -> TargetDescriptor:
            raise RuntimeError("boom")

    with pytest.raises(typer.Exit) as excinfo:
        refuse_uncoverable_weakness_classes(tf, _FailingAdapter())
    assert excinfo.value.exit_code == 2
    err = capsys.readouterr().err
    assert "could not describe the server" in err
    assert "RuntimeError" in err
    # A crash is not a slow start: point at the launch, not at timeout_s.
    assert "command" in err
    assert "timeout_s" not in err


def test_describe_timeout_fails_closed_and_names_the_budget(
    capsys: pytest.CaptureFixture[str],
) -> None:
    import asyncio

    tf = SimpleNamespace(weakness_classes=["W4"])

    class _SlowAdapter:
        async def describe(self) -> TargetDescriptor:
            await asyncio.sleep(5)
            raise AssertionError("unreachable")

    with pytest.raises(typer.Exit) as excinfo:
        refuse_uncoverable_weakness_classes(tf, _SlowAdapter(), timeout_s=0.05)
    assert excinfo.value.exit_code == 2
    err = capsys.readouterr().err
    assert "within 0.05s" in err
    assert "Re-run" in err
    assert "timeout_s" in err


def test_describe_failure_on_a_dry_run_is_a_warning(
    capsys: pytest.CaptureFixture[str],
) -> None:
    tf = SimpleNamespace(weakness_classes=["W3"])

    class _FailingAdapter:
        async def describe(self) -> TargetDescriptor:
            raise RuntimeError("boom")

    refuse_uncoverable_weakness_classes(tf, _FailingAdapter(), dry_run=True)  # must not raise
    assert "warning: could not describe the server" in capsys.readouterr().err


def test_a_class_added_by_the_flag_names_the_flag_not_the_file(
    capsys: pytest.CaptureFixture[str],
) -> None:
    tf = SimpleNamespace(weakness_classes=["W4", "W3"])
    adapter = _FakeAdapter(
        _descriptor(
            weakness_classes=["W4", "W3"],
            tools=[ToolSpec(name="send_email", description="send")],
        )
    )
    with pytest.raises(typer.Exit):
        refuse_uncoverable_weakness_classes(tf, adapter, added_by_flag=["W3"])
    err = capsys.readouterr().err
    assert "W3 was added by --weakness-class" in err
    assert "remove W3 from weakness_classes" not in err


def test_gate_w2_refusal_points_at_scans_auto_wired_target(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """gate has no seed_arm auto-wire; scan does. The refusal must say so."""
    tf = SimpleNamespace(weakness_classes=["W2"], seed_arm=None, transport="stdio")
    adapter = _FakeAdapter(
        _descriptor(
            weakness_classes=["W2"],
            tools=[ToolSpec(name="get_status", description="read-only")],
        )
    )
    with pytest.raises(typer.Exit):
        refuse_uncoverable_weakness_classes(tf, adapter, command="gate")
    err = capsys.readouterr().err
    assert "mylonite scan" in err
    assert "target.yaml" in err


def test_describe_budget_honours_a_larger_target_timeout(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A target that sets timeout_s above 20 gets that budget for the describe
    too, so the fix the message names (raise timeout_s) actually works."""
    tf = SimpleNamespace(weakness_classes=["W3"], timeout_s=45.0)

    class _FailingAdapter:
        async def describe(self) -> TargetDescriptor:
            raise TimeoutError

    with pytest.raises(typer.Exit):
        refuse_uncoverable_weakness_classes(tf, _FailingAdapter())
    assert "within 45s" in capsys.readouterr().err
