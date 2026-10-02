"""Reference differential iterations replay the committed exploit body.

Offline: a scripted completion function stands in for every LLM call. Every
iteration drives both twins with the committed exploit body and the customiser
off, so the differential measures the finding the test was written for rather
than a fresh rewording of its seed, and the two twins always see the same text.
"""

from __future__ import annotations

from typing import Any

import pytest
from tests.plugins.test_differential_validator import (
    _build_exploit,
    _emit_test,
    _ScriptedCompletion,
)

from mylonite.contracts import ValidationOutcome
from mylonite.plugins._reference import reference_validator as rv
from mylonite.plugins._reference.reference_validator import (
    DifferentialValidator,
    ReferenceVulnerableOracle,
)

_CUSTOMISER_MARKER = "craft security probes"


class _SpyCompletion(_ScriptedCompletion):
    """Counts customiser calls on top of the scripted twin behaviour."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.customiser_calls = 0

    async def __call__(self, **kwargs: Any) -> Any:
        system = next(
            (
                str(m.get("content", ""))
                for m in kwargs.get("messages", [])
                if m["role"] == "system"
            ),
            "",
        )
        if _CUSTOMISER_MARKER in system:
            self.customiser_calls += 1
        return await super().__call__(**kwargs)


def _skip_metamorphic(monkeypatch: pytest.MonkeyPatch) -> None:
    """Isolate the differential loop: the metamorphic stage has its own tests."""

    def _passing(self: Any, exploit: Any) -> ValidationOutcome:
        return ValidationOutcome(stage="metamorphic", passed=True, detail="skipped", metric=1.0)

    monkeypatch.setattr(DifferentialValidator, "_metamorphic_outcome", _passing)


def _validate(validator: DifferentialValidator, exploit: Any) -> Any:
    return validator.validate(
        _emit_test(exploit), ReferenceVulnerableOracle().adapter(), ReferenceVulnerableOracle()
    )


def test_every_iteration_replays_the_committed_body_on_both_twins(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _skip_metamorphic(monkeypatch)
    exploit = _build_exploit()
    spy = _SpyCompletion()
    validator = DifferentialValidator(iterations=3, completion_fn=spy, run_build=False)

    report = _validate(validator, exploit)

    assert report.kept is True, report.notes
    assert spy.customiser_calls == 0
    note_reads = [body for body in spy.observed_note_bodies if "attacker@example.com" in body]
    assert note_reads, "the planner never read the planted note"
    assert all(exploit.payload.body in body for body in note_reads)
    # The scripted customiser answers with a fixed rewording; none may reach a twin.
    assert not any("REFINED" in body for body in spy.observed_note_bodies)


def test_both_twins_receive_the_identical_payload_each_iteration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _skip_metamorphic(monkeypatch)
    seen: dict[str, list[str]] = {"vulnerable": [], "guarded": []}
    real_build_scan = rv.build_scan

    def _spy_build_scan(variant: str, **kwargs: Any) -> Any:
        payload = kwargs.get("replay_payload")
        seen[variant].append(payload.body if payload is not None else "<customised>")
        return real_build_scan(variant, **kwargs)

    monkeypatch.setattr(rv, "build_scan", _spy_build_scan)
    exploit = _build_exploit()
    validator = DifferentialValidator(
        iterations=2, completion_fn=_ScriptedCompletion(), run_build=False
    )

    _validate(validator, exploit)

    assert seen["vulnerable"] == [exploit.payload.body] * 2
    assert seen["guarded"] == seen["vulnerable"]
