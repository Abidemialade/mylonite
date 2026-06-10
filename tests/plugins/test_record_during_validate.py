"""Offline tests for PR-D: record canonical fixtures during validate + full-pass build.

Every test here is OFFLINE — NO live LLM call happens:

* The differential loop is driven by the same scripted ``completion_fn`` the
  sibling ``test_differential_validator`` uses (the in-process servers produce
  the differential).
* The RECORD leg (``LiteLLMRecorder._record``) imports ``litellm`` lazily and
  calls ``litellm.acompletion``. We monkeypatch ``sys.modules["litellm"]`` with a
  fake whose ``acompletion`` is a coroutine routing through the SAME scripted
  completion logic, so the recorder serialises those scripted responses into real
  fixture JSON — no network, no key.

The crux test proves the full record→replay round-trip works offline: validate
records the canonical guarded fixtures, writes the on-disk test + exploit next to
them, and runs that committed test offline as a FULL pass (guard holds against
the recorded fixtures).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

# Reuse the scripted-completion machinery + exploit/test builders from the
# sibling validator test module (same package).
from tests.plugins.test_differential_validator import (
    _build_exploit,
    _emit_test,
    _outcome,
    _ScriptedCompletion,
)

from mylonite.plugins._reference.reference_validator import (
    DifferentialValidator,
    ReferenceVulnerableOracle,
)


def _meta(fixtures_dir: Path) -> dict[str, Any]:
    return json.loads((fixtures_dir / "_meta.json").read_text(encoding="utf-8"))


def _fixture_jsons(fixtures_dir: Path) -> list[Path]:
    """Recorded fixture files (excludes the _meta.json sidecar)."""
    return [p for p in sorted(fixtures_dir.glob("*.json")) if p.name != "_meta.json"]


class _FakeLiteLLM:
    """Stand-in for the ``litellm`` module the recorder imports lazily.

    ``acompletion`` is an async method routing through a fresh
    :class:`_ScriptedCompletion`, so the recorder records the SAME deterministic
    guarded responses the differential loop sees — entirely offline.
    """

    def __init__(self) -> None:
        self._script = _ScriptedCompletion()

    async def acompletion(self, *, model: str, messages: Any, **kwargs: Any) -> SimpleNamespace:
        return await self._script(model=model, messages=messages, **kwargs)


# ---------------------------------------------------------------------------
# Canonical-run selection (D4)
# ---------------------------------------------------------------------------


def test_canonical_run_index_picks_first_clean_iteration() -> None:
    """``_canonical_run_index`` returns the FIRST iteration that fired AND resisted.

    The helper reads only ``vuln_fired`` / ``guard_resisted``, so a lightweight
    duck-typed stand-in for ``_IterationTally`` suffices (no real ScanResults).
    """

    def _tally(*, fired: bool, resisted: bool) -> Any:
        return SimpleNamespace(vuln_fired=fired, guard_resisted=resisted)

    # First clean (fired AND resisted) iteration is index 2.
    tallies = [
        _tally(fired=True, resisted=False),  # not clean (guard leaked)
        _tally(fired=False, resisted=True),  # not clean (vuln didn't fire)
        _tally(fired=True, resisted=True),  # clean ← first
        _tally(fired=True, resisted=True),
    ]
    assert DifferentialValidator._canonical_run_index(tallies) == 2

    # No clean iteration → None (recording is skipped).
    none_clean = [
        _tally(fired=True, resisted=False),
        _tally(fired=False, resisted=True),
    ]
    assert DifferentialValidator._canonical_run_index(none_clean) is None


def test_no_clean_run_skips_recording(tmp_path: Path) -> None:
    """No clean discriminating iteration → NO fixtures recorded; collect-only build."""
    exploit = _build_exploit()
    test = _emit_test(exploit)
    fixtures_dir = tmp_path / "gen" / "fixtures"

    # vuln_fire_budget=0 → the vulnerable twin never fires, so no iteration has
    # (vuln_fired AND guard_resisted): canonical selection finds nothing.
    validator = DifferentialValidator(
        iterations=3,
        completion_fn=_ScriptedCompletion(vuln_fire_budget=0),
        record_fixtures_dir=fixtures_dir,
    )
    report = validator.validate(
        test, ReferenceVulnerableOracle().adapter(), ReferenceVulnerableOracle()
    )

    build = _outcome(report, "build")
    # No recording → fixtures dir not created / no fixture files, no _meta.json.
    assert not fixtures_dir.exists() or not _fixture_jsons(fixtures_dir)
    assert not (fixtures_dir / "_meta.json").exists()
    assert "collect-only" in build.detail
    assert "not recorded" in build.detail


# ---------------------------------------------------------------------------
# Record leg via faked litellm — the offline round-trip (THE key test)
# ---------------------------------------------------------------------------


def test_record_then_full_pass_offline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """validate records canonical guarded fixtures + the on-disk test FULL-passes.

    The differential loop is driven by a scripted completion_fn; the record leg's
    lazy ``import litellm`` is faked so the recorder serialises scripted guarded
    responses into real fixture JSON. Then the on-disk committed test replays
    those fixtures offline → guard holds → exit 0 → build.passed is True.
    """
    exploit = _build_exploit()
    test = _emit_test(exploit)
    gen_dir = tmp_path / "gen"
    fixtures_dir = gen_dir / "fixtures"

    # Fake the lazily-imported litellm module at the recorder seam.
    monkeypatch.setitem(sys.modules, "litellm", _FakeLiteLLM())

    validator = DifferentialValidator(
        iterations=2,
        completion_fn=_ScriptedCompletion(),
        record_fixtures_dir=fixtures_dir,
    )
    report = validator.validate(
        test, ReferenceVulnerableOracle().adapter(), ReferenceVulnerableOracle()
    )

    # Fixtures were written and the sidecar is v2 with model + pattern_id.
    written = _fixture_jsons(fixtures_dir)
    assert written, "expected recorded fixture JSON files"
    meta = _meta(fixtures_dir)
    assert meta["format_version"] == 2
    assert meta["model"] == validator._model
    assert meta["pattern_id"] == exploit.pattern_id

    # The on-disk test + co-located exploit were written next to the fixtures.
    assert (gen_dir / test.filename).is_file()
    assert (gen_dir / f"exploit_{exploit.pattern_id}.json").is_file()

    # Build leg = FULL offline pass (the recorded fixtures replay → guard holds).
    build = _outcome(report, "build")
    assert build.passed is True, build.detail
    assert "full offline pass" in build.detail


# ---------------------------------------------------------------------------
# record_fixtures_dir=None preserves collect-only
# ---------------------------------------------------------------------------


def test_record_fixtures_dir_none_is_collect_only(tmp_path: Path) -> None:
    """With record_fixtures_dir=None, no fixtures are written; build is collect-only."""
    exploit = _build_exploit()
    test = _emit_test(exploit)

    validator = DifferentialValidator(
        iterations=2,
        completion_fn=_ScriptedCompletion(),
        record_fixtures_dir=None,
    )
    report = validator.validate(
        test, ReferenceVulnerableOracle().adapter(), ReferenceVulnerableOracle()
    )

    build = _outcome(report, "build")
    assert build.passed is True
    assert "collect-only" in build.detail
    # Nothing was written anywhere under tmp_path.
    assert not list(tmp_path.rglob("_meta.json"))
