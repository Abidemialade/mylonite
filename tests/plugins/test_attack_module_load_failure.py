"""An attack module that fails to load must leave its classes NOT TESTED, never silent (#222).

Before this, ``registry.discover`` called ``ep.load()`` unguarded and only logged a
warning when construction failed. The scan then ran every other module, the failed
module's weakness classes dropped out of the result, and the summary could read clean.

Entry-point discovery is faked by patching ``registry.entry_points``, so no package
is installed.
"""

from __future__ import annotations

import asyncio
import json
import tomllib
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any, ClassVar

import pytest

from mylonite.contracts import (
    AttackModuleBase,
    AttackPattern,
    ComplianceTags,
    Payload,
    ScanAttempt,
    ScanReport,
    TargetDescriptor,
)
from mylonite.contracts.attack_module import CONTRACT_VERSION
from mylonite.plugins import registry
from mylonite.reason_codes import NT_MODULE_LOAD_FAILED, NT_NO_ATTACK_EMITTED
from mylonite.scan.artefacts import VERDICTS_FILENAME, render_summary, write_artefacts
from mylonite.scan.assembly import (
    ATTACK_MODULES_ENV,
    SHIPPED_ATTACK_MODULES,
    build_scan_engine,
    load_attack_modules,
    no_usable_modules_message,
    relevant_load_failures,
)
from mylonite.scan.class_verdict import STATUS_NOT_TESTED, UNKNOWN_CLASS, class_verdicts
from mylonite.scan.coverage import MODULE_LOAD_FAILURE_KEY, ScanOutcome
from mylonite.scan.engine import ScanConfig, ScanResult

_GROUP = "mylonite.attack_modules"
_PRIVATE_DETAIL = "cannot import from a private location (marker DO-NOT-LEAK-7f3a)"


class _EntryPoint:
    """Stands in for ``importlib.metadata.EntryPoint``: a name and a ``load()``."""

    def __init__(self, name: str, load: Callable[[], Any]) -> None:
        self.name = name
        self._load = load

    def load(self) -> Any:
        return self._load()


def _healthy(attack_id: str) -> type[AttackModuleBase]:
    """A module that loads fine and yields nothing (so no LLM call is needed)."""

    class _Healthy(AttackModuleBase):
        contract_version: ClassVar[str] = CONTRACT_VERSION

        def attack_metadata(self) -> AttackPattern:
            return AttackPattern(
                id=attack_id,
                name="healthy stub",
                summary="loads fine",
                target_kinds=["mcp"],
                compliance=ComplianceTags(owasp_llm=["LLM01"]),
            )

        def generate_payloads(self, target: TargetDescriptor) -> Iterable[Payload]:
            del target
            return []

    return _Healthy


def _import_fails() -> Any:
    raise ImportError(_PRIVATE_DETAIL)


class _ConstructorFails(AttackModuleBase):
    contract_version: ClassVar[str] = CONTRACT_VERSION

    def __init__(self) -> None:
        raise RuntimeError(_PRIVATE_DETAIL)

    def attack_metadata(self) -> AttackPattern:  # pragma: no cover - never constructed
        raise NotImplementedError

    def generate_payloads(self, target: TargetDescriptor) -> Iterable[Payload]:  # pragma: no cover
        raise NotImplementedError


def _install(monkeypatch: pytest.MonkeyPatch, *eps: _EntryPoint) -> None:
    def fake_entry_points(*, group: str) -> list[_EntryPoint]:
        return list(eps) if group == _GROUP else []

    monkeypatch.setattr(registry, "entry_points", fake_entry_points)


class _Adapter:
    async def describe(self) -> TargetDescriptor:
        return TargetDescriptor(target_id="reference:vulnerable", kind="mcp")

    async def invoke(self, payload: Payload) -> Any:  # pragma: no cover - nothing is invoked
        raise AssertionError("no payload should run")


def _scan(**config: Any) -> ScanResult:
    cfg = ScanConfig(target_id="reference:vulnerable", provider="stub", model="stub", **config)
    return asyncio.run(build_scan_engine(cfg, _Adapter()).run())


def _summary(result: ScanResult) -> str:
    """The rendered summary with Rich's line wrapping folded back into spaces."""
    return " ".join(render_summary(result, ascii_safe=True).split())


def _rows(result: ScanResult) -> dict[str, Any]:
    return {v.weakness: v for v in class_verdicts(result.report)}


# --- discovery ----------------------------------------------------------------


def test_discovery_records_an_import_failure_and_keeps_loading(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(
        monkeypatch,
        _EntryPoint("prompt_injection", _import_fails),
        _EntryPoint("excessive_agency", lambda: _healthy("excessive-agency-family")),
    )
    loaded, failures = registry.discover_with_failures(_GROUP)
    assert [m.attack_metadata().id for m in loaded] == ["excessive-agency-family"]
    assert len(failures) == 1
    failure = failures[0]
    assert (failure.entry_point, failure.stage, failure.error_type) == (
        "prompt_injection",
        "import",
        "ImportError",
    )
    # The plain discover() keeps its shape: instances only.
    assert len(registry.discover(_GROUP)) == 1


def test_discovery_records_a_constructor_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, _EntryPoint("excessive_agency", lambda: _ConstructorFails))
    loaded, failures = registry.discover_with_failures(_GROUP)
    assert loaded == []
    assert [(f.entry_point, f.stage, f.error_type) for f in failures] == [
        ("excessive_agency", "construct", "RuntimeError")
    ]


# --- the scan -----------------------------------------------------------------


def test_failed_import_reports_its_classes_not_tested_with_the_reason_code(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _install(
        monkeypatch,
        _EntryPoint("prompt_injection", _import_fails),
        _EntryPoint("excessive_agency", lambda: _healthy("excessive-agency-family")),
    )
    result = _scan()

    rows = _rows(result)
    for weakness in ("W1", "W2"):
        assert rows[weakness].status == STATUS_NOT_TESTED
        assert rows[weakness].codes == (NT_MODULE_LOAD_FAILED,)
    # The module that loaded lost nothing to a load failure. This stub emits no
    # payload, so its classes read NOT TESTED under their own code (#221).
    for weakness in ("W3", "W4"):
        assert rows[weakness].codes == (NT_NO_ATTACK_EMITTED,)
    assert result.report.aborted is None

    summary = _summary(result)
    assert "attack modules: 1 failed to load" in summary
    assert "prompt_injection (import failed: ImportError; W1, W2 NOT TESTED)" in summary
    assert "classes:" in summary
    assert NT_MODULE_LOAD_FAILED in summary
    # The cause list names the load failure, not only seed_arm causes.
    assert "an attack module that failed to load" in summary

    # The engine writes, and the summary line reads, the same evidence keys.
    lost = [a for a in result.report.attempts if a.outcome == "error"]
    assert {a.judge_evidence[MODULE_LOAD_FAILURE_KEY] for a in lost} == {"prompt_injection"}
    assert {a.judge_evidence["load_stage"] for a in lost} == {"import"}
    assert {a.judge_evidence["weakness"] for a in lost} == {"W1", "W2"}

    outcome = ScanOutcome.from_report(result.report)
    assert outcome.exit_code != 0
    assert outcome.operator_message is not None
    assert NT_MODULE_LOAD_FAILED in outcome.operator_message

    scan_dir = write_artefacts(result, tmp_path)
    verdicts = json.loads((scan_dir / VERDICTS_FILENAME).read_text(encoding="utf-8"))
    by_class = {c["weakness"]: c for c in verdicts["classes"]}
    assert by_class["W1"]["status"] == STATUS_NOT_TESTED
    assert by_class["W1"]["codes"] == [NT_MODULE_LOAD_FAILED]
    # The saved report reads back the same way, so `mylonite report` agrees.
    saved = ScanReport.model_validate_json(
        (scan_dir / "scan_report.json").read_text(encoding="utf-8")
    )
    assert {v.weakness for v in class_verdicts(saved) if NT_MODULE_LOAD_FAILED in v.codes} == {
        "W1",
        "W2",
    }


def test_failed_constructor_reports_its_classes_not_tested(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(
        monkeypatch,
        _EntryPoint("prompt_injection", lambda: _healthy("prompt-injection-family")),
        _EntryPoint("excessive_agency", lambda: _ConstructorFails),
    )
    result = _scan()

    rows = _rows(result)
    lost = {w for w, v in rows.items() if NT_MODULE_LOAD_FAILED in v.codes}
    assert lost == {"W3", "W4"}
    assert rows["W3"].status == STATUS_NOT_TESTED
    assert rows["W3"].codes == (NT_MODULE_LOAD_FAILED,)
    assert "excessive_agency (construct failed: RuntimeError; W3, W4 NOT TESTED)" in (
        _summary(result)
    )
    assert ScanOutcome.from_report(result.report).exit_code != 0


def test_unknowable_import_failure_shows_a_scan_level_line(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A third-party module that fails to import has no class to read. Its loss
    still shows: one scan-level line and one row in the ``unknown`` class."""
    monkeypatch.setenv(ATTACK_MODULES_ENV, "acme-probe")
    _install(
        monkeypatch,
        _EntryPoint("prompt_injection", lambda: _healthy("prompt-injection-family")),
        _EntryPoint("acme_probe", _import_fails),
    )
    result = _scan()

    rows = _rows(result)
    assert rows[UNKNOWN_CLASS].status == STATUS_NOT_TESTED
    assert rows[UNKNOWN_CLASS].codes == (NT_MODULE_LOAD_FAILED,)
    summary = _summary(result)
    assert "acme_probe (import failed: ImportError; classes unknown, NOT TESTED; " in summary
    # The opted-in id nothing provides is named, so a typo is not blamed on acme_probe.
    assert "MYLONITE_ATTACK_MODULES names acme-probe, which no loaded module provides" in summary
    assert ScanOutcome.from_report(result.report).exit_code != 0


def test_a_lost_class_keeps_an_exercised_scan_from_exiting_clean() -> None:
    """With one real negative alongside, the lost classes still stop a clean exit."""
    resisted = ScanAttempt(
        seed_id="w3-ssrf-web-fetch",
        pattern_id="w3-ssrf-web-fetch",
        outcome="no_finding",
        verdict_mechanism="predicate",
    )
    lost = ScanAttempt(
        seed_id="module-load-failed:prompt_injection:W1",
        pattern_id="module-load-failed:prompt_injection:W1",
        outcome="error",
        error_detail="ImportError",
        judge_evidence={"module_load_failure": "prompt_injection", "weakness": "W1"},
    )

    def report(attempts: list[ScanAttempt]) -> ScanReport:
        return ScanReport(
            target_id="t",
            provider="p",
            model="m",
            elapsed_seconds=1.0,
            attempts=attempts,
            findings_count=0,
            mylonite_version="0.0.0",
        )

    assert ScanOutcome.from_report(report([resisted])).exit_code == 0
    assert ScanOutcome.from_report(report([resisted, lost])).exit_code != 0


def test_the_exception_message_never_reaches_the_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(
        monkeypatch,
        _EntryPoint("prompt_injection", _import_fails),
        _EntryPoint("excessive_agency", lambda: _ConstructorFails),
    )
    result = _scan()
    dumped = result.report.model_dump_json()
    assert "module-load-failed" in dumped
    assert "DO-NOT-LEAK-7f3a" not in dumped
    assert "private location" not in dumped


def test_a_failed_module_nobody_enabled_costs_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    """The shipped authoring example and an un-enabled third-party module never run,
    so their failure loses no coverage and adds no NOT TESTED row."""
    monkeypatch.delenv(ATTACK_MODULES_ENV, raising=False)
    _install(
        monkeypatch,
        _EntryPoint("prompt_injection", lambda: _healthy("prompt-injection-family")),
        _EntryPoint("excessive_agency", lambda: _healthy("excessive-agency-family")),
        _EntryPoint("reference_example", _import_fails),
        _EntryPoint("acme_probe", _import_fails),
    )
    result = _scan()
    # No load-failure row. The healthy stubs emit no payload, so each class they
    # own reads NOT TESTED under its own code instead (#221).
    attempts = result.report.attempts
    assert not [a for a in attempts if a.judge_evidence.get(MODULE_LOAD_FAILURE_KEY)]
    assert {a.judge_evidence.get("weakness") for a in attempts} == {"W1", "W2", "W3", "W4"}


def test_a_one_seed_redrive_and_a_dry_run_record_no_load_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(
        monkeypatch,
        _EntryPoint("prompt_injection", _import_fails),
        _EntryPoint("excessive_agency", lambda: _healthy("excessive-agency-family")),
    )
    assert _scan(pattern_id_filter="w3-ssrf-web-fetch").report.attempts == []
    assert _scan(dry_run=True).report.attempts == []


def test_no_usable_modules_message_names_the_failed_modules(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(ATTACK_MODULES_ENV, raising=False)
    _install(monkeypatch, _EntryPoint("prompt_injection", _import_fails))
    loaded, failures = registry.discover_with_failures(_GROUP)
    message = no_usable_modules_message(relevant_load_failures(failures, loaded))
    assert NT_MODULE_LOAD_FAILED in message
    assert "prompt_injection (import failed: ImportError; covers W1, W2)" in message


def test_no_usable_modules_message_names_an_unmatched_opt_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(ATTACK_MODULES_ENV, "acme-probe")
    _install(monkeypatch, _EntryPoint("acme_probe", _import_fails))
    loaded, failures = registry.discover_with_failures(_GROUP)
    message = no_usable_modules_message(relevant_load_failures(failures, loaded))
    assert "acme_probe (import failed: ImportError; its weakness classes are unknown; " in message
    assert "MYLONITE_ATTACK_MODULES names acme-probe, which no loaded module provides" in message
    assert "DO-NOT-LEAK-7f3a" not in message


def test_the_shipped_module_table_matches_the_shipped_modules() -> None:
    """The host's table is the only source of a failed shipped module's classes,
    so it must name every shipped entry point with the right id and classes."""
    from mylonite.plugins._reference import (
        excessive_agency_module,
        markdown_egress_module,
        prompt_injection_module,
    )

    pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
    declared = tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]["entry-points"][
        _GROUP
    ]
    assert set(SHIPPED_ATTACK_MODULES) == set(declared)
    for name, target in declared.items():
        module_path, class_name = target.split(":")
        module = __import__(module_path, fromlist=[class_name])
        instance = getattr(module, class_name)()
        assert SHIPPED_ATTACK_MODULES[name][0] == instance.attack_metadata().id, name

    assert set(SHIPPED_ATTACK_MODULES["prompt_injection"][1]) == {
        str(w) for w in prompt_injection_module._W1_W2
    }
    assert set(SHIPPED_ATTACK_MODULES["excessive_agency"][1]) == set(excessive_agency_module._W3_W4)
    descriptor = TargetDescriptor(target_id="reference:vulnerable", kind="mcp")
    egress = markdown_egress_module.MarkdownImageEgressAttackModule()
    assert set(SHIPPED_ATTACK_MODULES["markdown_egress"][1]) == {
        p.metadata["weakness"] for p in egress.generate_payloads(descriptor)
    }


def test_scan_and_gate_discovery_returns_every_module_and_the_relevant_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``scan`` and ``gate`` select modules themselves, so they get them unfiltered,
    with the failures that cost coverage alongside to pass on to the engine."""
    monkeypatch.delenv(ATTACK_MODULES_ENV, raising=False)
    _install(
        monkeypatch,
        _EntryPoint("prompt_injection", _import_fails),
        _EntryPoint("excessive_agency", lambda: _healthy("excessive-agency-family")),
        _EntryPoint("reference_example", lambda: _healthy("reference-indirect-injection")),
    )
    modules, failures = load_attack_modules()
    assert {m.attack_metadata().id for m in modules} == {
        "excessive-agency-family",
        "reference-indirect-injection",
    }
    assert [(f.entry_point, f.weakness_classes) for f in failures] == [
        ("prompt_injection", ("W1", "W2"))
    ]


# --- the plugin listing -----------------------------------------------------------


def test_plugin_listing_shows_a_module_that_failed_to_load(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``mylonite plugins`` is where the operator looks next, so it must list a
    broken module as failed instead of crashing or calling it "configured"."""
    from typer.testing import CliRunner

    from mylonite.cli import app

    _install(
        monkeypatch,
        _EntryPoint("prompt_injection", _import_fails),
        _EntryPoint("excessive_agency", lambda: _ConstructorFails),
    )
    infos = {i.entry_point: i for i in registry.describe(_GROUP)}
    assert infos["prompt_injection"].load_failed == "ImportError"
    assert infos["excessive_agency"].load_failed == "RuntimeError"
    assert infos["excessive_agency"].needs_config is False

    result = CliRunner().invoke(app, ["plugins"])
    output = " ".join(result.output.split())
    assert "prompt_injection (contract ?) — FAILED TO LOAD (ImportError)" in output
    assert "_ConstructorFails (contract " in output
    assert "FAILED TO LOAD (RuntimeError)" in output
    assert "DO-NOT-LEAK-7f3a" not in result.output
