"""Verify the checked-in JSON schemas match the live Pydantic models.

CI runs the schema regenerator and diffs the result against the checked-in
schemas; this test mirrors that check locally so contributors get a fast
signal.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO = Path(__file__).resolve().parent.parent
SCHEMA_DIR = REPO / "src" / "mylonite" / "schemas"
_VERSION_SNAPSHOT = REPO / "tests" / "fixtures" / "schema_versions.snapshot.json"


def _load_script(relative: str, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, REPO / relative)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "filename",
    sorted(p.name for p in SCHEMA_DIR.glob("*.schema.json")),
)
def test_schema_is_up_to_date(filename: str, tmp_path: Path) -> None:
    # Run the regenerator into a temp clone so we don't dirty the working tree.
    work = tmp_path / "schemas"
    work.mkdir()
    # Easiest path: regenerate in-place and compare.
    expected = (SCHEMA_DIR / filename).read_text(encoding="utf-8")
    # Re-import the model and regenerate just this schema.
    from mylonite.contracts._types import (
        AdapterResponse,
        AttackPattern,
        ComplianceTags,
        ExploitRecord,
        GeneratedTest,
        Payload,
        ScanAttempt,
        ScanReport,
        TargetDescriptor,
        ValidationReport,
    )

    models = {
        "attack_pattern.schema.json": AttackPattern,
        "payload.schema.json": Payload,
        "target_descriptor.schema.json": TargetDescriptor,
        "adapter_response.schema.json": AdapterResponse,
        "exploit_record.schema.json": ExploitRecord,
        "generated_test.schema.json": GeneratedTest,
        "validation_report.schema.json": ValidationReport,
        "compliance_tags.schema.json": ComplianceTags,
        "scan_attempt.schema.json": ScanAttempt,
        "scan_report.schema.json": ScanReport,
    }
    fresh = json.dumps(models[filename].model_json_schema(), indent=2, sort_keys=True) + "\n"
    assert fresh == expected, f"{filename} is stale. Run: python scripts/regenerate_schemas.py"


def test_regenerate_script_runs() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/regenerate_schemas.py"],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=True,
    )
    assert "wrote" in result.stdout


# -- schema change requires a contract-version bump somewhere ----------------
#
# test_schema_is_up_to_date (above) only catches a checked-in schema going
# STALE relative to the live Pydantic models -- it says nothing about whether
# a genuine shape change was accompanied by bumping any of the five extension
# contracts' CONTRACT_VERSION. The five contracts' models overlap (Payload and
# TargetDescriptor back both attack_module and target_adapter; ScanAttempt/
# ScanReport back none of the five directly), so there's no clean one-to-one
# schema-to-contract mapping to freeze. Instead: if any schema's content hash
# moved from the snapshot, at least one CONTRACT_VERSION must have moved too.


def test_schema_change_requires_a_contract_version_bump() -> None:
    """Update deliberately: ``python scripts/update_snapshots.py``, then add a
    CHANGELOG.md line. A pull request also needs the snapshot-change label
    (enforced by scripts/check_snapshot_changes.py in CI)."""
    update_snapshots = _load_script("scripts/update_snapshots.py", "update_snapshots")
    snapshot = json.loads(_VERSION_SNAPSHOT.read_text(encoding="utf-8"))
    current = update_snapshots.build_schema_versions()

    changed_schemas = sorted(
        name
        for name, current_hash in current["schema_hashes"].items()
        if snapshot["schema_hashes"].get(name) != current_hash
    )
    changed_versions = sorted(
        name
        for name, current_version in current["contract_versions"].items()
        if snapshot["contract_versions"].get(name) != current_version
    )
    if changed_schemas:
        assert changed_versions, (
            f"schema(s) changed shape with no CONTRACT_VERSION bump anywhere: "
            f"{changed_schemas}. Bump the CONTRACT_VERSION of the contract(s) this "
            "schema backs (see GOVERNANCE.md), then update "
            f"{_VERSION_SNAPSHOT.name} (python scripts/update_snapshots.py) and add a "
            "CHANGELOG.md line."
        )
    assert current == snapshot, (
        f"schema/contract-version snapshot drifted from {_VERSION_SNAPSHOT.name}. If "
        "intentional, update it (python scripts/update_snapshots.py) and add a "
        "CHANGELOG.md line."
    )
