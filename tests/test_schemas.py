"""Verify the checked-in JSON schemas match the live Pydantic models.

CI runs the schema regenerator and diffs the result against the checked-in
schemas; this test mirrors that check locally so contributors get a fast
signal.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SCHEMA_DIR = REPO / "src" / "mylonite" / "schemas"


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
