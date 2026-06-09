"""Regenerate JSON schemas from the Pydantic contract models.

Run from the repo root::

    python scripts/regenerate_schemas.py

Schemas land under ``src/mylonite/schemas/`` and are checked in so downstream
tooling can validate plugin manifests, registry entries, and config files
without a runtime dependency on the Mylonite Python package.

The script is idempotent: a clean checkout running this script must produce
no diff. CI enforces this.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

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

if TYPE_CHECKING:
    from pydantic import BaseModel

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DIR = ROOT / "src" / "mylonite" / "schemas"

MODELS: dict[str, type[BaseModel]] = {
    "attack_pattern.schema.json": AttackPattern,
    "payload.schema.json": Payload,
    "target_descriptor.schema.json": TargetDescriptor,
    "adapter_response.schema.json": AdapterResponse,
    "exploit_record.schema.json": ExploitRecord,
    "generated_test.schema.json": GeneratedTest,
    "validation_report.schema.json": ValidationReport,
    "compliance_tags.schema.json": ComplianceTags,
}


def main() -> None:
    SCHEMA_DIR.mkdir(parents=True, exist_ok=True)
    for filename, model in MODELS.items():
        schema = model.model_json_schema()
        # Sort keys for stable diffs across Pydantic minor releases.
        text = json.dumps(schema, indent=2, sort_keys=True) + "\n"
        (SCHEMA_DIR / filename).write_text(text, encoding="utf-8")
        print(f"wrote {filename}")


if __name__ == "__main__":
    main()
