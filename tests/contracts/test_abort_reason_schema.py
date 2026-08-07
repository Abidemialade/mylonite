"""0.7.10 Change 2: ``ScanReport.aborted`` is promoted from a bare
unconstrained string to a real ``AbortReason``-enum-constrained field.

Covers:

* The regenerated ``scan_report.schema.json`` genuinely carries an ``enum``
  constraint (via a shared ``$defs`` entry) listing all 5 known
  :class:`~mylonite.contracts._types.AbortReason` values, plus ``null``.
* Every one of the 5 known abort-reason strings validates cleanly into a
  ``ScanReport`` and round-trips as the identical wire string (``StrEnum``
  serialises byte-identical to the pre-0.7.10 bare string, so this is
  non-breaking for any consumer already comparing against these 5 values).
* An unrecognised abort-reason string now genuinely FAILS Pydantic
  validation — the regression-protection this change adds (see
  ``tests/scan/test_coverage.py::TestUnknownAbortReason`` for the
  actionable-error-message companion tests).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from mylonite.contracts._types import AbortReason, ScanReport

SCHEMA_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "src"
    / "mylonite"
    / "schemas"
    / "scan_report.schema.json"
)


def _report(*, aborted: object) -> ScanReport:
    return ScanReport(
        target_id="t",
        provider="p",
        model="m",
        elapsed_seconds=1.0,
        attempts=[],
        findings_count=0,
        aborted=aborted,  # type: ignore[arg-type]
        fallback_breakdown={},
        mylonite_version="0.0.0",
    )


def test_schema_aborted_field_refs_a_constrained_enum() -> None:
    """``scan_report.schema.json``'s ``aborted`` field must ``$ref`` a
    ``$defs`` entry carrying a proper ``enum`` — not a bare ``{"type":
    "string"}`` — listing exactly the 5 known AbortReason values."""
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    aborted_field = schema["properties"]["aborted"]
    refs = [branch["$ref"] for branch in aborted_field["anyOf"] if "$ref" in branch]
    assert len(refs) == 1, aborted_field
    def_name = refs[0].rsplit("/", 1)[-1]

    enum_def = schema["$defs"][def_name]
    assert enum_def["type"] == "string"
    assert set(enum_def["enum"]) == {r.value for r in AbortReason}
    assert len(enum_def["enum"]) == 5

    # null must still be an allowed alternative (aborted is optional).
    assert {"type": "null"} in aborted_field["anyOf"]


@pytest.mark.parametrize("reason", list(AbortReason))
def test_every_known_abort_reason_string_validates(reason: AbortReason) -> None:
    """All 5 known abort-reason strings validate and round-trip identically
    (StrEnum wire representation == the pre-0.7.10 bare string)."""
    report = _report(aborted=reason.value)
    assert report.aborted == reason
    assert report.aborted.value == reason.value
    assert report.model_dump(mode="json")["aborted"] == reason.value


def test_aborted_none_still_validates() -> None:
    report = _report(aborted=None)
    assert report.aborted is None
    assert report.model_dump(mode="json")["aborted"] is None


def test_unrecognised_abort_reason_string_fails_validation() -> None:
    """Before this change, ``aborted`` was a bare ``str | None`` — any string
    was silently accepted. It is now genuinely rejected."""
    with pytest.raises(ValidationError):
        _report(aborted="made_up_reason")
