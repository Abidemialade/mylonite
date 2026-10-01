#!/usr/bin/env python3
"""Regenerate the frozen-surface snapshots under ``tests/fixtures/``.

Three stability-promised surfaces are pinned by a snapshot so a change to any
of them fails loudly instead of drifting unnoticed:

* ``testkit_signatures.snapshot.json`` -- every name in
  ``mylonite.testkit.__all__``: its kind, and for a callable, its parameters
  (name, kind, default, annotation) and return annotation; for an exception
  class, its base classes.
* ``exit_codes.snapshot.json`` -- every ``EXIT_*`` constant in
  ``mylonite.exit_codes`` and the explicit ``SEVERITY_ORDER``.
* ``schema_versions.snapshot.json`` -- a content hash of every checked-in JSON
  schema under ``src/mylonite/schemas/``, plus the ``CONTRACT_VERSION`` of each
  of the five extension-point contracts.

This script is the deliberate way to update any of them after a reviewed,
intentional change. Run it from the repo root::

    python scripts/update_snapshots.py

It is idempotent: a clean checkout running it twice produces no diff. It does
not touch ``tests/fixtures/reason_codes.snapshot.json``, which has its own
regeneration path (see ``tests/test_reason_codes.py``).

Changing a frozen snapshot on a pull request needs the ``snapshot-change``
label plus a ``CHANGELOG.md`` entry -- enforced by
``scripts/check_snapshot_changes.py`` in CI. See "Updating a frozen snapshot"
in ``CONTRIBUTING.md``.
"""

from __future__ import annotations

import hashlib
import inspect
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
FIXTURES_DIR = ROOT / "tests" / "fixtures"
SCHEMA_DIR = ROOT / "src" / "mylonite" / "schemas"


def _annotation_str(annotation: Any) -> str | None:
    """Render a parameter/return annotation as a stable string.

    ``testkit`` is built with ``from __future__ import annotations``, so
    ``inspect`` already hands back the literal source string (e.g.
    ``"str | os.PathLike[str] | None"``) rather than a resolved type object --
    this just normalises the empty-annotation sentinel to ``None``.
    """
    if annotation is inspect.Signature.empty:
        return None
    return str(annotation)


def _default_repr(param: inspect.Parameter) -> str | None:
    if param.default is inspect.Parameter.empty:
        return None
    return repr(param.default)


def _qualname(cls: type) -> str:
    return f"{cls.__module__}.{cls.__qualname__}"


def build_testkit_signatures() -> dict[str, Any]:
    """The stability-promised ``mylonite.testkit`` surface, by shape not name.

    ``test_public_surface`` (tests/testkit/test_testkit.py) already pins the
    *names* in ``__all__``. This pins the shape behind each name: a parameter
    added, removed, reordered, or changed in kind/default/annotation is a
    public-API change for every emitted test that imports these by name, so
    it must fail here even though the name itself didn't move.
    """
    from mylonite import testkit

    entries: dict[str, Any] = {}
    for name in testkit.__all__:
        obj = getattr(testkit, name)
        if isinstance(obj, type):
            entries[name] = {
                "kind": "exception",
                "bases": [_qualname(base) for base in obj.__bases__],
            }
            continue
        sig = inspect.signature(obj)
        entries[name] = {
            "kind": "function",
            "parameters": [
                {
                    "name": p.name,
                    "kind": p.kind.name,
                    "default": _default_repr(p),
                    "annotation": _annotation_str(p.annotation),
                }
                for p in sig.parameters.values()
            ],
            "return": _annotation_str(sig.return_annotation),
        }
    return entries


def build_exit_codes() -> dict[str, Any]:
    """The full set of process exit codes, frozen against silent add/remove."""
    from mylonite import exit_codes

    codes = {
        name: value
        for name, value in vars(exit_codes).items()
        if name.startswith("EXIT_") and isinstance(value, int)
    }
    return {
        "codes": dict(sorted(codes.items())),
        "severity_order": list(exit_codes.SEVERITY_ORDER),
    }


def build_schema_versions() -> dict[str, Any]:
    """Schema content hashes plus every contract's ``CONTRACT_VERSION``.

    The five contracts' Pydantic models overlap (``Payload`` and
    ``TargetDescriptor`` back both ``attack_module`` and ``target_adapter``;
    ``ScanAttempt``/``ScanReport`` back none of the five directly), so there is
    no clean one-to-one schema-to-contract mapping to freeze. Instead this
    snapshot freezes both sides together: if any schema's hash moves from what
    is recorded here, at least one ``CONTRACT_VERSION`` below must have moved
    too, or the comparing test fails -- a schema shape changed with no version
    bump anywhere to show for it.
    """
    from mylonite.contracts import (
        attack_module,
        compliance_mapper,
        target_adapter,
        test_generator,
        validator,
    )

    # Hash the parsed schema, not the file bytes: a Windows checkout with
    # core.autocrlf rewrites line endings and would change every byte hash.
    schema_hashes = {
        path.name: hashlib.sha256(
            json.dumps(
                json.loads(path.read_text(encoding="utf-8")),
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        for path in sorted(SCHEMA_DIR.glob("*.schema.json"))
    }
    contract_versions = {
        "attack_module": attack_module.CONTRACT_VERSION,
        "target_adapter": target_adapter.CONTRACT_VERSION,
        "test_generator": test_generator.CONTRACT_VERSION,
        "validator": validator.CONTRACT_VERSION,
        "compliance_mapper": compliance_mapper.CONTRACT_VERSION,
    }
    return {"schema_hashes": schema_hashes, "contract_versions": contract_versions}


BUILDERS: dict[str, Any] = {
    "testkit_signatures.snapshot.json": build_testkit_signatures,
    "exit_codes.snapshot.json": build_exit_codes,
    "schema_versions.snapshot.json": build_schema_versions,
}


def main() -> None:
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    for filename, builder in BUILDERS.items():
        data = builder()
        text = json.dumps(data, indent=2, sort_keys=True) + "\n"
        (FIXTURES_DIR / filename).write_text(text, encoding="utf-8")
        print(f"wrote {filename}")


if __name__ == "__main__":
    main()
