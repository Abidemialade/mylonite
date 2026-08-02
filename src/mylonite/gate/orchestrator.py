"""Gate orchestration: sequence scan -> generate -> validate -> assemble -> PR.

Owns the SEQUENCE and the exit-code decision only. Collaborators are injected so
the Typer command supplies live ones and tests supply offline fakes.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mylonite._cli_io import echo
from mylonite.contracts._types import ExploitRecord, GeneratedTest, ValidationReport
from mylonite.gate.mitigation import build_pr_body

EXIT_SUCCESS = 0
EXIT_NOT_KEPT = 5


@dataclass
class GateResult:
    exit_code: int
    opened_pr: bool = False
    branch: str | None = None
    kept: bool | None = None


def run_gate(
    *,
    out_dir: Path,
    scan_fn: Callable[[], list[ExploitRecord]],
    generate_fn: Callable[[ExploitRecord], GeneratedTest | None],
    validate_fn: Callable[[GeneratedTest], ValidationReport | None],
    open_pr_fn: Callable[..., Any],
    open_pr: bool,
    llm_enrich: bool = False,
) -> GateResult:
    exploits = scan_fn()
    if not exploits:
        echo("Mylonite gate: no exploit found — nothing to gate.")
        return GateResult(exit_code=EXIT_SUCCESS, opened_pr=False, kept=None)

    exploit = exploits[0]
    generated = generate_fn(exploit)
    assert generated is not None  # noqa: S101  # removed in P9

    out_dir.mkdir(parents=True, exist_ok=True)
    test_path = out_dir / generated.filename
    test_path.write_text(generated.source, encoding="utf-8")
    (out_dir / f"exploit_{exploit.pattern_id}.json").write_text(
        json.dumps(exploit.model_dump(mode="json"), indent=2, sort_keys=True),
        encoding="utf-8",
    )

    report = validate_fn(generated)
    assert report is not None  # noqa: S101  # removed in P9
    if not report.kept:
        echo("Mylonite gate: the generated test was REJECTED (not kept) — no PR opened.")
        return GateResult(exit_code=EXIT_NOT_KEPT, opened_pr=False, kept=False)

    body = build_pr_body(exploit, report, llm_enrich=llm_enrich)
    pr = open_pr_fn(out_dir=out_dir, exploit=exploit, report=report, body=body, open_pr=open_pr)
    opened = bool(getattr(pr, "opened", False))
    branch = getattr(pr, "branch", None)
    return GateResult(exit_code=EXIT_SUCCESS, opened_pr=opened, branch=branch, kept=True)
