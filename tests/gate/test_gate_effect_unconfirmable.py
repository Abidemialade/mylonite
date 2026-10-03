"""`gate` on a custom W3/W4 target with no effect_probe and no finding exits 2.

The scan behind it reads the class NOT TESTED (MYL-NT-017), so its coverage is
incomplete and the gate reports that instead of "nothing to gate". A gate
committed against such a target turns red until it declares an effect_probe.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from tests.scan.test_effect_unconfirmable import _SEND, _scan

from mylonite.exit_codes import EXIT_SUCCESS
from mylonite.gate.orchestrator import ScanOutcomeBundle, run_gate
from mylonite.reason_codes import NT_EFFECT_UNCONFIRMABLE
from mylonite.scan.coverage import ScanOutcome


def _gate(tmp_path: Path, *, probe: bool) -> int:
    result = asyncio.run(_scan([_SEND], probe=probe))
    outcome = ScanOutcome.from_report(result.report)

    def _never(*_a: object, **_k: object) -> None:
        raise AssertionError("no finding, so nothing is generated, validated or opened")

    gated = run_gate(
        out_dir=tmp_path / ".mylonite" / "gate",
        scan_fn=lambda: ScanOutcomeBundle(outcome=outcome, exploits=list(result.exploits)),
        generate_fn=_never,
        validate_fn=_never,
        open_pr_fn=_never,
        open_pr=False,
    )
    return gated.exit_code


def test_gate_exits_2_when_the_class_ran_without_a_probe(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _gate(tmp_path, probe=False) == 2
    out = capsys.readouterr()
    assert NT_EFFECT_UNCONFIRMABLE in out.out + out.err


def test_gate_with_a_probe_declared_still_reads_nothing_to_gate(tmp_path: Path) -> None:
    assert _gate(tmp_path, probe=True) == EXIT_SUCCESS
