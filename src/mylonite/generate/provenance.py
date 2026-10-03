"""Whether a generated test is proven, and the header that says it is not.

A test ``generate`` writes straight from a scan is a candidate: nothing has yet
shown that it fails on the vulnerable build and passes on the guarded one.
``mylonite validate`` decides that, and writes ``validation_report.json`` next
to the test and its exploit. ``gate`` writes the same file into each finding's
directory.

So an input exploit counts as validated when the ``validation_report.json``
beside it earns the ``KEPT`` label (:func:`mylonite._verdict.verdict_label`).
A test written from anything else carries :data:`UNVALIDATED_MARKER` as its
first line; ``validate`` removes the header on a KEPT verdict and leaves it on
STABLE, NOT PROVEN, which is a candidate, never a gate test.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Final

import typer

from mylonite._cli_io import echo, echo_err
from mylonite._verdict import KEPT, verdict_label
from mylonite.contracts import ValidationReport
from mylonite.exit_codes import EXIT_NOT_KEPT

#: First line of a stamped test: one fixed line a script can grep for.
UNVALIDATED_MARKER: Final = "# mylonite: unvalidated"

_STAMP: Final = (
    f"{UNVALIDATED_MARKER}\n"
    "# UNVALIDATED: a candidate test, not a proven gate test. Nothing has shown yet\n"
    "# that it fails on the vulnerable build and passes on the guarded one.\n"
    "# Run `mylonite validate` on this directory: a KEPT verdict removes this header.\n"
)

#: :func:`input_verdict` for a ``validation_report.json`` that does not parse.
UNREADABLE: Final = "UNREADABLE"

UNVALIDATED_HELP: Final = (
    "Write the test even when the validation next to the input did not keep it "
    "(REJECTED, or STABLE, NOT PROVEN). The test is stamped UNVALIDATED."
)


def is_unvalidated(source: str) -> bool:
    """True when ``source`` starts with the unvalidated header."""
    return source.startswith(UNVALIDATED_MARKER)


def stamp_unvalidated(source: str) -> str:
    """``source`` with the unvalidated header in front (once)."""
    return source if is_unvalidated(source) else _STAMP + source


def strip_unvalidated(source: str) -> str:
    """``source`` without the unvalidated header, if it has it."""
    return source[len(_STAMP) :] if source.startswith(_STAMP) else source


def input_verdict(exploit_path: Path) -> str | None:
    """The verdict label of the ``validation_report.json`` beside ``exploit_path``.

    ``None`` when there is none (a raw scan finding), :data:`UNREADABLE` when it
    does not parse.
    """
    report_path = exploit_path.parent / "validation_report.json"
    if not report_path.is_file():
        return None
    try:
        report = ValidationReport.model_validate_json(report_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return UNREADABLE
    return verdict_label(report)


def stamps_for(exploit_paths: Sequence[Path], *, allow_unvalidated: bool) -> list[bool]:
    """Per input exploit, whether its test must carry the unvalidated header.

    Exits with ``EXIT_NOT_KEPT`` before anything is written when a validation
    beside an input did not keep its test and ``--unvalidated`` was not passed.
    """
    stamps: list[bool] = []
    for path in exploit_paths:
        verdict = input_verdict(path)
        if verdict not in (None, KEPT) and not allow_unvalidated:
            echo_err(
                f"refusing to generate from {path}: the validation_report.json beside it "
                f"reads {verdict}, so the test is a candidate, not a proven gate test. "
                "Re-run `mylonite validate`, or pass --unvalidated to write it stamped "
                "UNVALIDATED."
            )
            raise typer.Exit(code=EXIT_NOT_KEPT)
        stamps.append(verdict != KEPT)
    return stamps


def announce_unvalidated(out_dir: Path) -> None:
    """The output line ``generate`` prints under a stamped test."""
    echo(
        "UNVALIDATED: this test is a candidate until `mylonite validate "
        f"{out_dir}` keeps it as KEPT. Do not commit it as a gate test before then."
    )


def clear_stamp_if_kept(test_path: Path, report: ValidationReport) -> None:
    """Remove the unvalidated header from ``test_path`` on a KEPT verdict."""
    if verdict_label(report) != KEPT:
        return
    source = test_path.read_text(encoding="utf-8")
    if not is_unvalidated(source):
        return
    test_path.write_text(strip_unvalidated(source), encoding="utf-8")
    echo(f"Removed the UNVALIDATED header from {test_path}: the test is KEPT.")
