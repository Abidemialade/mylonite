"""Whether a generated test is proven, and the header that says it is not.

A test ``generate`` writes straight from a scan is a candidate: nothing has yet
shown that it fails on the vulnerable build and passes on the guarded one.
``mylonite validate`` decides that, and writes ``validation_report.json`` next
to the test and its exploit. ``gate`` writes the same file into each finding's
directory.

A test is written without the header only when a KEPT report beside its input
proved this very test: the folder holds one exploit, no newer than the report,
the test the report names is still there, and it matches what ``generate`` is
about to write. Anything else carries :data:`UNVALIDATED_MARKER` as its first
line. ``validate`` keeps the header in step with its latest verdict: it removes
it on KEPT and adds it on STABLE, NOT PROVEN or REJECTED, so a candidate never
reads as a gate test.
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
    """``source`` without the unvalidated header, if it has one.

    Removes the marker line and the ``#`` comment lines right after it, so a
    header whose wording was edited (by hand, or by another release) still
    comes off whole.
    """
    if not is_unvalidated(source):
        return source
    lines = source.splitlines(keepends=True)
    end = 1
    while end < len(lines) and lines[end].startswith("#"):
        end += 1
    return "".join(lines[end:])


def _read_report(report_path: Path) -> ValidationReport | None:
    try:
        return ValidationReport.model_validate_json(report_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def input_verdict(exploit_path: Path) -> str | None:
    """The verdict label of the ``validation_report.json`` beside ``exploit_path``.

    ``None`` when there is none (a raw scan finding), :data:`UNREADABLE` when it
    does not parse.
    """
    report_path = exploit_path.parent / "validation_report.json"
    if not report_path.is_file():
        return None
    report = _read_report(report_path)
    return UNREADABLE if report is None else verdict_label(report)


def _proving_test(exploit_path: Path, *, prove_control: bool) -> Path | None:
    """The test a KEPT report beside ``exploit_path`` proved, if it can only be this one.

    ``None`` (so the new test is stamped) when the folder holds more than one
    exploit, ``--prove-control`` asks for a different test than the one proved,
    the exploit is newer than the report (replaced after the keep), or the
    test the report names is gone.
    """
    folder = exploit_path.parent
    report_path = folder / "validation_report.json"
    report = _read_report(report_path)
    if report is None or prove_control or len(list(folder.glob("exploit_*.json"))) != 1:
        return None
    if exploit_path.stat().st_mtime_ns > report_path.stat().st_mtime_ns:
        return None
    test_path = folder / Path(report.test_filename).name
    return test_path if test_path.is_file() else None


def stamps_for(
    exploit_paths: Sequence[Path], *, allow_unvalidated: bool, prove_control: bool = False
) -> list[Path | None]:
    """Per input exploit, the KEPT test that may vouch for its new test, or ``None``.

    ``None`` means the new test is stamped. A path means it is written without
    the header only if it matches that already-proven test
    (:func:`source_is_proven`). Exits with ``EXIT_NOT_KEPT`` before anything is
    written when a validation beside an input did not keep its test and
    ``--unvalidated`` was not passed.
    """
    proving: list[Path | None] = []
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
        proving.append(
            _proving_test(path, prove_control=prove_control) if verdict == KEPT else None
        )
    return proving


def source_is_proven(source: str, proving_test: Path | None) -> bool:
    """True when ``source`` is exactly the test a KEPT report proved."""
    if proving_test is None:
        return False
    try:
        proved = proving_test.read_text(encoding="utf-8")
    except OSError:
        return False
    return strip_unvalidated(proved) == source


def announce_unvalidated(out_dir: Path) -> None:
    """The output line ``generate`` prints under a stamped test."""
    echo(
        "UNVALIDATED: this test is a candidate until `mylonite validate "
        f"{out_dir}` keeps it as KEPT. Do not commit it as a gate test before then."
    )


def sync_stamp(test_path: Path, report: ValidationReport) -> None:
    """Keep ``test_path``'s header in step with ``report``'s verdict.

    KEPT removes the header; any other verdict adds it, also to a test that was
    written without one (an older test, or one kept earlier that now fails).
    Prints a line only when the file changed.
    """
    label = verdict_label(report)
    source = test_path.read_text(encoding="utf-8")
    updated = strip_unvalidated(source) if label == KEPT else stamp_unvalidated(source)
    if updated == source:
        return
    test_path.write_text(updated, encoding="utf-8")
    if label == KEPT:
        echo(f"Removed the UNVALIDATED header from {test_path}: the test is KEPT.")
    else:
        echo(f"Added the UNVALIDATED header to {test_path}: the verdict is {label}.")
