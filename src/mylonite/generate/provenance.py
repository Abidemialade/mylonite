"""Whether a generated test is proven, and the header that says it is not.

A test ``generate`` writes straight from a scan is a candidate: nothing has yet
shown that it fails on the vulnerable build and passes on the guarded one.
``mylonite validate`` decides that, and writes ``validation_report.json`` next
to the test and its exploit. ``gate`` writes the same file into each finding's
directory.

A test is written without the header only when a KEPT report beside its input
proved this very test against the same target: the folder holds one exploit,
it and the folder's ``target.yaml`` are no newer than the report, any
``--target-file`` matches that ``target.yaml``, and the test the report names
is still there and matches what ``generate`` is about to write. Anything else carries :data:`UNVALIDATED_MARKER` as its first
line. ``validate`` keeps the header in step with its latest verdict: it removes
it on KEPT and adds it on STABLE, NOT PROVEN or REJECTED, so a candidate never
reads as a gate test.
"""

from __future__ import annotations

import json
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


#: The header's own lines, newline-free, for stripping a header that lost some.
_STAMP_LINES: Final = frozenset(_STAMP.splitlines())


def _stamp_for(source: str) -> str:
    """The header in ``source``'s own line endings, so a CRLF file stays CRLF."""
    return _STAMP.replace("\n", "\r\n") if "\r\n" in source else _STAMP


_BOM: Final = "\ufeff"


def _split_bom(source: str) -> tuple[str, str]:
    """``(bom, rest)``: the header goes after a byte-order mark, never before it."""
    return (_BOM, source[1:]) if source.startswith(_BOM) else ("", source)


def is_unvalidated(source: str) -> bool:
    """True when ``source`` starts with the unvalidated header."""
    return _split_bom(source)[1].startswith(UNVALIDATED_MARKER)


def stamp_unvalidated(source: str) -> str:
    """``source`` with the unvalidated header in front (once)."""
    if is_unvalidated(source):
        return source
    bom, rest = _split_bom(source)
    return bom + _stamp_for(source) + rest


def has_exact_stamp(source: str) -> bool:
    """True when ``source`` starts with the header exactly as Mylonite wrote it."""
    return _split_bom(source)[1].startswith(_stamp_for(source))


def strip_unvalidated(source: str) -> str:
    """``source`` without the unvalidated header, if it has one.

    Removes the header exactly as written. When the header was edited, removes
    the marker line and any of the header's own lines that directly follow it,
    and nothing else: a comment of the user's own (a licence line, a ``noqa``)
    is never touched.
    """
    if not is_unvalidated(source):
        return source
    bom, rest = _split_bom(source)
    stamp = _stamp_for(source)
    if rest.startswith(stamp):
        return bom + rest[len(stamp) :]
    lines = rest.splitlines(keepends=True)
    end = 1
    while end < len(lines) and lines[end].rstrip("\r\n") in _STAMP_LINES:
        end += 1
    return bom + "".join(lines[end:])


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


def _same_target(folder_target: Path, target_file: Path | None, report_mtime: int) -> bool:
    """True when the run targets the app the KEPT report was proved against.

    That is the ``target.yaml`` beside the report, unchanged since the report
    was written. An explicit ``--target-file`` must match it once redacted (the
    form ``generate`` writes); with no ``target.yaml`` beside the report, any
    ``--target-file`` is a different target.
    """
    if folder_target.is_file() and folder_target.stat().st_mtime_ns > report_mtime:
        return False
    if target_file is None:
        return True
    if not folder_target.is_file():
        return False
    from mylonite._redaction import redact_target_yaml

    try:
        wanted = redact_target_yaml(target_file.read_text(encoding="utf-8"))
        return wanted == folder_target.read_text(encoding="utf-8")
    except (OSError, ValueError):  # unreadable or not UTF-8: stamp; generate reports it
        return False


def _is_reference_target(exploit_path: Path) -> bool:
    """True when the exploit targets a bundled reference build (no target.yaml needed)."""
    try:
        data = json.loads(exploit_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    target_id = data.get("target_id") if isinstance(data, dict) else None
    return isinstance(target_id, str) and target_id.startswith("reference:")


def _proving_test(
    exploit_path: Path, *, prove_control: bool, target_file: Path | None
) -> Path | None:
    """The test a KEPT report beside ``exploit_path`` proved, if it can only be this one.

    ``None`` (so the new test is stamped) when the folder holds more than one
    exploit, ``--prove-control`` asks for a different test than the one proved,
    the exploit or the folder's ``target.yaml`` is newer than the report
    (replaced after the keep), ``--target-file`` names a different target, a
    custom target's ``target.yaml`` is gone, or the test the report names is gone.
    """
    folder = exploit_path.parent
    report_path = folder / "validation_report.json"
    report = _read_report(report_path)
    if report is None or prove_control or len(list(folder.glob("exploit_*.json"))) != 1:
        return None
    report_mtime = report_path.stat().st_mtime_ns
    if exploit_path.stat().st_mtime_ns > report_mtime:
        return None
    folder_target = folder / "target.yaml"
    if not _same_target(folder_target, target_file, report_mtime):
        return None
    if not folder_target.is_file() and not _is_reference_target(exploit_path):
        return None  # a custom target's target.yaml was removed after the keep
    test_path = folder / Path(report.test_filename).name
    return test_path if test_path.is_file() else None


def stamps_for(
    exploit_paths: Sequence[Path],
    *,
    allow_unvalidated: bool,
    prove_control: bool = False,
    target_file: Path | None = None,
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
            _proving_test(path, prove_control=prove_control, target_file=target_file)
            if verdict == KEPT
            else None
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


def announce_unvalidated(out_dir: Path, *, authorize: str | None = None) -> None:
    """The output line ``generate`` prints under a stamped test.

    Names the exact ``mylonite validate`` command the "Next"/"Then:" block
    above also prints — rendered the same way (:func:`mylonite._paths.
    path_for_shell`) and, for a custom target, carrying the same
    ``--authorize`` value (``authorize``, the target's required scope/family;
    ``None`` for a reference target, which needs none) — so this line is
    never a second, stale copy of a command the real gate would refuse.
    """
    from mylonite._paths import path_for_shell, quote_for_shell

    command = f"mylonite validate {path_for_shell(out_dir)}"
    if authorize:
        command += f" --authorize {quote_for_shell(authorize)}"
    echo(
        f"UNVALIDATED: this test is a candidate until `{command}` keeps it as "
        "KEPT. Do not commit it as a gate test before then."
    )


def sync_stamp(test_path: Path, report: ValidationReport) -> None:
    """Keep ``test_path``'s header in step with ``report``'s verdict.

    KEPT removes the header; any other verdict adds it, also to a test that was
    written without one (an older test, or one kept earlier that now fails).
    Prints a line only when the file changed. Keeps the file's own line endings.
    """
    label = verdict_label(report)
    with test_path.open(encoding="utf-8", newline="") as fh:
        source = fh.read()
    updated = strip_unvalidated(source) if label == KEPT else stamp_unvalidated(source)
    if updated == source:
        return
    with test_path.open("w", encoding="utf-8", newline="") as fh:
        fh.write(updated)
    if label == KEPT:
        echo(f"Removed the UNVALIDATED header from {test_path}: the test is KEPT.")
        if not has_exact_stamp(source):
            echo(
                "The header had been edited: only its marker and unchanged lines were "
                f"removed. Check the comment lines at the top of {test_path}."
            )
    else:
        echo(f"Added the UNVALIDATED header to {test_path}: the verdict is {label}.")
