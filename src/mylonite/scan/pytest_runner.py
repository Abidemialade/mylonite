"""Programmatic pytest runner used by the validation engine.

The validator hands an *emitted* pytest file to ``run_test_file`` and
needs a clean pass/fail signal plus captured output. This runner shells out to
``sys.executable -m pytest`` in a **subprocess** rather than calling
``pytest.main()`` in-process, deliberately:

* The validator that calls this is itself executing under pytest, so an
  in-process ``pytest.main()`` would be a re-entrant pytest invocation — a
  documented footgun (shared plugin state, fixture caches, capture managers).
* The emitted test drives ``asyncio.run`` against an MCP target; nesting an
  event loop inside an already-running one is fragile. A fresh process gets a
  fresh interpreter and a fresh default event loop.
* Process isolation also means a crash / hang in the target can't take down the
  validator: we cap it with ``timeout`` and reap the child.

**Windows UTF-8 handling (A3 — this project has a cp1252 history).** On Windows
the child interpreter's stdio defaults to the legacy ANSI code page, so a test
that prints non-ASCII (or pytest rendering a unicode assertion repr) raises
``UnicodeEncodeError`` in the child and/or yields mojibake we can't decode. We
force the child to emit UTF-8 via ``PYTHONUTF8=1`` *and* ``PYTHONIOENCODING=utf-8``
(``PYTHONUTF8`` alone is insufficient on 3.11; ``PYTHONIOENCODING`` covers the
remaining stdio paths), and decode the captured bytes as UTF-8 with
``errors="replace"`` as a final backstop so a stray undecodable byte never
crashes the runner.

**Exit-code ambiguity (T5 — root-cause fix).** pytest exit 1
(``TESTS_FAILED``) is only unambiguous once we already know pytest itself ran:
the SAME exit code 1 is also what ``python -m pytest ...`` produces when
pytest isn't installed at all (``No module named pytest``), because that
failure is reported by the ``-m`` machinery, not by pytest's own
``ExitCode``. Trying to disambiguate the two from the integer alone is a
losing game, so we don't: before ever invoking the real ``pytest``
subprocess, a cheap, memoized preflight (:func:`_pytest_importable`) probes
``sys.executable -c "import pytest"`` once per process. If that fails,
:func:`run_test_file` returns :attr:`PytestOutcome.PYTEST_UNAVAILABLE`
without shelling out to the real run at all — a missing pytest can never be
misread as "tests ran, some failed" (which downstream logic could otherwise
misclassify as ``collected=True``).

Exit code 5 (``NO_TESTS_COLLECTED``) — an empty file, or every test
deselected — is mapped to :attr:`PytestOutcome.NO_TESTS`, which is NOT
``collected``: if nothing was collected, the file was not meaningfully
validated.

**A pass means a test ran and passed.** Exit 0 is also what pytest returns
when every collected test was skipped (the custom-target test skips without a
live target) or xfailed. :attr:`PytestOutcome.PASSED` therefore needs exit 0
*and* at least one passed test in pytest's summary line; exit 0 with nothing
passed is :attr:`PytestOutcome.ALL_SKIPPED`, which is not a pass.

``collect_only=True`` runs ``pytest --collect-only``: it proves the file
collects without running anything, and returns
:attr:`PytestOutcome.COLLECTED`. That is never a pass either.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path

from mylonite._redaction import redact

__all__ = ["PytestOutcome", "PytestRunResult", "failure_tail", "run_test_file"]


class PytestOutcome(Enum):
    """The classified outcome of one ``run_test_file`` invocation.

    Deliberately richer than a ``(passed, collected)`` bool pair (see
    :class:`PytestRunResult`, which still exposes those as *properties* for
    source-compatibility) so a caller that wants to distinguish "pytest isn't
    installed" from "no tests in this file" from "pytest crashed internally"
    can, instead of collapsing them all into ``collected=False``.
    """

    #: Exit 0 and at least one test passed (none failed).
    PASSED = auto()
    #: Exit 0 but no test passed: every test was skipped or xfailed, so the
    #: file ran nothing that could prove it. NOT a pass.
    ALL_SKIPPED = auto()
    #: ``collect_only=True`` and at least one test collected. The tests were
    #: not run, so this is NOT a pass.
    COLLECTED = auto()
    #: Exit 1, WITH pytest confirmed importable — tests ran, at least one failed.
    FAILED = auto()
    #: Exit 5 (``NO_TESTS_COLLECTED``) — the file collected but contained no
    #: tests (or every test was deselected). NOT the same as "validated".
    NO_TESTS = auto()
    #: Exit 2 (``INTERRUPTED``) — a collection error (import/syntax error) or
    #: an interruption before/while collecting.
    COLLECTION_ERROR = auto()
    #: Exit 3 (``INTERNAL_ERROR``) — pytest itself crashed.
    INTERNAL_ERROR = auto()
    #: Exit 4 (``USAGE_ERROR``) — bad CLI usage (a mylonite-side bug in the
    #: constructed ``cmd``, not a property of the emitted test file).
    USAGE_ERROR = auto()
    #: The import preflight failed — pytest is not importable in this
    #: interpreter at all. The real pytest subprocess was never invoked, so
    #: there is no meaningful exit code (this is the fix for the exit-1
    #: ambiguity documented in the module docstring).
    PYTEST_UNAVAILABLE = auto()
    #: The child was killed after exceeding ``timeout`` before it exited.
    TIMEOUT = auto()
    #: An exit code pytest does not document. Should not happen in practice;
    #: kept as an honest fallback rather than silently defaulting to a
    #: specific classification.
    UNKNOWN = auto()


@dataclass(frozen=True)
class PytestRunResult:
    """Outcome of running a single emitted test file under pytest.

    Attributes:
        outcome: The classified :class:`PytestOutcome`.
        exit_code: The child pytest process exit code. ``-1`` on timeout;
            ``-2`` (sentinel) when the import preflight failed and pytest was
            never actually invoked (see ``PYTEST_UNAVAILABLE``).
        stdout: Decoded child stdout (UTF-8, ``errors="replace"``); empty when
            pytest was never invoked.
        stderr: Decoded child stderr (UTF-8, ``errors="replace"``); empty when
            pytest was never invoked.
        detail: One-line human-readable summary of the outcome.
    """

    outcome: PytestOutcome
    exit_code: int
    stdout: str
    stderr: str
    detail: str

    @property
    def passed(self) -> bool:
        """True only when pytest exited 0 and at least one test ran and passed.

        A file whose every test skipped, a collect-only run, a failure and an
        error are all ``False``."""
        return self.outcome is PytestOutcome.PASSED

    @property
    def collected(self) -> bool:
        """True iff pytest collected at least one test from the file.

        This says nothing about whether a test passed: ``FAILED``,
        ``ALL_SKIPPED`` and ``COLLECTED`` are all collected. Use :attr:`passed`
        for a pass. False for a missing pytest (never invoked), a collection
        error, an internal/usage error, a timeout, an unrecognised exit code,
        and ``NO_TESTS`` (exit 5).
        """
        return self.outcome in {
            PytestOutcome.PASSED,
            PytestOutcome.FAILED,
            PytestOutcome.ALL_SKIPPED,
            PytestOutcome.COLLECTED,
        }


# Sentinel exit code used when the real pytest subprocess was never invoked
# (the import preflight failed) — distinct from any real pytest ExitCode
# (0-5) and from the timeout sentinel (-1).
_EXIT_CODE_PYTEST_UNAVAILABLE = -2


# pytest's documented ExitCode values (see ``pytest.ExitCode``):
#   0 OK                 — all collected tests passed
#   1 TESTS_FAILED        — tests ran, some failed
#   2 INTERRUPTED         — collection error / interrupted before/while running
#   3 INTERNAL_ERROR      — internal pytest error
#   4 USAGE_ERROR         — bad CLI usage
#   5 NO_TESTS_COLLECTED  — file collected but contained no tests
#: pytest's summary line counts, e.g. "1 passed, 2 skipped in 0.12s" or, under
#: ``--collect-only``, "2 tests collected in 0.01s". The space before "passed" keeps
#: "xpassed" out. Only the final summary line is matched (:func:`_summary_line`): a
#: warning or captured output earlier in stdout can say "3 passed" too.
_PASSED_RE = re.compile(r"\b(\d+) passed\b")
_COLLECTED_RE = re.compile(r"\b(\d+) tests? collected\b")


def _summary_line(stdout: str) -> str:
    """pytest's final summary line: the last non-empty line of ``stdout``."""
    for line in reversed(stdout.splitlines()):
        if line.strip():
            return line
    return ""


def _classify(
    exit_code: int, *, stdout: str = "", collect_only: bool = False
) -> tuple[PytestOutcome, str]:
    """Map a REAL pytest exit code (pytest was confirmed importable and ran)
    to ``(outcome, detail)``. Exit 1 here is unambiguous — see the module
    docstring for why that's only true once the import preflight passed.

    Exit 0 is split by ``stdout``: a run is a pass only when the summary
    counts at least one passed test, and a collect-only run is ``COLLECTED``
    only when it counts at least one collected test. Without a readable count
    exit 0 is not taken as proof of anything."""
    if exit_code == 0:
        if collect_only:
            found = _COLLECTED_RE.search(_summary_line(stdout))
            if found and int(found.group(1)) > 0:
                return PytestOutcome.COLLECTED, f"{found.group(1)} collected, not run"
            return PytestOutcome.NO_TESTS, "no tests collected"
        found = _PASSED_RE.search(_summary_line(stdout))
        if found and int(found.group(1)) > 0:
            return PytestOutcome.PASSED, "all tests passed"
        return (
            PytestOutcome.ALL_SKIPPED,
            "pytest exited 0 but no test passed (every test was skipped or none ran)",
        )
    if exit_code == 1:
        return PytestOutcome.FAILED, "tests ran but some failed"
    if exit_code == 2:
        # Collection error (import/syntax error) or interruption before run.
        return PytestOutcome.COLLECTION_ERROR, "collection error or interruption (exit 2)"
    if exit_code == 3:
        return PytestOutcome.INTERNAL_ERROR, "internal pytest error (exit 3)"
    if exit_code == 4:
        return PytestOutcome.USAGE_ERROR, "pytest usage error (exit 4)"
    if exit_code == 5:
        return PytestOutcome.NO_TESTS, "no tests collected"
    return PytestOutcome.UNKNOWN, f"unexpected pytest exit code {exit_code}"


# Memoized import-preflight result: None = not yet probed, True/False = probed
# once this process's lifetime. `run_test_file` may be called once per emitted
# test — potentially many times in one `mylonite validate` run — so the probe
# must not re-shell-out on every call.
_pytest_available_cache: bool | None = None


def _probe_pytest_importable() -> bool:
    """Actually shell out once to check whether ``import pytest`` succeeds in
    ``sys.executable``. Never raises — any failure (missing interpreter,
    timeout, ``OSError``) is treated as "not importable" rather than
    propagating, since the caller's job is a boolean preflight, not a
    diagnostic."""
    try:
        # Fixed argv list, shell=False, no string interpolation — safe by
        # construction, matching the real pytest invocation below.
        completed = subprocess.run(
            [sys.executable, "-c", "import pytest"],
            capture_output=True,
            shell=False,
            timeout=30.0,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0


def _pytest_importable() -> bool:
    """Memoized wrapper around :func:`_probe_pytest_importable`."""
    global _pytest_available_cache
    if _pytest_available_cache is None:
        _pytest_available_cache = _probe_pytest_importable()
    return _pytest_available_cache


def run_test_file(
    path: str | os.PathLike[str],
    *,
    timeout: float = 120.0,
    collect_only: bool = False,
) -> PytestRunResult:
    """Run a single test file under pytest in an isolated subprocess.

    Before invoking pytest at all, a memoized preflight confirms pytest is
    importable in ``sys.executable`` (see the module docstring's "Exit-code
    ambiguity" section). If it isn't, this returns
    :attr:`PytestOutcome.PYTEST_UNAVAILABLE` WITHOUT ever spawning the real
    pytest subprocess.

    Args:
        path: Path to the emitted pytest file.
        timeout: Seconds before the child is killed; on expiry a result with
            ``outcome=PytestOutcome.TIMEOUT, exit_code=-1`` is returned (the
            ``TimeoutExpired`` is caught, never propagated).
        collect_only: Run ``pytest --collect-only``: prove the file collects
            without running any test. Success is ``PytestOutcome.COLLECTED``.

    Returns:
        A :class:`PytestRunResult` describing the outcome.
    """
    if not _pytest_importable():
        return PytestRunResult(
            outcome=PytestOutcome.PYTEST_UNAVAILABLE,
            exit_code=_EXIT_CODE_PYTEST_UNAVAILABLE,
            stdout="",
            stderr="",
            detail=(
                f"pytest is not importable via {sys.executable!r}; the file "
                "was never run (this is NOT the same as a pytest exit-1 "
                "'tests ran, some failed' — pytest itself is missing). "
                "Install pytest, e.g. `pip install pytest`."
            ),
        )

    test_path = Path(path)
    # Use the test file's parent as an isolated rootdir so the project's own
    # pytest config / plugins / addopts don't bleed into the emitted run. A bare
    # filename has an empty parent (``Path("")``); fall back to the cwd.
    rootdir = test_path.parent if str(test_path.parent) else Path.cwd()

    try:
        # `-o addopts=` alone is NOT enough: pytest's own ini-file discovery
        # ignores `--rootdir` and walks UP from the test file looking for an
        # ini (pyproject.toml / pytest.ini / setup.cfg / tox.ini). When the
        # emitted test is written inside this project's own checkout (as
        # `validate`/`gate` do, since the committed artefact lives in the
        # user's repo), that walk finds THIS project's `pyproject.toml` —
        # whose `[tool.pytest.ini_options]` carries `filterwarnings = ["error",
        # ...]` and `asyncio_mode = "auto"` (an option only `pytest-asyncio`,
        # a dev-only extra NOT installed alongside a plain `pip install
        # mylonite`, understands). With that ini picked up and
        # `pytest-asyncio` absent, pytest's own "unknown config option:
        # asyncio_mode" warning gets promoted to an exception by the
        # inherited `filterwarnings=error`, raised inside the
        # `pytest_collection` hook where nothing catches it —
        # `PytestOutcome.INTERNAL_ERROR` (exit 3), confirmed by actually
        # reproducing it: a wheel install (no `pytest-asyncio`) running an
        # emitted test from inside this checkout crashes; from an editable
        # install (where `pytest-asyncio` IS present as a dev dependency) or
        # from outside the checkout (no ini to find) it passes. An empty,
        # throwaway ini pinned with `-c` makes pytest use EXACTLY that file —
        # it never searches for another — so no project setting, not just
        # `addopts`, can reach the emitted run regardless of where it lives.
        with tempfile.TemporaryDirectory() as ini_dir:
            isolated_ini = Path(ini_dir) / "pytest.ini"
            isolated_ini.write_text("[pytest]\n", encoding="utf-8")

            cmd = [
                sys.executable,
                "-m",
                "pytest",
                str(test_path),
                "-p",
                "no:cacheprovider",
                "-c",
                str(isolated_ini),
                "-o",
                "addopts=",  # belt-and-suspenders: also drop `-c`'s own addopts
                "--rootdir",
                str(rootdir),
                "-q",
            ]
            if collect_only:
                cmd.append("--collect-only")

            # Force the child to speak UTF-8 on every platform (Windows A3
            # guard). Drop PYTEST_ADDOPTS for the same reason `-o addopts=`
            # drops the ini addopts: an inherited flag (say -rA) changes the
            # output the pass check reads.
            env = {
                **{k: v for k, v in os.environ.items() if k != "PYTEST_ADDOPTS"},
                "PYTHONUTF8": "1",
                "PYTHONIOENCODING": "utf-8",
            }

            # cmd is a fixed argv list (sys.executable -m pytest <path>
            # <flags>); shell=False and no string is shell-interpolated, so
            # this is safe by construction — not deferred to a later phase.
            completed = subprocess.run(  # noqa: S603
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                shell=False,
                timeout=timeout,
                env=env,
            )
    except subprocess.TimeoutExpired as exc:
        # Decode any partial captured output for diagnostics; never re-raise.
        out = _coerce_stream(exc.stdout)
        err = _coerce_stream(exc.stderr)
        return PytestRunResult(
            outcome=PytestOutcome.TIMEOUT,
            exit_code=-1,
            stdout=out,
            stderr=err,
            detail=f"pytest timed out after {timeout:g}s",
        )

    outcome, detail = _classify(
        completed.returncode, stdout=completed.stdout or "", collect_only=collect_only
    )
    return PytestRunResult(
        outcome=outcome,
        exit_code=completed.returncode,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
        detail=detail,
    )


def _coerce_stream(stream: str | bytes | None) -> str:
    """Normalise a possibly-bytes/None subprocess stream to a UTF-8 string."""
    if stream is None:
        return ""
    if isinstance(stream, bytes):
        return stream.decode("utf-8", errors="replace")
    return stream


#: Lines pytest itself marks as diagnostic: an internal-error traceback line
#: (``INTERNALERROR> ...``, always on stderr) or an assertion-failure line
#: from its own report (``E   ...``).
_DIAGNOSTIC_PREFIXES = ("INTERNALERROR", "E ")


def failure_tail(result: PytestRunResult, *, max_chars: int = 600) -> str:
    """A short, redacted tail of ``result``'s captured output for a non-pass run.

    A caller that only reports ``exit_code`` and :attr:`PytestRunResult.detail`
    (a one-line classification such as ``"internal pytest error (exit 3)"``)
    gives no clue WHY pytest failed that way — e.g. a wheel install missing a
    plugin's entry point, or a rootdir/fixture-path problem, each produce a
    different ``INTERNALERROR`` traceback. This surfaces a bounded excerpt of
    the real pytest output instead.

    ``INTERNALERROR>`` and ``E   `` lines are the most diagnostic, so they are
    surfaced first; when THOSE alone overflow the budget, their own tail is
    kept (the raised exception is the last line of an internal-error
    traceback, not the first). Any remaining budget is filled from the tail of
    the rest of the combined stdout/stderr. The result is passed through
    :func:`mylonite._redaction.redact` so a secret-shaped string captured in
    the test's own output never reaches a report, and is capped at
    approximately ``max_chars``.

    Returns ``""`` when there is no captured output at all (e.g. a timeout
    with nothing captured, or the import preflight never invoked pytest).
    """
    lines = [
        ln for stream in (result.stderr, result.stdout) if stream for ln in stream.splitlines()
    ]
    if not lines:
        return ""

    is_diagnostic = [ln.lstrip().startswith(_DIAGNOSTIC_PREFIXES) for ln in lines]
    diagnostic_text = "\n".join(ln for ln, hit in zip(lines, is_diagnostic, strict=True) if hit)
    if len(diagnostic_text) > max_chars:
        return redact(diagnostic_text[-max_chars:])

    other_text = "\n".join(ln for ln, hit in zip(lines, is_diagnostic, strict=True) if not hit)
    remaining = max_chars - len(diagnostic_text)
    filler = other_text[-remaining:] if remaining > 0 and other_text else ""
    text = "\n".join(part for part in (diagnostic_text, filler) if part)
    if len(text) > max_chars:
        text = text[-max_chars:]
    return redact(text)
