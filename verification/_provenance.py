"""Provenance stamp + install "silo" guard for the verification harness.

Two invariants live here, and both are load-bearing enough that the harness
should refuse to produce numbers rather than get them wrong.

Silo
----
Verification exists to score the *published* artefact. Mylonite uses a ``src/``
layout, so ``import mylonite`` from the repo root fails unless something put the
package on the path -- and the two things that can do that are (a) a venv
holding ``mylonite==<version>`` from PyPI, which is what we want, and (b) an
editable install / ``pythonpath`` entry pointing at the working tree, which is
not. Case (b) does not announce itself: the import succeeds, the run completes,
and the results land in ``verification/results/<version>/`` labelled with a
version number they do not actually measure. Numbers labelled "0.9.0" that
really measure uncommitted local edits are worse than no numbers, because they
are quotable. So the silo is ASSERTED at run start, never assumed.

No local-machine information in committed output
------------------------------------------------
Everything this module emits ends up in a file that gets committed. Absolute
paths, usernames, hostnames and ports are all forbidden -- a leak of exactly
this class previously forced a force-push. The consequence for the code below
is that the origin of the import is reduced to one of a small closed set of
labels (:func:`safe_install_origin`) BEFORE it can reach a message or a payload;
the resolved path is never interpolated into either, not even into the error
that fires when the silo is violated. That is why the violation message tells
you what shape of install was found and how to fix it rather than where it was.
"""

from __future__ import annotations

import importlib
import importlib.metadata
import re
from typing import Any, Final, Literal

#: Path separator on either platform - see :func:`_classify`.
_SEPARATORS: Final = re.compile(r"[\\/]+")

#: Directory names that mean "installed package", across platforms and packaging
#: tools (Debian's system Python uses ``dist-packages``).
_INSTALLED_MARKERS: Final = frozenset({"site-packages", "dist-packages"})

#: Directory name that marks a src-layout checkout. An editable install resolves
#: ``mylonite.__file__`` to ``<repo>/src/mylonite/__init__.py``, so this is the
#: signal that we are measuring the working tree rather than a wheel.
_SOURCE_MARKER: Final = "src"

#: The closed vocabulary :func:`safe_install_origin` may return. Closed on
#: purpose: the return value is written into a committed file, so it must be
#: impossible for a path fragment to reach it.
Origin = Literal["site-packages", "working-tree", "unknown"]

#: The closed vocabulary a layer state may take in ``meta.json``.
LayerState = Literal["ran", "not-run"]

_META_SCHEMA_VERSION: Final = "1.0"


class SiloViolation(RuntimeError):
    """Raised when the imported ``mylonite`` is not the published artefact.

    A hard error, not a warning: the whole point is that the harness must not be
    able to emit numbers under a version label it did not actually measure.
    """


def _classify(module_file: str) -> Origin:
    """Reduce an import path to one of the closed :data:`Origin` labels.

    Split out from :func:`safe_install_origin` so the decision is testable
    without touching the ambient interpreter state, and so exactly one function
    is responsible for the path -> label reduction that keeps machine-identifying
    strings out of everything downstream.

    The rule is positional, not a bare membership test. A venv can live inside
    the repo (``<repo>/.venv/Lib/site-packages/mylonite``), and a repo can live
    under a directory called ``src``, so both markers can be present at once.
    What settles it is which one is *innermost*: whichever marker sits closest to
    the package decides, because that is the directory the import actually
    resolved through.

    Splitting is done on BOTH separators rather than via ``Path``: ``PosixPath``
    treats a Windows path as one undivided component, so a Linux CI runner
    scoring a Windows-recorded path -- or a test asserting on either shape --
    would silently see zero markers and classify a real install as "unknown".
    """
    parts = [part.lower() for part in _SEPARATORS.split(str(module_file)) if part]
    installed_at = max(
        (i for i, part in enumerate(parts) if part in _INSTALLED_MARKERS),
        default=-1,
    )
    source_at = max((i for i, part in enumerate(parts) if part == _SOURCE_MARKER), default=-1)
    if installed_at > source_at:
        return "site-packages"
    if source_at >= 0:
        return "working-tree"
    # Neither marker: a vendored copy, a zipapp, a sys.path hack, something
    # unforeseen. Reported honestly as "unknown" and rejected by
    # assert_siloed -- an unrecognised origin is not evidence of a silo.
    return "unknown"


def _resolve_mylonite_file() -> str | None:
    """Return ``mylonite.__file__``, or ``None`` if it cannot be determined.

    Isolated as a module-level function so tests can substitute an origin
    without installing anything, and so the import happens lazily: importing
    this module must not itself drag in the package under test.

    A namespace package (or any exotic loader) leaves ``__file__`` unset. That
    is not a silo either, so it is surfaced as ``None`` and turned into a
    violation by the caller rather than being papered over.
    """
    module = importlib.import_module("mylonite")
    file = getattr(module, "__file__", None)
    return str(file) if file else None


def _installed_version() -> str | None:
    """Distribution version of the installed ``mylonite``, or ``None``.

    ``None`` means the import resolved without any distribution metadata behind
    it, which is itself a silo failure (a PyPI install always has metadata).
    """
    try:
        return importlib.metadata.version("mylonite")
    except importlib.metadata.PackageNotFoundError:
        return None


def safe_install_origin() -> str:
    """Non-identifying description of where ``mylonite`` was imported from.

    Returns one of ``"site-packages"``, ``"working-tree"`` or ``"unknown"``.
    Never a path, never a username, never a hostname -- this value is written
    verbatim into a committed ``meta.json``.
    """
    module_file = _resolve_mylonite_file()
    if module_file is None:
        return "unknown"
    return _classify(module_file)


def _fix_hint(expected_version: str | None) -> str:
    pin = f"mylonite=={expected_version}" if expected_version else "mylonite==<version>"
    return (
        "Fix: create a fresh virtualenv outside the repo checkout, "
        f"run 'pip install {pin}', and run the harness with that interpreter."
    )


def assert_siloed(expected_version: str | None = None) -> None:
    """Assert that the imported ``mylonite`` is the published PyPI artefact.

    Raises :class:`SiloViolation` if the import resolved to anything other than
    an installed package, or -- when ``expected_version`` is given -- if the
    installed distribution version is not the one the results will be filed
    under. Both checks are about the same failure: results that claim to
    describe a released version while actually describing something else.

    The message names what was found and what was expected, and never contains
    the resolved path (see the module docstring).
    """
    origin = safe_install_origin()
    if origin != "site-packages":
        found = (
            "the repo working tree (editable install or src/ on sys.path)"
            if origin == "working-tree"
            else "an unrecognised location (no site-packages in the import path)"
        )
        raise SiloViolation(
            f"verification must measure the published artefact, but 'mylonite' "
            f"imported from {found}. Expected: an installed package under "
            f"site-packages. {_fix_hint(expected_version)}"
        )

    installed = _installed_version()
    if installed is None:
        raise SiloViolation(
            "verification must measure the published artefact, but no distribution "
            "metadata was found for 'mylonite' - the import did not come from a real "
            f"install. {_fix_hint(expected_version)}"
        )
    if expected_version is not None and installed != expected_version:
        raise SiloViolation(
            f"verification is filing results under mylonite {expected_version!r} but the "
            f"installed distribution is {installed!r}. Results labelled with a version they "
            f"do not measure are worse than no results. {_fix_hint(expected_version)}"
        )


def _layer_state(state: str) -> LayerState:
    """Coerce a caller-supplied layer state into the closed vocabulary.

    Fails CLOSED: anything that is not exactly ``"ran"`` becomes ``"not-run"``.
    Project doctrine is that NOT-TESTED is never reported as clean, so the safe
    direction for an unrecognised value (a typo, a state added later, a layer
    that crashed halfway) is to understate coverage, never to overstate it.
    """
    return "ran" if state == "ran" else "not-run"


def build_meta(
    *,
    mylonite_version: str,
    git_sha: str,
    harness_sha: str,
    model: str,
    recorded_at: str,
    layers: dict[str, str],
) -> dict[str, Any]:
    """Build the ``meta.json`` payload that accompanies a results directory.

    The payload is written as an explicit literal -- an allowlist by
    construction. The caller's ``layers`` mapping is rebuilt key by key rather
    than spliced in, so no caller can widen a committed file with an extra
    field, and no unvetted value (a path, a hostname, an env dump) can ride into
    the output on a key nobody reviewed. ``mylonite_origin`` is derived here
    rather than accepted as an argument for the same reason.

    A layer that did not run MUST still appear, recorded as ``"not-run"``:
    an absent layer reads to a downstream consumer as a zero, and a zero reads
    as "nothing found", which is the exact opposite of "we did not look".

    ``git_sha`` is what makes the version stamp honest. A campaign is run AFTER
    the tag is published (the silo requires an installed artifact, which requires
    a release), so "when did this run" and "what did it measure" are different
    questions. Recording the commit answers the second one, and lets a reader
    confirm the results describe the tagged tree rather than whatever happened to
    be checked out. ``harness_sha`` is recorded SEPARATELY: if the scorer changes,
    numbers move without Mylonite changing at all, and a trend line that cannot
    tell "the tool got better" from "we changed how we measure" is worse than
    none.
    """
    return {
        "schema_version": _META_SCHEMA_VERSION,
        "mylonite_version": mylonite_version,
        "mylonite_origin": safe_install_origin(),
        "git_sha": git_sha,
        "harness_sha": harness_sha,
        "model": model,
        "recorded_at": recorded_at,
        "layers": {str(name): _layer_state(state) for name, state in layers.items()},
    }


__all__ = [
    "SiloViolation",
    "assert_siloed",
    "build_meta",
    "safe_install_origin",
]
