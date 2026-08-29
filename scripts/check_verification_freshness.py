#!/usr/bin/env python
"""Gate a minor/major release on fresh third-party verification evidence.

Why this exists
----------------
The verification harness (``verification/``) is Mylonite's independent proof
against ground truth it did not author (see ``verification/README.md``,
``verification/FINDINGS.md``). A release whose numbers were last measured two
minor versions ago is citing evidence for a product that no longer exists --
the same class of "docs vs reality" drift ``scripts/prepare_release.py``
already guards for version/CHANGELOG/tag consistency. This script guards the
verification side: a **minor or major** release (``X.Y.0``) must ship a
committed ``verification/results/X.Y.0/meta.json`` recorded against exactly
that version. Patch releases (``X.Y.Z``, ``Z != 0``) don't change the AI
surface being verified enough to justify re-running a live, opt-in, model-key
-consuming campaign for every one -- see ``verification/README.md``'s
"opt-in workflow" section -- so they are exempt.

Stdlib-only, mirroring ``prepare_release.py --check``
------------------------------------------------------
This must run with **no dependencies installed** (no ``pip install -e .``),
the same constraint ``prepare_release.py --check`` documents for the release
gate: CI's tag-check job needs no setup step and runs in seconds. So the
version is read by regexing ``src/mylonite/version.py`` directly rather than
``import mylonite`` -- importing the package would pull in its runtime
dependencies just to read one string.

This script never writes anything, in any mode. ``--check`` is accepted (and
is the only mode) purely so invocations read the same in CI recipes and docs
as ``prepare_release.py --check``; omitting it is equivalent.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

#: Same shape as ``release_version.VERSION_RE`` in ``prepare_release.py``'s
#: sibling module -- kept independent (not imported) because that module is
#: outside this script's file boundary and stdlib-only-ness is load-bearing.
_VERSION_RE = re.compile(r'__version__\s*=\s*"(?P<version>\d+\.\d+\.\d+)"')
_SEMVER_RE = re.compile(r"^(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)$")


def read_version(version_file: Path) -> str:
    """Regex ``__version__`` out of ``version_file``. Raises if it's not there."""
    try:
        text = version_file.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise SystemExit(f"{version_file} does not exist") from exc
    match = _VERSION_RE.search(text)
    if match is None:
        raise SystemExit(f'no __version__ = "X.Y.Z" assignment found in {version_file}')
    return match.group("version")


def is_minor_or_major(version: str) -> bool:
    """True for ``X.Y.0`` (a minor or major bump), false for a patch ``X.Y.Z``."""
    match = _SEMVER_RE.match(version)
    if match is None:
        raise SystemExit(f"{version!r} is not a semantic X.Y.Z version")
    return match.group("patch") == "0"


def check(version: str, *, results_root: Path) -> list[str]:
    """Every reason ``version`` is not verification-fresh. Empty means good.

    Only inspects the filesystem; never writes. Patch versions short-circuit
    to "no problems" before touching ``results_root`` at all.
    """
    if not is_minor_or_major(version):
        return []

    meta_path = results_root / version / "meta.json"
    if not meta_path.exists():
        return [
            f"{version} is a minor/major release but {meta_path} does not exist. "
            f"Run the verification campaign (see verification/README.md) and commit "
            f"its results under verification/results/{version}/ before releasing."
        ]

    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return [f"{meta_path} is not readable/valid JSON ({exc}). Re-run the campaign."]

    if not isinstance(meta, dict):
        return [f"{meta_path} must be a JSON object, got {type(meta).__name__}."]

    recorded = meta.get("mylonite_version")
    if recorded != version:
        return [
            f"{meta_path} records mylonite_version={recorded!r}, expected {version!r}. "
            f"These verification results were measured against a different release -- "
            f"re-run the campaign against {version} and commit fresh results."
        ]

    return []


def main(argv: list[str] | None = None) -> int:
    doc = __doc__.splitlines()[0] if __doc__ else ""
    parser = argparse.ArgumentParser(description=doc)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify only (the only mode this script has; accepted for symmetry "
        "with prepare_release.py --check)",
    )
    parser.add_argument(
        "--version-file",
        default=str(ROOT / "src" / "mylonite" / "version.py"),
        help="where __version__ is declared",
    )
    parser.add_argument(
        "--results-root",
        default=str(ROOT / "verification" / "results"),
        help="directory of per-version verification result directories",
    )
    args = parser.parse_args(argv)

    version_file = Path(args.version_file)
    results_root = Path(args.results_root)
    version = read_version(version_file)

    problems = check(version, results_root=results_root)
    if problems:
        for problem in problems:
            print(f"::error::{problem}", file=sys.stderr)
        print(f"\n{len(problems)} problem(s) -- {version} is not verification-fresh.")
        return 1

    if is_minor_or_major(version):
        meta_path = results_root / version / "meta.json"
        print(f"{version}: verification results present and match ({meta_path}).")
    else:
        print(
            f"{version}: patch release, exempt from the verification-freshness gate "
            "(only minor/major releases require fresh verification results)."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
