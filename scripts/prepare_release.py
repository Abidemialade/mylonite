"""Prepare a release, or verify that one is well-formed.

Two modes, one parser::

    python scripts/prepare_release.py 0.8.0          # mutate the tree
    python scripts/prepare_release.py --check 0.8.0  # verify only, never writes
    python scripts/prepare_release.py --check --tag v0.8.0

``--check`` is what the ``gate`` job in ``.github/workflows/release.yml`` runs
against the pushed tag, *before* anything is built or uploaded. It is the reason
a mistagged or unbumped release can no longer reach PyPI: the four ways 0.7.6 and
0.7.7 went wrong (version bumped in one file only, CHANGELOG not updated, no tag
pushed, tag not matching the version) are all failures it reports by name.

**``--check`` never writes.** Every mutation lives behind a single ``if not
check:`` branch and the two modes share only the pure functions in
``release_version.py``. A verification run that dirtied the tree would be worse
than no verification at all, because CI would then be validating a file it had
itself just modified.

It reports *every* problem it finds rather than stopping at the first, so one run
tells you everything to fix.

Scope note: refreshing ``.secrets.baseline`` is a write-mode step only. ``--check``
stays standard-library-only so the gate needs no ``pip install`` and runs in
seconds; baseline staleness is already caught on every PR by CI's ``security``
job, and (once ``release.yml`` calls ``ci.yml``) on the tagged commit too.
"""

from __future__ import annotations

import argparse
import datetime as _datetime
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from release_version import (
    ROOT,
    UNRELEASED_RE,
    changelog_path,
    changelog_versions,
    compare_url,
    has_content,
    hatch_version_path,
    link_refs,
    package_version,
    pyproject_dynamic_fields,
    pyproject_static_version,
    section_body,
    unreleased_url,
    version_from_tag,
    version_module_path,
)

#: Windows caps a whole command line at 32,767 characters. The tracked-file list
#: is ~12k today, so a single call is fine -- but the scan MUST be one call:
#: ``detect-secrets scan --baseline`` trims the baseline against the files it was
#: given, so chunking would silently drop every entry outside the last chunk.
_MAX_CMDLINE = 30_000


def _resolve_version_file(root: Path, explicit: str | None) -> Path:
    """Where ``__version__`` lives for this package.

    Prefers ``[tool.hatch.version].path`` so the script keeps working after the
    version becomes hatch-dynamic, and falls back to the historical location.
    """
    if explicit:
        return root / explicit
    declared = hatch_version_path(root)
    return root / declared if declared else version_module_path(root)


# --------------------------------------------------------------------------- #
# check mode
# --------------------------------------------------------------------------- #


def run_checks(
    version: str,
    *,
    root: Path,
    tag: str | None,
    tag_prefix: str,
    version_file: Path,
    check_changelog: bool,
) -> list[str]:
    """Every inconsistency found, as human-readable strings. Empty means good."""
    problems: list[str] = []

    if tag is not None:
        from_tag = version_from_tag(tag, prefix=tag_prefix)
        if from_tag is None:
            problems.append(
                f"tag {tag!r} is not a release tag: expected {tag_prefix}X.Y.Z "
                "(prereleases are not published)"
            )
        elif from_tag != version:
            problems.append(f"tag {tag!r} does not match version {version!r}")

    try:
        declared = package_version(root) if version_file == version_module_path(root) else None
        if declared is None:
            from release_version import VERSION_RE

            match = VERSION_RE.search(version_file.read_text(encoding="utf-8"))
            declared = match.group("version") if match else None
    except FileNotFoundError:
        problems.append(f"{version_file} does not exist")
        declared = None

    if declared is None:
        problems.append(f"no __version__ assignment found in {version_file}")
    elif declared != version:
        problems.append(f"{version_file.name} says {declared!r}, expected {version!r}")

    static = pyproject_static_version(root)
    if static is None:
        if "version" not in pyproject_dynamic_fields(root):
            problems.append(
                "pyproject.toml declares neither [project].version nor "
                'dynamic = ["version"]'
            )
        else:
            hatch_path = hatch_version_path(root)
            expected = version_file.relative_to(root).as_posix()
            if hatch_path is None:
                problems.append(
                    'pyproject.toml sets dynamic = ["version"] but no '
                    "[tool.hatch.version].path -- the build has no version source"
                )
            elif hatch_path != expected:
                problems.append(
                    f"[tool.hatch.version].path is {hatch_path!r}, expected {expected!r}"
                )
    elif static != version:
        problems.append(f"pyproject.toml [project].version is {static!r}, expected {version!r}")

    if check_changelog:
        problems.extend(_changelog_problems(version, root=root))

    return problems


def _changelog_problems(version: str, *, root: Path) -> list[str]:
    problems: list[str] = []
    path = changelog_path(root)
    text = path.read_text(encoding="utf-8")

    headers = [v for v, _ in changelog_versions(text)]
    count = headers.count(version)
    if count == 0:
        problems.append(
            f"CHANGELOG.md has no '## [{version}] - YYYY-MM-DD' section "
            "(the release notes are generated from it verbatim)"
        )
    elif count > 1:
        problems.append(f"CHANGELOG.md has {count} sections for {version}, expected exactly 1")
    elif not has_content(section_body(text, version)):
        problems.append(
            f"CHANGELOG.md's '## [{version}]' section is empty -- it would publish "
            "a GitHub Release with a blank body"
        )

    if not UNRELEASED_RE.search(text):
        problems.append("CHANGELOG.md has no '## [Unreleased]' header")

    refs = link_refs(text)
    if version not in refs:
        problems.append(f"CHANGELOG.md has no '[{version}]:' link-reference definition")
    elif not refs[version].rstrip("/").endswith(f"v{version}"):
        problems.append(
            f"CHANGELOG.md's '[{version}]:' link points at {refs[version]!r}, "
            f"which does not resolve to tag v{version}"
        )

    expected_unreleased = unreleased_url(version)
    if "Unreleased" not in refs:
        problems.append("CHANGELOG.md has no '[Unreleased]:' link-reference definition")
    elif refs["Unreleased"] != expected_unreleased:
        problems.append(
            f"CHANGELOG.md's '[Unreleased]:' link is {refs['Unreleased']!r}, "
            f"expected {expected_unreleased!r}"
        )

    return problems


# --------------------------------------------------------------------------- #
# write mode
# --------------------------------------------------------------------------- #


def bump_version_file(version_file: Path, version: str) -> None:
    from release_version import VERSION_RE

    text = version_file.read_text(encoding="utf-8")
    new_text, count = VERSION_RE.subn(f'__version__ = "{version}"', text, count=1)
    if count != 1:
        raise SystemExit(f"could not rewrite __version__ in {version_file}")
    version_file.write_text(new_text, encoding="utf-8", newline="\n")


def roll_changelog(root: Path, version: str, today: str) -> None:
    path = changelog_path(root)
    text = path.read_text(encoding="utf-8")

    matches = list(UNRELEASED_RE.finditer(text))
    if len(matches) != 1:
        raise SystemExit(
            f"expected exactly one '## [Unreleased]' header in CHANGELOG.md, found {len(matches)}"
        )

    previous = [v for v, _ in changelog_versions(text)]
    if version in previous:
        raise SystemExit(f"CHANGELOG.md already has a section for {version}")

    # Trailing "\n" so the dated header is followed by a blank line, matching
    # every existing section (the text after match.end() starts with the newline
    # that terminated the old "## [Unreleased]" line).
    match = matches[0]
    text = (
        f"{text[: match.start()]}## [Unreleased]\n\n"
        f"## [{version}] - {today}\n{text[match.end() :]}"
    )

    refs = link_refs(text)
    new_unreleased = f"[Unreleased]: {unreleased_url(version)}"
    # `previous[0]` is the newest dated section *before* this release, which is
    # not necessarily the numeric predecessor -- 0.7.0 followed 0.5.0 on PyPI.
    new_ref = f"[{version}]: {compare_url(previous[0], version)}" if previous else None

    lines = text.splitlines()
    if "Unreleased" in refs:
        lines = [new_unreleased if line.startswith("[Unreleased]:") else line for line in lines]
    else:
        anchor = next(
            (i for i, line in enumerate(lines) if line.startswith("[")),
            len(lines),
        )
        lines.insert(anchor, new_unreleased)

    if new_ref is not None:
        insert_at = next(i for i, line in enumerate(lines) if line.startswith("[Unreleased]:")) + 1
        lines.insert(insert_at, new_ref)

    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def refresh_secrets_baseline(root: Path) -> None:
    """Rescan the tracked tree into ``.secrets.baseline`` and stage the result.

    Editing CHANGELOG.md shifts the line numbers of the deliberately-fake
    credentials baselined in it, which fails CI's ``precommit`` and ``security``
    jobs. This is the step that kept being skipped -- partly because the command
    CONTRIBUTING.md documented piped filenames to stdin, where an argparse
    *positional* never saw them, so it scanned nothing and exited 0.
    """
    baseline = root / ".secrets.baseline"
    if not baseline.exists():
        print("no .secrets.baseline; skipping refresh")
        return

    listing = subprocess.run(
        ["git", "ls-files", "-z"], cwd=root, capture_output=True, text=True, check=True
    )
    files = [name for name in listing.stdout.split("\0") if name]
    budget = sum(len(name) + 3 for name in files)
    if budget > _MAX_CMDLINE:
        raise SystemExit(
            f"tracked-file list is {budget} chars, over the {_MAX_CMDLINE} command-line "
            "budget. Chunking is NOT a safe fix: `detect-secrets scan --baseline` trims "
            "the baseline against the files it is given, so a chunked run would drop "
            "every entry outside the final chunk."
        )

    result = subprocess.run(
        [sys.executable, "-m", "detect_secrets", "scan", "--baseline", str(baseline), *files],
        cwd=root,
    )
    if result.returncode != 0:
        raise SystemExit(f"detect-secrets scan failed with exit {result.returncode}")

    _normalise_baseline_separators(baseline)
    subprocess.run(["git", "add", "--", str(baseline)], cwd=root, check=True)
    print(f"refreshed and staged {baseline.name}")


def _normalise_baseline_separators(baseline: Path) -> None:
    """Rewrite ``results`` keys with POSIX separators.

    detect-secrets keys its results with ``os.sep``, so regenerating on Windows
    spells every path with backslashes. CI runs the same check on ubuntu, where
    ``git ls-files`` yields forward slashes -- a backslash-keyed baseline matches
    nothing there and every entry reads as a brand-new secret.
    """
    data = json.loads(baseline.read_text(encoding="utf-8"))
    results = {key.replace("\\", "/"): value for key, value in data["results"].items()}
    data["results"] = {key: results[key] for key in sorted(results)}
    baseline.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8", newline="\n")


# --------------------------------------------------------------------------- #


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("version", nargs="?", help="the X.Y.Z being released")
    parser.add_argument("--check", action="store_true", help="verify only; never writes")
    parser.add_argument("--tag", help="the release tag, e.g. v0.8.0 (implies --check semantics)")
    parser.add_argument("--tag-prefix", default="v", help="tag prefix (ks-v for the kitchen sink)")
    parser.add_argument("--package", default=".", help="package root, relative to the repo root")
    parser.add_argument("--version-file", help="override where __version__ is declared")
    parser.add_argument(
        "--no-changelog",
        action="store_true",
        help="skip CHANGELOG checks (for packages that don't keep one)",
    )
    args = parser.parse_args(argv)

    root = (ROOT / args.package).resolve()
    version = args.version
    if version is None and args.tag:
        version = version_from_tag(args.tag, prefix=args.tag_prefix)
        if version is None:
            print(
                f"::error::tag {args.tag!r} is not a release tag: expected "
                f"{args.tag_prefix}X.Y.Z (prereleases are not published)"
            )
            return 1
    if version is None:
        parser.error("give a version, or a --tag to derive it from")

    version_file = _resolve_version_file(root, args.version_file)

    if args.check or args.tag:
        problems = run_checks(
            version,
            root=root,
            tag=args.tag,
            tag_prefix=args.tag_prefix,
            version_file=version_file,
            check_changelog=not args.no_changelog,
        )
        for problem in problems:
            print(f"::error::{problem}")
        if problems:
            print(f"\n{len(problems)} problem(s) -- release {version} is not ready.")
            return 1
        checked = "tag, version file, pyproject"
        if not args.no_changelog:
            checked += ", CHANGELOG"
        print(f"release {version} is consistent: {checked}.")
        return 0

    today = _datetime.date.today().isoformat()
    bump_version_file(version_file, version)
    print(f"bumped {version_file.relative_to(ROOT).as_posix()} to {version}")
    if not args.no_changelog:
        roll_changelog(root, version, today)
        print(f"rolled CHANGELOG.md: [Unreleased] -> [{version}] - {today}")
    refresh_secrets_baseline(root)

    print(
        f"\nPrepared {version}. Next:\n"
        f"  1. review the diff (git diff)\n"
        f"  2. commit and merge to main\n"
        f"  3. git tag {args.tag_prefix}{version} && git push origin {args.tag_prefix}{version}\n"
        f"\nThe tag push is what publishes. Nothing here tagged or pushed anything."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
