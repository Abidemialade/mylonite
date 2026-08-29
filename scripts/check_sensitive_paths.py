#!/usr/bin/env python3
"""Require a conscious maintainer decision on PRs that touch the trust base.

WHY THIS EXISTS
---------------
``.github/CODEOWNERS`` names a reviewer for every file, but branch protection
sets ``required_approving_review_count: 0`` and ``require_code_owner_reviews:
false``, so nothing enforces it. CODEOWNERS is documentation. Raising the review
count is the textbook fix and it does not work here: ``enforce_admins`` is on and
there is one maintainer, who cannot approve their own pull request — the repo
would be unmergeable by its only maintainer.

This closes the gap from the other side. Most files in this repository are
ordinary: a bad change to them gets caught by tests, review, or a user. A small
set is different, because a malicious change there subverts the machinery that
would otherwise catch it:

- workflows and composite actions decide what runs in CI and with which token;
- ``.pre-commit-config.yaml`` decides what the local hooks check;
- ``pyproject.toml`` declares entry points, so it decides which code the plugin
  loader imports at runtime;
- ``scripts/check_*.py`` are the guards themselves;
- ``reference_targets/`` is the deliberately-vulnerable server, where insecure
  code is expected and a backdoor is therefore cheapest to disguise;
- ``.secrets.baseline`` decides which strings the secret scanner ignores.

A pull request touching any of those fails this check until a maintainer applies
the override label. The label is the point: it is a deliberate, timestamped,
attributable act recorded on the pull request, rather than a review that never
happened because nothing required one.

WHY A LABEL AND NOT A BLOCK
---------------------------
An outside contributor may have a perfectly good reason to touch a workflow.
Refusing outright would make those contributions impossible; passing silently
would make the check pointless. A label lets the maintainer say "I read this
specific diff" in a way that survives in the pull request record — and, because
only users with write access can apply labels, it cannot be self-granted by the
contributor whose diff is under review.
"""

from __future__ import annotations

import argparse
import fnmatch
import subprocess
import sys

#: Paths whose modification subverts a control rather than merely changing code.
#: Ordered roughly by how directly a change grants execution.
SENSITIVE_PATTERNS: tuple[tuple[str, str], ...] = (
    (".github/workflows/*", "decides what runs in CI, and with which token permissions"),
    (".github/actions/**", "composite action code executed by CI"),
    ("gate-action/**", "the composite action downstream users run in THEIR CI"),
    (".pre-commit-config.yaml", "decides which checks run on a contributor's machine"),
    ("pyproject.toml", "declares entry points, so it decides what the plugin loader imports"),
    ("scripts/check_*.py", "a repository guard; weakening one hides everything it checks"),
    (".secrets.baseline", "decides which strings the secret scanner is allowed to ignore"),
    (
        "reference_targets/**",
        "the deliberately-vulnerable target, where a backdoor is cheapest to disguise",
    ),
)

#: Applying it requires write access, so a contributor cannot self-clear.
OVERRIDE_LABEL = "reviewed:sensitive-paths"


def changed_files(base_ref: str) -> list[str]:
    """Files this branch changes relative to ``base_ref``.

    Uses the three-dot form, so the answer is what the pull request adds rather
    than everything that landed on the base branch meanwhile.
    """
    try:
        out = subprocess.run(
            ["git", "diff", "--name-only", f"{base_ref}...HEAD"],
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"error: could not diff against {base_ref}: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    return [line.strip() for line in out.stdout.splitlines() if line.strip()]


def classify(paths: list[str]) -> list[tuple[str, str]]:
    """Sensitive paths among ``paths``, each with the reason it is sensitive."""
    hits: list[tuple[str, str]] = []
    for path in sorted(paths):
        for pattern, reason in SENSITIVE_PATTERNS:
            # fnmatch treats '*' as matching '/', so '.github/workflows/*'
            # already covers nested files; '**' is spelled for the reader.
            if fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(path, pattern.replace("**", "*")):
                hits.append((path, reason))
                break
    return hits


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-ref", default="origin/main", help="branch this PR targets")
    parser.add_argument(
        "--labels",
        default="",
        help="comma- or newline-separated labels currently on the pull request",
    )
    args = parser.parse_args()

    hits = classify(changed_files(args.base_ref))
    if not hits:
        print("No trust-base files touched.")
        return 0

    labels = {label.strip() for chunk in args.labels.split(",") for label in chunk.splitlines()}
    width = max(len(path) for path, _ in hits)
    listing = "\n".join(f"  {path.ljust(width)}  {reason}" for path, reason in hits)

    if OVERRIDE_LABEL in labels:
        print(f"Trust-base files touched, cleared by the {OVERRIDE_LABEL!r} label:\n{listing}")
        return 0

    print(
        f"This pull request modifies {len(hits)} file(s) that control what the "
        f"project's own checks do:\n\n{listing}\n\n"
        f"That is allowed, but it must be a decision rather than an oversight -- a "
        f"change here can disable the machinery that would catch the rest of the "
        f"diff. A maintainer should read these files specifically, then apply the "
        f"{OVERRIDE_LABEL!r} label to clear this check.\n\n"
        f"Applying the label needs write access, so it cannot be self-granted.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
