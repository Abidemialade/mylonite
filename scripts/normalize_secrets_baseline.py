"""Normalise `.secrets.baseline` so it is platform-independent and non-volatile.

Two kinds of churn are removed here, both of them metadata that carries no
security signal.

**Path separators.** `detect-secrets` records each finding under the path
separator of whichever OS regenerated the baseline. A contributor on Windows
produces `docs\\quarry.md` where CI (ubuntu) expects `docs/quarry.md`. The
audited entry then no longer matches the file being scanned, every finding in it
reads as new and unaudited, and the `precommit` job fails on a change that
touched none of those files.

**Line numbers.** `detect-secrets` rewrites the baseline whenever a recorded
finding's line number shifts — which *any* edit above it causes. With 50 audited
findings across 17 files (13 in `tests/test_cli.py`, 12 in `tests/test_redaction.py`,
2 in `CHANGELOG.md`), almost every commit moved at least one, and every release
moved the `CHANGELOG.md` pair. Because pre-commit fails a hook that modifies a
tracked file *regardless of its exit code*
(`pre_commit.commands.run._run_single_hook`: ``if retcode or files_modified``),
that rewrite failed the commit and forced a `git add` and a second attempt —
every time, on a change unrelated to any secret.

Storing `line_number: 0` stops it at the source. `detect-secrets` treats a zero
line number as "not provided" and skips the comparison entirely
(`SecretsCollection.__eq__`: *"If line numbers are not provided (for either one),
then don't compare line numbers"*), so `should_update_baseline` returns False and
the baseline is left alone. This is the library's own escape hatch, not a trick
played on it.

**What this does not weaken.** A genuinely new secret is caught before any of
this: `pre_commit_hook.main` returns 1 from ``if new_secrets`` — a set difference
keyed on `(hashed_secret, type)` — and never reaches the baseline-update branch.
Only the bookkeeping refresh is suppressed. The cost is that the baseline no
longer records *where* a finding was, so `detect-secrets audit` cannot jump
straight to it; grep for the file instead.

This runs as a `local` pre-commit hook immediately after `detect-secrets`, so the
baseline is normalised before it is staged. Idempotent: once normalised there is
nothing to change and the file is left byte-identical.

Exit codes follow the pre-commit convention: 0 = unchanged, 1 = rewritten (so
the commit is retried with the corrected file).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

BASELINE = Path(".secrets.baseline")


def normalise(raw: str) -> str:
    data = json.loads(raw)
    results = data.get("results", {})
    data["results"] = {
        path.replace("\\", "/"): [
            {
                **entry,
                "filename": str(entry.get("filename", "")).replace("\\", "/"),
                # 0 == "not provided". See the module docstring: this is what
                # stops an unrelated edit from rewriting the baseline.
                "line_number": 0,
            }
            for entry in findings
        ]
        for path, findings in results.items()
    }
    # Sort so two machines that audit the same set produce the same bytes.
    data["results"] = dict(sorted(data["results"].items()))
    # `generated_at` churns on every run and carries no signal; detect-secrets
    # tolerates its absence and the baseline is version-controlled anyway.
    data.pop("generated_at", None)
    return json.dumps(data, indent=2) + "\n"


def main() -> int:
    if not BASELINE.is_file():
        return 0
    before = BASELINE.read_text(encoding="utf-8")
    after = normalise(before)
    if after == before:
        return 0
    BASELINE.write_text(after, encoding="utf-8")
    print(f"{BASELINE}: normalised to POSIX paths")
    return 1


if __name__ == "__main__":
    sys.exit(main())
