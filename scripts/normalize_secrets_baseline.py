"""Normalise `.secrets.baseline` to POSIX paths so it is platform-independent.

`detect-secrets` records each finding under the path separator of whichever OS
regenerated the baseline. It rewrites the baseline whenever line numbers shift —
which any edit to a tracked file can cause — so a contributor on Windows
produces `docs\\quarry.md` where CI (ubuntu) expects `docs/quarry.md`. The
audited entry then no longer matches the file being scanned, every finding in it
reads as new and unaudited, and the `precommit` job fails on a change that
touched none of those files.

This runs as a `local` pre-commit hook immediately after `detect-secrets`, so the
baseline is normalised before it is staged. Idempotent: on a POSIX machine there
is nothing to change and the file is left byte-identical.

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
            {**entry, "filename": str(entry.get("filename", "")).replace("\\", "/")}
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
