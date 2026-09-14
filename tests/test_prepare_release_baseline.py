"""`prepare_release` must stage a baseline the pre-commit hook leaves alone.

Issue #137. The release flow refreshed `.secrets.baseline` and normalised it with
its own partial copy of the logic — path separators only — while the
`normalize-secrets-baseline` hook also zeroes `line_number` and drops
`generated_at`. pre-commit fails any hook that modifies a tracked file
regardless of exit code, so the release commit aborted every time. The abort is
invisible when the commit output is piped: the only symptom is that `HEAD` did
not move, which is how it got through the 0.9.0 release twice.

The invariant these pin is a fixed point: whatever `prepare_release` writes, the
hook must report unchanged.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from normalize_secrets_baseline import normalise
from scripts import prepare_release

#: A baseline in the exact shape `detect-secrets scan` leaves on Windows: a
#: backslash-keyed result, a real line number, and a `generated_at` stamp.
_RAW_BASELINE = {
    "version": "1.5.0",
    "generated_at": "2026-09-14T00:00:00Z",
    "results": {
        "src\\mylonite\\thing.py": [
            {
                "type": "Base64 High Entropy String",
                "filename": "src\\mylonite\\thing.py",
                "hashed_secret": "0" * 40,
                "is_verified": False,
                "line_number": 42,
            }
        ],
        "CHANGELOG.md": [
            {
                "type": "Secret Keyword",
                "filename": "CHANGELOG.md",
                "hashed_secret": "1" * 40,
                "is_verified": False,
                "line_number": 7,
            }
        ],
    },
}


def _write_raw(tmp_path: Path) -> Path:
    baseline = tmp_path / ".secrets.baseline"
    baseline.write_text(json.dumps(_RAW_BASELINE, indent=2) + "\n", encoding="utf-8")
    return baseline


def test_what_prepare_release_writes_is_the_hooks_fixed_point(tmp_path: Path) -> None:
    """THE test. Normalising again must be a no-op — that is precisely the
    condition under which the pre-commit hook reports "unchanged" and the
    release commit is allowed to proceed."""
    baseline = _write_raw(tmp_path)

    prepare_release._normalise_baseline(baseline)
    staged = baseline.read_text(encoding="utf-8")

    assert normalise(staged) == staged, (
        "the hook would rewrite what prepare_release staged, which aborts the "
        "release commit (issue #137)"
    )


def test_line_numbers_are_zeroed(tmp_path: Path) -> None:
    """The half the old partial copy missed. A real line number makes an
    unrelated edit above it churn the baseline."""
    baseline = _write_raw(tmp_path)

    prepare_release._normalise_baseline(baseline)
    data = json.loads(baseline.read_text(encoding="utf-8"))

    assert [e["line_number"] for findings in data["results"].values() for e in findings] == [0, 0]


def test_generated_at_is_dropped(tmp_path: Path) -> None:
    """The other half it missed: a timestamp that churns on every run."""
    baseline = _write_raw(tmp_path)

    prepare_release._normalise_baseline(baseline)

    assert "generated_at" not in json.loads(baseline.read_text(encoding="utf-8"))


def test_paths_are_posix_and_sorted(tmp_path: Path) -> None:
    """The half it did handle, kept: a backslash-keyed baseline matches nothing
    on the ubuntu runner, so every entry reads as a brand-new secret."""
    baseline = _write_raw(tmp_path)

    prepare_release._normalise_baseline(baseline)
    data = json.loads(baseline.read_text(encoding="utf-8"))

    keys = list(data["results"])
    assert keys == sorted(keys)
    assert all("\\" not in key for key in keys)
    assert all(
        "\\" not in entry["filename"] for findings in data["results"].values() for entry in findings
    )


def test_there_is_only_one_normaliser(tmp_path: Path) -> None:
    """The duplication was the bug. If a second private copy reappears in the
    release path, the two will drift again exactly as they did before."""
    source = (Path(__file__).resolve().parent.parent / "scripts" / "prepare_release.py").read_text(
        encoding="utf-8"
    )

    assert "from normalize_secrets_baseline import normalise" in source
    assert "_normalise_baseline_separators" not in source, (
        "the partial separators-only normaliser is back; delegate to the hook's "
        "own normalise() instead"
    )
