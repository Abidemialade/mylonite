"""The ruff pin in `pyproject.toml` and the ruff-pre-commit `rev` must agree.

`.pre-commit-config.yaml` already says so in a comment:

    Keep in lockstep with the `ruff==` pin in pyproject's [dev] extra. CI runs
    both paths -- the `lint` job installs ruff from that pin, the `precommit`
    job runs this hook -- so a drift between them lets one job pass while the
    other fails on the same file.

Nothing enforced it, and it drifted: `pyproject.toml` reached `ruff==0.16.5`
while the hook stayed at `v0.16.4`, because a dependency bump touches the
Python pin and never the hook `rev`. Both CI jobs stayed green, since each was
internally consistent with the version it installed — the drift is only visible
when a formatting rule changes between the two releases, and then it surfaces as
one job disagreeing with the other about an unmodified file.

An invariant recorded only in a comment is discipline, and this repository has
already learned that discipline is the thing that fails. This is the gate.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_PYPROJECT = _REPO_ROOT / "pyproject.toml"
_PRE_COMMIT = _REPO_ROOT / ".pre-commit-config.yaml"

#: `- repo: https://github.com/astral-sh/ruff-pre-commit` followed, within the
#: same mapping, by `rev: vX.Y.Z`. Matched textually rather than by parsing YAML
#: so the test needs no yaml dependency, matching this file's stdlib-only
#: siblings (`test_typing_marker.py`, `check_verification_freshness.py`).
_HOOK_REV_RE = re.compile(
    r"-\s*repo:\s*https://github\.com/astral-sh/ruff-pre-commit\s*\n\s*rev:\s*v(?P<version>\d+\.\d+\.\d+)"
)
_PIN_RE = re.compile(r'"ruff==(?P<version>\d+\.\d+\.\d+)"')


def _pyproject_ruff_pin() -> str:
    """The exact ruff version the `[dev]` extra installs."""
    data = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    dev: list[str] = data["project"]["optional-dependencies"]["dev"]
    pins = [spec for spec in dev if spec.startswith("ruff==")]

    assert len(pins) == 1, (
        f"expected exactly one `ruff==` pin in pyproject's [dev] extra, found {pins}. "
        "The `lint` CI job installs ruff from this pin; more than one (or none) "
        "makes what CI runs ambiguous."
    )
    match = _PIN_RE.fullmatch(f'"{pins[0]}"')
    assert match is not None, (
        f"ruff must be pinned to an exact X.Y.Z version, got {pins[0]!r}. A range "
        "would let two CI runs of the same commit format differently."
    )
    return match.group("version")


def _pre_commit_hook_rev() -> str:
    """The ruff-pre-commit `rev` the `precommit` CI job runs."""
    text = _PRE_COMMIT.read_text(encoding="utf-8")
    matches = _HOOK_REV_RE.findall(text)

    assert len(matches) == 1, (
        f"expected exactly one ruff-pre-commit repo entry with a `rev: vX.Y.Z`, "
        f"found {matches}. Without one, this test cannot tell what the "
        f"`precommit` job actually runs."
    )
    return matches[0]


def test_the_ruff_pin_and_the_hook_rev_are_in_lockstep() -> None:
    """The assertion that would have caught the drift when it happened.

    A dependency bump that raises the Python pin must raise the hook `rev` in
    the same commit, and vice versa.
    """
    pin = _pyproject_ruff_pin()
    rev = _pre_commit_hook_rev()

    assert pin == rev, (
        f"ruff is pinned to {pin} in pyproject's [dev] extra but the "
        f"ruff-pre-commit hook is at v{rev}. CI's `lint` job installs the "
        f"former and its `precommit` job runs the latter, so the two jobs can "
        f"disagree about an unmodified file. Bump both in the same commit."
    )


def test_the_hook_rev_is_tag_shaped() -> None:
    """`ruff-pre-commit` publishes `vX.Y.Z` tags. A bare `X.Y.Z`, a branch name
    or a moving tag would silently change what `precommit` enforces between two
    runs of the same commit."""
    text = _PRE_COMMIT.read_text(encoding="utf-8")

    assert _HOOK_REV_RE.search(text) is not None, (
        "the ruff-pre-commit entry's `rev` is not a `vX.Y.Z` tag. Pin it to an "
        "exact released tag so a given commit always formats identically."
    )
