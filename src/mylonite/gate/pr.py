"""Branch + commit + PR for the gating artifacts. The only outward/git module.

Every git subprocess in here is gated on ``open_pr``. With ``open_pr=False``
NOTHING runs: the caller's repository is untouched and the full command sequence
(checkout / add / commit / push / gh) is printed for the operator to run by
hand. With ``open_pr=True`` the branch is created, the artifacts committed, and
the PR opened via ``gh`` -- degrading to printing the last two commands when
``gh`` is missing or unauthenticated.
"""

from __future__ import annotations

import shlex
import shutil
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mylonite._cli_io import echo, echo_err
from mylonite._redaction import redact

Runner = Callable[..., Any]


class GatePrError(RuntimeError):
    """A git or gh step in the gate PR flow failed."""


def _default_run(cmd: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    # cmd is always a fixed argv list built by this module (git/gh subcommands
    # plus already-validated arguments); shell=False and nothing here is
    # shell-interpolated, so this is safe by construction.
    return subprocess.run(cmd, text=True, capture_output=True, check=False, **kwargs)  # noqa: S603


@dataclass
class GatePaths:
    repo_root: Path
    gate_dir: Path
    workflow_files: list[Path] = field(default_factory=list)

    def all_paths(self) -> list[Path]:
        return [self.gate_dir, *self.workflow_files]


@dataclass
class PrResult:
    branch: str
    opened: bool
    pr_url: str | None = None
    printed_command: str | None = None


def gh_available(_run: Runner = _default_run) -> bool:
    """True iff the gh CLI is installed AND authenticated."""
    if shutil.which("gh") is None:
        return False
    cp = _run(["gh", "auth", "status"])
    return bool(getattr(cp, "returncode", 1) == 0)


def _git(args: list[str], *, cwd: Path, _run: Runner) -> Any:
    cp = _run(["git", *args], cwd=str(cwd))
    # Fail CLOSED: a runner that doesn't (or can't) report a returncode is
    # treated as a failure, matching gh_available's default (DCR-0018 cli-config).
    if getattr(cp, "returncode", 1) != 0:
        stderr = redact((getattr(cp, "stderr", "") or "").strip())
        raise GatePrError(f"git {' '.join(args)} failed (rc={cp.returncode}): {stderr}")
    return cp


def _relative(path: Path, cwd: Path) -> Path:
    """Resolve ``path`` relative to ``cwd`` (the repo root), or as-is if already relative."""
    return path.relative_to(cwd) if path.is_absolute() else path


def _rollback(*, cwd: Path, original_branch: str, branch: str, _run: Runner) -> None:
    """Best-effort: restore ``original_branch`` and delete the half-created ``branch``.

    Uses raw ``_run`` (not :func:`_git`) so a failure HERE never raises and masks
    the original ``GatePrError`` that triggered the rollback. But a silently
    swallowed rollback failure leaves the repo in a half-rolled-back state with
    zero operator-visible signal — e.g. a dirty tree blocking the ``checkout``
    back — which can reproduce the exact "branch already exists" retry failure
    this rollback exists to prevent, with no diagnostic pointing at why. So each
    step's returncode is checked and a warning (never a raise) is emitted on
    failure, stderr redacted the same way :func:`_git` already does.
    """
    checkout_cp = _run(["git", "checkout", original_branch], cwd=str(cwd))
    if getattr(checkout_cp, "returncode", 1) != 0:
        stderr = redact((getattr(checkout_cp, "stderr", "") or "").strip())
        echo_err(
            f"warning: rollback failed to check out '{original_branch}' after a gate PR "
            f"error — the repo may still be on branch '{branch}': {stderr}"
        )

    delete_cp = _run(["git", "branch", "-D", branch], cwd=str(cwd))
    if getattr(delete_cp, "returncode", 1) != 0:
        stderr = redact((getattr(delete_cp, "stderr", "") or "").strip())
        echo_err(
            f"warning: rollback failed to delete half-created branch '{branch}' after a "
            f"gate PR error — retrying may fail with 'branch already exists': {stderr}"
        )


def open_or_print_pr(
    paths: GatePaths,
    *,
    branch: str,
    pr_title: str,
    pr_body: str,
    open_pr: bool,
    base: str = "main",
    _run: Runner = _default_run,
) -> PrResult:
    """Commit the gate artifacts to ``branch``; open the PR iff ``open_pr`` and gh works."""
    cwd = paths.repo_root
    body_path = paths.gate_dir / "PR_BODY.md"

    # Resolve every path BEFORE anything destructive runs, so an out-of-tree
    # gate_dir raises GatePrError here instead of a bare ValueError AFTER the
    # branch switch (DCR-0016). Nothing below this block is a git subprocess.
    try:
        rels = [str(_relative(p, cwd)) for p in paths.all_paths()]
        rel_body = _relative(body_path, cwd)
    except ValueError as exc:
        raise GatePrError(f"gate paths must live inside the repo root {cwd}: {exc}") from exc

    gh_cmd = (
        f"gh pr create --base {shlex.quote(base)} --head {shlex.quote(branch)} "
        f"--title {shlex.quote(pr_title)} --body-file {shlex.quote(str(rel_body))}"
    )

    if not open_pr:
        # Committing to the operator's repository is part of the PR flow, so it
        # is gated on the flag that REQUESTS the PR flow. This used to run
        # unconditionally, above the old `if not open_pr` check, so a user
        # running plain `mylonite gate` to see what it finds got a branch and a
        # commit they never asked for. Read-only is the default; the artifacts
        # are on disk and the exact command sequence is printed instead.
        body_path.write_text(pr_body, encoding="utf-8")
        add_cmd = " ".join(shlex.quote(str(r)) for r in rels)
        manual = (
            f"git checkout -b {shlex.quote(branch)}\n"
            f"  git add {add_cmd}\n"
            f"  git commit -m {shlex.quote(pr_title)}\n"
            f"  git push -u origin {shlex.quote(branch)}\n"
            f"  {gh_cmd}"
        )
        echo(
            f"\nGate artifacts written to '{paths.gate_dir}'. "
            f"Your repository was not modified.\n"
            f"To commit them and open the gating PR, run:\n"
            f"  {manual}\n"
            f"Or re-run with --open-pr to do all of it automatically.\n"
        )
        return PrResult(branch=branch, opened=False, printed_command=manual)

    # Capture whatever branch was actually checked out BEFORE doing anything
    # destructive, so a mid-sequence failure can restore exactly that — not a
    # hardcoded assumption (``base`` is the PR's merge target, which may differ
    # from the branch the operator actually had checked out).
    original_branch = _git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=cwd, _run=_run).stdout.strip()

    try:
        _git(["checkout", "-b", branch], cwd=cwd, _run=_run)
        _git(["add", *rels], cwd=cwd, _run=_run)
        _git(["commit", "-m", pr_title], cwd=cwd, _run=_run)
    except GatePrError:
        # Best-effort rollback: leave the repo back on the branch it started
        # on and delete the half-created branch so a retry with the same
        # deterministic branch name doesn't immediately fail (DCR-0017). Never
        # raises — a rollback-step failure is warned about, not raised, so it
        # can't mask the original error re-raised below.
        _rollback(cwd=cwd, original_branch=original_branch, branch=branch, _run=_run)
        raise

    if not gh_available(_run=_run):
        # The operator asked for the PR flow, so the commit above is what they
        # wanted; only the gh half is unavailable. Degrade to printing the
        # remaining two steps.
        body_path.write_text(pr_body, encoding="utf-8")
        echo(
            f"\nGate artifacts committed to branch '{branch}'.\n"
            f"To open the gating PR, run:\n"
            f"  git push -u origin {shlex.quote(branch)}\n  {gh_cmd}\n"
        )
        return PrResult(branch=branch, opened=False, printed_command=gh_cmd)

    _git(["push", "-u", "origin", branch], cwd=cwd, _run=_run)
    cp = _run(
        [
            "gh",
            "pr",
            "create",
            "--base",
            base,
            "--head",
            branch,
            "--title",
            pr_title,
            "--body",
            pr_body,
        ],
        cwd=str(cwd),
    )
    if getattr(cp, "returncode", 1) != 0:
        stderr = redact((getattr(cp, "stderr", "") or "").strip())
        raise GatePrError(f"gh pr create failed (rc={cp.returncode}): {stderr}")
    url = (getattr(cp, "stdout", "") or "").strip() or None
    return PrResult(branch=branch, opened=True, pr_url=url)
