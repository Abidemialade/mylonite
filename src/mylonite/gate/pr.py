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
    #: Exact paths ``git add`` should stage (Critical fix, round 1 of review):
    #: each KEPT finding's directory, ``PR_BODY.md`` and ``target.yaml``copies
    #: — never the bare ``gate_dir`` swept whole, which used to sweep in a
    #: REJECTED finding's un-validated test too (a mixed-verdict multi-finding
    #: run wrote every finding under ``gate_dir``, and `git add gate_dir`
    #: cannot distinguish a kept subdirectory from a rejected one).
    #: ``None`` (the default) falls back to the historical single-path sweep
    #: of ``gate_dir`` — every existing single-finding caller/test keeps
    #: working unchanged; only ``gate/wiring.py``'s multi-finding-aware
    #: ``open_pr_fn`` passes an explicit list.
    add_paths: list[Path] | None = None

    def all_paths(self) -> list[Path]:
        base = self.add_paths if self.add_paths is not None else [self.gate_dir]
        return [*base, *self.workflow_files]


@dataclass
class PrResult:
    branch: str
    opened: bool
    pr_url: str | None = None
    printed_command: str | None = None


def resolve_repo_root(*, cwd: Path | None = None, _run: Runner = _default_run) -> Path:
    """Return the git repository root that anchors the gate output directory,
    the scaffolded workflows, and the commit/PR flow (#203).

    ``gate`` used to take ``Path.cwd()`` as the repo root outright, with no
    upward search for ``.git`` — run from a subdirectory, ``--open-pr``
    committed the gate output under THAT subdirectory instead of the repo
    root, and ``--workflows`` would have put the scaffolded files at
    ``<subdir>/.github/workflows/``, where GitHub never looks for them.

    Uses ``git rev-parse --show-toplevel`` (the same ``_run`` seam every other
    git call in this module goes through) rather than a hand-rolled upward
    walk for ``.git``, so worktrees/submodules resolve exactly the way `git`
    itself does. Raises :class:`GatePrError` — the same named-error type every
    other failure in this module raises — when ``cwd`` is not inside a git
    repository at all, so the CLI's existing ``except GatePrError`` handler
    reports it as a clean, actionable error on exit code 8 instead of a bare
    traceback or (worse) silently writing to the wrong place.
    """
    cwd = cwd if cwd is not None else Path.cwd()
    cp = _run(["git", "rev-parse", "--show-toplevel"], cwd=str(cwd))
    out = (getattr(cp, "stdout", "") or "").strip()
    if getattr(cp, "returncode", 1) != 0 or not out:
        stderr = redact((getattr(cp, "stderr", "") or "").strip())
        raise GatePrError(
            f"'{cwd}' is not inside a git repository (git rev-parse --show-toplevel "
            f"failed{f': {stderr}' if stderr else ''}). `gate` resolves its output "
            "directory and workflows relative to the repository root — run it from "
            "inside a git repo, or `cd` to the repo's top level first."
        )
    return Path(out)


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

    # Write PR_BODY.md before any git command touches it (round-1 review fix):
    # GatePaths.add_paths now names it as an EXPLICIT pathspec rather than
    # relying on a directory-wide `git add gate_dir` (which tolerated the file
    # not existing yet). The auto `--open-pr` + `gh` path below used to never
    # write it to disk at all -- the body went straight to `gh pr create
    # --body` -- so `git add`ing its explicit path would have failed outright
    # on a missing pathspec. Writing it unconditionally, up front, means every
    # path (print, degrade, full auto) commits the same PR_BODY.md.
    body_path.write_text(pr_body, encoding="utf-8")

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
        # remaining two steps. body_path was already written (and committed,
        # since it's in `rels`) above.
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
