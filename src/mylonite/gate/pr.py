"""Branch + commit + PR for the gating artifacts. The only outward/git module.

Isolated behind ``--open-pr``: by default it commits to a branch and PRINTS the
exact command; only ``open_pr=True`` pushes and opens the PR via ``gh``.
"""

from __future__ import annotations

import shlex
import shutil
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

Runner = Callable[..., Any]


class GatePrError(RuntimeError):
    """A git or gh step in the gate PR flow failed."""


def _default_run(cmd: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, text=True, capture_output=True, check=False, **kwargs)


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
    if getattr(cp, "returncode", 0) != 0:
        stderr = (getattr(cp, "stderr", "") or "").strip()
        raise GatePrError(f"git {' '.join(args)} failed (rc={cp.returncode}): {stderr}")
    return cp


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
    _git(["checkout", "-b", branch], cwd=cwd, _run=_run)
    rels = [str(p.relative_to(cwd)) for p in paths.all_paths()]
    _git(["add", *rels], cwd=cwd, _run=_run)
    _git(["commit", "-m", pr_title], cwd=cwd, _run=_run)

    if not open_pr or not gh_available(_run=_run):
        body_path = paths.gate_dir / "PR_BODY.md"
        body_path.write_text(pr_body, encoding="utf-8")
        rel_body = body_path.relative_to(cwd)
        gh_cmd = (
            f"gh pr create --base {base} --head {branch} "
            f"--title {shlex.quote(pr_title)} --body-file {rel_body}"
        )
        print(
            f"\nGate artifacts committed to branch '{branch}'.\n"
            f"To open the gating PR, run:\n  git push -u origin {branch}\n  {gh_cmd}\n"
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
    if getattr(cp, "returncode", 0) != 0:
        stderr = (getattr(cp, "stderr", "") or "").strip()
        raise GatePrError(f"gh pr create failed (rc={cp.returncode}): {stderr}")
    url = (getattr(cp, "stdout", "") or "").strip() or None
    return PrResult(branch=branch, opened=True, pr_url=url)
