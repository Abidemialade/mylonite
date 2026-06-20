"""Live GitHub check-run annotations from localized findings (R4).

In-PR, on-the-line findings are fixed far faster than ones described in a PR body.
GitHub renders annotations only against a real file + line in the PR's head commit,
so this posts them **only for loci that map to a source line** — today, a
system-prompt finding when the prompt is a committed file. A remote MCP tool has no
source line in the scanned repo, so those findings are localized in the PR body and
the SARIF logical location instead (see ``localize`` / ``report.sarif``); they are
never silently dropped, just surfaced where GitHub can actually render them.

The poster is best-effort: creating a check run needs a token with ``checks:write``,
which a plain ``gh`` login may lack — a failure is swallowed so it never breaks the
gate PR flow. Pure payload assembly is unit-tested; the ``gh`` call is smoke-tested.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mylonite.gate.localize import localize

#: GitHub's per-request annotation cap (the rest stay in the PR body).
_MAX_ANNOTATIONS = 50

Runner = Callable[..., Any]


@dataclass(frozen=True)
class Annotation:
    """One GitHub check annotation: a repo file line + a message."""

    path: str
    start_line: int
    message: str
    level: str = "warning"  # GitHub annotation_level: notice | warning | failure


def annotations_from_findings(
    findings: Sequence[tuple[Any, Any | None]],
    *,
    system_prompt: str | None = None,
    system_prompt_text: str | None = None,
) -> list[Annotation]:
    """Build annotations for the findings whose locus maps to a real repo file line.

    ``system_prompt`` is the repo-relative PATH of the prompt file (if the target's
    prompt is a committed file); ``system_prompt_text`` is its contents (so the line
    can be localized). Only system-prompt findings with both qualify — every other
    locus (a remote tool description / handler / returned-content path) has no source
    line and is surfaced in the PR body + SARIF instead.
    """
    out: list[Annotation] = []
    for exploit, _report in findings:
        loc = localize(exploit, system_prompt=system_prompt_text)
        if loc.kind == "system_prompt" and system_prompt and loc.line:
            out.append(
                Annotation(
                    path=system_prompt,
                    start_line=loc.line,
                    message=f"Mylonite: {loc.why}",
                )
            )
    return out


def check_run_payload(
    *, head_sha: str, annotations: Sequence[Annotation], title: str, summary: str
) -> dict[str, Any]:
    """The body for ``POST /repos/{owner}/{repo}/check-runs`` (GitHub Checks API)."""
    capped = list(annotations)[:_MAX_ANNOTATIONS]
    return {
        "name": "mylonite-ai-security",
        "head_sha": head_sha,
        "status": "completed",
        "conclusion": "neutral" if capped else "success",
        "output": {
            "title": title,
            "summary": summary,
            "annotations": [
                {
                    "path": a.path,
                    "start_line": a.start_line,
                    "end_line": a.start_line,
                    "annotation_level": a.level,
                    "message": a.message,
                }
                for a in capped
            ],
        },
    }


def post_check_run(repo_root: Path, payload: dict[str, Any], *, _run: Runner) -> str | None:
    """Create the check run via ``gh api`` (live-only). Returns its URL, or ``None``.

    No-op when the payload carries no annotations. Best-effort: any ``gh`` failure
    (e.g. a token without ``checks:write``) is swallowed — the loci already ride in
    the PR body and SARIF, so the gate must not fail on a missing annotation scope.
    """
    if not payload.get("output", {}).get("annotations"):
        return None
    body_file = repo_root / ".mylonite" / "gate" / "check_run.json"
    try:
        body_file.parent.mkdir(parents=True, exist_ok=True)
        body_file.write_text(json.dumps(payload), encoding="utf-8")
        cp = _run(
            [
                "gh",
                "api",
                "-X",
                "POST",
                "repos/{owner}/{repo}/check-runs",
                "--input",
                str(body_file),
            ],
            cwd=str(repo_root),
        )
        if getattr(cp, "returncode", 1) != 0:
            return None
        stdout = (getattr(cp, "stdout", "") or "").strip()
        return str(json.loads(stdout).get("html_url")) if stdout else None
    except Exception:  # best-effort: never break the gate PR flow on annotation failure
        return None
