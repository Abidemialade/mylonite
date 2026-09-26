"""Tests for the writing and docs-sync checks (``scripts/check_prose.py``,
``scripts/check_docs_sync.py``) and the Claude Code hook that runs them.

Hermetic: every case feeds the checks strings and file lists directly, so
nothing depends on the state of the working tree. Both checks must FIRE on the
problems they exist for and STAY QUIET on ordinary project prose, because a
check that cries wolf gets bypassed.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load(relative: str, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / relative)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


prose = _load("scripts/check_prose.py", "check_prose")
docs = _load("scripts/check_docs_sync.py", "check_docs_sync")
hook = _load(".claude/hooks/enforce_writing.py", "enforce_writing")


def _errors(findings: list) -> list:
    return [f for f in findings if f.severity == "error"]


# --- prose ------------------------------------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        "In this guide we delve into the gate.",
        "We leverage the differential to prove findings.",
        "It works seamlessly with GitHub Actions.",
        "It's worth noting that replay is keyless.",
        "Furthermore, the scan is faster.",
        "This may potentially reduce cost.",
        "This PR aims to improve the gate.",
    ],
)
def test_prose_flags_bot_phrasing(line: str) -> None:
    assert _errors(prose.lint_text(line, "t")), line


@pytest.mark.parametrize(
    "line",
    [
        "`mylonite gate` turns a confirmed exploit into a pytest test that fails CI.",
        "Every kept finding reproduced across 5 runs and was stopped in all 5.",
        "A clean result is a result, not a failure of the tool.",
        "Mylonite tests MCP servers over stdio and remote transports.",
    ],
)
def test_prose_stays_quiet_on_project_prose(line: str) -> None:
    assert not _errors(prose.lint_text(line, "t")), line


def test_prose_skips_code_blocks_inline_code_and_allow_marker() -> None:
    text = "\n".join(
        [
            "```python",
            "leverage = seamless()",
            "```",
            "Call `utilize()` to start.",
            'He wrote "we delve deep". <!-- prose-lint: allow -->',
        ]
    )
    assert not _errors(prose.lint_text(text, "t"))


def test_prose_ignores_html_comments_in_pr_bodies() -> None:
    body = "## Summary\n<!-- feel free to delve -->\nFixes the gate.\n## How this was tested\npytest -q\n"
    assert not _errors(prose.check_pr_body(body))


def test_undercutting_words_warn_but_do_not_fail() -> None:
    findings = prose.lint_text("Unfortunately this is merely a fix.", "t")
    assert findings and not _errors(findings)


@pytest.mark.parametrize(
    "title",
    [
        "fix(scan): report attempts that never launched as launch_failure",
        "feat: add a two-build proof route",
        "chore(deps): bump ruff in the python-minor-and-patch group",
        "feat(contracts)!: freeze the adapter contract at 1.0",
    ],
)
def test_conventional_titles_pass(title: str) -> None:
    assert not _errors(prose.check_pr_title(title))


@pytest.mark.parametrize(
    "title",
    [
        "Update stuff",
        "fix(scan): trailing full stop.",
        "feat(scan): " + "x" * 80,
        "feature(scan): wrong type",
    ],
)
def test_bad_titles_fail(title: str) -> None:
    assert _errors(prose.check_pr_title(title))


def test_pr_body_requires_filled_sections() -> None:
    template = (REPO_ROOT / ".github" / "PULL_REQUEST_TEMPLATE.md").read_text(encoding="utf-8")
    assert _errors(prose.check_pr_body(template)), "an unfilled template must not pass"
    filled = template.replace(
        "## Summary\n",
        "## Summary\n\nThe gate now fails closed on stale replays.\n",
    ).replace(
        "## How this was tested\n",
        "## How this was tested\n\n`pytest tests/gate -q` (58 passed).\n",
    )
    assert not _errors(prose.check_pr_body(filled))


def test_diff_parsing_tracks_added_line_numbers() -> None:
    diff = "\n".join(
        [
            "diff --git a/docs/x.md b/docs/x.md",
            "--- a/docs/x.md",
            "+++ b/docs/x.md",
            "@@ -3,0 +4,2 @@",
            "+We leverage it.",
            "+A plain line.",
        ]
    )
    added = prose.parse_added_lines(diff)
    assert added == {"docs/x.md": [(4, "We leverage it."), (5, "A plain line.")]}
    findings = _errors(prose.lint_diff(added))
    assert [(f.source, f.line) for f in findings] == [("docs/x.md", 4)]


def test_style_guide_and_skill_are_exempt_from_the_diff_lint() -> None:
    added = {
        "docs/contributing/writing-style.md": [(1, "| delve, dive into | look at |")],
        ".claude/skills/mylonite-writing/SKILL.md": [(1, "phrases like delve")],
    }
    assert not prose.lint_diff(added)


# --- docs sync --------------------------------------------------------------


def test_docs_only_or_test_only_changes_pass() -> None:
    assert not docs.check(["docs/quickstart.md", "tests/test_cli.py", "README.md"])


def test_code_without_changelog_fails() -> None:
    problems = docs.check(["src/mylonite/scan/engine.py"])
    assert len(problems) == 1 and "CHANGELOG.md" in problems[0].message


def test_code_with_changelog_passes() -> None:
    assert not docs.check(["src/mylonite/scan/engine.py", "CHANGELOG.md"])


def test_user_facing_module_needs_its_page() -> None:
    problems = docs.check(["src/mylonite/cli.py", "CHANGELOG.md"])
    assert len(problems) == 1 and "docs/cli-reference.md" in problems[0].message
    assert not docs.check(["src/mylonite/cli.py", "CHANGELOG.md", "docs/cli-reference.md"])


def test_opt_out_needs_a_real_reason() -> None:
    change = ["src/mylonite/cli.py"]
    assert not docs.check(change, ["Docs-Impact: none - internal refactor, no flag changes"])
    assert not docs.check(change, ["Docs-Impact: none — renamed a private helper only"])
    assert docs.check(change, ["Docs-Impact: none"]), "a bare opt-out must not pass"
    assert docs.check(change, ["Docs-Impact: none - n/a"]), "a token reason must not pass"
    inline = (
        'git commit -m "fix: x" -m "Docs-Impact: none - comment-only change, no behaviour change"'
    )
    assert not docs.check(change, [inline]), "an inline -m opt-out must be recognised"
    assert docs.check(change, ['git commit -m "Docs-Impact: none - n/a"']), (
        "an inline token must not"
    )


def test_no_docs_label_opts_out() -> None:
    assert not docs.check(["src/mylonite/cli.py"], labels=["no-docs"])


def test_every_mapped_doc_page_exists() -> None:
    for rule in docs.DOC_RULES:
        for page in rule.docs:
            assert (REPO_ROOT / page).exists(), page


# --- hook -------------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "ls -la",
        "git status",
        "git log --oneline -5",
        "gh pr view 12",
        "pytest -q",
    ],
)
def test_hook_ignores_unrelated_commands(command: str) -> None:
    assert hook.run({"tool_input": {"command": command}, "cwd": str(REPO_ROOT)}) == []


@pytest.mark.parametrize(
    ("command", "commit", "push", "pr"),
    [
        ('git commit -s -m "fix: x"', True, False, False),
        ("git -c user.name=x commit -m y", True, False, False),
        ("git add -A && git commit -m y", True, False, False),
        ("git push -u origin my-branch", False, True, False),
        ("gh pr create --title t --body-file b.md", False, False, True),
        ('cd repo; gh pr edit 12 --body "x"', False, False, True),
        ('echo "remember to git commit later"', False, False, False),
        ("grep -n 'git push' docs/ci-gating.md", False, False, False),
    ],
)
def test_hook_recognises_commit_push_and_pr(
    command: str, commit: bool, push: bool, pr: bool
) -> None:
    assert bool(hook.COMMIT_RE.search(command)) is commit
    assert bool(hook.PUSH_RE.search(command)) is push
    assert bool(hook.PR_RE.search(command)) is pr


def test_hook_reads_pr_titles() -> None:
    assert hook._pr_title('gh pr create --title "fix(scan): x" --body-file b.md') == "fix(scan): x"
    assert hook._pr_title("gh pr create -t 'feat: y'") == "feat: y"
    assert hook._pr_title("gh pr create --fill") is None
