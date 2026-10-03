"""Tests for ``scripts/check_fenced_commands.py``, which checks every fenced
```bash/```console ``mylonite ...`` command in the docs against the committed
CLI golden (``tests/cli_golden/goldens/command_tree.json``).

Hermetic cases build a throwaway command tree and markdown text; the final
tests run the check against the real, committed docs and golden.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_fenced_commands as cfc  # noqa: E402

_TOY_TREE = {
    "root": {"params": [{"opts": ["--env-file"], "secondary_opts": []}]},
    "commands": {
        "scan": {
            "params": [
                {"opts": ["--authorize"], "secondary_opts": []},
                {"opts": ["--dry-run"], "secondary_opts": []},
            ]
        },
        "demo": {"params": [{"opts": ["--live"], "secondary_opts": []}]},
        "check": {"params": [{"opts": ["--enforce"], "secondary_opts": []}]},
    },
}


def _write_tree(root: Path, tree: dict = _TOY_TREE) -> None:
    path = root / cfc.COMMAND_TREE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(tree), encoding="utf-8")


def _write_doc(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_extracts_only_bash_and_console_fences() -> None:
    text = (
        "```bash\nmylonite scan --authorize x\n```\n"
        "```python\nmylonite scan --nonsense\n```\n"
        "```console\nmylonite demo\n```\n"
    )
    found = cfc.extract_fenced_mylonite_commands(text)
    assert found == ["mylonite scan --authorize x", "mylonite demo"]


def test_joins_backslash_continuations() -> None:
    text = "```bash\nmylonite scan \\\n  --authorize x\n```\n"
    assert cfc.extract_fenced_mylonite_commands(text) == ["mylonite scan --authorize x"]


def test_drops_trailing_comment() -> None:
    text = "```bash\nmylonite demo   # replays a recording\n```\n"
    assert cfc.extract_fenced_mylonite_commands(text) == ["mylonite demo"]


def test_known_command_and_flag_is_clean(tmp_path: Path) -> None:
    _write_tree(tmp_path)
    _write_doc(tmp_path, "README.md", "```bash\nmylonite scan --authorize x\n```\n")
    assert cfc.check(tmp_path) == []


def test_unknown_subcommand_fails(tmp_path: Path) -> None:
    _write_tree(tmp_path)
    _write_doc(tmp_path, "README.md", "```bash\nmylonite frobnicate\n```\n")
    problems = cfc.check(tmp_path)
    assert any("frobnicate" in p.message and "not a known command" in p.message for p in problems)


def test_unknown_flag_fails(tmp_path: Path) -> None:
    _write_tree(tmp_path)
    _write_doc(tmp_path, "README.md", "```bash\nmylonite scan --made-up-flag\n```\n")
    problems = cfc.check(tmp_path)
    assert any("--made-up-flag" in p.message for p in problems)


def test_root_flag_is_known_with_no_subcommand(tmp_path: Path) -> None:
    _write_tree(tmp_path)
    _write_doc(tmp_path, "README.md", "```bash\nmylonite --env-file secrets.env\n```\n")
    assert cfc.check(tmp_path) == []


def test_retired_command_is_not_flagged(tmp_path: Path) -> None:
    _write_tree(tmp_path)
    _write_doc(tmp_path, "docs/cli-reference.md", "```bash\nmylonite init-target --scope x\n```\n")
    assert cfc.check(tmp_path) == []


def test_allowlisted_non_launch_command_is_skipped(tmp_path: Path) -> None:
    _write_tree(tmp_path)
    _write_doc(tmp_path, "README.md", "```bash\nmylonite check --made-up-flag\n```\n")
    allow_path = tmp_path / cfc.ALLOWLIST_PATH
    allow_path.parent.mkdir(parents=True, exist_ok=True)
    allow_path.write_text(
        json.dumps([{"command": "check", "reason": "test only"}]), encoding="utf-8"
    )
    assert cfc.check(tmp_path) == []


def test_launch_set_command_may_not_be_allowlisted(tmp_path: Path) -> None:
    _write_tree(tmp_path)
    _write_doc(tmp_path, "README.md", "```bash\nmylonite demo\n```\n")
    allow_path = tmp_path / cfc.ALLOWLIST_PATH
    allow_path.parent.mkdir(parents=True, exist_ok=True)
    allow_path.write_text(json.dumps([{"command": "demo", "reason": "nope"}]), encoding="utf-8")
    problems = cfc.check(tmp_path)
    assert any("launch-set" in p.message for p in problems)


def test_real_docs_match_the_real_golden() -> None:
    """The committed docs/README/golden trio must already pass this check."""
    problems = cfc.check(ROOT)
    assert not problems, "\n".join(p.message for p in problems)


def test_real_allowlist_has_no_launch_set_entries() -> None:
    problems = cfc.check_allowlist_has_no_launch_set_entries(ROOT)
    assert not problems, "\n".join(p.message for p in problems)


def test_real_collection_is_not_vacuous() -> None:
    """Guard against the collector silently finding nothing."""
    total = 0
    for pattern in cfc._SOURCE_GLOBS:
        for path in ROOT.glob(pattern):
            if path.is_file():
                total += len(cfc.extract_fenced_mylonite_commands(path.read_text(encoding="utf-8")))
    assert total >= 20, (
        f"collected only {total} fenced mylonite commands -- has the collector drifted?"
    )
