"""Two-way ratchet between three stability-promised registries and the docs
pages that describe them: the CLI's flags, the `mylonite.testkit` public
surface, and the reason-code registry.

"Two-way" means each registry is checked in both directions:

* **forward** — every live entry (a non-hidden CLI flag, a `testkit.__all__`
  name, a reason code) has a mention in its docs page. A gap here is a reader
  who runs `--help` (or hits a code) and finds nothing written down for it —
  the drift class issue #209 reported for the CLI (`cli-reference.md` was
  missing several flags `--help` already showed).
* **backward** — every CLI-flag-shaped (`--xxx`) token, testkit name, or
  `MYL-xxx-nnn` heading the docs page carries actually exists. A gap here is
  a reader who copies a flag or name from the docs and it doesn't work — the
  drift class `tests/test_docs_consistency.py` already guards for specific
  past incidents (`--prove-control`, `--runs`, a stale `.mylonite/validated`
  path); this is the same idea applied uniformly to all three registries.

Reason codes are checked here in both directions, using the shared
heading-parsing helper (`tests._doc_registry_sync`), in the same parametrised
sweep as the other two registries, so all three live under one ratchet with
one allowlist. (An older standalone check in `test_docs_consistency.py` was
retired as a duplicate of this row.)

The allowlist
-------------
`tests/fixtures/docs_ratchet_allowlist.json` lists today's known gaps, one
entry per registry, each with a `key` (matching a gap string below) and a
`reason`. A gap that is NOT in the allowlist fails loudly, telling you to fix
the docs (the preferred outcome) or add a reasoned entry. An allowlist entry
that no longer matches a real gap (the doc got fixed) also fails, so the list
can't quietly rot into claiming gaps that no longer exist.

Growing the allowlist is a deliberate, reviewable act, mirroring
`scripts/hardcoded_models_allowlist.txt`'s ratchet (see CONTRIBUTING.md): the
per-registry ceilings below may only shrink. Raise one only in the same PR
that adds a new, reasoned allowlist entry; lower it whenever a gap gets fixed
instead of carried.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
from tests._doc_registry_sync import markdown_sections_by_heading, reason_code_headings
from typer.main import get_command

from mylonite import reason_codes, testkit
from mylonite.cli import app

_REPO_ROOT = Path(__file__).resolve().parents[1]
_DOCS_DIR = _REPO_ROOT / "docs"
_ALLOWLIST_PATH = Path(__file__).parent / "fixtures" / "docs_ratchet_allowlist.json"

#: The allowlist may only shrink. Lower these whenever a gap is fixed for
#: real (the preferred outcome) or a stale entry is deleted; raise one only
#: in the same PR that adds a new, reasoned allowlist entry for that
#: registry -- never to make silent room for an unreviewed gap.
_CEILINGS: dict[str, int] = {
    "cli_flags": 0,
    "testkit": 0,
    "reason_codes": 0,
}

#: `--xxx`-shaped tokens in cli-reference.md that name something other than
#: a `mylonite` CLI option, so the backward CLI check must not treat them as
#: undocumented-but-real flags (they're not CLI flags at all). Not allowlist
#: material: nothing is missing from the docs here, the checker's own
#: `--xxx` pattern just also matches these two mentions.
#:
#: * `--help` is Click's built-in on every command; Click adds it at
#:   invocation time rather than listing it in `Command.params`, so it never
#:   appears in the live command tree this module walks.
#: * `--show-toplevel` is `git rev-parse --show-toplevel`, named in `gate`'s
#:   own doc section to explain how `gate` resolves the repository root.
_NOT_A_MYLONITE_FLAG = frozenset({"--help", "--show-toplevel"})

_FLAG_TOKEN_RE = re.compile(r"(?<![\w-])--[a-z][a-z0-9-]*(?![\w-])")


def _load_allowlist() -> dict[str, list[dict[str, str]]]:
    return json.loads(_ALLOWLIST_PATH.read_text(encoding="utf-8"))


def _allowed_keys(registry: str) -> set[str]:
    return {entry["key"] for entry in _load_allowlist().get(registry, [])}


# --- CLI flags ----------------------------------------------------------------
#
# Forward: every non-hidden command's non-hidden `--flag` option is mentioned
# in that command's own `## \`command\` ...` section of cli-reference.md.
# Backward: every `--flag`-shaped token anywhere on the page names a real
# option of SOME command (hidden commands included -- their flags are real,
# just not required reading for a non-hidden command's own section).


def _cli_command_tree() -> Any:
    return get_command(app)


def _cli_doc_sections() -> dict[str, str]:
    """`{command_name: section_text}` for every backtick-named `## ` heading
    in cli-reference.md, plus `""` for the page's own intro (the global
    `--api-key-file`/`--env-file` options are documented there, not under any
    one command's heading).
    """
    text = (_DOCS_DIR / "cli-reference.md").read_text(encoding="utf-8")
    intro, _, rest = text.partition("\n## ")
    sections: dict[str, str] = {"": intro}
    # Re-attach the marker `partition` consumed so heading-level splitting
    # inside the loop body below sees it on the first chunk too.
    for name, body in markdown_sections_by_heading("## " + rest, marker="## ").items():
        # `markdown_sections_by_heading`'s marker is `## `, which also means a
        # `### ` sub-heading under one command stays inside that command's
        # body (see its own docstring) -- exactly what's wanted here: a
        # worked sub-example belongs to the command it's under, not a
        # section of its own.
        match = re.match(r"^`([a-z][a-z0-9_-]*)`", name)
        if match:
            sections[match.group(1)] = sections.get(match.group(1), "") + body
    return sections


def _cli_primary_flags(params: Any) -> list[str]:
    return [opts[0] for p in params if (opts := [o for o in p.opts if o.startswith("--")])]


def _cli_known_flags() -> set[str]:
    """Every real `--flag` (primary or negated) on the whole command tree,
    hidden commands included -- this is what the backward check must not
    flag as unknown.
    """
    tree = _cli_command_tree()
    flags = {o for p in tree.params for o in p.opts if o.startswith("--")}
    for cmd in tree.commands.values():
        for p in cmd.params:
            flags.update(o for o in p.opts if o.startswith("--"))
            flags.update(o for o in p.secondary_opts if o.startswith("--"))
    return flags


def _cli_forward_gaps() -> list[str]:
    tree = _cli_command_tree()
    sections = _cli_doc_sections()
    gaps = []
    for flag in _cli_primary_flags(tree.params):
        if not re.search(rf"(?<![\w-]){re.escape(flag)}(?![\w-])", sections.get("", "")):
            gaps.append(f"undocumented:(root) {flag}")
    for name, cmd in tree.commands.items():
        if cmd.hidden:
            continue
        section = sections.get(name, "")
        for flag in _cli_primary_flags(cmd.params):
            if not re.search(rf"(?<![\w-]){re.escape(flag)}(?![\w-])", section):
                gaps.append(f"undocumented:{name} {flag}")
    return sorted(gaps)


def _cli_backward_gaps() -> list[str]:
    text = (_DOCS_DIR / "cli-reference.md").read_text(encoding="utf-8")
    found = set(_FLAG_TOKEN_RE.findall(text))
    unknown = found - _cli_known_flags() - _NOT_A_MYLONITE_FLAG
    return sorted(f"stale-doc:{flag}" for flag in unknown)


# --- testkit API ----------------------------------------------------------
#
# Forward: every `testkit.__all__` name has a qualified `testkit.<name>`
# mention somewhere in docs/testkit.md. Backward: every qualified
# `testkit.<name>` mention in that page names a real `__all__` entry.
#
# Scoped to qualified mentions (not a bare name like `load_exploit`) because
# an unqualified name is too easy to confuse with ordinary prose ("assert",
# "load") -- the qualifying `testkit.` prefix is what makes a mention
# unambiguously ABOUT the testkit API rather than just using an English word
# that happens to match one of its names.

_TESTKIT_DOC_PATH = _DOCS_DIR / "testkit.md"
_QUALIFIED_NAME_RE = re.compile(r"testkit\.(?!md\b)([A-Za-z_][A-Za-z0-9_]*)")


def _testkit_doc_names() -> set[str]:
    text = _TESTKIT_DOC_PATH.read_text(encoding="utf-8")
    return set(_QUALIFIED_NAME_RE.findall(text))


def _testkit_forward_gaps() -> list[str]:
    documented = _testkit_doc_names()
    return sorted(f"undocumented:{name}" for name in testkit.__all__ if name not in documented)


def _testkit_backward_gaps() -> list[str]:
    all_names = set(testkit.__all__)
    return sorted(f"stale-doc:{name}" for name in _testkit_doc_names() if name not in all_names)


# --- reason codes -----------------------------------------------------------
#
# Reuses `tests._doc_registry_sync.reason_code_headings` rather than
# re-parsing `## ` sections -- see the module docstring.

_REASON_CODES_DOC_PATH = _DOCS_DIR / "reason-codes.md"


def _reason_code_doc_headings() -> set[str]:
    return reason_code_headings(_REASON_CODES_DOC_PATH.read_text(encoding="utf-8"))


def _reason_codes_forward_gaps() -> list[str]:
    headings = _reason_code_doc_headings()
    return sorted(f"undocumented:{code}" for code in reason_codes.REGISTRY if code not in headings)


def _reason_codes_backward_gaps() -> list[str]:
    headings = _reason_code_doc_headings()
    return sorted(f"stale-doc:{code}" for code in headings if code not in reason_codes.REGISTRY)


# --- the sweep ---------------------------------------------------------------

_GAP_FUNCS: dict[str, tuple[Any, Any]] = {
    "cli_flags": (_cli_forward_gaps, _cli_backward_gaps),
    "testkit": (_testkit_forward_gaps, _testkit_backward_gaps),
    "reason_codes": (_reason_codes_forward_gaps, _reason_codes_backward_gaps),
}


def _current_gaps(registry: str) -> list[str]:
    forward, backward = _GAP_FUNCS[registry]
    return sorted({*forward(), *backward()})


@pytest.mark.parametrize("registry", sorted(_GAP_FUNCS))
def test_every_gap_is_allowlisted_or_fixed(registry: str) -> None:
    """Every current forward/backward gap for ``registry`` is either absent
    (the preferred outcome) or carries a reasoned entry in
    ``docs_ratchet_allowlist.json``.
    """
    gaps = _current_gaps(registry)
    allowed = _allowed_keys(registry)
    unallowed = [g for g in gaps if g not in allowed]
    assert not unallowed, (
        f"{registry}: these are undocumented (or the docs name something that "
        f"doesn't exist) and not in {_ALLOWLIST_PATH.name}: {unallowed}. Fix the "
        "docs page for real, or add a reasoned allowlist entry and raise this "
        "registry's ceiling in the same PR."
    )


@pytest.mark.parametrize("registry", sorted(_GAP_FUNCS))
def test_allowlist_entries_are_not_stale(registry: str) -> None:
    """Every allowlisted key still names a real, current gap.

    An entry that doesn't match anything live means the doc got fixed (or
    the registry changed) without the allowlist catching up -- delete the
    entry and lower the ceiling instead of carrying dead weight."""
    gaps = set(_current_gaps(registry))
    allowed = _allowed_keys(registry)
    stale = sorted(allowed - gaps)
    assert not stale, (
        f"{registry}: these allowlist entries no longer match a real gap: {stale}. "
        f"Delete them from {_ALLOWLIST_PATH.name} and lower this registry's ceiling."
    )


@pytest.mark.parametrize("registry", sorted(_CEILINGS))
def test_allowlist_does_not_grow_past_its_ceiling(registry: str) -> None:
    count = len(_load_allowlist().get(registry, []))
    ceiling = _CEILINGS[registry]
    assert count <= ceiling, (
        f"{registry}: the allowlist grew to {count} entries, past the committed "
        f"ceiling of {ceiling}. Allowlists only shrink -- raising the ceiling is a "
        "deliberate, reviewed act: do it in the same PR as the new reasoned entry, "
        "with the reason explaining why the doc can't be fixed instead."
    )


def test_allowlist_has_no_unknown_registries() -> None:
    """Every top-level key in the allowlist file is one this module actually
    checks -- a typo'd registry name would otherwise sit there unenforced."""
    unknown = sorted(set(_load_allowlist()) - set(_GAP_FUNCS))
    assert not unknown, f"{_ALLOWLIST_PATH.name} names unchecked registries: {unknown}"
