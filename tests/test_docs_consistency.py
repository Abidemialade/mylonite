"""Docs-consistency guard (T17, 0.7.7-honest-results).

`cli.py`'s `--help` epilogs and `demo/render.py`'s printed next-step text are
copy-paste bait: a reader (or a script) will run the ``mylonite ...`` example
verbatim. A `cli.py` change that renames/removes a flag or a command doesn't
by itself touch anything under `docs/`, so it never trips `docs.yml` (which
only builds on `docs/**` / `mkdocs.yml` changes) -- that is exactly how
`--runs` (attack-modes.md), `gate-action@v1` (no such tag), and the
`--prove-control` flags (removed in commit 12cf8e0, see CHANGELOG) went stale
without CI ever failing.

This module makes the EMBEDDED examples the source of truth: it introspects
the real Typer `app` at runtime (never a copy of the epilog text), extracts
every backtick-quoted `` `mylonite ...` `` example, and proves it PARSES
against the live Click command tree -- Click's own argument binder, via
``Command.make_context`` -- without invoking any command body (no live LLM
call, no network, no side effect). A renamed/removed flag or subcommand shows
up as ``NoSuchOption`` / ``UsageError`` here, at collection time, on any
branch that touches `cli.py` -- not just ones that also touch `docs/`.

It does NOT verify the *values* used (e.g. that `--authorize my-app` is the
correct family for a specific `app.yaml`) -- that is a semantic property of
the surrounding prose, not something a generic parser can check. A handful of
those (family/scope <-> --authorize pairings) are pinned directly against
``mylonite._authz.check_authorization`` below instead, as a second, narrower
regression guard for the exact bug class T17 fixed (~13 doc examples using
`--authorize me`, `--authorize your-scope`, etc. that didn't match the
target's actual required value).
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path
from typing import Any

import pytest
import typer

from mylonite._authz import check_authorization
from mylonite.cli import app

_REPO_ROOT = Path(__file__).resolve().parents[1]
_DOCS_DIR = _REPO_ROOT / "docs"

_BACKTICK_MYLONITE_RE = re.compile(r"`(mylonite [^`]+)`")
#: Loose enough to pull a `mylonite ...` invocation out of plain prose (used
#: for demo/render.py, which prints next-step hints, not backtick-fenced
#: markdown) -- stops at an opening paren, an em dash, or end of string.
_PROSE_MYLONITE_RE = re.compile(r"mylonite\s+[^()—\n]+?(?=\s*\(|\s+—|$)")


def _click_command_tree() -> Any:
    """The real Click command tree Typer builds from ``mylonite.cli.app``."""
    return typer.main.get_command(app)


def _iter_commands(cmd: Any, prefix: tuple[str, ...] = ()) -> list[tuple[tuple[str, ...], Any]]:
    """Depth-first walk of every (sub)command, including nested groups like
    ``taxonomy list``. Duck-types "is this a group" via ``.commands`` rather
    than ``isinstance(x, click.Group)`` -- this Typer version vendors its own
    internal Click fork (``typer._click``), so the top-level ``click``
    package's classes are NOT its base classes.
    """
    out: list[tuple[tuple[str, ...], Any]] = [(prefix, cmd)]
    sub_commands = getattr(cmd, "commands", None)
    if sub_commands:
        for name, sub in sub_commands.items():
            out.extend(_iter_commands(sub, (*prefix, name)))
    return out


def _all_epilog_examples() -> list[tuple[str, str]]:
    """Every ``` `mylonite ...` ``` example embedded in any command's epilog.

    Returns (location, example) pairs, ``location`` naming the command path
    the epilog belongs to, for a legible failure message.
    """
    examples: list[tuple[str, str]] = []
    for path, cmd in _iter_commands(_click_command_tree()):
        epilog = getattr(cmd, "epilog", None)
        if not epilog:
            continue
        location = "mylonite " + " ".join(path) if path else "mylonite (root)"
        for match in _BACKTICK_MYLONITE_RE.finditer(epilog):
            examples.append((location, match.group(1)))
    return examples


def _demo_render_examples() -> list[tuple[str, str]]:
    """Every ``mylonite ...`` example embedded in ``demo/render.py``'s printed
    next-step / teaser strings (the text ``mylonite demo`` actually prints).
    """
    from mylonite.demo import render as demo_render

    examples: list[tuple[str, str]] = []
    for attr in ("_TEASER", "_NEXT_STEP"):
        text = getattr(demo_render, attr, None)
        if not text:
            continue
        for match in _PROSE_MYLONITE_RE.finditer(text):
            examples.append((f"mylonite.demo.render.{attr}", match.group(0)))
    return examples


def _assert_example_parses(location: str, example: str) -> None:
    """Resolve ``example`` (a full ``mylonite ...`` invocation) down to its
    leaf Click command and prove the remaining tokens PARSE against it
    (``make_context`` -- binds args to the command's registered params;
    never invokes the callback, so this makes no live call and has no side
    effect). A renamed/removed flag, a removed subcommand, or a dropped
    positional argument all surface as an exception here.
    """
    tokens = shlex.split(example)
    assert tokens and tokens[0] == "mylonite", f"{location}: {example!r} must start with 'mylonite'"
    tokens = tokens[1:]

    cmd = _click_command_tree()
    consumed: list[str] = []
    while getattr(cmd, "commands", None):
        if not tokens:
            pytest.fail(
                f"{location}: {example!r} names a group "
                f"({'mylonite ' + ' '.join(consumed) or 'mylonite'}) but no subcommand"
            )
        name = tokens.pop(0)
        sub = cmd.commands.get(name)
        if sub is None:
            pytest.fail(
                f"{location}: {example!r} -- {name!r} is not a known subcommand under "
                f"{'mylonite ' + ' '.join(consumed) if consumed else 'mylonite'} "
                f"(known: {sorted(cmd.commands)})"
            )
        consumed.append(name)
        cmd = sub

    try:
        cmd.make_context("mylonite " + " ".join(consumed), tokens)
    except Exception as exc:
        pytest.fail(f"{location}: {example!r} does not parse against the real CLI: {exc}")


@pytest.mark.parametrize(
    "location,example",
    _all_epilog_examples(),
    ids=lambda v: v if isinstance(v, str) else None,
)
def test_cli_epilog_example_parses(location: str, example: str) -> None:
    """Every `` `mylonite ...` `` example in any `--help` epilog must parse
    against the CURRENT CLI -- catches a renamed/removed flag or subcommand
    that a `cli.py`-only change (no `docs/` touch) would otherwise hide from
    `docs.yml`'s path-filtered `mkdocs build --strict`.
    """
    _assert_example_parses(location, example)


def test_cli_epilog_examples_were_actually_collected() -> None:
    """Guard against the extraction itself silently finding nothing (e.g. a
    future refactor moves the epilogs somewhere `_all_epilog_examples` no
    longer looks) -- a parametrize list of zero tests would pass trivially
    and stop catching anything.
    """
    examples = _all_epilog_examples()
    assert len(examples) >= 10, (
        f"expected at least 10 `mylonite ...` examples across cli.py's epilogs, "
        f"found {len(examples)} -- did the epilogs move?"
    )


@pytest.mark.parametrize(
    "location,example",
    _demo_render_examples(),
    ids=lambda v: v if isinstance(v, str) else None,
)
def test_demo_render_example_parses(location: str, example: str) -> None:
    """Every ``mylonite ...`` example printed by ``mylonite demo`` (via
    `demo/render.py`'s `_TEASER`/`_NEXT_STEP`) must parse against the CURRENT
    CLI, for the same reason as the epilog examples above.
    """
    _assert_example_parses(location, example)


def test_demo_render_examples_were_actually_collected() -> None:
    """Same collection-not-empty guard as the epilog test, for render.py."""
    examples = _demo_render_examples()
    assert len(examples) >= 2, (
        f"expected at least 2 `mylonite ...` examples in demo/render.py's printed "
        f"text, found {len(examples)} -- did _TEASER/_NEXT_STEP move or get renamed?"
    )


def test_demo_render_next_step_scaffold_then_scan_chain_actually_authorizes() -> None:
    """`_assert_example_parses` above only proves the two `_NEXT_STEP` commands
    PARSE individually -- it can't see that they are a two-step CHAIN (scaffold
    app.yaml, then scan that same app.yaml) where step 2's `--authorize` must
    match whatever `family`/`scope` step 1's `--scaffold` actually produced.
    That is exactly how this string went stale: it read `--scaffold app.yaml
    ... --authorize my-app` with no `--scope` on the scaffold step, so the
    scaffolded target got `family: custom` while the second command demanded
    `--authorize my-app` -- `mylonite scan --command python --arg server.py
    --scaffold app.yaml` (as it read before this fix) then `mylonite scan
    --target-file app.yaml --authorize my-app` raised `AuthorizationRefused`
    for real, verified live.

    This test extracts BOTH commands from the live `_NEXT_STEP` string, reads
    `--scope` off the scaffold command (mirroring exactly what
    `_scaffold_target_file`/`_target_file_from_flags` does: family is always
    the literal `"custom"` for the plain MCP scaffold path; scope is whatever
    `--scope` was passed, or `None`), and `--authorize` off the scan command,
    then proves the pairing via the same `check_authorization` the CLI itself
    calls -- so a future edit to `_NEXT_STEP` that reintroduces a mismatch
    fails here, not just in a live user's terminal.
    """
    from mylonite.demo import render as demo_render

    examples = [m.group(0) for m in _PROSE_MYLONITE_RE.finditer(demo_render._NEXT_STEP)]
    assert len(examples) == 2, (
        f"expected exactly 2 `mylonite ...` commands in _NEXT_STEP (scaffold, then scan), "
        f"found {len(examples)}: {examples} -- update this test if _NEXT_STEP's shape changed"
    )
    scaffold_cmd, scan_cmd = examples
    assert "--scaffold" in scaffold_cmd, f"expected the first command to scaffold: {scaffold_cmd!r}"
    assert "--authorize" in scan_cmd, f"expected the second command to authorize: {scan_cmd!r}"

    scope_match = re.search(r"--scope\s+(\S+)", scaffold_cmd)
    scope = scope_match.group(1) if scope_match else None
    authorize_match = re.search(r"--authorize\s+(\S+)", scan_cmd)
    assert authorize_match, f"no --authorize value found in {scan_cmd!r}"
    authorize = authorize_match.group(1)

    # `_scaffold_target_file` -> `_target_file_from_flags` always sets
    # family="custom" for the plain (non --rest-url) MCP scaffold path;
    # `--scope`, if given, becomes the target's scope.
    check_authorization(family="custom", scope=scope, authorize=authorize, command="scan")


# --------------------------------------------------------------------------
# Narrower regression guards for specific stale references T17 fixed. Each
# pins ONE concrete fact against live source (never a copy of the doc text),
# so a future doc edit that reintroduces the same mistake fails loudly.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "doc_description,family,scope,authorize",
    [
        # docs/test-your-app.md's minimal target file (`family: my-app`, no
        # scope) is scanned/gated/ablated with `--authorize my-app`.
        ("test-your-app.md family: my-app example", "my-app", None, "my-app"),
        # docs/test-your-app.md's bundled-target example:
        # `mcp:filesystem:/tmp/sandbox --authorize /tmp/sandbox`.
        ("test-your-app.md mcp:filesystem:/tmp/sandbox example", "filesystem", "/tmp/sandbox", "/tmp/sandbox"),
        # docs/quarry.md: `mylonite scan mcp:fetch --authorize fetch`.
        ("quarry.md mcp:fetch example", "fetch", None, "fetch"),
        # docs/ci-gating.md / cli.py's root epilog: `scan --scaffold` with no
        # `--scope` writes `family: custom`, then `--authorize custom`.
        ("ci-gating.md / cli.py root epilog scaffold-then-gate chain", "custom", None, "custom"),
        # docs/target-file.md's full annotated example: `scope: tenant-a`.
        ("target-file.md scope: tenant-a example", "my-app", "tenant-a", "tenant-a"),
        # docs/http-agent.md: `family: my-http-agent`, no scope.
        ("http-agent.md family: my-http-agent example", "my-http-agent", None, "my-http-agent"),
    ],
)
def test_documented_authorize_examples_match_the_target(
    doc_description: str, family: str, scope: str | None, authorize: str
) -> None:
    """Pins a handful of (family, scope, --authorize) triples straight out of
    the docs against the REAL rule (`mylonite._authz.check_authorization`):
    `--authorize` must equal the declared `scope` if one exists, else the
    `family`. Before T17, ~13 examples across docs/ used `--authorize me` (or
    `your-scope`) against a target whose actual required value was something
    else entirely -- a reader who copy-pasted them got a config-error exit,
    not a working scan. Fails loudly (via `check_authorization` itself) if a
    future doc edit reintroduces that mismatch.
    """
    check_authorization(family=family, scope=scope, authorize=authorize, command="scan")


def test_no_stale_mylonite_validated_path_in_docs() -> None:
    """No code path ever creates `.mylonite/validated/` (`generate` writes
    `.mylonite/generated/<slug>`; `validate` updates that SAME dir in place
    -- see `mylonite.layout.Layout`, which has `.scans`/`.generated`/`.gate`
    and no `.validated`). A doc pointing a reader at `.mylonite/validated/`
    sends them to a directory that will never exist.
    """
    offenders = []
    for md in _DOCS_DIR.rglob("*.md"):
        if "superpowers" in md.parts:  # gitignored planning docs, not published
            continue
        text = md.read_text(encoding="utf-8")
        if ".mylonite/validated" in text or r".mylonite\validated" in text:
            offenders.append(md.relative_to(_REPO_ROOT).as_posix())
    assert not offenders, f"stale '.mylonite/validated' path referenced in: {offenders}"


def test_mylonite_live_target_is_documented() -> None:
    """`MYLONITE_LIVE_TARGET` gates every custom-target live regression test
    (see `mylonite.testkit.assert_target_resists` /
    `mylonite.plugins._reference.reference_pytest_generator`) -- without it
    the test is skipped and a plain `pytest` still exits 0. This must be
    documented somewhere under `docs/`, not just in the emitted test's own
    docstring, or an operator adopting CI gating has no way to discover it.
    """
    hits = [
        md.relative_to(_REPO_ROOT).as_posix()
        for md in _DOCS_DIR.rglob("*.md")
        if "MYLONITE_LIVE_TARGET" in md.read_text(encoding="utf-8")
    ]
    assert hits, "MYLONITE_LIVE_TARGET has zero occurrences under docs/"


def test_scan_has_no_runs_flag() -> None:
    """Regression guard for the `--runs` claim removed from attack-modes.md:
    `scan`'s scan-time flakiness filter (`ScanEngineConfig.runs`) exists at
    the engine/API level but is NOT wired to a CLI flag. If a future change
    adds `--runs` to `scan`, this (intentionally inverted) assertion starts
    failing as a prompt to restore the docs claim rather than leaving it
    silently correct-again-but-undocumented.
    """
    scan_cmd = _click_command_tree().commands["scan"]
    option_names = {name for param in scan_cmd.params for name in getattr(param, "opts", [])}
    assert "--runs" not in option_names, (
        "scan now HAS a --runs flag -- docs/attack-modes.md's flakiness-filter section "
        "was deliberately softened to say this doesn't exist yet; restore the CLI-flag "
        "wording now that it does."
    )


def test_control_config_synthetic_accepts_a_control_list_not_a_bool() -> None:
    """Regression guard for docs/target-file.md's `control_config.synthetic`
    example, which used to be `synthetic: true` -- `ControlConfig.synthetic`
    is `tuple[str, ...]`, so that failed Pydantic validation. Loads the
    field's current shape straight from the model rather than hardcoding a
    doc copy, so a future field-type change is what breaks this test (a
    prompt to re-check the doc), not doc drift going undetected.
    """
    from pydantic import ValidationError

    from mylonite.plugins._mcp.target_registry import ControlConfig

    field = ControlConfig.model_fields["synthetic"]
    with pytest.raises(ValidationError):
        ControlConfig.model_validate({"synthetic": True})
    # A real list of control names must still validate.
    ControlConfig.model_validate({"synthetic": ["W3", "W4"]})
    assert field.default == (), "ControlConfig.synthetic's default changed shape"
