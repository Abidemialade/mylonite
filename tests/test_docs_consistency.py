"""Docs-consistency guard (T17, 0.7.7-honest-results).

`cli.py`'s `--help` epilogs are copy-paste bait: a reader (or a script) will
run the ``mylonite ...`` example verbatim. A `cli.py` change that
renames/removes a flag or a command doesn't by itself touch anything under
`docs/`, so it never trips `docs.yml` (which only builds on `docs/**` /
`mkdocs.yml` changes) -- that is exactly how `--runs` (attack-modes.md),
`gate-action@v1` (no such tag), and the `--prove-control` flags (removed in
commit 12cf8e0, see CHANGELOG) went stale without CI ever failing.

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
        (
            "test-your-app.md mcp:filesystem:/tmp/sandbox example",
            "filesystem",
            "/tmp/sandbox",
            "/tmp/sandbox",
        ),
        # docs/quarry.md: `mylonite scan mcp:fetch --authorize fetch`.
        ("quarry.md mcp:fetch example", "fetch", None, "fetch"),
        # docs/ci-gating.md / cli.py's root epilog: `scan --scaffold` with no
        # `--scope` writes `family: custom`, then `--authorize custom`.
        ("ci-gating.md / cli.py root epilog scaffold-then-gate chain", "custom", None, "custom"),
        # docs/target-file.md's full annotated example: `scope: tenant-a`.
        ("target-file.md scope: tenant-a example", "my-app", "tenant-a", "tenant-a"),
        # docs/http-agent.md: `--scaffold my-agent.yaml` writes `family: my-agent`
        # (the file stem), no scope; the hand-written file uses the same family.
        ("http-agent.md family: my-agent example", "my-agent", None, "my-agent"),
        # docs/cli-reference.md: `--scaffold app.yaml --scope my-app`, then every
        # scan/validate/gate/ablate example passes `--authorize my-app`.
        ("cli-reference.md --scope my-app scaffold chain", "custom", "my-app", "my-app"),
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


_AUTHORIZE_RE = re.compile(r"--authorize\s+(\S+)")


def test_http_agent_doc_authorizes_the_scaffolded_family() -> None:
    """`scan --scaffold my-agent.yaml --rest-url ...` names the family after the
    file stem, so every `--authorize` on the page must be `my-agent`."""
    text = (_DOCS_DIR / "http-agent.md").read_text(encoding="utf-8")
    assert "--scaffold my-agent.yaml" in text
    assert "family: my-agent\n" in text
    values = set(_AUTHORIZE_RE.findall(text))
    assert values == {"my-agent"}, values
    check_authorization(family="my-agent", scope=None, authorize="my-agent", command="scan")


def test_cli_reference_authorize_examples_match_the_scaffold() -> None:
    """The scaffold example sets `--scope my-app`; every `--target-file app.yaml`
    example on the page must then authorize `my-app`, not `custom`."""
    text = (_DOCS_DIR / "cli-reference.md").read_text(encoding="utf-8")
    assert "--scaffold app.yaml --scope my-app" in text
    values = {
        m.group(1)
        for line in text.splitlines()
        if "--target-file app.yaml" in line
        for m in _AUTHORIZE_RE.finditer(line)
    }
    assert values == {"my-app"}, values


def test_test_your_app_doc_has_no_placeholder_authorize() -> None:
    text = (_DOCS_DIR / "test-your-app.md").read_text(encoding="utf-8")
    assert "--authorize <you>" not in text


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


def test_max_llm_calls_help_does_not_claim_a_cap() -> None:
    """`--max-llm-calls`'s own help text must call it a budget, not a cap:
    every seed keeps a floor of it (see docs/ci-gating.md), so the engine can
    spend well past the flag value -- calling it a "cap" overstates the
    guarantee.

    Reads the option's own ``.help`` straight off the live Click command,
    never a fixed-width slice of ``--help`` output -- a slice can bleed into
    the NEXT option's text and pass or fail for the wrong reason.
    """
    tree = _click_command_tree()
    for cmd_name in ("scan", "gate"):
        cmd = tree.commands[cmd_name]
        opt = next(p for p in cmd.params if "--max-llm-calls" in getattr(p, "opts", []))
        help_text = (opt.help or "").lower()
        assert "budget" in help_text, f"{cmd_name} --max-llm-calls help: {opt.help!r}"
        assert "cap" not in help_text, f"{cmd_name} --max-llm-calls help: {opt.help!r}"


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


# --- README vs the code it describes ---------------------------------------

#: The zero-install route. CI's `demo` job runs the same command from the
#: local checkout (`--from ".[demo]"`) on Linux and Windows at 80 columns, on
#: Python 3.14, so this string is what the README promises and the job is what
#: proves it. No `--python`: every Python uv might pick (3.11-3.14) is supported.
UVX_DEMO = 'uvx --from "mylonite[demo]" mylonite demo'


def test_readme_has_uvx_one_liner() -> None:
    assert UVX_DEMO in (_REPO_ROOT / "README.md").read_text(encoding="utf-8")


def test_quickstart_has_uvx_one_liner() -> None:
    assert UVX_DEMO in (_DOCS_DIR / "quickstart.md").read_text(encoding="utf-8")


def test_readme_does_not_overstate_the_api_key_requirement() -> None:
    """The README said scanning "needs an LLM API key", full stop.

    `docs/self-hosted-models.md` documents the opposite for Ollama/vLLM, and
    `scan/providers.py` backs it: those providers map to `()`, no env var
    required. The unqualified claim undersold a no-key path the project's own
    docs and code support — the kind of drift this module exists to catch, one
    file over from the CLI epilogs.
    """
    from mylonite.scan.providers import PROVIDER_ENV_VARS

    readme = (_REPO_ROOT / "README.md").read_text(encoding="utf-8")

    assert "Scanning\nneeds an LLM API key" not in readme
    assert "self-hosted" in readme, "the no-key path must be discoverable from the README"
    assert "docs/self-hosted-models.md" in readme

    # The claim the README now makes, pinned against the code that makes it true.
    keyless = {p for p, env in PROVIDER_ENV_VARS.items() if not env and p != "stub"}
    assert {"ollama", "vllm", "litellm-proxy"} <= keyless


def test_record_script_does_not_promise_a_ci_guard_that_does_not_exist() -> None:
    """`scripts/record_demo_fixtures.py` claimed CI hashes its trigger set.

    No such hash exists. A maintainer trusting that promise would skip a needed
    re-record and find out via a user's silent cache miss, which is precisely
    what the promise said could not happen.
    """
    raw = (_REPO_ROOT / "scripts" / "record_demo_fixtures.py").read_text(encoding="utf-8")
    # Whitespace-normalised: the docstring is hard-wrapped, so a literal match
    # would break on a reflow rather than on the claim actually returning.
    script = " ".join(raw.split())

    # Asserted positively. The docstring QUOTES the old false claim in order to
    # correct it, so "is this phrase absent?" cannot tell a retraction from a
    # reassertion -- only the presence of the correction can.
    assert "no such hash exists anywhere in the repo" in script
    assert "manual and trust-based" in script
    assert "do not rely on CI to notice" in script


# --- the same guard, pointed at verification/ (issue #138) -------------------
#
# `verification/runner.py` printed `mylonite scan --target-file <t> --json
# <report>`. `scan` has no `--json` flag, so anyone following the instruction
# verbatim got a usage error at exactly the point they were furthest from a
# working Layer 1 run.
#
# The machinery above parses every backtick-quoted `mylonite ...` example in a
# CLI epilog against the real CLI. `verification/` prints operator-facing
# invocations of its own, and README.md and docs/ carry the examples a reader is
# most likely to copy; all three are covered below.

_VERIFICATION_DIR = _REPO_ROOT / "verification"

#: Placeholder spellings that appear in these operator-facing strings. Click
#: parses them as ordinary values, so they need no special handling — but a
#: shell-metacharacter placeholder would break `shlex.split`, and that is worth
#: failing on, since it would also break the copy-paste it exists for.
_PLACEHOLDER_SAFE = re.compile(r"^[A-Za-z0-9 _\-./<>*={}$:,'\"\[\]]+$")


def _verification_mylonite_examples() -> list[tuple[str, str]]:
    """Every backtick-quoted or printed `mylonite ...` invocation under
    `verification/`, as (location, example) pairs."""
    found: list[tuple[str, str]] = []
    for path in sorted(_VERIFICATION_DIR.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        rel = path.relative_to(_REPO_ROOT).as_posix()
        for match in _BACKTICK_MYLONITE_RE.finditer(text):
            found.append((rel, match.group(1).strip()))
        # Printed instructions are not backticked, so also take any string
        # literal line that *starts* with the command.
        for raw in re.finditer(r'"(\s*mylonite [^"]+)"', text):
            candidate = raw.group(1).strip()
            if candidate not in {e for _, e in found}:
                found.append((rel, candidate))
    return found


def test_verification_prints_only_parseable_mylonite_commands() -> None:
    """Issue #138. Every `mylonite ...` invocation `verification/` shows an
    operator must parse against the real CLI."""
    examples = _verification_mylonite_examples()
    assert examples, (
        "collected no `mylonite ...` invocations under verification/ — the "
        "collector has drifted and this guard is now vacuous"
    )
    for location, example in examples:
        if not _PLACEHOLDER_SAFE.match(example):
            pytest.fail(f"{location}: {example!r} contains characters shlex cannot split")
        _assert_example_parses(location, example)


def test_verification_runner_no_longer_advertises_a_json_flag() -> None:
    """The specific regression: `scan --json` never existed."""
    source = (_VERIFICATION_DIR / "runner.py").read_text(encoding="utf-8")

    assert "scan --target-file <t> --json" not in source, (
        "the unparseable `mylonite scan ... --json <report>` instruction is back; "
        "scan writes into --output-dir and the Layer 1 scorer globs {family}*.json"
    )


# --- README.md and docs/ examples parse against the real CLI -----------------
#
# The epilog guard above covers examples embedded in `--help` output. The
# examples a reader is most likely to copy live in README.md and under docs/,
# and nothing parsed those: a renamed or removed flag could ship with the
# quickstart still advertising it. A README audit found several such drifts, all
# outside the guard's reach.

_README = _REPO_ROOT / "README.md"

#: Fenced-block languages that hold shell commands worth checking.
_SHELL_FENCES = ("bash", "sh", "shell", "console")


def _markdown_mylonite_examples() -> list[tuple[str, str]]:
    """Every `mylonite ...` invocation in README.md and docs/, as (where, cmd).

    Collects both backtick-quoted spans and lines inside shell fences. Skips
    `docs/superpowers/` (local working notes, not published) and `docs/reviews/`
    (point-in-time records that intentionally quote historical commands).
    """
    sources = [_README, *sorted(_DOCS_DIR.rglob("*.md"))]
    found: list[tuple[str, str]] = []
    for path in sources:
        parts = path.parts
        if "superpowers" in parts or "reviews" in parts:
            continue
        rel = path.relative_to(_REPO_ROOT).as_posix()
        text = path.read_text(encoding="utf-8")

        for match in _BACKTICK_MYLONITE_RE.finditer(text):
            found.append((rel, match.group(1).strip()))

        in_shell = False
        for raw in text.splitlines():
            stripped = raw.strip()
            if stripped.startswith("```"):
                lang = stripped[3:].strip().lower()
                in_shell = bool(lang) and lang in _SHELL_FENCES
                continue
            if in_shell and stripped.startswith("mylonite "):
                # Drop a trailing `# comment`, which these examples use heavily.
                command = stripped.split("#", 1)[0].strip()
                found.append((rel, command))
    return found


#: Characters `shlex` can split and Click can bind. A `$VAR`, a pipe or a
#: redirect means the line is a shell snippet rather than a single invocation,
#: and parsing it as one would fail for the wrong reason.
_PARSEABLE_EXAMPLE = re.compile(r"^[A-Za-z0-9 _\-./:@=,\"'<>\[\]{}*]+$")

#: Documentation templates rather than invocations: `mylonite COMMAND --help`,
#: `--target-file <path>`, `{version}`. Parsing these tells us nothing about
#: drift, because the placeholder is not meant to be a real token.
#: Commands that no longer exist and that the docs may still name on purpose, to
#: tell a reader where the functionality went. `cli-reference.md` carries such a
#: note for `init-target`, which became `scan --scaffold`. A migration note is
#: good documentation, so the guard must not treat it as drift — but it is listed
#: here explicitly, so a doc cannot quietly reference a removed command without
#: someone adding it to this set.
_GENERATED_DIR_RE = re.compile(r"\.mylonite[/\\]generated[/\\]([A-Za-z0-9_\-]+)")

_RETIRED_COMMANDS = frozenset({"init-target", "export", "doctor", "taxonomy"})

_TEMPLATE_PLACEHOLDER = re.compile(r"<[^>]*>|\{[^}]*\}|\b[A-Z][A-Z_]{1,}\b")


def _assert_command_exists(location: str, example: str) -> None:
    """Resolve `example` down to a real Click command without binding arguments.

    For a bare reference like `` `mylonite validate` `` in a command table, the
    claim being made is that the command exists — not that the bare form is a
    runnable invocation. `make_context` would reject it for a missing required
    argument, which says nothing about drift.
    """
    tokens = shlex.split(example)[1:]
    cmd = _click_command_tree()
    consumed: list[str] = []
    while tokens and getattr(cmd, "commands", None):
        name = tokens.pop(0)
        sub = cmd.commands.get(name)
        if sub is None:
            pytest.fail(
                f"{location}: {example!r} — {name!r} is not a known subcommand under "
                f"{'mylonite ' + ' '.join(consumed) if consumed else 'mylonite'} "
                f"(known: {sorted(cmd.commands)})"
            )
        consumed.append(name)
        cmd = sub
    assert consumed, f"{location}: {example!r} names no subcommand"


def _assert_markdown_example(location: str, example: str) -> None:
    """Prove `example` names a real command and only real options.

    Prose in these files references flags without values (`` `mylonite gate
    --authorize` ``) and commands without their required argument. Click tells
    the two cases apart for us: an unrecognised flag raises "No such option",
    while a recognised one missing its value raises "requires an argument", and
    an omitted positional raises "Missing parameter". The last two prove the flag
    or command exists, which is the drift this guard is for; only the first is a
    failure.
    """
    try:
        _assert_example_parses(location, example)
    except BaseException as exc:  # pytest.fail raises Failed, not Exception
        message = str(exc)
        tolerated = ("requires an argument", "Missing parameter", "Missing argument")
        if any(hint in message for hint in tolerated):
            return
        raise


def test_markdown_mylonite_examples_parse() -> None:
    """Every `mylonite ...` example in README.md and docs/ must resolve against the
    CURRENT CLI — the drift class a docs audit found repeatedly.

    An example carrying arguments is parsed in full, so a renamed or removed flag
    fails. A bare `mylonite <command>` reference is only resolved to its command,
    since a command table is naming the command, not demonstrating a run.
    """
    examples = _markdown_mylonite_examples()
    assert len(examples) >= 20, (
        f"collected only {len(examples)} `mylonite ...` examples from README.md and "
        "docs/; the collector has drifted and this guard is going vacuous"
    )
    checked_with_args = 0
    for location, example in examples:
        if not _PARSEABLE_EXAMPLE.match(example):
            continue  # a shell snippet, not a single invocation
        if _TEMPLATE_PLACEHOLDER.search(example):
            continue  # a documentation template, not an invocation
        tokens = shlex.split(example)[1:]
        if tokens and tokens[0] in _RETIRED_COMMANDS:
            continue  # a documented migration note, not a live invocation
        if len(tokens) == 1 and not tokens[0].startswith("-"):
            _assert_command_exists(location, example)
            continue
        _assert_markdown_example(location, example)
        checked_with_args += 1
    assert checked_with_args >= 10, (
        f"only {checked_with_args} example(s) with arguments were checked; the "
        "flag-drift half of this guard is going vacuous"
    )


def test_documented_generated_dirs_match_the_real_slug() -> None:
    """A `.mylonite/generated/<slug>` path that names a seed must equal what
    `generate` actually writes.

    `generate` slugifies a pattern id by mapping every non-alphanumeric character
    to `_`. The quickstart documented the hyphenated pattern id instead, so its
    third command failed with "path not found" — the headline three-command flow,
    broken by a character. Parsing alone could not catch it: the command parses
    fine, the *value* was wrong.

    Only a path naming a SEED is checkable. `--out` takes an arbitrary directory
    name, and `cli-reference.md` rightly shows `generated/my-finding` for it, so
    flagging every hyphen would be a false positive.
    """
    from mylonite.cli import _slugify_pattern
    from mylonite.scan.seeds import SEED_CATALOGUE

    pattern_ids = {seed.pattern_id for seed in SEED_CATALOGUE}
    offenders: list[str] = []
    for path in [_README, *sorted(_DOCS_DIR.rglob("*.md"))]:
        if "superpowers" in path.parts:
            continue
        rel = path.relative_to(_REPO_ROOT).as_posix()
        for match in _GENERATED_DIR_RE.finditer(path.read_text(encoding="utf-8")):
            slug = match.group(1)
            if slug in pattern_ids and slug != _slugify_pattern(slug):
                offenders.append(f"{rel}: {slug!r} -> should be {_slugify_pattern(slug)!r}")

    assert not offenders, "documented generated/ paths that `generate` never writes:\n" + "\n".join(
        offenders
    )


def test_documented_not_tested_outcomes_are_complete() -> None:
    """`docs/reading-results.md` lists the outcomes reported as NOT TESTED. Every
    outcome the code classifies that way must appear.

    The table had drifted to five of ten entries. `undecided` and
    `launch_failure` were both missing, so a user seeing `⚠ NO VERDICT` or
    `⚠ LAUNCH FAILED` had no documentation anywhere explaining what they mean —
    and these are precisely the marks that must not be read as a pass.
    """
    from mylonite.scan.coverage import ATTEMPT_CLASS

    not_tested = {outcome for outcome, cls in ATTEMPT_CLASS.items() if cls.name == "NOT_TESTED"}
    page = (_DOCS_DIR / "reading-results.md").read_text(encoding="utf-8")

    missing = sorted(outcome for outcome in not_tested if f"`{outcome}`" not in page)
    assert not missing, (
        f"docs/reading-results.md does not document these NOT-TESTED outcomes: {missing}. "
        "A reader who sees one in the output has nothing to look it up in."
    )
