"""Two-way ratchet between seven stability-promised registries and the docs
pages that describe them: the CLI's flags, the `mylonite.testkit` public
surface, the reason-code registry, the process exit-code enum, every
`MYLONITE_*` environment variable `src/` reads, every `target.yaml` field,
and the approved-provider registry.

"Two-way" means each registry is checked in both directions:

* **forward** — every live entry (a non-hidden CLI flag, a `testkit.__all__`
  name, a reason code, an exit code, an env var, a `target.yaml` field, a
  provider id) has a mention in its docs page. A gap here is a reader who
  runs `--help` (or hits a code, or reads a field in `target_file.py`) and
  finds nothing written down for it — the drift class issue #209 reported
  for the CLI (`cli-reference.md` was missing several flags `--help` already
  showed).
* **backward** — every CLI-flag-shaped (`--xxx`) token, testkit name,
  `MYL-xxx-nnn` heading, exit code, `MYLONITE_*` token, `target.yaml` key or
  provider id the docs page carries actually exists. A gap here is a reader
  who copies a flag, name or key from the docs and it doesn't work — the
  drift class `tests/test_docs_consistency.py` already guards for specific
  past incidents (`--prove-control`, `--runs`, a stale `.mylonite/validated`
  path); this is the same idea applied uniformly to every registry here.

Reason codes are checked here in both directions, using the shared
heading-parsing helper (`tests._doc_registry_sync`), in the same parametrised
sweep as the other registries, so they all live under one ratchet with
one allowlist. (An older standalone check in `test_docs_consistency.py` was
retired as a duplicate of this row.)

The exit-code, env-var, `target.yaml`-field and provider rows below are the
same shape, added once each registry existed and the CLI/testkit/reason-code
rows had already proven the pattern out (DOC-B-2). The provider row reuses
`scripts/gen_provider_table.py`'s own committed-table parsing rather than
re-deriving it — that script (and `tests/test_choose_a_model_docs.py`) is
already the stricter, byte-exact ratchet for that one page; this row only
adds it to the same parametrised sweep and allowlist as everything else.

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
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml
from tests._doc_registry_sync import markdown_sections_by_heading, reason_code_headings
from typer.main import get_command

from mylonite import exit_codes, reason_codes, testkit
from mylonite._experimental import ENV_VAR as _EXPERIMENTAL_ENV
from mylonite.cli import app
from mylonite.config import _EnvRunConfig
from mylonite.layout import ROOT_ENV_VAR as _ROOT_ENV
from mylonite.plugins._mcp.target_file import TargetFile
from mylonite.plugins._mcp.target_registry import (
    CalibrationSettings,
    ControlConfig,
    EffectProbeSpec,
    LaunchOverride,
    RequestSpec,
    SeedArmSpec,
)
from mylonite.providers.registry import PROVIDERS
from mylonite.scan._llm import REQUEST_CEILING_ENV
from mylonite.scan.assembly import ATTACK_MODULES_ENV
from mylonite.scan.llm_headers import LLM_HEADERS_ENV
from mylonite.testkit import REDRIVE_ATTEMPTS_ENV
from mylonite.testkit._pytest_plugin import REQUIRE_GATE_RUN_ENV

_REPO_ROOT = Path(__file__).resolve().parents[1]
_DOCS_DIR = _REPO_ROOT / "docs"
_ALLOWLIST_PATH = Path(__file__).parent / "fixtures" / "docs_ratchet_allowlist.json"

# `scripts/` is not a package; added to `sys.path` the same way
# `tests/test_choose_a_model_docs.py` already does, so the providers row below
# reuses that script's own table parsing instead of a second copy of it.
_SCRIPTS_DIR = _REPO_ROOT / "scripts"
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))
import gen_provider_table  # noqa: E402

#: The allowlist may only shrink. Lower these whenever a gap is fixed for
#: real (the preferred outcome) or a stale entry is deleted; raise one only
#: in the same PR that adds a new, reasoned allowlist entry for that
#: registry -- never to make silent room for an unreviewed gap.
_CEILINGS: dict[str, int] = {
    "cli_flags": 0,
    "testkit": 0,
    "reason_codes": 0,
    "exit_codes": 0,
    "env_vars": 0,
    "target_yaml_fields": 0,
    "providers": 0,
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


# --- exit codes --------------------------------------------------------------
#
# Canonical page: "## Exit codes (for CI)" in reading-results.md -- the table
# `docs/ci-gating.md` itself points at as "the full table" (its own "### Exit
# codes" section is a deliberately partial, gate-only subset, never meant to
# list every code). Forward: every exit_codes.py code is a row there.
# Backward: every row there is a real code -- catches a stray/renumbered row
# the same way the CLI check catches a stale flag.

_READING_RESULTS_DOC_PATH = _DOCS_DIR / "reading-results.md"
_EXIT_CODE_HEADING = "Exit codes (for CI)"
_EXIT_CODE_ROW_RE = re.compile(r"^\|\s*([0-9]+)\s*\|", re.MULTILINE)


def _live_exit_codes() -> set[int]:
    """Every ``EXIT_*`` constant in :mod:`mylonite.exit_codes` -- live, so a
    new code (like ``9``/``10`` were) is picked up with no edit here."""
    return {
        value
        for name, value in vars(exit_codes).items()
        if name.startswith("EXIT_") and isinstance(value, int)
    }


def _exit_code_doc_rows() -> set[int]:
    sections = markdown_sections_by_heading(_READING_RESULTS_DOC_PATH.read_text(encoding="utf-8"))
    section = sections.get(_EXIT_CODE_HEADING, "")
    return {int(code) for code in _EXIT_CODE_ROW_RE.findall(section)}


def _exit_codes_forward_gaps() -> list[str]:
    rows = _exit_code_doc_rows()
    return sorted(f"undocumented:{code}" for code in _live_exit_codes() if code not in rows)


def _exit_codes_backward_gaps() -> list[str]:
    live = _live_exit_codes()
    return sorted(f"stale-doc:{code}" for code in _exit_code_doc_rows() if code not in live)


# --- MYLONITE_* environment variables ----------------------------------------
#
# Live set: the flat run-config vars pydantic-settings derives from
# `_EnvRunConfig.model_fields` (env_prefix="MYLONITE_", no nested delimiter --
# see config.py), plus every other MYLONITE_* name `src/` reads directly via
# `os.environ`, each imported from its own module's named constant so this
# can't drift from the real read site. Three names (below) have no named
# constant -- `os.environ.get("MYLONITE_...")` is called with the literal
# string inline -- so they're listed by hand, each with the file:line that
# reads it.
#
# Forward/backward scan the whole `docs/` tree, not one page: unlike the
# other registries here, these vars are legitimately documented wherever the
# command that reads them is (testkit.md, ci-gating.md, experimental.md,
# enterprise-networking.md, ...), not on one canonical page.

_DIRECT_ENV_VAR_LITERALS: frozenset[str] = frozenset(
    {
        "MYLONITE_NO_TRUSTSTORE",  # _bootstrap.py -- os.environ.get("MYLONITE_NO_TRUSTSTORE")
        "MYLONITE_FS_SCOPE_ROOT",  # plugins/_mcp/target_registry.py -- same, inline literal
        "MYLONITE_LIVE_TARGET",  # plugins/_reference/reference_pytest_generator.py -- same
    }
)

#: Names that are `MYLONITE_`-prefixed but are NOT one of `src/`'s own fixed
#: env var reads, so the backward check must not flag them as stale:
#: `MYLONITE_API_KEY` is a CI secret NAME convention the scaffolded gate
#: workflow docs/templates name (mapped to whichever provider's real key the
#: run needs; see `scan/providers.py`'s `looks_like_provider_env_var`), and
#: `MYLONITE_AUTHORIZE` is a `vars`/shell variable inside the generated
#: discovery workflow YAML (`gate/templates/mylonite-discovery.yml`) -- CI
#: configuration, not something Mylonite's own Python ever reads from
#: `os.environ`.
_NOT_A_FIXED_ENV_VAR: frozenset[str] = frozenset({"MYLONITE_API_KEY", "MYLONITE_AUTHORIZE"})

#: `${MYLONITE_TARGET_...}` is the dynamically-named placeholder
#: `redact_target_yaml` mints for a masked secret (one per credential field,
#: e.g. `MYLONITE_TARGET_ENV_GITHUB_TOKEN`) -- never a fixed name `src/`
#: reads by itself, so any token with this prefix is exempt from the
#: backward check the same way `_NOT_A_MYLONITE_FLAG` exempts non-flag tokens
#: from the CLI check above.
_DYNAMIC_ENV_VAR_PREFIX = "MYLONITE_TARGET_"

_ENV_VAR_TOKEN_RE = re.compile(r"\bMYLONITE_[A-Z0-9_]+\b")


def _live_env_vars() -> frozenset[str]:
    flat = {f"MYLONITE_{name.upper()}" for name in _EnvRunConfig.model_fields}
    named = {
        ATTACK_MODULES_ENV,
        LLM_HEADERS_ENV,
        REQUEST_CEILING_ENV,
        REQUIRE_GATE_RUN_ENV,
        REDRIVE_ATTEMPTS_ENV,
        _ROOT_ENV,
        _EXPERIMENTAL_ENV,
    }
    return frozenset(flat | named | _DIRECT_ENV_VAR_LITERALS)


def _env_var_doc_tokens() -> set[str]:
    text = "\n".join(p.read_text(encoding="utf-8") for p in sorted(_DOCS_DIR.glob("*.md")))
    return set(_ENV_VAR_TOKEN_RE.findall(text))


def _env_vars_forward_gaps() -> list[str]:
    tokens = _env_var_doc_tokens()
    return sorted(f"undocumented:{var}" for var in _live_env_vars() if var not in tokens)


def _env_vars_backward_gaps() -> list[str]:
    live = _live_env_vars()
    tokens = _env_var_doc_tokens()
    stale = (
        t
        for t in tokens
        if t not in live
        and t not in _NOT_A_FIXED_ENV_VAR
        and not t.startswith(_DYNAMIC_ENV_VAR_PREFIX)
    )
    return sorted(f"stale-doc:{t}" for t in stale)


# --- target.yaml fields -------------------------------------------------------
#
# Live set: every Pydantic field across the 7 models a target.yaml can
# declare (TargetFile itself, plus the 6 nested specs) -- `source_dir` is
# excluded, it's derived bookkeeping `load_target_file` always overwrites,
# never something a target.yaml author sets (see TargetFile's own docstring).
#
# Forward: each field name is mentioned (anywhere -- the page uses backtick
# inline code almost everywhere a field is named) on target-file.md OR
# http-agent.md -- `RequestSpec`'s `method`/`response_path` are the `rest`
# transport's own fields and are documented on http-agent.md, which
# target-file.md itself points readers at for that transport, rather than
# duplicated onto target-file.md.
#
# Backward: schema-aware, not a flat token scan -- a field name alone (e.g.
# `env`, `tool`, `body`) is far too common an English/YAML word for a flat
# scan to tell a real stale field from an ordinary dict key or sentence.
# Every fenced ```yaml block on both pages is actually parsed, and only keys
# at a position this schema says is a model field are checked; the three
# opaque dict fields (`env`, `headers`, `control_env`) and the two ad-hoc
# payload dicts (`args_template`, `verify_args_template`, `description_pins`)
# hold the AUTHOR's own arbitrary keys (an env var name, an HTTP header, a
# per-class env toggle, a JSON field) and are never recursed into.

_TARGET_FILE_DOC_PATHS: tuple[Path, ...] = (
    _DOCS_DIR / "target-file.md",
    _DOCS_DIR / "http-agent.md",
)

_TARGET_YAML_SCHEMAS: dict[str, frozenset[str]] = {
    "TargetFile": frozenset(TargetFile.model_fields) - {"source_dir"},
    "SeedArmSpec": frozenset(SeedArmSpec.model_fields),
    "EffectProbeSpec": frozenset(EffectProbeSpec.model_fields),
    "CalibrationSettings": frozenset(CalibrationSettings.model_fields),
    "ControlConfig": frozenset(ControlConfig.model_fields),
    "LaunchOverride": frozenset(LaunchOverride.model_fields),
    "RequestSpec": frozenset(RequestSpec.model_fields),
}

#: TargetFile field name -> the nested model schema it holds, for the
#: backward walker to recurse into.
_TARGET_YAML_NESTED_MODELS: dict[str, str] = {
    "seed_arm": "SeedArmSpec",
    "effect_probe": "EffectProbeSpec",
    "calibration": "CalibrationSettings",
    "control_config": "ControlConfig",
    "vulnerable_launch": "LaunchOverride",
    "request": "RequestSpec",
}

#: Fields whose VALUE is the target.yaml author's own arbitrary mapping
#: (an env var name, an HTTP header, a per-weakness-class env toggle, a JSON
#: request/result template) -- never walked for "is this key a real field".
_TARGET_YAML_OPAQUE_DICT_FIELDS: frozenset[str] = frozenset(
    {"env", "headers", "control_env", "args_template", "verify_args_template", "description_pins"}
)


def _live_target_yaml_fields() -> frozenset[str]:
    fields: set[str] = set()
    for names in _TARGET_YAML_SCHEMAS.values():
        fields |= names
    return frozenset(fields)


def _target_yaml_doc_text() -> str:
    return "".join(p.read_text(encoding="utf-8") for p in _TARGET_FILE_DOC_PATHS)


def _target_yaml_forward_gaps() -> list[str]:
    text = _target_yaml_doc_text()
    return sorted(
        f"undocumented:{field}"
        for field in _live_target_yaml_fields()
        if not re.search(rf"\b{re.escape(field)}\b", text)
    )


def _target_yaml_fenced_blocks() -> list[dict[str, Any]]:
    """Every fenced ```yaml block on the target.yaml doc pages, parsed."""
    blocks: list[dict[str, Any]] = []
    for path in _TARGET_FILE_DOC_PATHS:
        for raw in re.findall(r"```yaml\n(.*?)```", path.read_text(encoding="utf-8"), re.DOTALL):
            data = yaml.safe_load(raw)
            if isinstance(data, dict):
                blocks.append(data)
    return blocks


def _target_yaml_backward_gaps() -> list[str]:
    gaps: list[str] = []

    def _walk(node: dict[str, Any], schema: str) -> None:
        for key, value in node.items():
            if key not in _TARGET_YAML_SCHEMAS[schema]:
                gaps.append(f"stale-doc:{schema}.{key}")
                continue
            if key in _TARGET_YAML_OPAQUE_DICT_FIELDS:
                continue
            nested_schema = _TARGET_YAML_NESTED_MODELS.get(key)
            if nested_schema is not None and isinstance(value, dict):
                _walk(value, nested_schema)

    for block in _target_yaml_fenced_blocks():
        _walk(block, "TargetFile")
    return sorted(gaps)


# --- approved providers -------------------------------------------------------
#
# Reuses `scripts/gen_provider_table.py`'s own committed-table markers rather
# than re-deriving the render -- `tests/test_choose_a_model_docs.py` already
# enforces a byte-exact match between the registry and this table (the
# stricter check); this row only adds the same registry to this ratchet's
# parametrised sweep and allowlist, by presence rather than exact rendering.

_PROVIDER_TABLE_ROW_RE = re.compile(r"^\| ([a-z0-9_-]+) \|", re.MULTILINE)


def _providers_committed_table() -> str:
    text = gen_provider_table.DOC_PATH.read_text(encoding="utf-8")
    begin = text.index(gen_provider_table.BEGIN_MARKER) + len(gen_provider_table.BEGIN_MARKER)
    end = text.index(gen_provider_table.END_MARKER)
    return text[begin:end]


def _providers_forward_gaps() -> list[str]:
    table = _providers_committed_table()
    return sorted(
        f"undocumented:{provider_id}"
        for provider_id in PROVIDERS
        if f"| {provider_id} |" not in table
    )


def _providers_backward_gaps() -> list[str]:
    table = _providers_committed_table()
    ids = set(_PROVIDER_TABLE_ROW_RE.findall(table))
    return sorted(f"stale-doc:{provider_id}" for provider_id in ids if provider_id not in PROVIDERS)


# --- the sweep ---------------------------------------------------------------

_GAP_FUNCS: dict[str, tuple[Any, Any]] = {
    "cli_flags": (_cli_forward_gaps, _cli_backward_gaps),
    "testkit": (_testkit_forward_gaps, _testkit_backward_gaps),
    "reason_codes": (_reason_codes_forward_gaps, _reason_codes_backward_gaps),
    "exit_codes": (_exit_codes_forward_gaps, _exit_codes_backward_gaps),
    "env_vars": (_env_vars_forward_gaps, _env_vars_backward_gaps),
    "target_yaml_fields": (_target_yaml_forward_gaps, _target_yaml_backward_gaps),
    "providers": (_providers_forward_gaps, _providers_backward_gaps),
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
