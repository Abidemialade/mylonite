#!/usr/bin/env python3
"""Fail when product code names a provider's model or reads its credential
env var directly, outside the approved-provider registry.

Why this exists
----------------
CLAUDE.md's "no default provider" rule (2026-09-30): never hardcode a
provider/model default or assume ``ANTHROPIC_API_KEY`` is set.
``mylonite.scan.providers`` is the one registry allowed to name providers and
their credential env vars; ``mylonite.config.MyloniteSettings.require_llm()``
is the one place that decides there is no default. Everything else should
receive a model/provider through that registry rather than spelling one out,
so a new hardcoded default anywhere in ``src/mylonite`` is exactly the defect
this rule exists to prevent, and nothing before this check caught it
mechanically.

What it flags
--------------
Every ``*.py`` file under ``src/mylonite`` (never ``tests/`` or ``docs/`` --
example strings and fixtures there legitimately name a model), per occurrence:

1. A provider-prefixed model literal: ``claude-``, ``gpt-``, ``gemini-``,
   ``ollama/``, ``anthropic/``, ``openai/``, ``bedrock/``.
2. A provider credential env var -- recognised the same way
   ``mylonite.scan.providers.looks_like_provider_env_var`` recognises one
   (the ``<PROVIDER>_API_KEY`` convention, the ``AZURE_*`` family, and the
   Bedrock credential pair), reused here rather than re-listing names so
   this check can never drift from what the CLI itself treats as a
   provider credential.

Two exemption mechanisms (2026-10, REG-1b: the allowlist file is now EMPTY
for ``src/`` -- every hit is fixed outright or exempted one of these two ways)
----------------------------------------------------------------------------
1. **By path.** :mod:`mylonite.providers.registry` (the approved-provider
   registry -- naming a provider's model prefix/credential env var(s) is its
   whole job) and :mod:`mylonite._redaction` (whose secret-SHAPE patterns and
   gate-runner-secret comments legitimately quote a provider credential var,
   never choose one for the user) are skipped entirely, like this script
   skips itself.
2. **By inline marker, for a help/docstring/comment line that shows an
   EXAMPLE model id or env var** (never a functional default/credential
   read): append ``# allow-literal: example`` to that physical line. A line
   carrying the marker is excluded from scanning altogether -- its hits never
   reach the allowlist logic below. This is deliberately a PER-LINE marker,
   not a file-wide or block one: it says "this exact line is an example",
   nothing broader, so it can't accidentally excuse a real default added
   later in the same function.

``scripts/hardcoded_models_allowlist.txt`` still exists for anything that is
neither of the above (a functional reason the marker/path exemptions don't
fit) -- one entry per line::

    <path> | <matched text or a stable regex> | <count> | <reason>

Deliberately NOT line-number-keyed. An earlier version was, and that meant
an unrelated edit anywhere ABOVE an allowlisted line -- adding a function, a
docstring paragraph, anything -- silently shifted every line number below it
and broke the check on a file nobody touched. That is exactly the kind of
"required check blocks an unrelated change" failure a solo maintainer's own
condition rules out (`nr-ci` is meant to be safe to mark required). Matching
is now by file + the matched text itself (or a regex covering more than one
literal spelling), with a count of how many times it is expected to appear in
that file. The check fails only when:

* a file holds a matched occurrence that no entry's pattern covers at all
  ("new hit" -- flag it, fix it, or add an entry), or
* a file holds MORE occurrences of a covered pattern than the entry's
  ``count`` allows ("more matches than allowed" -- a new, unreviewed
  occurrence slipped in alongside the ones already excused).

It never looks at which line anything is on, so inserting, deleting or moving
lines anywhere in the file is invisible to it. A stale entry (its pattern no
longer matches ANYTHING in the named file -- the text it was excusing is
gone) is also reported, so the list doesn't accumulate dead rows.

Usage::

    python scripts/check_no_hardcoded_models.py
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = ROOT / "src" / "mylonite"
ALLOWLIST_PATH = ROOT / "scripts" / "hardcoded_models_allowlist.txt"

#: Provider-prefixed model literals. Deliberately this exact, short list --
#: see the module docstring. A plain "anthropic" or "openai" with no
#: following "/" is not flagged: that matches ordinary prose ("the anthropic
#: provider") far more often than a hardcoded model string.
_MODEL_LITERAL_RE = re.compile(r"claude-|gpt-|gemini-|ollama/|anthropic/|openai/|bedrock/")

#: Candidate env-var-shaped identifiers: ALL_CAPS_WITH_UNDERSCORES, at least
#: two words. Each candidate is then checked against
#: ``looks_like_provider_env_var`` -- see the module docstring for why that
#: reuse matters.
_CAPS_TOKEN_RE = re.compile(r"\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\b")

#: A line carrying this marker is skipped entirely -- see the module
#: docstring's "by inline marker" exemption. Checked as a plain substring
#: (not a regex) against the RAW line, so it also works inside a triple-
#: quoted docstring, where it isn't a real Python comment but is still an
#: unambiguous, grep-able "this line is an example" marker.
_ALLOW_LITERAL_MARKER = "# allow-literal: example"

# This file's own docstring and comments quote the patterns above to explain
# them, which would otherwise flag itself.
_SELF = Path(__file__).resolve()

# The two by-path exemptions -- see the module docstring's "by path" section.
# mylonite.providers.registry is the one module allowed to name a provider's
# model prefix or credential env var(s) BY DESIGN -- that's its whole job
# (see its own module docstring). mylonite._redaction's secret-SHAPE pattern
# definitions and gate-runner-secret comments legitimately quote a provider
# credential var without ever choosing one for the user. Exempting both by
# path keeps this check from needing a growing block of rows that would just
# restate what those modules' own docstrings already explain; everywhere
# else, a hit still means "fix it or mark it as an example."
_REGISTRY_PATH = (ROOT / "src" / "mylonite" / "providers" / "registry.py").resolve()
_REDACTION_PATH = (ROOT / "src" / "mylonite" / "_redaction.py").resolve()


@dataclass(frozen=True)
class Hit:
    path: str  # POSIX, relative to repo root
    line: int  # diagnostic only -- never part of allowlist matching
    matched: str  # the exact substring that fired
    text: str  # the full line, for a readable report


@dataclass(frozen=True)
class AllowlistEntry:
    path: str
    pattern: str  # literal matched text, or a regex covering more than one
    count: int  # how many occurrences of `pattern` are expected in `path`
    reason: str
    source_line: str  # for a clear parse error / report


def _provider_env_var_matches(line: str) -> list[str]:
    from mylonite.scan.providers import looks_like_provider_env_var

    return [token for token in _CAPS_TOKEN_RE.findall(line) if looks_like_provider_env_var(token)]


def _hits_in_line(line: str) -> list[str]:
    matches = [m.group(0) for m in _MODEL_LITERAL_RE.finditer(line)]
    matches.extend(_provider_env_var_matches(line))
    return matches


def iter_py_files(root: Path = SRC_ROOT) -> list[Path]:
    return sorted(root.rglob("*.py"))


def scan(root: Path = SRC_ROOT) -> list[Hit]:
    hits: list[Hit] = []
    for path in iter_py_files(root):
        if path.resolve() in (_SELF, _REGISTRY_PATH, _REDACTION_PATH):
            continue
        resolved = path.resolve()
        try:
            # The usual case: scanning the real src/mylonite tree, reported
            # relative to the repo root ("src/mylonite/cli.py").
            rel = resolved.relative_to(ROOT).as_posix()
        except ValueError:
            # A caller-supplied root outside the repo (tests, against a
            # synthetic tmp_path tree) -- report relative to that root instead.
            rel = resolved.relative_to(root.resolve()).as_posix()
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if _ALLOW_LITERAL_MARKER in line:
                continue
            for matched in _hits_in_line(line):
                hits.append(Hit(rel, lineno, matched, line.strip()))
    return hits


class AllowlistError(ValueError):
    pass


def parse_allowlist(text: str) -> list[AllowlistEntry]:
    """Parse ``scripts/hardcoded_models_allowlist.txt``.

    Format, one entry per line::

        <path> | <matched text or a stable regex> | <count> | <reason>

    Blank lines and lines starting with ``#`` are ignored. Every field is
    required and ``count`` must be a positive integer -- a malformed edit
    fails loudly rather than quietly allowing nothing (or everything).
    """
    entries: list[AllowlistEntry] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # A regex pattern may itself contain "|" (alternation, e.g.
        # ``AZURE_API_(BASE|VERSION)``), so a plain 4-way split on "|" would
        # misparse it. `path` is always the first segment and `reason` the
        # last; `count` is the second-to-last; everything in between is the
        # pattern, rejoined with "|" if it was itself split.
        fields = [f.strip() for f in line.split("|")]
        if len(fields) < 4:
            raise AllowlistError(
                f"expected '<path> | <matched text or regex> | <count> | <reason>': {raw!r}"
            )
        path = fields[0]
        reason = fields[-1]
        count_text = fields[-2]
        pattern = "|".join(fields[1:-2]).strip()
        if not path or not pattern or not reason:
            raise AllowlistError(f"empty path, pattern or reason: {raw!r}")
        try:
            count = int(count_text)
        except ValueError as exc:
            raise AllowlistError(f"count is not an integer: {raw!r}") from exc
        if count < 1:
            raise AllowlistError(f"count must be >= 1: {raw!r}")
        try:
            re.compile(pattern)
        except re.error as exc:
            raise AllowlistError(f"invalid regex {pattern!r}: {raw!r}") from exc
        entries.append(AllowlistEntry(path, pattern, count, reason, raw))
    return entries


def load_allowlist(path: Path = ALLOWLIST_PATH) -> list[AllowlistEntry]:
    if not path.exists():
        return []
    return parse_allowlist(path.read_text(encoding="utf-8"))


def _entry_covers(entry: AllowlistEntry, hit: Hit) -> bool:
    return entry.path == hit.path and re.fullmatch(entry.pattern, hit.matched) is not None


def count_for_entry(hits: list[Hit], entry: AllowlistEntry) -> int:
    """How many scanned occurrences this entry's pattern actually covers."""
    return sum(1 for h in hits if _entry_covers(entry, h))


def unmatched_hits(hits: list[Hit], entries: list[AllowlistEntry]) -> list[Hit]:
    """Hits that no allowlist entry's pattern covers at all, at that path."""
    return [h for h in hits if not any(_entry_covers(e, h) for e in entries)]


def over_limit_entries(
    hits: list[Hit], entries: list[AllowlistEntry]
) -> list[tuple[AllowlistEntry, int]]:
    """Entries whose pattern now matches MORE occurrences than ``count`` allows."""
    out = []
    for entry in entries:
        actual = count_for_entry(hits, entry)
        if actual > entry.count:
            out.append((entry, actual))
    return out


def stale_entries(hits: list[Hit], entries: list[AllowlistEntry]) -> list[AllowlistEntry]:
    """Entries whose pattern no longer matches ANYTHING in the named file."""
    return [e for e in entries if count_for_entry(hits, e) == 0]


def main(argv: list[str] | None = None) -> int:
    del argv
    hits = scan()
    try:
        entries = load_allowlist()
    except AllowlistError as exc:
        print(f"scripts/hardcoded_models_allowlist.txt is malformed: {exc}", file=sys.stderr)
        return 1

    problems = unmatched_hits(hits, entries)
    over_limit = over_limit_entries(hits, entries)
    stale = stale_entries(hits, entries)

    if not problems and not over_limit and not stale:
        print(f"no hardcoded provider models or credential env vars ({len(entries)} allowlisted)")
        return 0

    if problems:
        print("Hardcoded provider model or credential env var found:\n", file=sys.stderr)
        for hit in problems:
            print(f"  {hit.path}:{hit.line}: {hit.matched!r} in: {hit.text}", file=sys.stderr)
        print(
            "\nUse mylonite.scan.providers / require_llm() instead of naming a provider "
            "directly, or add a line to scripts/hardcoded_models_allowlist.txt:\n"
            "  <path> | <matched text or a stable regex> | <count> | <reason>",
            file=sys.stderr,
        )
    if over_limit:
        if problems:
            print(file=sys.stderr)
        print(
            "More occurrences than the allowlist expects (a new, unreviewed one "
            "slipped in alongside the excused ones):\n",
            file=sys.stderr,
        )
        for entry, actual in over_limit:
            print(f"  {entry.source_line}  (found {actual})", file=sys.stderr)
    if stale:
        if problems or over_limit:
            print(file=sys.stderr)
        print(
            "Stale allowlist entries (the pattern no longer matches anything in that "
            "file -- update or remove them):\n",
            file=sys.stderr,
        )
        for entry in stale:
            print(f"  {entry.source_line}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
