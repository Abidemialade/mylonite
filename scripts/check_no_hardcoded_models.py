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
example strings and fixtures there legitimately name a model), line by line:

1. A provider-prefixed model literal: ``claude-``, ``gpt-``, ``gemini-``,
   ``ollama/``, ``anthropic/``, ``openai/``, ``bedrock/``.
2. A provider credential env var -- recognised the same way
   ``mylonite.scan.providers.looks_like_provider_env_var`` recognises one
   (the ``<PROVIDER>_API_KEY`` convention, the ``AZURE_*`` family, and the
   Bedrock credential pair), reused here rather than re-listing names so
   this check can never drift from what the CLI itself treats as a
   provider credential.

A hit is an error unless it is listed in
``scripts/hardcoded_models_allowlist.txt``. Each allowlist line names the
file, the line number, the exact text that was flagged, and the reason it is
there (the registry itself, the demo's pinned replay provider, an
error-remedy or docstring that names an env var for a human to set). The
entry is checked against the CURRENT line, not trusted blindly: if the named
line no longer contains the named text, the entry is stale and the check
fails, asking for it to be updated -- it can mask a different, unreviewed
hit otherwise.

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

# This file's own docstring and comments quote the patterns above to explain
# them, which would otherwise flag itself.
_SELF = Path(__file__).resolve()


@dataclass(frozen=True)
class Hit:
    path: str  # POSIX, relative to repo root
    line: int
    matched: str  # the exact substring that fired
    text: str  # the full line, for a readable report


@dataclass(frozen=True)
class AllowlistEntry:
    path: str
    line: int
    matched: str
    reason: str
    source_line: str  # for a clear parse error


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
        if path.resolve() == _SELF:
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
            for matched in _hits_in_line(line):
                hits.append(Hit(rel, lineno, matched, line.strip()))
    return hits


class AllowlistError(ValueError):
    pass


def parse_allowlist(text: str) -> list[AllowlistEntry]:
    """Parse ``scripts/hardcoded_models_allowlist.txt``.

    Format, one entry per line::

        <path>:<line>:<matched text> | <reason>

    Blank lines and lines starting with ``#`` are ignored. Every field is
    required -- an entry with no reason, or no matched text to re-check
    against the current line, is a parse error rather than a silent no-op,
    so a malformed edit fails loudly instead of quietly allowing nothing (or
    everything).
    """
    entries: list[AllowlistEntry] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "|" not in line:
            raise AllowlistError(f"missing ' | <reason>': {raw!r}")
        location, reason = line.split("|", 1)
        reason = reason.strip()
        if not reason:
            raise AllowlistError(f"empty reason: {raw!r}")
        parts = location.strip().split(":", 2)
        if len(parts) != 3:
            raise AllowlistError(f"expected '<path>:<line>:<matched text>': {raw!r}")
        path, lineno_text, matched = parts
        path = path.strip()
        matched = matched.strip()
        if not path or not matched:
            raise AllowlistError(f"empty path or matched text: {raw!r}")
        try:
            lineno = int(lineno_text.strip())
        except ValueError as exc:
            raise AllowlistError(f"line number is not an integer: {raw!r}") from exc
        entries.append(AllowlistEntry(path, lineno, matched, reason, raw))
    return entries


def load_allowlist(path: Path = ALLOWLIST_PATH) -> list[AllowlistEntry]:
    if not path.exists():
        return []
    return parse_allowlist(path.read_text(encoding="utf-8"))


def _allowed_key(entry: AllowlistEntry) -> tuple[str, int, str]:
    return (entry.path, entry.line, entry.matched)


def unmatched_hits(hits: list[Hit], entries: list[AllowlistEntry]) -> list[Hit]:
    """Hits not covered by any allowlist entry."""
    allowed = {_allowed_key(e) for e in entries}
    return [h for h in hits if (h.path, h.line, h.matched) not in allowed]


def stale_entries(hits: list[Hit], entries: list[AllowlistEntry]) -> list[AllowlistEntry]:
    """Allowlist entries that no longer match a real hit at that location --
    the line moved, was edited, or the matched text is gone."""
    live = {(h.path, h.line, h.matched) for h in hits}
    return [e for e in entries if _allowed_key(e) not in live]


def main(argv: list[str] | None = None) -> int:
    del argv
    hits = scan()
    try:
        entries = load_allowlist()
    except AllowlistError as exc:
        print(f"scripts/hardcoded_models_allowlist.txt is malformed: {exc}", file=sys.stderr)
        return 1

    problems = unmatched_hits(hits, entries)
    stale = stale_entries(hits, entries)

    if not problems and not stale:
        print(f"no hardcoded provider models or credential env vars ({len(entries)} allowlisted)")
        return 0

    if problems:
        print("Hardcoded provider model or credential env var found:\n", file=sys.stderr)
        for hit in problems:
            print(f"  {hit.path}:{hit.line}: {hit.matched!r} in: {hit.text}", file=sys.stderr)
        print(
            "\nUse mylonite.scan.providers / require_llm() instead of naming a provider "
            "directly, or add a line to scripts/hardcoded_models_allowlist.txt:\n"
            "  <path>:<line>:<matched text> | <reason>",
            file=sys.stderr,
        )
    if stale:
        if problems:
            print(file=sys.stderr)
        print(
            "Stale allowlist entries (the line no longer matches -- update or remove "
            "them; a stale entry can hide a different, unreviewed hit):\n",
            file=sys.stderr,
        )
        for entry in stale:
            print(f"  {entry.source_line}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
