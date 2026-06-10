"""Secret-shaped-token redaction for runtime logs and console-rendered reports.

This module implements the control that ``LoggingConfig.redact_secrets`` (default
on) promises and that ``SECURITY.md`` documents: secret-shaped strings are masked
before they reach a log record or a rendered CLI report.

Scope is deliberately narrow. Redaction applies to **runtime log records and
console-rendered strings ONLY**. It is *never* applied to persisted data that is
later parsed or replayed — recorded demo fixtures, persisted ``exploit_*.json`` /
``scan_report.json`` artefacts, or the generated test source — because masking
those would corrupt loadable/replayable data and break the
generate -> validate -> replay pipeline. By construction those persisted artefacts
are deterministic and contain no raw provider secrets; this filter is
defense-in-depth so that a future or accidental secret-shaped log line is masked.

The patterns are conservative on purpose: they match genuinely secret-shaped
tokens (provider key prefixes, AWS access-key ids, bearer tokens, PEM private-key
blocks, and ``key=value`` credential assignments) and deliberately do NOT match
plain emails, short words, attack strings, tool-call ids, or note ids.
"""

from __future__ import annotations

import logging
import re
from typing import Final

REDACTION_PLACEHOLDER: Final = "***REDACTED***"

__all__ = [
    "REDACTION_PLACEHOLDER",
    "SecretRedactingFilter",
    "install_log_redaction",
    "redact",
]

# Value shape shared by the key=value rule: long-ish credential-looking runs.
# 12+ chars of the credential alphabet — long enough to skip ordinary words.
_KV_VALUE = r"[A-Za-z0-9_\-./+]{12,}"

# Credential key names whose assigned value we mask (keeping the key name).
_KV_KEYS = r"api[_-]?key|apikey|secret|token|password"

# Whole-token patterns: each match is replaced wholesale by the placeholder.
_FULL_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    # Anthropic-style keys: sk-ant-<...>. Listed before the generic sk- rule so
    # the longer, more specific form wins.
    re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"),
    # Generic provider keys: sk-<20+ alnum>.
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    # AWS access key id.
    re.compile(r"AKIA[0-9A-Z]{16}"),
    # Bearer tokens (Authorization header style).
    re.compile(r"Bearer [A-Za-z0-9._-]{20,}"),
    # PEM private-key blocks (any key type), across newlines.
    re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        re.DOTALL,
    ),
)

# key=value / key: value credential assignments. The key name is preserved; only
# the value is masked. Case-insensitive on the key; the separator may be ``=`` or
# ``:`` with optional surrounding whitespace.
_KV_PATTERN: Final = re.compile(
    rf"(?P<key>{_KV_KEYS})(?P<sep>\s*[:=]\s*)(?P<val>{_KV_VALUE})",
    re.IGNORECASE,
)


def _mask_kv(match: re.Match[str]) -> str:
    return f"{match.group('key')}{match.group('sep')}{REDACTION_PLACEHOLDER}"


def redact(text: str) -> str:
    """Return ``text`` with secret-shaped tokens replaced by the placeholder.

    Non-``str`` inputs are returned unchanged (defensive). The operation is
    idempotent: redacting already-redacted text is a no-op because the
    placeholder matches none of the patterns.
    """
    if not isinstance(text, str):
        return text

    redacted = text
    for pattern in _FULL_PATTERNS:
        redacted = pattern.sub(REDACTION_PLACEHOLDER, redacted)
    redacted = _KV_PATTERN.sub(_mask_kv, redacted)
    return redacted


class SecretRedactingFilter(logging.Filter):
    """Logging filter that redacts secret-shaped tokens from each record.

    Renders the record's final message (applying any ``%`` args), runs
    :func:`redact`, and rewrites ``record.msg`` to the redacted text while
    clearing ``record.args`` so the redacted string is what handlers emit. Never
    drops a record.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # never let message formatting kill a log line
            return True
        record.msg = redact(message)
        record.args = ()
        return True


def install_log_redaction(enabled: bool = True, logger_name: str = "mylonite") -> None:
    """Install (or skip) the redacting filter on the ``mylonite`` logger tree.

    Idempotent: at most one :class:`SecretRedactingFilter` is ever attached to the
    named logger. When ``enabled`` is false this installs nothing and removes an
    existing filter if present, so the flag is honoured for library users who
    toggle it off.
    """
    target = logging.getLogger(logger_name)
    existing = [f for f in target.filters if isinstance(f, SecretRedactingFilter)]

    if not enabled:
        for flt in existing:
            target.removeFilter(flt)
        return

    if existing:
        return
    target.addFilter(SecretRedactingFilter())
