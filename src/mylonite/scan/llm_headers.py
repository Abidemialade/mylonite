"""Extra HTTP headers sent on every LLM request.

Some keys need a header beyond the key itself: an unscoped Anthropic key needs
its workspace id, and some gateways route on a header. The operator sets them
with ``--llm-header NAME=VALUE`` (repeatable) or the ``MYLONITE_LLM_HEADERS``
env var (comma-separated ``NAME=VALUE`` pairs). A flag wins over the env var
for the same name, compared case-insensitively.

Header values are treated as secrets. They go into the provider call
(``LLMPolicy.extra_headers``) and nowhere else: each one is registered with
:mod:`mylonite._redaction`, so ``redact()`` masks it in console messages and
in persisted error details, and no parse error here ever echoes any part of
an entry. In logs, the filters ``install_log_redaction`` adds mask it in the
message, exception traceback, stack info and string ``extra=`` fields of
records on the ``mylonite`` logger tree, on LiteLLM's ``LiteLLM`` and
``litellm`` loggers, and on records reaching the root logger's handlers and
Python's fallback stderr handler, and on handlers already attached to the
``mylonite`` loggers at installation. Not covered: a handler added after
installation, on any logger, for a record from a module logger created
after installation. Values shorter than four characters are not
registered (masking them would shred ordinary text).

The configured set is process-wide, like the request ceiling: the root CLI
callback configures it once per invocation.
"""

from __future__ import annotations

import os
import re
from collections.abc import Sequence
from typing import Final

from mylonite._redaction import clear_secret_values, register_secret_value

LLM_HEADERS_ENV: Final = "MYLONITE_LLM_HEADERS"

#: An HTTP header field name (RFC 9110 ``token``).
_HEADER_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")

LLMHeaders = tuple[tuple[str, str], ...]

_configured: LLMHeaders = ()


class InvalidLLMHeaderError(ValueError):
    """A malformed ``--llm-header`` or ``MYLONITE_LLM_HEADERS`` entry.

    The message names the source and the entry's position, never its value.
    """


def _parse_entry(entry: str, *, where: str) -> tuple[str, str]:
    """Split one ``NAME=VALUE`` entry. Errors name only ``where`` and the
    expected form: a malformed entry may be a secret in another shape (a
    curl-style ``Name: value``), so no part of it is ever echoed."""
    name, sep, value = entry.partition("=")
    name, value = name.strip(), value.strip()
    if not sep or not name or not value:
        raise InvalidLLMHeaderError(
            f"{where}: malformed -- expected NAME=VALUE with a non-empty name and value"
        )
    if not _HEADER_NAME.match(name):
        raise InvalidLLMHeaderError(
            f"{where}: malformed -- the text before '=' is not a valid HTTP header name "
            "(use NAME=VALUE, not 'Name: value')"
        )
    if "\r" in value or "\n" in value:
        raise InvalidLLMHeaderError(f"{where}: malformed -- the value has a line break")
    return name, value


def parse_llm_headers(cli_values: Sequence[str] | None, env_value: str | None) -> LLMHeaders:
    """Parse the env var then the flags into ``(name, value)`` pairs.

    A flag replaces an env entry with the same name (case-insensitive). Order
    is env entries first, then flags, each in the order given.
    """
    merged: dict[str, tuple[str, str]] = {}
    if env_value:
        for index, entry in enumerate(env_value.split(","), start=1):
            if not entry.strip():
                continue
            pair = _parse_entry(entry, where=f"{LLM_HEADERS_ENV} entry {index}")
            merged[pair[0].lower()] = pair
    for index, entry in enumerate(cli_values or (), start=1):
        pair = _parse_entry(entry, where=f"--llm-header #{index}")
        merged.pop(pair[0].lower(), None)
        merged[pair[0].lower()] = pair
    return tuple(merged.values())


def configure_llm_headers(cli_values: Sequence[str] | None) -> LLMHeaders:
    """Set the process-wide headers from the flags and the env var.

    Raises :class:`InvalidLLMHeaderError` on a malformed entry, leaving nothing
    configured. Also forgets which models the key preflight already proved,
    since a different header set can change the answer.
    """
    reset_llm_headers()
    headers = parse_llm_headers(cli_values, os.environ.get(LLM_HEADERS_ENV))
    global _configured
    _configured = headers
    for _name, value in headers:
        register_secret_value(value)
    return headers


def configured_llm_headers() -> LLMHeaders:
    """The headers configured for this run, or ``()``."""
    return _configured


def reset_llm_headers() -> None:
    """Forget the configured headers, their redaction, and the preflight memo."""
    global _configured
    _configured = ()
    clear_secret_values()
    from mylonite.scan.auth_preflight import reset_auth_preflight
    from mylonite.scan.providers import reset_emitted_warnings

    reset_auth_preflight()
    reset_emitted_warnings()
