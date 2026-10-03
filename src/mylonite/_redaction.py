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
from collections.abc import Callable
from typing import Final

REDACTION_PLACEHOLDER: Final = "***REDACTED***"

__all__ = [
    "CREDENTIAL_ENV_FIELD",
    "CREDENTIAL_NESTED_SECTIONS",
    "CREDENTIAL_TOP_LEVEL_SECTIONS",
    "REDACTION_PLACEHOLDER",
    "SecretRedactingFilter",
    "clear_masked_values",
    "install_log_redaction",
    "is_unresolved_var_placeholder",
    "looks_like_api_key",
    "looks_like_credential_arg",
    "mask_registered_values",
    "redact",
    "redact_env",
    "redact_exception",
    "redact_target_yaml",
    "redact_url_query",
    "redact_value",
    "register_masked_value",
    "target_env_refs",
    "target_file_var_names",
    "target_masked_fields",
    "target_yaml_env_ref_name",
]

# Value shape shared by the key=value rule: long-ish credential-looking runs.
# 12+ chars of the credential alphabet — long enough to skip ordinary words.
_KV_VALUE = r"[A-Za-z0-9_\-./+]{12,}"

# Credential key names whose assigned value we mask (keeping the key name).
_KV_KEYS = r"api[_-]?key|apikey|secret|token|password|passwd|pwd|credential"

# Whole-token patterns: each match is replaced wholesale by the placeholder.
_FULL_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    # Anthropic-style keys: sk-ant-<...>. Listed before the generic sk- rule so
    # the longer, more specific form wins.
    re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"),
    # Generic provider keys: sk-<20+ chars>, hyphens and underscores included,
    # so a project-scoped key (sk-proj-...) is caught whole. Not preceded by a
    # letter or digit, so ordinary words ending in "sk" ("risk-...") survive.
    re.compile(r"(?<![A-Za-z0-9])sk-[A-Za-z0-9_-]{20,}"),
    # Groq keys: gsk_<20+ alnum>.
    re.compile(r"(?<![A-Za-z0-9])gsk_[A-Za-z0-9]{20,}"),
    # AWS access key id.
    re.compile(r"AKIA[0-9A-Z]{16}"),
    # Google-style keys: AIza<...> (Gemini/Maps/etc). Same shape as the
    # anchored rule `_API_KEY_SHAPES` uses for `looks_like_api_key`, but
    # unanchored so it also catches one embedded mid-string (e.g. inside a
    # provider error's message text, not just a bare standalone value).
    re.compile(r"AIza[A-Za-z0-9_-]{30,}"),
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
# ``:`` with optional surrounding whitespace. An optional quote character is
# allowed between the key and the separator, and between the separator and the
# value, so a quoted dict-repr rendering (e.g. "'GH_TOKEN': 'ghp_...'" from
# str(exc) embedding a headers/env dict) still matches (DCR-0014) even though
# the closing/opening quotes would otherwise break key-sep-value adjacency.
# Both quote spans are captured (not just matched) so _mask_kv can re-emit
# them and keep the surrounding quote structure intact in the output.
_KV_PATTERN: Final = re.compile(
    rf"(?P<key>{_KV_KEYS})(?P<keyquote>['\"]?)(?P<sep>\s*[:=]\s*)"
    rf"(?P<valquote>['\"]?)(?P<val>{_KV_VALUE})",
    re.IGNORECASE,
)


def _mask_kv(match: re.Match[str]) -> str:
    return (
        f"{match.group('key')}{match.group('keyquote')}{match.group('sep')}"
        f"{match.group('valquote')}{REDACTION_PLACEHOLDER}"
    )


# A bare ``key=``/``key:`` parameter -- the literal query-parameter name some
# providers use for their own API key (Gemini: ``?key=AIza...``), distinct
# from ``api_key``/``apikey`` above. ``_KV_KEYS`` deliberately has no bare
# ``key`` alternative of its own: unlike ``api_key``, the single word "key" is
# a common suffix/compound ("monkey", "sort_key", "primary_key", "cache_key"),
# and matching it unconditionally would redact those ordinary identifiers'
# values too. The negative lookbehind requires "key" to start a genuine word
# -- not preceded by a letter/digit/underscore -- so "monkey=" and
# "sort_key="/"primary_key=" (compound, underscore-joined) are left alone,
# while "?key=", "&key=", "key=", "'key':" and "\"key\":" still match.
_BARE_KEY_PATTERN: Final = re.compile(
    rf"(?<![A-Za-z0-9_])(?P<key>key)(?P<keyquote>['\"]?)(?P<sep>\s*[:=]\s*)"
    rf"(?P<valquote>['\"]?)(?P<val>{_KV_VALUE})",
    re.IGNORECASE,
)


def _key_looks_secret(name: str) -> bool:
    """True when a field/env/argument KEY NAME alone signals a credential.

    The single place the ``_KV_KEYS`` key-name rule lives — :func:`_is_secret_env`
    and :func:`redact_value` both call this instead of each independently
    running ``re.search(_KV_KEYS, ...)``, which is exactly the kind of
    duplication that drifts the next time ``_KV_KEYS`` changes (a review found
    the two copies already existed before this was extracted).
    """
    return bool(re.search(_KV_KEYS, name, re.IGNORECASE))


#: ``scheme://user:secret@host`` — the shape a DB/remote URL takes when it
#: carries an inline credential. Masks only the password span so the host stays
#: legible in an error message (DCR-0016 cli-config, DCR-0019 gate-report).
_URL_CRED_PATTERN: Final = re.compile(
    r"(?P<prefix>[A-Za-z][A-Za-z0-9+.\-]*://[^\s:/@]+:)(?P<secret>[^\s@/]+)(?P<at>@)"
)


def _mask_url_cred(match: re.Match[str]) -> str:
    return f"{match.group('prefix')}{REDACTION_PLACEHOLDER}{match.group('at')}"


#: API-key-shaped prefixes used by ``looks_like_api_key`` — a positive check
#: (does this LOOK like a provider key?), distinct from the redaction patterns
#: which match anywhere in a blob. AWS keys are 20 chars; provider keys are long.
_API_KEY_SHAPES: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"^sk-ant-[A-Za-z0-9_-]{20,}$"),
    re.compile(r"^sk-[A-Za-z0-9_-]{20,}$"),
    re.compile(r"^AKIA[0-9A-Z]{16}$"),
    re.compile(r"^gsk_[A-Za-z0-9]{20,}$"),  # Groq
    re.compile(r"^AIza[A-Za-z0-9_-]{30,}$"),  # Google
)


def looks_like_api_key(value: str) -> bool:
    """True if ``value`` has the shape of a known provider API key.

    Used to warn when a resolved key clearly isn't one (e.g. a placeholder, a
    path, or a truncated paste) — WITHOUT printing it. Deliberately
    permissive: a very long opaque token also passes, so it only flags
    obviously-wrong values, never a real-but-unrecognised key.
    """
    if not isinstance(value, str):
        return False
    v = value.strip()
    if any(p.match(v) for p in _API_KEY_SHAPES):
        return True
    # A long, whitespace-free, mostly-key-charset token is plausibly a key.
    return len(v) >= 32 and " " not in v and "/" not in v and "\\" not in v


#: Query-parameter names that contain a credential word but are known to be
#: harmless request options (pagination cursors, sampling limits, sort fields).
#: Masking them would break a working REST target's copies. Kept short and
#: explicit: any other name holding a credential word is masked (safe default).
_QUERY_HARMLESS_NAMES: Final[frozenset[str]] = frozenset(
    {
        "max_tokens",
        "max_new_tokens",
        "tokenizer",
        "tokens",
        "num_tokens",
        "page_token",
        "next_token",
        "continuation_token",
        "sort_key",
        "order_key",
        "partition_key",
        "keyword",
        "keywords",
    }
)

#: Words that mark a credential only as a whole ``_``/``-``-separated part of a
#: name (``key``, ``secret_key``, ``x-sig``), never inside another word
#: (``monkey``, ``keyword``, ``design``).
_QUERY_CREDENTIAL_PARTS: Final[frozenset[str]] = frozenset({"key", "sig", "signature"})


def _query_name_looks_secret(name: str) -> bool:
    """True when a decoded query-parameter NAME signals a credential.

    Safe by default: the substring rule :func:`_key_looks_secret` (``token``,
    ``secret``, ``api_key``, ``password``, ...) plus ``key``/``sig``/
    ``signature`` as a separated part, minus :data:`_QUERY_HARMLESS_NAMES`.
    """
    lowered = name.strip().lower()
    if lowered in _QUERY_HARMLESS_NAMES:
        return False
    if _key_looks_secret(lowered):
        return True
    return any(part in _QUERY_CREDENTIAL_PARTS for part in re.split(r"[_-]", lowered))


def redact_url_query(url: str) -> str:
    """Mask each credential-shaped query-string VALUE in ``url``.

    The one rule every target-file writer uses for a URL's query string (the
    ``scan --scaffold --rest-url`` path and :func:`redact_target_yaml`'s ``url``
    and ``request.url``). A value is masked when its parameter NAME holds a
    credential word (:func:`_query_name_looks_secret`: ``api_token``,
    ``secret_key``, ``access_key``, ``key``, ``sig``, ...; a few named
    exceptions such as ``max_tokens`` and ``page_token`` are not) or the value
    itself looks like an API key (:func:`looks_like_api_key`, which catches an
    opaque token under any name).

    Only ``&`` separates parameters; a legacy ``;`` separator is not parsed,
    so ``a=1;key=x`` is one parameter named ``a``.

    A masked value becomes the literal :data:`REDACTION_PLACEHOLDER`, not a
    ``${VAR}`` reference: ``url`` never expands variables, by design (see
    ``CREDENTIAL_TOP_LEVEL_SECTIONS``). The URL is edited in place, never
    re-encoded, so every other parameter, the path and the fragment stay
    byte-for-byte as written.
    """
    from urllib.parse import unquote_plus

    if not isinstance(url, str):
        return url
    base, hash_sep, fragment = url.partition("#")
    head, q_sep, query = base.partition("?")
    if not q_sep or not query:
        return url
    pairs: list[str] = []
    changed = False
    for pair in query.split("&"):
        name, eq, value = pair.partition("=")
        if (
            eq
            and value
            and value != REDACTION_PLACEHOLDER
            and (
                _query_name_looks_secret(unquote_plus(name))
                or looks_like_api_key(unquote_plus(value))
            )
        ):
            pairs.append(f"{name}={REDACTION_PLACEHOLDER}")
            changed = True
        else:
            pairs.append(pair)
    if not changed:
        return url
    return f"{head}?{'&'.join(pairs)}{hash_sep}{fragment}"


#: Exact values known to be secret for this run, whatever their shape: today,
#: the values of ``--llm-header``/``MYLONITE_LLM_HEADERS`` (a workspace id
#: matches none of the shape patterns, yet must never reach a log or a
#: console line). Longest first, so a value containing another is masked whole.
_MASKED_VALUES: list[str] = []

#: Values shorter than this are not registered: masking every occurrence of a
#: two-letter value would shred ordinary text.
_MIN_MASKED_VALUE_LEN: Final = 4


def register_masked_value(value: str) -> None:
    """Mask every exact occurrence of ``value`` in :func:`redact`'s output."""
    if len(value) < _MIN_MASKED_VALUE_LEN or value in _MASKED_VALUES:
        return
    _MASKED_VALUES.append(value)
    _MASKED_VALUES.sort(key=len, reverse=True)


def clear_masked_values() -> None:
    """Forget every value registered with :func:`register_masked_value`."""
    _MASKED_VALUES.clear()


def mask_registered_values(text: str) -> str:
    """Mask only the registered exact values, leaving everything else as is.

    For text that is persisted (a failed call's detail in a verdict reason),
    where the shape-based patterns of :func:`redact` are deliberately not
    applied, but a registered value must still never land on disk.
    """
    for value in _MASKED_VALUES:
        text = text.replace(value, REDACTION_PLACEHOLDER)
    return text


def redact(text: str) -> str:
    """Return ``text`` with secret-shaped tokens replaced by the placeholder.

    Also masks every value registered with :func:`register_masked_value`.
    Non-``str`` inputs are returned unchanged (defensive). The operation is
    idempotent: redacting already-redacted text is a no-op because the
    placeholder matches none of the patterns.
    """
    if not isinstance(text, str):
        return text

    redacted = mask_registered_values(text)
    for pattern in _FULL_PATTERNS:
        redacted = pattern.sub(REDACTION_PLACEHOLDER, redacted)
    redacted = _URL_CRED_PATTERN.sub(_mask_url_cred, redacted)
    redacted = _KV_PATTERN.sub(_mask_kv, redacted)
    redacted = _BARE_KEY_PATTERN.sub(_mask_kv, redacted)
    return redacted


def redact_value(value: object) -> object:
    """Recursively mask every credential leaf in ``value``, by key name OR shape.

    Used for a probed tool's call arguments (``_session_adapter.py``'s recorded
    ``mcp_trace_planner``): a target's tool schema can legitimately accept a
    credential-bearing parameter, and a planner steered by injected content may
    pass a real one, which then rides into the persisted exploit/scan-report JSON
    (DCR-0003). Two independent masking rules apply when recursing into a dict:

    * a value whose KEY matches ``_KV_KEYS`` (``password``, ``api_key``,
      ``token``, ``secret``, ...), via the shared :func:`_key_looks_secret`, is
      masked unconditionally, even if the value itself doesn't independently
      look secret-shaped (e.g. a plain passphrase with no provider-key prefix)
      — key name alone is enough signal;
    * every other string value still goes through the shape-based :func:`redact`,
      so a URL or prose body that happens to embed something secret-shaped is
      still caught.

    This DELIBERATELY does NOT also call :func:`looks_like_api_key` on the
    shape-fallback path, unlike :func:`_is_secret_env`. ``looks_like_api_key``'s
    permissive branch (any 32+-char, whitespace/slash-free token) is right for
    an ``env:`` VALUE — a static, operator-supplied config string — but wrong
    for a LIVE tool-call argument: a note id, a tool-call id, or a
    planner-visible attacker-planted payload can easily be a long opaque
    alnum/underscore run with no spaces or slashes, and the oracle predicates
    (``plugins/_mcp/predicates/{fetch,filesystem,github}.py``, via
    ``tool_was_called_with_arg``) need those values to survive UNMASKED to
    detect the attack. :func:`redact`'s own docstring makes the same call for
    exactly this reason ("deliberately do NOT match ... tool-call ids, or note
    ids"); this keeps that contract instead of quietly widening it.
    """
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {
            k: (_mask_all_strings(v) if _key_looks_secret(str(k)) else redact_value(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [redact_value(v) for v in value]
    if isinstance(value, tuple):
        return tuple(redact_value(v) for v in value)
    return value


def _walk_strings(value: object, leaf: Callable[[str], str]) -> object:
    """Recurse through ``value``, applying ``leaf`` to every string found,
    preserving the shape of any nested dict/list/tuple containers.

    The single shared tree-walk both :func:`_mask_all_strings` and
    :func:`_redact_remaining` build on — they differ only in what happens at a
    string leaf (an unconditional placeholder vs. shape-based :func:`redact`),
    not in how the tree is walked. Keeping one walker here is what stops that
    walk logic drifting apart the next time either caller changes, exactly the
    duplication :func:`_key_looks_secret`'s docstring warns about elsewhere in
    this module.
    """
    if isinstance(value, str):
        return leaf(value)
    if isinstance(value, dict):
        return {k: _walk_strings(v, leaf) for k, v in value.items()}
    if isinstance(value, list):
        return [_walk_strings(v, leaf) for v in value]
    if isinstance(value, tuple):
        return tuple(_walk_strings(v, leaf) for v in value)
    return value


def _mask_all_strings(value: object) -> object:
    """Replace every string leaf in ``value`` with the placeholder unconditionally.

    Used by :func:`redact_value` when a key name alone already signals a
    credential (``_key_looks_secret``): the mask must apply no matter how the
    value is shaped — a direct string, or a list/dict/tuple of strings
    (DCR-0010: a list of passwords under a ``password`` key is still a list of
    passwords). Non-string leaves (ints, bools, ``None``) are left alone —
    there is nothing to mask.
    """
    return _walk_strings(value, lambda _s: REDACTION_PLACEHOLDER)


#: Attributes every ``LogRecord`` has. Anything else on a record came from
#: ``extra=`` and is masked too.
_STANDARD_RECORD_ATTRS: Final = frozenset(
    logging.LogRecord("", 0, "", 0, "", (), None).__dict__
) | {"message", "asctime"}


class SecretRedactingFilter(logging.Filter):
    """Logging filter that redacts secrets from each record. Never drops one.

    With ``tree=None`` (the filter on the ``mylonite`` logger itself) every
    record gets the full :func:`redact`. With ``tree="mylonite"`` (the filter
    on a handler, or on LiteLLM's loggers, which see other libraries' records
    too) a record from that logger tree gets the full :func:`redact`, and any
    other record has only the registered secret values masked
    (:func:`register_masked_value`), and is left untouched when nothing
    matched.

    Covers the rendered message (``msg`` with its ``%`` args), the exception
    traceback text (``exc_info``, rendered and masked into ``exc_text``; the
    exception object itself is dropped from the record only when its text
    held a secret), ``stack_info``, and string ``extra=`` attributes.
    """

    def __init__(self, tree: str | None = None) -> None:
        super().__init__()
        self.tree = tree

    def _masker(self, record: logging.LogRecord) -> Callable[[str], str] | None:
        if self.tree is None:
            return redact
        name = record.name or ""  # makeLogRecord() builds records with name=None
        if name == self.tree or name.startswith(self.tree + "."):
            return redact
        return mask_registered_values if _MASKED_VALUES else None

    def filter(self, record: logging.LogRecord) -> bool:
        mask = self._masker(record)
        if mask is None:
            return True
        try:
            message = record.getMessage()
        except Exception:  # never let message formatting kill a log line
            # getMessage() itself raised (e.g. a malformed %-format call whose
            # arg is secret-shaped) — record.msg/args were never rendered or
            # redacted. Clearing record.args here is load-bearing: left as-is,
            # stdlib logging.Handler.handleError() prints
            # 'Message: %r\nArguments: %s\n' % (record.msg, record.args)
            # straight to stderr, leaking the raw arg verbatim (DCR-0008).
            record.args = ()
            return True
        masked = mask(message)
        if masked != message or self.tree is None:
            record.msg = masked
            record.args = ()
        self._mask_exception(record, mask)
        if isinstance(record.stack_info, str):
            record.stack_info = mask(record.stack_info)
        for key, value in list(record.__dict__.items()):
            if key not in _STANDARD_RECORD_ATTRS and isinstance(value, str):
                masked_value = mask(value)
                if masked_value != value:
                    setattr(record, key, masked_value)
        return True

    @staticmethod
    def _mask_exception(record: logging.LogRecord, mask: Callable[[str], str]) -> None:
        text = record.exc_text
        if not text and record.exc_info:
            try:
                text = logging.Formatter().formatException(record.exc_info)
            except Exception:  # a broken exception must not kill the line
                return
        if not text:
            return
        masked = mask(text)
        if masked != text:
            # Only now touch the record: a record with nothing to mask keeps
            # its exc_info and an unset exc_text, so a host handler's own
            # formatException still renders it. Formatters print exc_text
            # when it is set; dropping exc_info stops a handler that renders
            # the exception object itself from printing the original.
            record.exc_text = masked
            record.exc_info = None


#: Every (logger-or-handler, filter) pair :func:`install_log_redaction`
#: added, per logger tree, so turning redaction off removes exactly those.
_INSTALLED: dict[str, list[tuple[logging.Filterer, SecretRedactingFilter]]] = {}

#: LiteLLM logs through these loggers by name. Its debug output can carry
#: request headers, so a registered header value is masked there too.
_LIBRARY_LOGGERS: Final = ("LiteLLM", "litellm")


def _redaction_targets(logger_name: str) -> list[tuple[logging.Filterer, str | None]]:
    """Where a filter goes: the tree's own logger (full redaction), every
    child logger that already exists, the handlers that will print the
    tree's records (those already on the tree's loggers and on the root
    logger, plus Python's last-resort stderr handler used when none is
    configured), and LiteLLM's loggers."""
    own = logging.getLogger(logger_name)
    targets: list[tuple[logging.Filterer, str | None]] = [(own, None)]
    handlers = list(own.handlers)
    prefix = logger_name + "."
    for name, child in list(logging.Logger.manager.loggerDict.items()):
        if name.startswith(prefix) and isinstance(child, logging.Logger):
            targets.append((child, None))
            handlers.extend(child.handlers)
    handlers.extend(logging.getLogger().handlers)
    if logging.lastResort is not None:
        handlers.append(logging.lastResort)
    targets.extend((handler, logger_name) for handler in handlers)
    targets.extend((logging.getLogger(name), logger_name) for name in _LIBRARY_LOGGERS)
    return targets


def _all_attached_handlers() -> list[logging.Handler]:
    loggers = [logging.getLogger()] + [
        lg
        for lg in list(logging.Logger.manager.loggerDict.values())
        if isinstance(lg, logging.Logger)
    ]
    handlers = [h for lg in loggers for h in lg.handlers]
    if logging.lastResort is not None:
        handlers.append(logging.lastResort)
    return handlers


def install_log_redaction(enabled: bool = True, logger_name: str = "mylonite") -> None:
    """Install (or remove) the redacting filters for the ``mylonite`` logger tree.

    A filter on a logger only sees records logged on that exact logger, so
    one filter on ``mylonite`` would miss every module logger beneath it.
    This adds a :class:`SecretRedactingFilter` to the targets listed in
    :func:`_redaction_targets`. Nothing process-wide is replaced: no record
    factory, no new handler.

    Idempotent: a target never gets a second filter for the same tree. When
    ``enabled`` is false, every filter this function added for the tree is
    removed, so the flag is honoured for library users who toggle it off.

    Limit: a handler added (on any logger) after this call does not see a
    record from a module logger created after this call through a filter;
    such records are still masked at source by the call sites that log
    exception text.
    """
    installed = _INSTALLED.setdefault(logger_name, [])
    if not enabled:
        for target, flt in installed:
            target.removeFilter(flt)
        installed.clear()
        own = logging.getLogger(logger_name)
        for leftover in list(own.filters):
            if isinstance(leftover, SecretRedactingFilter):
                own.removeFilter(leftover)
        return
    # Forget handlers no longer attached to any logger (a test's capture
    # handler, a host handler since removed): nothing left to undo there.
    attached = {id(h) for h in _all_attached_handlers()}
    installed[:] = [
        (t, f) for t, f in installed if not isinstance(t, logging.Handler) or id(t) in attached
    ]
    for target, tree in _redaction_targets(logger_name):
        if any(isinstance(f, SecretRedactingFilter) and f.tree == tree for f in target.filters):
            continue
        flt = SecretRedactingFilter(tree)
        target.addFilter(flt)
        installed.append((target, flt))


def redact_exception(exc: BaseException) -> str:
    """Render ``exc`` safely for console/CI output.

    A pydantic ``ValidationError``'s default ``str()`` embeds ``input_value`` —
    the offending field's raw content. When the offending field is
    ``request.headers`` or ``env``, that raw content is a live credential, and
    printing ``f"...: {exc}"`` to the console puts it straight into a CI log
    (DCR-0007, DCR-0011). So a ValidationError is rendered as field paths plus
    messages only. Anything else is ``str()``-ed and passed through
    :func:`redact`.
    """
    # An anyio/asyncio ExceptionGroup (raised by the MCP SDK's SSE/HTTP transport
    # task groups) str()s to only "unhandled errors in a TaskGroup (N sub-
    # exception)" — hiding the real cause (e.g. an HTTP 401). Recurse into the
    # sub-exceptions so the actual error (status, message) reaches the operator.
    subs = getattr(exc, "exceptions", None)
    if subs:
        rendered = "; ".join(redact_exception(sub) for sub in subs)
        return f"{type(exc).__name__}: {rendered}"
    errors = getattr(exc, "errors", None)
    if callable(errors):
        try:
            lines = [
                f"{'.'.join(str(p) for p in err.get('loc', ())) or '<root>'}: {err.get('msg', '')}"
                for err in errors()
            ]
        except Exception:  # a non-pydantic .errors() — fall through to str()
            lines = []
        if lines:
            joined = "; ".join(redact(line) for line in lines)
            return f"{type(exc).__name__}: {joined}"
    return redact(f"{type(exc).__name__}: {exc}")


#: Target-file sections whose values are credential-bearing by construction.
#: An ``Authorization`` header is always a credential; masking the whole section
#: is correct and needs no shape heuristic. ``headers`` is the sse/http transport's
#: field; ``request.headers`` is the rest transport's own nested equivalent
#: (``RequestSpec.headers`` — "may carry auth ... and are NEVER logged") and is
#: just as live a leak if left unmasked when a rest target.yaml is copied/persisted.
#:
#: PUBLIC and shared with ``plugins._mcp.target_file``'s loader: these three
#: names (plus :data:`CREDENTIAL_ENV_FIELD` for ``env``) are the ONLY target.yaml
#: locations ``redact_target_yaml`` replaces with a ``${VAR}`` reference, and —
#: critically — the ONLY locations ``load_target_file`` expands a ``${VAR}``
#: reference in. Keeping this list as the single shared source of truth for
#: both halves of the T9 contract (mask here / expand there) is what stops a
#: future change silently widening the loader's blast radius to the rest of
#: the document (system_prompt, purpose, args, url, request.body, ...) — an
#: AI-security tool's operators routinely write literal ``${IDENTIFIER}``-shaped
#: text as SSTI/template-injection test payloads in exactly those fields, and a
#: CI gate runner has real secrets (``ANTHROPIC_API_KEY``, ``GH_TOKEN``, ...) in
#: its environment (see ``SECURITY.md``), so expanding ``${VAR}`` outside the
#: credential-bearing fields would silently substitute a live secret into (or
#: raise a confusing error on) a field that was never meant as an env reference.
CREDENTIAL_TOP_LEVEL_SECTIONS: Final[tuple[str, ...]] = ("headers",)
CREDENTIAL_NESTED_SECTIONS: Final[tuple[tuple[str, str], ...]] = (("request", "headers"),)
CREDENTIAL_ENV_FIELD: Final[str] = "env"

#: ``${VAR_NAME}`` anywhere inside a string, NAME captured — the same
#: shell-style indirection syntax ``load_target_file``'s ``_expand_env_refs``
#: expands and ``docs/http-agent.md`` documents an operator can hand-write
#: directly (e.g. ``Authorization: Bearer ${MY_TOKEN}``).
_VAR_REF_PATTERN: Final = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")

#: A value safe to leave UNMASKED: exactly one ``${VAR}`` reference, optionally
#: preceded by a single auth-scheme word and a space, and nothing else.
#: Anything else that merely CONTAINS ``${...}`` — a literal secret alongside a
#: reference, e.g. ``postgres://admin:FAKEPW@${DB_HOST}/db``  # pragma: allowlist secret
#: or ``session=FAKE; csrf=${X}`` — is NOT this shape and must still be masked
#: (review fix: an earlier version of :func:`_is_pure_var_ref` matched with
#: ``search`` instead of requiring the WHOLE value to be only this, so a
#: literal secret riding alongside an unrelated reference was written to disk
#: verbatim).
_AUTH_SCHEME_VAR_REF: Final = re.compile(
    r"^\s*(?:(?:Bearer|Basic|Token)\s+)?\$\{[A-Za-z_][A-Za-z0-9_]*\}\s*$", re.IGNORECASE
)


def _is_pure_var_ref(value: object) -> bool:
    """True when ``value`` is a string that is PURELY a ``${VAR}`` reference
    (optionally preceded by one ``Bearer``/``Basic``/``Token`` auth-scheme word
    and a space) — the only shape safe to leave unmasked.

    Shared by :func:`redact_env` and :func:`redact_target_yaml`'s
    header-section masking: both skip replacing a value of exactly this shape,
    instead of re-wrapping it into a second, disconnected placeholder (#183).
    Anything ELSE containing ``${...}`` — a literal secret next to a
    reference — is masked exactly as it always was; this is deliberately NOT
    an anywhere-in-the-string check.
    """
    return isinstance(value, str) and _AUTH_SCHEME_VAR_REF.match(value) is not None


def target_file_var_names(text: str) -> list[str]:
    """Every ``${VAR}`` NAME a target file's ``headers``/``request.headers``/
    ``env`` sections reference, in file order, each name once — user-named
    tokens included, not only the ``${MYLONITE_TARGET_...}`` placeholders
    Mylonite itself writes (see :func:`target_env_refs` for those).

    ``--env-file`` (``mylonite.cli._load_env_file``) additionally recognises
    these names (#183): a hand-written target file's own
    ``Authorization: Bearer ${MY_TOKEN}`` can then have ``MY_TOKEN`` set from
    a ``.env`` file too, not only from the shell. Deliberately scoped to the
    same three sections :func:`redact_target_yaml`/``_expand_env_refs``
    already treat as credential-bearing — never ``system_prompt``,
    ``purpose``, ``args`` or ``url``, which legitimately hold literal
    ``${IDENTIFIER}``-shaped SSTI/template-injection test payloads.

    Text that does not parse as a YAML mapping yields ``[]``.
    """
    import yaml

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        return []
    if not isinstance(data, dict):
        return []
    names: list[str] = []

    def _collect(block: object) -> None:
        if not isinstance(block, dict):
            return
        for value in block.values():
            if isinstance(value, str):
                for match in _VAR_REF_PATTERN.finditer(value):
                    name = match.group(1)
                    if name not in names:
                        names.append(name)

    for section in CREDENTIAL_TOP_LEVEL_SECTIONS:
        _collect(data.get(section))
    for parent_key, child_key in CREDENTIAL_NESTED_SECTIONS:
        parent = data.get(parent_key)
        if isinstance(parent, dict):
            _collect(parent.get(child_key))
    _collect(data.get(CREDENTIAL_ENV_FIELD))
    return names


def is_unresolved_var_placeholder(value: str) -> bool:
    """True when ``value`` is EXACTLY one ``${VAR}``-shaped reference, nothing
    else — the shape ``--env-file`` must never load as a literal credential.

    A dotenv/CI templating tool that expands ``${VAR}`` references leaves
    exactly this shape behind when the referenced variable wasn't set at
    template time (``ANTHROPIC_API_KEY=${SOME_SECRET_MANAGER_VAR}`` in the
    ``.env`` file, never substituted). Loading that text and handing it to a
    provider as the literal key value is never useful — at best the request
    fails with a confusing auth error, at worst (a value that happens to
    parse) it's silently wrong. ``--env-file`` (``mylonite.cli._load_env_file``)
    refuses it with a clear, named error instead of setting it.

    Deliberately a WHOLE-value match: an operator-chosen value that merely
    CONTAINS ``${`` text (vanishingly rare for a provider key, but not
    impossible) is not this specific, well-understood footgun.
    """
    return isinstance(value, str) and _VAR_REF_PATTERN.fullmatch(value.strip()) is not None


def looks_like_credential_arg(value: str) -> bool:
    """True when a launch-argument string (a positional ``args`` entry, or a
    ``--arg``/``--env`` CLI value) looks like it carries a credential.

    Shape-based, reusing the exact rules :func:`redact` and
    :func:`looks_like_api_key` already apply elsewhere: a ``--flag=value`` or
    ``key=value`` assignment whose key or value matches a credential pattern
    (``redact(value) != value`` — this also catches a credential embedded in a
    URL's query string, e.g. ``?access_token=...``, since the key-name rule
    matches a substring wherever it falls), a recognised provider-key-shaped
    literal (``sk-...``, ``AKIA...``, a bearer token, ...), or a bare opaque
    token (:func:`looks_like_api_key`, which already excludes anything
    containing a path separator, so an ordinary file-path argument is not
    flagged).

    Used only to WARN (never mask or block): ``args`` is an unstructured
    string list with no key name to replace a value by (see
    ``docs/target-file.md#a-credential-in-args-is-written-in-plain-text-and-now-warns``), so
    the caller names the position and withholds the value — never prints it,
    even redacted — and points the operator at ``env:``/``--env-file`` instead.
    """
    if not isinstance(value, str) or not value:
        return False
    return redact(value) != value or looks_like_api_key(value)


_REDACTION_BANNER: Final = (
    "# Written by mylonite. Credential-shaped values are replaced with ${VAR}\n"
    "# references (see mylonite._redaction.target_yaml_env_ref_name) — set the\n"
    "# corresponding environment variable(s) (named below) to the real values\n"
    "# before running this target file; an unset one fails loudly at load time\n"
    "# instead of silently running with an empty/broken credential.\n"
)

#: Characters a derived env-var-name SEGMENT may keep as-is; everything else
#: (spaces, hyphens in a header like ``X-Api-Key``, ...) becomes ``_``.
_ENV_REF_INVALID_CHARS: Final = re.compile(r"[^A-Za-z0-9_]")


def target_yaml_env_ref_name(*path: str) -> str:
    """Derive the ``MYLONITE_TARGET_``-prefixed env-var name a masked
    ``target.yaml`` field is replaced with.

    Deterministic and collision-resistant by construction: ``path`` is the
    field's full location in the document (e.g. ``("env", "API_TOKEN")`` for a
    top-level ``env`` entry, ``("headers", "Authorization")`` for the sse/http
    transport's top-level ``headers``, or ``("request", "headers",
    "Authorization")`` for the rest transport's nested ``request.headers``).
    Every segment is upper-cased, any character outside ``[A-Za-z0-9_]`` becomes
    ``_``, and the segments are joined with ``_`` under one shared
    ``MYLONITE_TARGET_`` prefix — so an ``env`` entry can never collide with a
    same-named ``headers`` entry (they land under different segment prefixes:
    ``MYLONITE_TARGET_ENV_...`` vs ``MYLONITE_TARGET_HEADERS_...``), and a
    top-level ``headers`` entry can never collide with a ``request.headers``
    one (``MYLONITE_TARGET_HEADERS_...`` vs
    ``MYLONITE_TARGET_REQUEST_HEADERS_...``).
    """
    segments = "_".join(_ENV_REF_INVALID_CHARS.sub("_", part).upper() for part in path)
    return f"MYLONITE_TARGET_{segments}"


def _dedupe_ref_names(path_prefix: tuple[str, ...], keys: list[str]) -> dict[str, str]:
    """Assign each of ``keys`` a DISTINCT derived env-var name under
    ``path_prefix``, even when two different keys normalise to the same
    :func:`target_yaml_env_ref_name` (e.g. ``X-Api-Key`` and ``X_Api_Key`` both
    become ``..._X_API_KEY`` after the ``[^A-Za-z0-9_]`` → ``_`` + upper-case
    transform).

    ``target_yaml_env_ref_name`` alone is collision-resistant ACROSS sections
    (``env`` vs ``headers`` vs ``request.headers``) by construction, but two
    keys within the SAME section can still normalise to the same string. Two
    fields silently sharing one env var would defeat the entire point of this
    scheme (T9: genuinely re-runnable, not just safely masked) — there would be
    no way to set both back to their own distinct original value.

    Deterministic (keys are processed in the given order — dict iteration
    order, i.e. insertion order): the first key to claim a base name keeps it
    unsuffixed; every subsequent key whose base name is already taken gets the
    lowest-numbered ``_N`` (``N`` >= 2) suffix not already assigned to another
    key in this same call, so a suffix can itself never collide with a
    naturally-derived or previously-disambiguated name.
    """
    assigned: set[str] = set()
    result: dict[str, str] = {}
    for key in keys:
        base = target_yaml_env_ref_name(*path_prefix, key)
        name = base
        suffix = 2
        while name in assigned:
            name = f"{base}_{suffix}"
            suffix += 1
        assigned.add(name)
        result[key] = name
    return result


def _is_secret_env(key: str, value: object) -> bool:
    """True when an ``env:`` entry should be masked before the file is persisted.

    Unlike :func:`redact_value`'s shape-fallback, this also calls
    :func:`looks_like_api_key` — appropriate here because an ``env:`` value is
    static, operator-supplied config (never something an oracle predicate
    needs to string-match against), so the broader "looks like an opaque key"
    heuristic has no false-positive cost.

    The key-name check runs BEFORE the ``isinstance(value, str)`` shape check
    (DCR-0009): a YAML-typed non-string value (e.g. an unquoted numeric/
    boolean literal like ``API_TOKEN: 8675309123456``, which ``yaml.safe_load``
    parses as a Python ``int``) must still be masked when its KEY name alone
    signals a credential — otherwise the raw value is written unmasked into
    the persisted ``target.yaml`` copy.

    A value that is PURELY a ``${VAR}`` reference (:func:`_is_pure_var_ref`,
    optionally preceded by a single auth-scheme word) is never masked,
    whatever its key name: it is already safely indirected, and masking it
    anyway would re-wrap it into a second, disconnected
    ``${MYLONITE_TARGET_...}`` placeholder, discarding the variable name the
    operator already set (#183). A value that merely CONTAINS one of these
    references alongside a literal secret — a DB URL with a real password and
    a ``${HOST}`` reference — is not this shape and is masked exactly as
    before.
    """
    if _is_pure_var_ref(value):
        return False
    if _key_looks_secret(key):
        return True
    if not isinstance(value, str):
        return False
    return looks_like_api_key(value) or redact(value) != value


def redact_env(env: dict[str, str]) -> dict[str, str]:
    """Replace every credential-shaped ``env`` entry with a ``${VAR}`` reference.

    Shared by :func:`redact_target_yaml` (persisted/copied target.yaml files) and
    the ``scan --scaffold`` starter renderer (``cli.py``'s
    ``_render_target_scaffold``) — a FOURTH origination path for the
    same DCR-0006/0010/0016/0019 leak class: a `--env` value (e.g. a live
    ``GITHUB_TOKEN``) that reaches a target.yaml written to disk. Key names and
    non-secret values survive so the file still documents the target. Unlike an
    opaque placeholder, the ``${VAR}`` reference (derived from the key via
    :func:`target_yaml_env_ref_name`, disambiguated against sibling keys by
    :func:`_dedupe_ref_names`) is genuinely re-runnable: set the named
    environment variable to the real value and ``load_target_file`` restores it.
    """
    secret_keys = [k for k, v in env.items() if _is_secret_env(k, v)]
    ref_names = _dedupe_ref_names((CREDENTIAL_ENV_FIELD,), secret_keys)
    return {k: (f"${{{ref_names[k]}}}" if k in ref_names else v) for k, v in env.items()}


def redact_target_yaml(text: str) -> str:
    """Return a copy of a ``target.yaml`` document safe to persist or publish.

    Mylonite's own documented workflow tells the operator to commit the scan and
    generated-test directories and to push the gate artefacts as a PR. Copying a
    target file byte-for-byte into any of those puts a live bearer token or DB
    password into git history (DCR-0006/0010/0016). This replaces every ``headers``
    value (both the sse/http transport's top-level ``headers`` and
    the rest transport's ``request.headers``) and every credential-shaped ``env``
    value with a ``${VAR}`` reference (:func:`target_yaml_env_ref_name`,
    disambiguated within each section by :func:`_dedupe_ref_names` so two keys
    that normalise to the same name — e.g. ``X-Api-Key`` and ``X_Api_Key`` — get
    DISTINCT ``${VAR}`` names, never one shared between two different secrets),
    leaving key names and structure intact so the copy still documents the
    target. Unlike a bare placeholder, this is genuinely OPERATIONAL, not just
    structurally parseable: the copy still round-trips through
    ``load_target_file`` to a RUNNABLE target once the operator sets the named
    environment variable(s) to the real values — ``load_target_file`` expands
    ``${VAR}`` references and fails loudly (never with an empty/broken
    credential) if one is unset.

    A value that is PURELY a ``${VAR}`` reference (:func:`_is_pure_var_ref`,
    optionally preceded by a single auth-scheme word such as ``Bearer``) is
    left exactly as written instead — never re-wrapped into a second,
    disconnected ``${MYLONITE_TARGET_...}`` placeholder (#183). Before this, an
    operator's own ``Authorization: Bearer ${MY_TOKEN}`` became
    ``Authorization: ${MYLONITE_TARGET_HEADERS_AUTHORIZATION}``, silently
    orphaning the ``MY_TOKEN`` export they already had in their shell, and
    requiring that new variable to hold the WHOLE header value (``Bearer
    ...``), not just the token. A value that merely CONTAINS a reference
    alongside a literal secret (a cookie with a real session value and a
    ``${X}`` reference, a DB URL with a real password and a ``${HOST}``
    reference) is NOT this shape and is masked whole, exactly as on a value
    with no reference at all — the check is purely-this-shape, never
    anywhere-in-the-string. This function never
    resolves a ``${VAR}`` reference from the live environment either way:
    writing never expands, only loading does, so no live secret value can
    reach the written file through this path.

    A document that does not parse as a YAML mapping falls back to
    :func:`redact` over the raw text — a malformed file is never persisted
    verbatim.

    Beyond the three named sections, every OTHER string leaf in the document
    (``url``, ``args``, ``command``, ``request.url``, ...) is still swept with
    shape-based :func:`redact` (DCR-0015) — so a credential embedded in, say,
    a DB connection URL (``postgres://<user>:<password>@host/db``) is still caught by
    ``_URL_CRED_PATTERN`` even though ``url`` isn't a named credential
    section. This sweep is shape-based ONLY (never the key-name-unconditional
    rule) and explicitly skips the fields already replaced with a ``${VAR}``
    reference above — running the key-name rule over them would clobber a
    correct ``${VAR}`` reference with a bare, non-runnable placeholder.

    ``url`` and ``request.url`` also go through :func:`redact_url_query`, so a
    credential in a query string (``?api_key=...``, or an opaque token under
    any name) becomes the literal :data:`REDACTION_PLACEHOLDER`. ``url`` expands
    no ``${VAR}``, so that value cannot be restored from the environment; the
    writer's notice names the field (:func:`target_masked_fields`).
    """
    import yaml

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        return redact(text)
    if not isinstance(data, dict):
        return redact(text)

    for section in CREDENTIAL_TOP_LEVEL_SECTIONS:
        block = data.get(section)
        if isinstance(block, dict):
            to_mask = [k for k, v in block.items() if not _is_pure_var_ref(v)]
            ref_names = _dedupe_ref_names((section,), to_mask)
            data[section] = {
                k: (f"${{{ref_names[k]}}}" if k in ref_names else v) for k, v in block.items()
            }

    nested_skip: dict[str, set[str]] = {}
    for parent_key, child_key in CREDENTIAL_NESTED_SECTIONS:
        nested_skip.setdefault(parent_key, set()).add(child_key)
        parent = data.get(parent_key)
        if isinstance(parent, dict):
            block = parent.get(child_key)
            if isinstance(block, dict):
                to_mask = [k for k, v in block.items() if not _is_pure_var_ref(v)]
                ref_names = _dedupe_ref_names((parent_key, child_key), to_mask)
                parent[child_key] = {
                    k: (f"${{{ref_names[k]}}}" if k in ref_names else v) for k, v in block.items()
                }

    env = data.get(CREDENTIAL_ENV_FIELD)
    if isinstance(env, dict):
        data[CREDENTIAL_ENV_FIELD] = redact_env(env)

    # A credential in a URL's query string: masked in place with the literal
    # placeholder (url expands no ${VAR}); other parameters stay as written.
    if isinstance(data.get("url"), str):
        data["url"] = redact_url_query(data["url"])
    request = data.get("request")
    if isinstance(request, dict) and isinstance(request.get("url"), str):
        request["url"] = redact_url_query(request["url"])

    already_masked = set(CREDENTIAL_TOP_LEVEL_SECTIONS) | {CREDENTIAL_ENV_FIELD}
    for key, val in list(data.items()):
        if key in already_masked:
            continue
        if key in nested_skip and isinstance(val, dict):
            data[key] = {
                k: (v if k in nested_skip[key] else _redact_remaining(v)) for k, v in val.items()
            }
            continue
        data[key] = _redact_remaining(val)

    return _REDACTION_BANNER + yaml.safe_dump(data, sort_keys=True, default_flow_style=False)


#: A whole-value ``${MYLONITE_TARGET_...}`` placeholder, as
#: :func:`redact_target_yaml` / :func:`redact_env` write it.
_TARGET_ENV_REF: Final = re.compile(r"\$\{(MYLONITE_TARGET_[A-Za-z0-9_]+)\}")


def target_env_refs(text: str) -> list[tuple[str, str]]:
    """Return ``(variable, original_key)`` for each ``${MYLONITE_TARGET_...}``
    placeholder in a WRITTEN target file, in file order, each variable once.

    Read back from the text itself rather than re-running the masking rules, so
    what the CLI tells the user to set is exactly what the file references
    (``redact_target_yaml``, ``redact_env`` and ``dump_target_file`` all produce
    input for this). A hand-written ``${MY_TOKEN}`` is not listed: only
    placeholders Mylonite wrote carry the ``MYLONITE_TARGET_`` prefix. Text that
    does not parse as YAML yields ``[]``; it cannot be loaded either.
    """
    import yaml

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        return []
    found: dict[str, str] = {}

    def _walk(node: object) -> None:
        if not isinstance(node, dict):
            return
        for key, value in node.items():
            if isinstance(value, str):
                match = _TARGET_ENV_REF.fullmatch(value.strip())
                if match is not None:
                    found.setdefault(match.group(1), str(key))
            else:
                _walk(value)

    _walk(data)
    return list(found.items())


def target_masked_fields(text: str) -> list[str]:
    """Return the dotted path (``url``, ``request.url``, ...) of each field in a
    WRITTEN target file whose value holds :data:`REDACTION_PLACEHOLDER`, in file
    order. Only the field names come back, never a value, so a writer can say
    where to put a masked value back without printing it.
    """
    import yaml

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        return []
    found: list[str] = []

    def _walk(node: object, path: str) -> None:
        if isinstance(node, str):
            if REDACTION_PLACEHOLDER in node and path and path not in found:
                found.append(path)
        elif isinstance(node, dict):
            for key, value in node.items():
                _walk(value, f"{path}.{key}" if path else str(key))
        elif isinstance(node, list):
            for item in node:
                _walk(item, path)

    _walk(data, "")
    return found


def _redact_remaining(value: object) -> object:
    """Shape-based sweep (DCR-0015) over every string leaf NOT already handled
    by :func:`redact_target_yaml`'s named-section ``${VAR}`` indirection.

    Deliberately shape-based only (:func:`redact`, never the key-name-
    unconditional rule from :func:`redact_value`/:func:`_mask_all_strings`) —
    fields swept here were never part of the credential contract, so there is
    no key name to trust as unconditional signal, only a shape to catch
    defense-in-depth (e.g. a URL with an embedded ``user:pass@`` credential).
    """
    return _walk_strings(value, redact)
