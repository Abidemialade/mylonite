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
    "looks_like_api_key",
    "redact",
    "redact_env",
    "redact_exception",
    "redact_target_yaml",
    "redact_value",
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

    Used by ``mylonite doctor`` to warn when a resolved key clearly isn't one
    (e.g. a placeholder, a path, or a truncated paste) — WITHOUT printing it.
    Deliberately permissive: a very long opaque token also passes, so it only
    flags obviously-wrong values, never a real-but-unrecognised key.
    """
    if not isinstance(value, str):
        return False
    v = value.strip()
    if any(p.match(v) for p in _API_KEY_SHAPES):
        return True
    # A long, whitespace-free, mostly-key-charset token is plausibly a key.
    return len(v) >= 32 and " " not in v and "/" not in v and "\\" not in v


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
    redacted = _URL_CRED_PATTERN.sub(_mask_url_cred, redacted)
    redacted = _KV_PATTERN.sub(_mask_kv, redacted)
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
            k: (
                REDACTION_PLACEHOLDER
                if isinstance(v, str) and _key_looks_secret(str(k))
                else redact_value(v)
            )
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [redact_value(v) for v in value]
    if isinstance(value, tuple):
        return tuple(redact_value(v) for v in value)
    return value


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
_ALWAYS_MASK_SECTIONS: Final[tuple[str, ...]] = ("headers",)
_ALWAYS_MASK_NESTED_SECTIONS: Final[tuple[tuple[str, str], ...]] = (("request", "headers"),)

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


def _env_ref_placeholder(*path: str) -> str:
    """The literal ``${VAR}`` text a masked field is replaced with."""
    return "${" + target_yaml_env_ref_name(*path) + "}"


def _is_secret_env(key: str, value: object) -> bool:
    """True when an ``env:`` entry should be masked before the file is persisted.

    Unlike :func:`redact_value`'s shape-fallback, this also calls
    :func:`looks_like_api_key` — appropriate here because an ``env:`` value is
    static, operator-supplied config (never something an oracle predicate
    needs to string-match against), so the broader "looks like an opaque key"
    heuristic has no false-positive cost.
    """
    if not isinstance(value, str):
        return False
    if _key_looks_secret(key):
        return True
    return looks_like_api_key(value) or redact(value) != value


def redact_env(env: dict[str, str]) -> dict[str, str]:
    """Replace every credential-shaped ``env`` entry with a ``${VAR}`` reference.

    Shared by :func:`redact_target_yaml` (persisted/copied target.yaml files) and
    the ``scan --scaffold`` / ``mylonite init --transport mcp`` starter renderer
    (``cli.py``'s ``_render_target_scaffold``) — a FOURTH origination path for the
    same DCR-0006/0010/0016/0019 leak class: a `--env` value (e.g. a live
    ``GITHUB_TOKEN``) that reaches a target.yaml written to disk. Key names and
    non-secret values survive so the file still documents the target. Unlike an
    opaque placeholder, the ``${VAR}`` reference (derived from the key via
    :func:`target_yaml_env_ref_name`) is genuinely re-runnable: set the named
    environment variable to the real value and ``load_target_file`` restores it.
    """
    return {
        k: (_env_ref_placeholder("env", k) if _is_secret_env(k, v) else v)
        for k, v in env.items()
    }


def redact_target_yaml(text: str) -> str:
    """Return a copy of a ``target.yaml`` document safe to persist or publish.

    Mylonite's own documented workflow tells the operator to commit the scan and
    generated-test directories and to push the gate artefacts as a PR. Copying a
    target file byte-for-byte into any of those puts a live bearer token or DB
    password into git history (DCR-0006/0010/0016). This replaces every ``headers``
    value unconditionally (both the sse/http transport's top-level ``headers`` and
    the rest transport's ``request.headers``) and every credential-shaped ``env``
    value with a ``${VAR}`` reference (:func:`target_yaml_env_ref_name`), leaving
    key names and structure intact so the copy still documents the target. Unlike
    a bare placeholder, this is genuinely OPERATIONAL, not just structurally
    parseable: the copy still round-trips through ``load_target_file`` to a
    RUNNABLE target once the operator sets the named environment variable(s) to
    the real values — ``load_target_file`` expands ``${VAR}`` references and
    fails loudly (never with an empty/broken credential) if one is unset.

    A document that does not parse as a YAML mapping falls back to
    :func:`redact` over the raw text — a malformed file is never persisted
    verbatim.
    """
    import yaml

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        return redact(text)
    if not isinstance(data, dict):
        return redact(text)

    for section in _ALWAYS_MASK_SECTIONS:
        block = data.get(section)
        if isinstance(block, dict):
            data[section] = {k: _env_ref_placeholder(section, k) for k in block}

    for parent_key, child_key in _ALWAYS_MASK_NESTED_SECTIONS:
        parent = data.get(parent_key)
        if isinstance(parent, dict):
            block = parent.get(child_key)
            if isinstance(block, dict):
                parent[child_key] = {
                    k: _env_ref_placeholder(parent_key, child_key, k) for k in block
                }

    env = data.get("env")
    if isinstance(env, dict):
        data["env"] = redact_env(env)

    return _REDACTION_BANNER + yaml.safe_dump(data, sort_keys=True, default_flow_style=False)
