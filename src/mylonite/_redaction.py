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
            # getMessage() itself raised (e.g. a malformed %-format call whose
            # arg is secret-shaped) — record.msg/args were never rendered or
            # redacted. Clearing record.args here is load-bearing: left as-is,
            # stdlib logging.Handler.handleError() prints
            # 'Message: %r\nArguments: %s\n' % (record.msg, record.args)
            # straight to stderr, leaking the raw arg verbatim (DCR-0008).
            record.args = ()
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
    """
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
    value unconditionally (both the sse/http transport's top-level ``headers`` and
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
            ref_names = _dedupe_ref_names((section,), list(block.keys()))
            data[section] = {k: f"${{{ref_names[k]}}}" for k in block}

    nested_skip: dict[str, set[str]] = {}
    for parent_key, child_key in CREDENTIAL_NESTED_SECTIONS:
        nested_skip.setdefault(parent_key, set()).add(child_key)
        parent = data.get(parent_key)
        if isinstance(parent, dict):
            block = parent.get(child_key)
            if isinstance(block, dict):
                ref_names = _dedupe_ref_names((parent_key, child_key), list(block.keys()))
                parent[child_key] = {k: f"${{{ref_names[k]}}}" for k in block}

    env = data.get(CREDENTIAL_ENV_FIELD)
    if isinstance(env, dict):
        data[CREDENTIAL_ENV_FIELD] = redact_env(env)

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
