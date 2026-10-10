"""LiteLLM record/replay core shared by the testkit, the reference validator,
and the provider-fixture recording scripts.

Promoted from ``tests/integration/_recorder.py`` (v0.2.x). Originally lived at
``mylonite.demo._replay`` to back the offline ``mylonite demo`` on-ramp; that
command and its packaged fixtures were removed, but this module's record/
replay core was never demo-specific and is still load-bearing for
``mylonite.testkit``, ``mylonite.plugins._reference.reference_validator``, and
the ``scripts/record_*_fixtures.py`` family, so it was relocated here rather
than deleted.

Cache-key format versions
--------------------------
Two cache-key algorithms exist, selected PER ``fixtures_dir`` (see
:func:`_resolve_key_version`):

* **v1** (:func:`_stable_key_v1`, the original ``_stable_key``) hashes the
  canonicalised ``(model, messages)`` pair ONLY — ``tools``,
  ``tool_choice``, ``response_format``, and ``api_base`` are excluded from
  the key (though still forwarded to the underlying call in record mode).
  This is a real gap: two calls with the same ``(model, messages)`` but a
  DIFFERENT tool schema or response-format mode collide on the same fixture
  file, and replay silently returns whichever response was recorded first.
  Because the tool schema is exactly what used to differ between the
  vulnerable and guarded reference variants, fixtures had to be namespaced
  per variant (``fixtures/vulnerable/``, ``fixtures/guarded/``) to avoid
  this collision. v1 is kept, byte-for-byte, purely for historical fixture
  sets that declared ``cache_key_version: 1`` before v2 existed (the demo's
  own such fixtures shipped this way and were removed along with it);
  nothing should record NEW fixtures with it.
* **v2** (:func:`_stable_key_v2`) additionally folds ``tools``,
  ``tool_choice``, ``response_format``, and ``api_base`` into the key —
  everything that changes what response comes back for the same
  conversation — while still excluding ``api_key`` (a secret, and rotating
  it must never cause a cache miss) and other non-identity call plumbing
  (e.g. ``timeout``). v2 is kept for replay of directories recorded before
  v3; nothing records NEW fixtures with it.
* **v3** (:func:`_stable_key_v3`, the current :data:`CACHE_KEY_VERSION`)
  hashes the same fields as v2 with secret-shaped spans handled by origin: a
  recorded reply, and the target's echo of a span the model introduced, are
  hashed in redacted form (a v3 recording stores only the redacted response,
  see "Redaction" below), and every other secret-shaped span enters the key
  only through a slow salted digest, so two conversations that differ inside
  a secret never share a key. A call with nothing secret-shaped in it hashes
  identically under v2 and v3.
  The masking rules have grown since 0.12.0 (more token shapes, the
  ``Authorization``-scheme rule, the target's own credentials), which changes
  the key of a conversation holding such a span. A replay miss therefore
  retries with the 0.12.0 rules (:func:`_stable_key_v3_legacy`) before it
  reports a miss, so a fixture recorded under 0.12.0 keeps replaying.

Redaction
---------
A recorded fixture is committed by ``mylonite gate`` and lives in the user's
repository, and a target can echo a live secret into a model reply. Record
mode therefore writes every response through
:func:`mylonite._redaction.redact_value` before it reaches disk; the live,
unredacted response is still what the record-time caller receives. Record mode
only writes v3: a directory that declares an older ``cache_key_version`` is
refused with :class:`FixtureVersionError` (its keys were computed over the
unredacted request, so redacted replies recorded into it would not replay).
Replay of an older directory still works with its own algorithm. A version
this module does not know is refused in either mode, never guessed.

A ``fixtures_dir`` declares its version via a ``_meta.json`` sidecar's
``cache_key_version`` field (``{"cache_key_version": 2, ...}``). This is a
DIFFERENT field from ``mylonite.testkit.FIXTURE_FORMAT_VERSION``'s
``format_version``, which lives in the SAME ``_meta.json`` file but means
something unrelated (per-exploit fixture-isolation SCOPE — predating this
module's cache-key versioning). The two fields are deliberately independent
so a future bump to either, for its own reason, cannot silently confuse
dispatch in the other subsystem — see :data:`CACHE_KEY_VERSION_FIELD`. No
sidecar, OR a legacy sidecar that only carries the unrelated
``format_version`` field, means :data:`CACHE_KEY_VERSION` (the best
available algorithm) in EITHER mode. Historically, pre-sidecar fixture
directories that needed v1 declared ``cache_key_version: 1`` EXPLICITLY via
their own ``_meta.json`` — there is no implicit "no sidecar means legacy v1"
assumption for REPLAY. See :func:`_resolve_key_version` for the full dispatch
rule.

Replay mode accepts any ``importlib.resources`` Traversable for
``fixtures_dir``, so fixtures can be read straight out of an installed
wheel or zip. Record mode requires a real ``pathlib.Path`` — it has to
``mkdir`` and write, which the Traversable protocol does not offer.

Error-surfacing contract: the scan engine's ``_llm.py`` fallback chain and
the adapter's skip-conversion swallow exceptions raised by
``completion_fn``, so a caller must inspect recorder state after the run
(``cache_misses``, ``last_error``) rather than rely on exception propagation.

This module must not import from ``mylonite.scan`` (keeps this dependency-free
core usable from the testkit, the validator, and standalone scripts alike).
"""

from __future__ import annotations

import functools
import hashlib
import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from importlib.resources.abc import Traversable
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Literal

from mylonite._redaction import (
    REDACTION_PLACEHOLDER,
    _redact_legacy,
    _secret_spans_legacy,
    redact,
    redact_value,
    secret_spans,
)

#: Generic re-record guidance used when a construction site doesn't supply
#: its own ``missing_fixture_hint`` (e.g. record-mode-only callers, where a
#: replay-error hint is never actually surfaced).
GENERIC_RERECORD_HINT = "Re-record this fixture set against a live provider."


class FixtureError(RuntimeError):
    """Common base for all fixture record/replay errors."""


class MissingFixtureError(FixtureError):
    """Raised in replay mode when no fixture matches the (model, messages) pair."""


class CorruptFixtureError(FixtureError):
    """Raised in replay mode when a fixture file exists but is not valid JSON."""


class FixtureConflictError(FixtureError):
    """Raised in record mode when a key already exists with different content."""


class FixtureVersionError(FixtureError):
    """Raised when a ``fixtures_dir`` declares a ``cache_key_version`` this
    recorder cannot use: unknown in either mode, or older than
    :data:`CACHE_KEY_VERSION` in record mode."""


def _stable_key_v1(model: str, messages: Sequence[Any]) -> str:
    """Original cache-key algorithm: ``(model, messages)`` ONLY.

    Kept byte-for-byte unchanged — any fixture directory that still declares
    ``cache_key_version: 1`` was recorded with this exact function, and
    :func:`_resolve_key_version` routes replay against it straight back here.
    Do not extend this function; add to :func:`_stable_key_v2` instead.
    """
    payload = json.dumps(
        {"model": model, "messages": list(messages)},
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


#: Back-compat alias — existing importers (tests, ``tests/integration/_recorder.py``)
#: use the un-suffixed name for the v1 algorithm.
_stable_key = _stable_key_v1


#: The extra call kwargs that are identity-relevant to a v2 cache key — i.e.
#: they change what response comes back for the same ``(model, messages)``
#: conversation. Deliberately an ALLOWLIST rather than "everything except a
#: denylist": an open-ended kwargs dict can carry litellm-internal objects
#: (callbacks, logging hooks, client/session objects) whose ``repr()``/``str()``
#: is not stable across calls, which would silently defeat caching if blindly
#: included. The complement of this allowlist — notably ``api_key`` (a secret;
#: rotating it must never cause a cache miss) and ``timeout`` (a client-side
#: call bound, not a request parameter) — is exactly what a denylist would
#: have named, just expressed the safer way round.
_KEY_V2_IDENTITY_KWARGS: tuple[str, ...] = ("tools", "tool_choice", "response_format", "api_base")


def _identity_payload(model: str, messages: Sequence[Any], **kwargs: Any) -> dict[str, Any]:
    """The ``(model, messages)`` pair plus the identity kwargs that are set."""
    payload: dict[str, Any] = {"model": model, "messages": list(messages)}
    for name in _KEY_V2_IDENTITY_KWARGS:
        value = kwargs.get(name)
        if value is not None:
            payload[name] = value
    return payload


def _stable_key_v2(model: str, messages: Sequence[Any], **kwargs: Any) -> str:
    """v2 cache-key algorithm: ``(model, messages)`` plus identity-relevant kwargs.

    Folds in ``tools``/``tool_choice``/``response_format``/``api_base`` (when
    present and not ``None``) so two calls that differ only in tool schema or
    response-format mode no longer collide on the same fixture. ``dict``
    values (e.g. individual tool schemas) are canonicalised the same way as
    ``messages`` already was — ``json.dumps(..., sort_keys=True)`` sorts keys
    recursively through nested dicts (including those inside lists), so key
    ordering never affects the hash. A non-JSON-native value (e.g. a Pydantic
    ``response_format`` class) falls back to ``str()``, which is stable for
    the same object/class across calls.
    """
    payload = _identity_payload(model, messages, **kwargs)
    body = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _stable_key_v3(model: str, messages: Sequence[Any], **kwargs: Any) -> str:
    """v3 cache-key algorithm: the v2 fields, with secret-shaped spans handled.

    The payload is canonicalised to plain JSON (``default=str``, as v2 does),
    then the messages are walked IN ORDER, tracking where each secret-shaped
    span (:func:`mylonite._redaction.secret_spans`) first appeared:

    1. **Recorded replies are keyed redacted.** An ``assistant`` message is
       a reply this recorder stored redacted, so every string in it goes
       through :func:`mylonite._redaction.redact`. At replay time the agent
       copies the redacted reply back; at record time it copied the raw one;
       both redact to the same text (:func:`redact` is idempotent).
    2. **A span the model introduced is keyed as its redacted echo.** A span
       in an assistant message that no EARLIER non-assistant message carried
       came from the model. At replay time the target is sent the redacted
       value, so in every LATER non-assistant message that span is replaced
       by the placeholder before keying.
    3. **Every other secret-shaped span is keyed by content, slowly.** A
       span that the target, the user or the system prompt emitted (including
       one the model later forwards: the exfiltration case) is the same at
       record and replay time and must tell two recordings apart, so a guard
       that masks a credential and one that leaks it never share a key. It is
       replaced by the placeholder in the hashed payload, and the string's
       spans enter the key only through :func:`_spans_digest` (one scrypt
       per string, salted with the string's redacted form), so the stored key
       and file name are not a fast hash of a secret-shaped value.

    Origin is decided from the conversation alone, the same way at record and
    replay time. One case still differs, loudly (a miss): a target that
    emitted a span, then later echoes the model's copy of that same span.
    With nothing secret-shaped in a call, the hashed body is exactly v2's.
    """
    return _v3_key(model, messages, redact, secret_spans, **kwargs)


def _stable_key_v3_legacy(model: str, messages: Sequence[Any], **kwargs: Any) -> str:
    """The v3 key as 0.12.0 computed it, for replay only.

    Same algorithm as :func:`_stable_key_v3`, with the 0.12.0 masking rules
    (``mylonite._redaction._redact_legacy`` and ``_secret_spans_legacy``):
    no token shapes added since, no ``Authorization``-scheme rule and no
    registered target credentials. A conversation with none of those spans
    keys the same both ways. :class:`LiteLLMRecorder` tries this key only
    when the current one misses in replay mode, so a fixture recorded under
    0.12.0 still replays; record mode always writes the current key.
    """
    return _v3_key(model, messages, _redact_legacy, _secret_spans_legacy, **kwargs)


def _v3_key(
    model: str,
    messages: Sequence[Any],
    redact_fn: Callable[[str], str],
    spans_fn: Callable[[str], list[str]],
    **kwargs: Any,
) -> str:
    canonical = json.loads(
        json.dumps(_identity_payload(model, messages, **kwargs), sort_keys=True, default=str)
    )
    digests: list[str] = []

    def keyed(value: Any, echoes: list[str]) -> Any:
        if isinstance(value, str):
            for echo in echoes:
                value = value.replace(echo, REDACTION_PLACEHOLDER)
            masked = redact_fn(value)
            spans = spans_fn(value)
            if spans:
                digests.append(_spans_digest(tuple(spans), masked))
            return masked
        if isinstance(value, dict):
            return {k: keyed(v, echoes) for k, v in sorted(value.items())}
        if isinstance(value, list):
            return [keyed(v, echoes) for v in value]
        return value

    hashed: dict[str, Any] = {}
    for name, value in sorted(canonical.items()):
        if name != "messages" or not isinstance(value, list):
            hashed[name] = keyed(value, [])
            continue
        emitted: set[str] = set()  # spans a non-assistant message carried so far
        model_spans: set[str] = set()  # spans the model introduced so far
        keyed_messages: list[Any] = []
        for message in value:
            if isinstance(message, dict) and message.get("role") == "assistant":
                for leaf in _string_leaves(message):
                    model_spans.update(span for span in spans_fn(leaf) if span not in emitted)
                keyed_messages.append(_redact_strings(message, redact_fn))
                continue
            for leaf in _string_leaves(message):
                emitted.update(spans_fn(leaf))
            echoes = sorted(model_spans, key=len, reverse=True)
            keyed_messages.append(keyed(message, echoes))
        hashed[name] = keyed_messages
    if digests:
        hashed[_SPAN_DIGESTS_FIELD] = digests
    body = json.dumps(hashed, sort_keys=True)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


#: Hashed-payload field (never stored) that carries the span digests.
_SPAN_DIGESTS_FIELD = "_secret_span_digests"

#: scrypt cost for :func:`_spans_digest`: 2**15 x 8 x 128 bytes = 32 MiB of
#: memory and on the order of 0.1 s per string on one core. A guess at a
#: span costs the same, so recovering a random 12-character
#: credential-alphabet value (64**12, about 4.7e21 candidates) from a stored
#: key is out of reach, and a dictionary attack pays this per guess per
#: context. It slows, but does not prevent, guessing a weak password.
_SCRYPT_N = 2**15
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_MAXMEM = 2**26


@functools.lru_cache(maxsize=4096)
def _spans_digest(spans: tuple[str, ...], context: str) -> str:
    """A slow, context-salted digest of the secret-shaped spans of one string.

    One scrypt per string, whatever its span count, so a tool output that
    lists hundreds of path-like ``key: ...`` values costs one call, not one
    per value. The salt is the string's redacted form, so a table built for
    one context does not carry over to another. Cached, because a
    conversation repeats its earlier messages on every later turn.
    """
    salt = hashlib.sha256(("mylonite-fixture-span-v3\0" + context).encode("utf-8")).digest()
    return hashlib.scrypt(
        json.dumps(list(spans)).encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        maxmem=_SCRYPT_MAXMEM,
        dklen=32,
    ).hex()


def _string_leaves(value: Any) -> list[str]:
    """Every string leaf of ``value``, depth first."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [leaf for v in value.values() for leaf in _string_leaves(v)]
    if isinstance(value, list):
        return [leaf for v in value for leaf in _string_leaves(v)]
    return []


def _redact_strings(value: Any, redact_fn: Callable[[str], str] = redact) -> Any:
    """Apply ``redact_fn`` (default :func:`mylonite._redaction.redact`) to every
    string leaf of ``value``."""
    if isinstance(value, str):
        return redact_fn(value)
    if isinstance(value, dict):
        return {k: _redact_strings(v, redact_fn) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_strings(v, redact_fn) for v in value]
    return value


def _key_v1_any_kwargs(model: str, messages: Sequence[Any], **_kwargs: Any) -> str:
    """:func:`_stable_key_v1` with the shared signature (v1 ignores kwargs)."""
    return _stable_key_v1(model, messages)


#: Every cache-key algorithm this module can replay, by version.
_KEY_ALGORITHMS: dict[int, Callable[..., str]] = {
    1: _key_v1_any_kwargs,
    2: _stable_key_v2,
    3: _stable_key_v3,
}


#: The ``_meta.json`` sidecar field this module reads for cache-key-algorithm
#: dispatch. Deliberately a DIFFERENT name from ``mylonite.testkit
#: .FIXTURE_FORMAT_VERSION``'s own ``format_version`` field, which lives in
#: the SAME sidecar file but means something unrelated (per-exploit
#: fixture-isolation SCOPE — see that module's docstring). Before this field
#: existed, ``_resolve_key_version`` read ``format_version`` directly, which
#: meant the two concerns only agreed by coincidence (both happened to equal
#: 2) with nothing cross-referencing the coupling — a future bump to either
#: constant, for its own unrelated reason, could have silently broken replay
#: in the OTHER subsystem. This field lets the two vary independently.
CACHE_KEY_VERSION_FIELD = "cache_key_version"

#: The cache-key algorithm this module uses by default — in EITHER mode —
#: when an EMPTY ``fixtures_dir`` has no ``_meta.json`` (or no
#: ``cache_key_version`` field in it) to declare otherwise. Writers that stamp ``_meta.json`` after
#: (or before) recording into a fresh directory should use THIS constant
#: rather than a locally hardcoded literal, so the sidecar can never drift
#: from what the recorder actually used.
CACHE_KEY_VERSION = 3


def _has_recorded_fixtures(fixtures_dir: Path | Traversable) -> bool:
    """True when ``fixtures_dir`` holds at least one recorded ``*.json`` file."""
    try:
        if not fixtures_dir.is_dir():
            return False
        return any(
            entry.name.endswith(".json") and entry.name != "_meta.json"
            for entry in fixtures_dir.iterdir()
        )
    except OSError:
        return False


def _read_meta_cache_key_version(fixtures_dir: Path | Traversable) -> int | None:
    """Read the :data:`CACHE_KEY_VERSION_FIELD` int out of ``_meta.json``.

    ``None`` means the directory declares no version: no sidecar, or a
    sidecar object without the field (a LEGACY sidecar that only carries the
    unrelated ``format_version`` field). A sidecar that exists but cannot be
    read, is not valid JSON, is not an object, or carries a field that is not
    a plain int (``true`` is refused, although Python counts it as an int)
    raises :class:`FixtureVersionError`: a damaged sidecar never silently
    resolves to the default.
    """
    meta_path = fixtures_dir / "_meta.json"
    try:
        if not meta_path.is_file():
            return None
        raw = meta_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise FixtureVersionError(f"cannot read {meta_path}: {exc}") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise FixtureVersionError(f"{meta_path} is not valid JSON ({exc})") from exc
    if not isinstance(data, dict):
        raise FixtureVersionError(f"{meta_path} is not a JSON object")
    if CACHE_KEY_VERSION_FIELD not in data:
        return None
    version = data[CACHE_KEY_VERSION_FIELD]
    if type(version) is not int:
        raise FixtureVersionError(
            f"{meta_path} has {CACHE_KEY_VERSION_FIELD}={version!r}, which is not an integer"
        )
    return version


def _resolve_key_version(
    fixtures_dir: Path | Traversable, mode: Literal["record", "replay"]
) -> int:
    """Pick which cache-key algorithm (1 to 3) a recorder over ``fixtures_dir`` uses.

    A directory that declares no version but already holds recorded fixtures
    raises :class:`FixtureVersionError` in either mode: guessing would replay
    or extend it under an algorithm it may not have been recorded with. A
    damaged sidecar raises too (see :func:`_read_meta_cache_key_version`).

    A directory that declares its own ``_meta.json`` :data:`CACHE_KEY_VERSION_FIELD`
    wins outright, in EITHER mode — an explicit sidecar speaks for itself.

    No sidecar, or a legacy sidecar that only carries the unrelated
    ``format_version`` field (see :data:`CACHE_KEY_VERSION_FIELD`'s
    docstring), means :data:`CACHE_KEY_VERSION` in EITHER mode — ``mode`` is
    accepted for API stability (existing callers pass it, and record mode's
    own guard rails elsewhere still reason about it independently) but no
    longer changes this function's answer.

    This used to be mode-dependent: REPLAY silently defaulted to **v1**
    while RECORD defaulted to :data:`CACHE_KEY_VERSION`. That asymmetry
    existed ONLY to keep pre-sidecar fixture directories that were recorded
    with v1 replaying — "no signal" had to mean "the original algorithm" or
    every lookup against them would miss. Retiring that implicit fallback
    (T-close-the-loop): any directory that still needs v1 now declares
    ``cache_key_version: 1`` EXPLICITLY via its own ``_meta.json`` (an
    explicit sidecar wins outright, per the first paragraph above), so
    nothing depends on the old mode-dependent guess any more. Collapsing the
    no-sidecar default to a
    single, mode-independent answer — the best available algorithm, always,
    unless a directory explicitly opts out — removes the implicit "assume
    legacy v1" behaviour :data:`CACHE_KEY_VERSION_FIELD`'s docstring warns
    can silently return a stale, wrong response for a tool-bearing call: a
    brand-new, sidecar-less directory now gets the current version (folding in
    ``tools``/``tool_choice``/``response_format``/``api_base``) rather than
    silently inheriting v1 behaviour it was never recorded with. A call with
    none of those extra kwargs hashes identically under v1 and v2 (see
    :func:`_stable_key_v2`'s docstring), so this default only ever changes
    behaviour for the case that mattered.
    """
    declared = _read_meta_cache_key_version(fixtures_dir)
    if declared is not None:
        return declared
    if _has_recorded_fixtures(fixtures_dir):
        raise FixtureVersionError(
            f"{fixtures_dir} holds recorded fixtures but its _meta.json declares no "
            f"{CACHE_KEY_VERSION_FIELD}, so Mylonite cannot tell how they were keyed. "
            "Restore the sidecar, or delete the directory and record again."
        )
    return CACHE_KEY_VERSION


def check_recordable(fixtures_dir: Path) -> None:
    """Raise :class:`FixtureVersionError` unless record mode can write to ``fixtures_dir``.

    The same checks :class:`LiteLLMRecorder` makes when it is built in record
    mode, without creating anything, so a caller can run them before it
    spends a live model call.
    """
    version = _resolve_key_version(fixtures_dir, "record")
    _check_version(fixtures_dir, version, "record")


def _check_version(
    fixtures_dir: Path | Traversable,
    version: int,
    mode: Literal["record", "replay"],
    hint: str = GENERIC_RERECORD_HINT,
) -> None:
    if version not in _KEY_ALGORITHMS:
        raise FixtureVersionError(
            f"{fixtures_dir} declares {CACHE_KEY_VERSION_FIELD}={version}, which this "
            f"mylonite does not support (it reads 1 to {CACHE_KEY_VERSION}). "
            f"Upgrade mylonite or re-record. {hint}"
        )
    if mode == "record" and version != CACHE_KEY_VERSION:
        raise FixtureVersionError(
            f"refusing to record into {fixtures_dir}: its _meta.json declares "
            f"{CACHE_KEY_VERSION_FIELD}={version}, the format from before recorded "
            f"fixtures were redacted (current: {CACHE_KEY_VERSION}). Delete that "
            "fixtures directory (its *.json files and _meta.json) and record again."
        )


#: How many leading hex digits of a cache key name a NEWLY recorded fixture
#: file. The full 64-digit SHA-256 made each name 69 characters, which is what
#: pushed a committed gate directory past Windows' 260-character path limit
#: from a moderately deep checkout. 12 hex digits is 48 bits: a collision
#: inside one fixture directory (tens of files) is not a practical concern:
#: record mode refuses to overwrite a different response, and a short-named
#: recording stores its full key (:data:`_KEY_FIELD`), which replay checks.
#:
#: Lookup tries the exact full 64-digit name first, then the short one, so
#: every directory recorded before this change keeps replaying unchanged.
FIXTURE_NAME_LENGTH = 12


#: Field a short-named recording carries with its full cache key, so a replay
#: whose key merely shares the 12-digit prefix is a miss, never another
#: call's answer. Full-length recordings are named by the key itself.
_KEY_FIELD = "_key"


def _fixture_candidates(
    fixtures_dir: Path | Traversable, key: str
) -> tuple[Path | Traversable, Path | Traversable]:
    """The short (current) and full-length (legacy) file for ``key``."""
    return (
        fixtures_dir / f"{key[:FIXTURE_NAME_LENGTH]}.json",
        fixtures_dir / f"{key}.json",
    )


def _response_from_dict(data: dict[str, Any]) -> SimpleNamespace:
    """Rebuild a minimal LiteLLM-shaped response object from JSON.

    ``finish_reason`` (per-choice) and ``usage`` (response-level) are
    reconstructed when present in the fixture JSON, ``None`` otherwise — v1
    fixtures never recorded either field, so this stays backward compatible:
    a v1-shaped fixture simply yields ``finish_reason=None`` / ``usage=None``.
    ``finish_reason == "length"`` is the signal a response was truncated
    (hit ``max_tokens``), which is exactly what a missing ``max_tokens``
    setting elsewhere would produce — capturing it lets a fixture-based test
    assert truncation was detected.
    """
    choices = []
    for choice in data.get("choices", []):
        message = choice.get("message", {})
        tool_calls_raw = message.get("tool_calls")
        tool_calls: list[Any] | None = None
        if tool_calls_raw:
            tool_calls = [
                SimpleNamespace(
                    id=tc.get("id", "call_0"),
                    function=SimpleNamespace(
                        name=tc["function"]["name"],
                        arguments=tc["function"]["arguments"],
                    ),
                )
                for tc in tool_calls_raw
            ]
        choices.append(
            SimpleNamespace(
                message=SimpleNamespace(
                    content=message.get("content", ""),
                    tool_calls=tool_calls,
                ),
                finish_reason=choice.get("finish_reason"),
            )
        )
    usage_data = data.get("usage")
    usage = SimpleNamespace(**usage_data) if isinstance(usage_data, dict) else None
    return SimpleNamespace(choices=choices, usage=usage)


def _usage_to_dict(usage: Any) -> dict[str, Any] | None:
    """Best-effort plain-dict shape for a LiteLLM/OpenAI ``usage`` object.

    Tries, in order: already a ``dict``; a Pydantic-style ``model_dump()``;
    falling back to the three well-known token-count attributes. Returns
    ``None`` when nothing usable is found rather than writing an empty/
    misleading ``usage`` key into the fixture.
    """
    if isinstance(usage, dict):
        return dict(usage)
    model_dump = getattr(usage, "model_dump", None)
    if callable(model_dump):
        try:
            dumped = model_dump()
        except Exception:  # pragma: no cover - defensive, provider-object dependent
            dumped = None
        if isinstance(dumped, dict):
            return dumped
    result: dict[str, Any] = {}
    for attr in ("prompt_tokens", "completion_tokens", "total_tokens"):
        value = getattr(usage, attr, None)
        if isinstance(value, int):
            result[attr] = value
    return result or None


def _dictify_response(response: Any) -> dict[str, Any]:
    """Best-effort JSON shape for an OpenAI-compatible LiteLLM completion.

    Captures ``finish_reason`` per choice and response-level ``usage`` when
    present — see :func:`_response_from_dict` for why. Both are omitted from
    the JSON entirely when unavailable (e.g. a test double that doesn't set
    them), so old and new fixtures stay structurally compatible.
    """
    choices = []
    for choice in getattr(response, "choices", []):
        msg = getattr(choice, "message", None)
        entry: dict[str, Any] = {
            "message": {
                "content": getattr(msg, "content", "") or "",
                "tool_calls": [
                    {
                        "id": getattr(tc, "id", "call_0"),
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        },
                    }
                    for tc in (getattr(msg, "tool_calls", None) or [])
                ],
            }
        }
        finish_reason = getattr(choice, "finish_reason", None)
        if finish_reason is not None:
            entry["finish_reason"] = finish_reason
        choices.append(entry)
    result: dict[str, Any] = {"choices": choices}
    usage_dict = _usage_to_dict(getattr(response, "usage", None))
    if usage_dict is not None:
        result["usage"] = usage_dict
    return result


@dataclass
class LiteLLMRecorder:
    """JSON-backed record/replay helper for ``litellm.acompletion``.

    ``fixtures_dir`` may be any ``importlib.resources`` Traversable in replay
    mode (e.g. reading straight out of an installed wheel or zip); record
    mode requires a real ``pathlib.Path`` because it must ``mkdir`` and write.

    ``missing_fixture_hint`` is appended to the cache-miss error message so
    each construction site can name its own re-record procedure (e.g.
    ``mylonite.testkit`` names ``mylonite generate``).

    ``cache_hits`` / ``cache_misses`` / ``last_error`` are runner-inspectable
    state: callers in the scan engine swallow ``completion_fn`` exceptions,
    so a post-run state check is the reliable way to detect replay problems.
    Note the counter asymmetry: a corrupt fixture increments neither
    ``cache_hits`` nor ``cache_misses`` (only ``last_error`` is set), so
    callers reconciling ``hits + misses == calls`` must also check
    ``last_error``.

    Instance state is cumulative across calls — construct one recorder per
    run or call :meth:`reset` between runs (the multi-run flakiness
    filter is the motivating case). The recorder is not thread-safe, and
    ``last_error`` reflects only the most recent failure — under concurrent
    calls use the counters as the aggregate signal; callers that need a
    reliable ``last_error`` (the testkit, the ablation runner, the reference
    validator) drive this with ``max_concurrent=1``.
    """

    fixtures_dir: Path | Traversable
    mode: Literal["record", "replay"] = "replay"
    missing_fixture_hint: str = GENERIC_RERECORD_HINT
    cache_hits: int = 0
    cache_misses: int = 0
    last_error: Exception | None = None

    def __post_init__(self) -> None:
        if isinstance(self.fixtures_dir, str):
            self.fixtures_dir = Path(self.fixtures_dir)
        if self.mode == "record":
            if not isinstance(self.fixtures_dir, Path):
                raise TypeError(
                    "record mode requires a real pathlib.Path fixtures_dir "
                    f"(mkdir/write are Path-only); got {type(self.fixtures_dir).__name__}"
                )
            self.fixtures_dir.mkdir(parents=True, exist_ok=True)
        # Resolved once at construction time (not re-checked per call): which
        # cache-key algorithm this instance uses, per the dispatch rule in
        # _resolve_key_version's docstring. A recorder is constructed fresh
        # per fixtures_dir/run, so a `_meta.json` written mid-run (e.g. by a
        # sibling recorder) is not expected to change an already-live instance.
        self._key_version: int = _resolve_key_version(self.fixtures_dir, self.mode)
        _check_version(self.fixtures_dir, self._key_version, self.mode, self.missing_fixture_hint)

    @property
    def key_version(self) -> int:
        """The cache-key algorithm (1 to 3) this instance resolved at construction.

        Callers that stamp a ``_meta.json`` sidecar for a fixtures_dir they
        just recorded into should write THIS value as
        :data:`CACHE_KEY_VERSION_FIELD`, rather than a locally hardcoded
        literal — it can never drift from what the recorder actually used to
        key the files it wrote (e.g. when an existing sidecar already
        declared a version and this instance honoured it instead of the
        record-mode default).
        """
        return self._key_version

    def reset(self) -> None:
        """Clear cumulative state (``cache_hits``, ``cache_misses``, ``last_error``)."""
        self.cache_hits = 0
        self.cache_misses = 0
        self.last_error = None

    async def __call__(self, *, model: str, messages: Sequence[Any], **kwargs: Any) -> Any:
        msgs = list(messages)
        key = _KEY_ALGORITHMS[self._key_version](model, msgs, **kwargs)
        short, full = _fixture_candidates(self.fixtures_dir, key)
        # An existing full-length file (a directory recorded before short names)
        # wins in both modes: replay reads it, and record compares against it
        # instead of writing a second copy under the short name.
        path = full if full.is_file() else short
        if self.mode == "replay":
            if path is short and short.is_file() and not self._short_name_matches(short, key):
                path = full  # another key's recording under the same prefix: a miss
            if not path.is_file() and self._key_version == 3:
                # A fixture recorded under 0.12.0 was keyed with that release's
                # masking rules; a conversation holding a span masked only
                # since then keys differently now. Try the 0.12.0 key before
                # reporting a miss, so an existing fixture keeps replaying.
                legacy = self._resolve_path(_stable_key_v3_legacy(model, msgs, **kwargs))
                if legacy is not None:
                    return self._load_fixture(key=key, model=model, path=legacy)
            return self._load_fixture(key=key, model=model, path=path)
        return await self._record(model=model, messages=messages, path=path, kwargs=kwargs, key=key)

    def _resolve_path(self, key: str) -> Path | Traversable | None:
        """The recorded file for ``key``, or ``None`` when there is none."""
        short, full = _fixture_candidates(self.fixtures_dir, key)
        if full.is_file():
            return full
        if short.is_file() and self._short_name_matches(short, key):
            return short
        return None

    @staticmethod
    def _short_name_matches(path: Path | Traversable, key: str) -> bool:
        """``False`` only when a short-named recording names a different key."""
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return True  # let _load_fixture report the file itself
        stored = data.get(_KEY_FIELD) if isinstance(data, dict) else None
        return stored is None or stored == key

    def _load_fixture(self, *, key: str, model: str, path: Path | Traversable) -> SimpleNamespace:
        if not path.is_file():
            self.cache_misses += 1
            older = (
                f" This directory uses cache_key_version={self._key_version}, the format "
                "from before recorded fixtures were redacted; a re-record writes the "
                "current one."
                if self._key_version < CACHE_KEY_VERSION
                else ""
            )
            missing = MissingFixtureError(
                f"No fixture for sha256={key} (model={model!r}) at {path}.{older} "
                f"{self.missing_fixture_hint}"
            )
            self.last_error = missing
            raise missing
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            corrupt = CorruptFixtureError(
                f"fixture corrupt — reinstall mylonite or re-record: {path} is not "
                f"valid JSON ({exc}). {self.missing_fixture_hint}"
            )
            self.last_error = corrupt
            raise corrupt from exc
        self.cache_hits += 1
        return _response_from_dict(data)

    async def _record(
        self,
        *,
        model: str,
        messages: Sequence[Any],
        path: Path | Traversable,
        kwargs: dict[str, Any],
        key: str,
    ) -> Any:
        # Record mode — defer to litellm.acompletion for the real call. The
        # import stays lazy so replay mode never needs litellm at call time.
        # Extra kwargs (notably ``tools=`` from LLMPlanner) are always
        # forwarded to the provider; whether they ALSO enter the cache key
        # depends on this instance's resolved format version (v1: no; v2:
        # yes for the identity-relevant subset — see ``_stable_key_v2``).
        import litellm

        real = await litellm.acompletion(model=model, messages=list(messages), **kwargs)
        # The fixture is committed to the user's repository: never write a
        # secret the target echoed into the reply. The caller still gets the
        # live response; the v3 key hashes the redacted conversation, so
        # replaying this redacted body reaches the same next key.
        recorded = redact_value(_dictify_response(real))
        if not isinstance(recorded, dict):  # pragma: no cover - redact_value keeps dicts
            raise TypeError("redacted fixture is not a JSON object")
        if path.name != f"{key}.json":
            # A short name drops most of the key; store it so replay can tell
            # this recording from another key's with the same prefix.
            recorded[_KEY_FIELD] = key
        serialised = json.dumps(recorded, indent=2, sort_keys=True) + "\n"
        if not isinstance(path, Path):
            # __post_init__ enforces a real Path in record mode (mkdir/write are
            # Path-only), so this should be unreachable — but never trust that an
            # invariant established elsewhere still holds at a write call site.
            raise TypeError(f"record mode requires a real pathlib.Path, got {type(path).__name__}")
        if path.is_file():
            existing = path.read_text(encoding="utf-8")
            if existing != serialised:
                conflict = FixtureConflictError(
                    f"Refusing to overwrite existing fixture {path} with different "
                    "content — the (model, messages) key collided. Namespace "
                    "fixtures per variant (fixtures/vulnerable/, fixtures/guarded/) "
                    "or delete the stale file and re-record."
                )
                self.last_error = conflict
                raise conflict
        path.write_text(serialised, encoding="utf-8")
        return real


__all__ = [
    "CACHE_KEY_VERSION",
    "CACHE_KEY_VERSION_FIELD",
    "FIXTURE_NAME_LENGTH",
    "GENERIC_RERECORD_HINT",
    "CorruptFixtureError",
    "FixtureConflictError",
    "FixtureError",
    "FixtureVersionError",
    "LiteLLMRecorder",
    "MissingFixtureError",
    "check_recordable",
]
