"""Record the provider-matrix LiteLLM fixtures (T16/H5) — maintainer-run, needs
real provider credentials, costs real money in small amounts, run once (or
whenever the probe scenario changes) and commit the results.

*** THIS SCRIPT IS NOT RUN IN CI. It is not run automatically by anything in
this repository. A human with real provider API keys runs it manually, once,
and commits the fixtures it writes. ***

What this is
------------
``tests/integration/test_provider_matrix.py`` proves Mylonite's LLM call
chokepoints (``scan._llm.litellm_json_call_async`` etc. — see T14/T15) work
against a REPRESENTATIVE set of real providers, not just whichever one the
test author happened to have a key for. Doing that in CI on every run would
mean CI needs six sets of live provider credentials AND burns real money on
every push — unacceptable. So the round-trip happens exactly ONCE, here, by
a maintainer, and every fixture it writes is replayed forever after with zero
network access and zero cost (see ``mylonite.demo._replay.LiteLLMRecorder`` —
the same record/replay core the offline ``mylonite demo`` uses, promoted in
v0.3.0).

This script drives the real production chokepoint
(``scan._llm.litellm_json_call_async`` — the exact function the customiser
and judge call) with a completion_fn of a real ``LiteLLMRecorder`` in
"record" mode, for each ``(name, model)`` pair in
``tests.integration._provider_matrix_spec.PROVIDER_MATRIX``. It deliberately
does NOT call ``litellm.completion``/``litellm.acompletion`` directly — that
would prove nothing about whether Mylonite's OWN call path (policy kwargs,
JSON-fence parsing, provider-error classification) works against each
provider, only that the provider itself is reachable.

How to run
----------
Set whichever provider credentials you have available — you do not need all
six; the script SKIPS (prints a clear reason, does not fail) any case whose
required env var(s) are unset:

bash::

    ANTHROPIC_API_KEY=… OPENAI_API_KEY=… python scripts/record_provider_fixtures.py

PowerShell::

    $env:ANTHROPIC_API_KEY="…"; python scripts/record_provider_fixtures.py

Provider credential env vars (see ``mylonite.scan.providers.PROVIDER_ENV_VARS``):

* ``anthropic/claude-haiku-4-5`` -- ``ANTHROPIC_API_KEY``
* ``openai/gpt-4o-mini`` -- ``OPENAI_API_KEY``
* ``gemini/gemini-2.5-flash`` -- ``GEMINI_API_KEY`` (or ``GOOGLE_API_KEY``)
* ``bedrock/anthropic.claude-3-5-haiku`` -- ``AWS_ACCESS_KEY_ID`` +
  ``AWS_SECRET_ACCESS_KEY`` (+ usually ``AWS_REGION_NAME`` -- not
  precondition-checked here, but a missing region surfaces as a clear
  provider-error skip rather than a crash)
* ``ollama/llama3.3`` and ``hosted_vllm/...`` -- no API key, but need an
  ``--api-base`` pointing at your running Ollama/vLLM server (see
  ``docs/self-hosted-models.md``), e.g.::

      python scripts/record_provider_fixtures.py --api-base http://localhost:11434 --only ollama-llama3-3

Selectively re-record one case with ``--only <name>`` (repeatable); list the
matrix with ``--list``.

After recording, eyeball the written fixtures under
``tests/integration/fixtures/provider_matrix/<name>/`` for accidental
secrets before committing them (the recorder never writes ``api_key``, but
eyeball anyway — see ``LiteLLMRecorder``'s own docstring on why ``api_key``
is excluded from both the cache key and the written fixture).

Non-negotiable: this script must NEVER be run by an automated agent without
real, explicitly-provided provider credentials, and its output must NEVER be
hand-written or fabricated to fake a "recorded" fixture -- the entire point
of this suite is proving REAL provider compatibility.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from contextlib import AbstractContextManager, nullcontext
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tests.integration._provider_matrix_spec import (
    PROBE_CALLER,
    PROBE_EXPECTED_KEYS,
    PROBE_FALLBACK,
    PROBE_PROMPT,
    PROBE_SYSTEM,
    PROVIDER_MATRIX,
    ProviderMatrixCase,
    fixture_dir_for,
)

from mylonite.demo._replay import (
    CACHE_KEY_VERSION,
    CACHE_KEY_VERSION_FIELD,
    LiteLLMRecorder,
    _read_meta_cache_key_version,
)
from mylonite.scan._llm import (
    FALLBACK_CALL_RAISED,
    NonRecoverableProviderError,
    litellm_json_call_async,
    llm_scope,
    pop_fallback_cause,
)
from mylonite.scan.llm_policy import LLMPolicy
from mylonite.scan.providers import provider_from_model, required_env_vars

#: Providers that route via a self-hosted endpoint (``api_base``) instead of
#: a hosted-vendor API key. Mirrors ``LLMPolicy``'s own module docstring:
#: "LiteLLM's wiring for Ollama/vLLM/a corporate proxy/gateway is a provider
#: prefix PLUS api_base".
_SELF_HOSTED_PROVIDERS = frozenset({"ollama", "vllm", "hosted_vllm"})


def _check_dir_safe_to_record(fixture_dir: Path, expected_version: int, name: str) -> str | None:
    """Mirrors ``record_demo_fixtures.py``'s own safety check: refuse to record
    into a directory that already holds fixtures keyed with a DIFFERENT (or
    no declared) cache-key version, which would leave a silently mixed,
    ambiguously-keyed directory. Returns an error message, or ``None`` if
    safe to proceed."""
    if not fixture_dir.is_dir():
        return None
    existing = [p for p in fixture_dir.glob("*.json") if p.name != "_meta.json"]
    if not existing:
        return None
    declared = _read_meta_cache_key_version(fixture_dir)
    if declared == expected_version:
        return None
    if declared is None:
        return (
            f"{name}: {fixture_dir} already has {len(existing)} fixture file(s) but no "
            "_meta.json declaring a cache_key_version -- delete the stale *.json files "
            "first, then re-run."
        )
    return (
        f"{name}: {fixture_dir}'s _meta.json declares cache_key_version={declared}, but "
        f"this run would use {expected_version} -- delete the stale fixtures (and "
        "_meta.json) first, then re-run."
    )


def _stamp_meta(fixture_dir: Path, case: ProviderMatrixCase) -> None:
    """Write ``_meta.json`` BEFORE recording (see ``record_demo_fixtures.py``'s
    own ``_stamp_meta`` docstring for why: an interrupted run must still leave
    a self-consistent directory a later replay resolves the same key for)."""
    fixture_dir.mkdir(parents=True, exist_ok=True)
    (fixture_dir / "_meta.json").write_text(
        json.dumps(
            {CACHE_KEY_VERSION_FIELD: CACHE_KEY_VERSION, "model": case.model, "name": case.name},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


async def _record_one(case: ProviderMatrixCase, *, api_base: str | None) -> bool:
    """Record ``case``'s fixture. Returns ``True`` on a genuine fixture write."""
    provider = provider_from_model(case.model)
    policy_cm: AbstractContextManager[None]
    if provider in _SELF_HOSTED_PROVIDERS:
        if not api_base:
            print(
                f"[skip] {case.name} ({case.model}): self-hosted provider {provider!r} "
                "needs --api-base (or MYLONITE_API_BASE) pointing at your running "
                "Ollama/vLLM server -- see docs/self-hosted-models.md"
            )
            return False
        policy_cm = llm_scope(policy=LLMPolicy(api_base=api_base))
    else:
        missing = [v for v in required_env_vars(provider) if not os.environ.get(v)]
        if missing:
            print(f"[skip] {case.name} ({case.model}): missing env var(s) {missing}")
            return False
        policy_cm = nullcontext()

    fixture_dir = fixture_dir_for(case)
    refusal = _check_dir_safe_to_record(fixture_dir, CACHE_KEY_VERSION, case.name)
    if refusal is not None:
        print(f"[refuse] {refusal}")
        return False
    _stamp_meta(fixture_dir, case)
    recorder = LiteLLMRecorder(fixture_dir, mode="record")

    try:
        with policy_cm:
            result = await litellm_json_call_async(
                model=case.model,
                prompt=PROBE_PROMPT,
                expected_keys=PROBE_EXPECTED_KEYS,
                fallback=PROBE_FALLBACK,
                caller=PROBE_CALLER,
                system=PROBE_SYSTEM,
                completion_fn=recorder,
            )
    except NonRecoverableProviderError as exc:
        print(f"[FAIL] {case.name} ({case.model}): non-recoverable provider error: {exc}")
        return False
    except Exception as exc:  # pragma: no cover - genuinely unexpected, still a clean report
        print(f"[FAIL] {case.name} ({case.model}): unexpected error: {exc!r}")
        return False

    cause, detail = pop_fallback_cause(result)
    if cause == FALLBACK_CALL_RAISED:
        print(f"[FAIL] {case.name} ({case.model}): call raised, no fixture recorded ({detail})")
        return False
    if cause is not None:
        print(
            f"[warn] {case.name} ({case.model}): fixture recorded but the response "
            f"wasn't clean JSON ({detail}) -- still a valid recorded round-trip"
        )
    else:
        print(f"[OK] {case.name} ({case.model}): fixture recorded -> {fixture_dir}")
    return True


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else "")
    parser.add_argument(
        "--only",
        action="append",
        default=None,
        metavar="NAME",
        help="Restrict to one ProviderMatrixCase.name (repeatable). Default: all.",
    )
    parser.add_argument(
        "--api-base",
        default=os.environ.get("MYLONITE_API_BASE"),
        metavar="URL",
        help="Base URL for self-hosted (ollama/vllm) cases. Defaults to $MYLONITE_API_BASE.",
    )
    parser.add_argument("--list", action="store_true", help="List the provider matrix and exit.")
    return parser.parse_args(argv)


async def _main(argv: list[str]) -> int:
    args = _parse_args(argv)
    if args.list:
        for case in PROVIDER_MATRIX:
            print(f"{case.name:<28} {case.model:<45} {case.note}")
        return 0

    cases = PROVIDER_MATRIX
    if args.only:
        wanted = set(args.only)
        cases = tuple(c for c in PROVIDER_MATRIX if c.name in wanted)
        unknown = wanted - {c.name for c in PROVIDER_MATRIX}
        if unknown:
            print(f"error: unknown --only name(s) {sorted(unknown)}", file=sys.stderr)
            return 2

    print(f"Recording {len(cases)} provider-matrix fixture(s)...")
    recorded = 0
    for case in cases:
        if await _record_one(case, api_base=args.api_base):
            recorded += 1

    print(f"\n=== Recording summary: {recorded}/{len(cases)} recorded ===")
    print(
        "Reminder: eyeball the written fixtures for accidental secrets before "
        "committing (see this script's module docstring)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main(sys.argv[1:])))
