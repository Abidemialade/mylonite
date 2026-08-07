"""Provider-matrix replay suite (T16/H5).

Proves Mylonite's LLM chokepoint (``scan._llm.litellm_json_call_async``)
round-trips correctly against a REPRESENTATIVE set of real providers
(``tests.integration._provider_matrix_spec.PROVIDER_MATRIX`` — one hosted
Anthropic, one hosted OpenAI, one hosted Gemini [STRICT tool-schema dialect],
one Bedrock-fronted Anthropic [STRICT dialect + AWS credential chain], one
self-hosted Ollama, one generic self-hosted vLLM prefix).

CI REPLAYS ONLY — it never makes a live call. Fixtures are recorded exactly
once by a maintainer running ``scripts/record_provider_fixtures.py`` with
real provider credentials, then committed under
``tests/integration/fixtures/provider_matrix/<case.name>/``.

*** As of this commit, NO fixtures have been recorded (no live provider keys
were available in the environment this suite was written in — see this
repo's remediation plan, T16). Every case below SKIPS with a clear,
actionable message. This is the CORRECT, honest state: fabricating a
"recorded" fixture file to make these pass would defeat the entire point of
proving real provider compatibility. Once a maintainer runs the recording
script, the corresponding case starts asserting for real, with no code
change needed here. ***

The other, arguably more valuable half of T16 — proving every LLM call SITE
(customiser/judge/planner/gate-mitigation) genuinely carries the active
``LLMPolicy`` kwargs, 100% offline, no fixtures required — lives in
``tests/scan/test_llm_capability_contract.py``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from tests.integration._provider_matrix_spec import (
    PROBE_CALLER,
    PROBE_EXPECTED_KEYS,
    PROBE_FALLBACK,
    PROBE_PROMPT,
    PROBE_SYSTEM,
    PROVIDER_MATRIX,
    ProviderMatrixCase,
    fixture_dir_for,
    has_recorded_fixture,
)

from mylonite.demo._replay import (
    CACHE_KEY_VERSION,
    CACHE_KEY_VERSION_FIELD,
    LiteLLMRecorder,
    MissingFixtureError,
)
from mylonite.scan._llm import litellm_json_call_async, pop_fallback_cause


def _skip_reason(case: ProviderMatrixCase) -> str:
    """The message a case skips with when no fixture has been recorded yet.

    Pulled into its own function (rather than inlined at the ``pytest.skip``
    call site) so its content can be asserted on directly, offline, with no
    fixture required — see ``test_skip_reason_names_the_model_and_the_fix``
    below (the "test-of-the-test" the T16 plan calls for).
    """
    return (
        f"no recorded fixture for {case.model!r} (case {case.name!r}) at "
        f"{fixture_dir_for(case)} — run `python scripts/record_provider_fixtures.py "
        f"--only {case.name}` with a maintainer's real provider credentials to "
        "record it, then commit the fixture."
    )


# --- The replay suite itself --------------------------------------------------


@pytest.mark.parametrize("case", PROVIDER_MATRIX, ids=lambda c: c.name)
@pytest.mark.asyncio
async def test_replay_provider_matrix_case(case: ProviderMatrixCase) -> None:
    """Replay-only: SKIP (never fail, never fabricate) when no fixture exists yet.

    Once recorded, this asserts the exact production chokepoint
    (``litellm_json_call_async``) round-trips through ``LiteLLMRecorder`` in
    replay mode and produces a genuinely-parsed JSON body (not a fallback) —
    i.e. that provider's real completion output, captured once, is still
    valid strict-JSON-mode output on replay.
    """
    if not has_recorded_fixture(case):
        pytest.skip(_skip_reason(case))

    recorder = LiteLLMRecorder(fixture_dir_for(case), mode="replay")
    result = await litellm_json_call_async(
        model=case.model,
        prompt=PROBE_PROMPT,
        expected_keys=PROBE_EXPECTED_KEYS,
        fallback=PROBE_FALLBACK,
        caller=PROBE_CALLER,
        system=PROBE_SYSTEM,
        completion_fn=recorder,
    )
    cause, detail = pop_fallback_cause(result)
    assert cause is None, (
        f"{case.name} ({case.model}): replay did not produce a genuine JSON parse "
        f"(cause={cause}, detail={detail}) — the recorded fixture may be stale"
    )
    assert "body" in result
    assert recorder.cache_hits == 1
    assert recorder.cache_misses == 0


# --- Test-of-the-test: the skip path is clear and actionable, offline --------


@pytest.mark.parametrize("case", PROVIDER_MATRIX, ids=lambda c: c.name)
def test_skip_reason_names_the_model_and_the_fix(case: ProviderMatrixCase) -> None:
    """A maintainer reading a skipped-test report must be able to act on it
    with no further digging: the model id, the fixture path, and the exact
    command to run. Pure offline assertion on the message-building function —
    no fixture, no network, always runs for real."""
    reason = _skip_reason(case)
    assert case.model in reason
    assert case.name in reason
    assert "scripts/record_provider_fixtures.py" in reason
    assert str(fixture_dir_for(case)) in reason


def test_no_fixtures_are_committed_yet() -> None:
    """Documents the current, honest state of this repo (see module docstring):
    no live provider keys were available when this suite was written, so
    nothing has been recorded. This test exists so a future CI run that DOES
    have a fixture committed makes that state change visible (this assertion
    will need updating then) rather than silently drifting."""
    recorded = [c.name for c in PROVIDER_MATRIX if has_recorded_fixture(c)]
    assert recorded == [], (
        f"fixtures ARE committed for {recorded} — update this test's expectation "
        "(and celebrate: the corresponding replay case above now asserts for real)"
    )


# --- Recorder-mechanism round-trip (offline, FAKE litellm.acompletion) ------
#
# This is deliberately NOT a "recorded provider fixture" — it drives the exact
# same record -> replay machinery scripts/record_provider_fixtures.py and the
# test above depend on, but with `litellm.acompletion` itself monkeypatched to
# a FAKE, in-test function (the same technique tests/demo/test_replay.py's own
# record-mode tests use — LiteLLMRecorder's record mode always calls the real
# litellm SDK function internally, so there is no other offline way to
# exercise it), in a tmp_path, so a maintainer never burns real API credits to
# find out the plumbing itself is broken before they ever run the live
# recording script.


@pytest.mark.asyncio
async def test_recorder_mechanism_round_trips_through_the_real_chokepoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Prove record-then-replay works end-to-end through
    ``litellm_json_call_async`` + ``LiteLLMRecorder`` — the exact call shape
    ``scripts/record_provider_fixtures.py`` uses — with `litellm.acompletion`
    itself faked instead of a real provider. If this breaks, the live
    recording script would too; catching that here costs nothing and burns no
    API credits."""
    import litellm

    async def fake_acompletion(**_: Any) -> Any:
        from types import SimpleNamespace

        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content=json.dumps({"body": "provider-matrix-ok"}), tool_calls=None
                    )
                )
            ]
        )

    monkeypatch.setattr(litellm, "acompletion", fake_acompletion)

    fixture_dir = tmp_path / "fake-provider"
    # Stamp the cache-key-version sidecar BEFORE recording — exactly what
    # scripts/record_provider_fixtures.py's own _stamp_meta does, and for the
    # same reason: a sidecar-less directory resolves v2 on record but v1 on
    # REPLAY (see demo/_replay.py's _resolve_key_version docstring), which
    # would make this round-trip depend on `tools`/`response_format`/
    # `api_base` all happening to be absent rather than on an explicit,
    # future-proof declaration.
    fixture_dir.mkdir(parents=True, exist_ok=True)
    (fixture_dir / "_meta.json").write_text(
        json.dumps({CACHE_KEY_VERSION_FIELD: CACHE_KEY_VERSION}), encoding="utf-8"
    )
    record_recorder = LiteLLMRecorder(fixture_dir, mode="record")
    assert record_recorder.key_version == CACHE_KEY_VERSION

    recorded = await litellm_json_call_async(
        model="fake/does-not-matter",
        prompt=PROBE_PROMPT,
        expected_keys=PROBE_EXPECTED_KEYS,
        fallback=PROBE_FALLBACK,
        caller=PROBE_CALLER,
        system=PROBE_SYSTEM,
        completion_fn=record_recorder,
    )
    cause, _ = pop_fallback_cause(recorded)
    assert cause is None
    assert recorded == {"body": "provider-matrix-ok"}
    written = [p for p in fixture_dir.glob("*.json") if p.name != "_meta.json"]
    assert len(written) == 1, "record mode must write exactly one fixture file"

    # Now replay it — a FRESH recorder in replay mode, no completion_fn stub
    # this time, proving the WRITTEN FILE (not just the in-memory call) is
    # what a later replay reads back.
    replay_recorder = LiteLLMRecorder(fixture_dir, mode="replay")
    replayed = await litellm_json_call_async(
        model="fake/does-not-matter",
        prompt=PROBE_PROMPT,
        expected_keys=PROBE_EXPECTED_KEYS,
        fallback=PROBE_FALLBACK,
        caller=PROBE_CALLER,
        system=PROBE_SYSTEM,
        completion_fn=replay_recorder,
    )
    cause, _ = pop_fallback_cause(replayed)
    assert cause is None
    assert replayed == {"body": "provider-matrix-ok"}
    assert replay_recorder.cache_hits == 1


@pytest.mark.asyncio
async def test_recorder_mechanism_replay_misses_loudly_not_silently(tmp_path: Path) -> None:
    """A replay against an EMPTY fixture dir must raise ``MissingFixtureError``
    (never silently return something) — this is what makes
    ``has_recorded_fixture``'s directory-presence gate in the real suite
    above trustworthy: an unrecorded case genuinely has no way to produce a
    false pass."""
    empty_dir = tmp_path / "nothing-here"
    empty_dir.mkdir()
    recorder = LiteLLMRecorder(empty_dir, mode="replay")
    with pytest.raises(MissingFixtureError):
        await recorder(model="fake/x", messages=[{"role": "user", "content": "hi"}])
