"""Shared provider-matrix probe spec (T16/H5).

Defines the ONE deterministic scenario both ``scripts/record_provider_fixtures.py``
(maintainer-run, needs real provider keys, records fixtures once) and
``tests/integration/test_provider_matrix.py`` (CI, replay-only, zero network)
drive — a single source of truth so the two can never drift the way
``demo/_replay.py``'s own module docstring warns about ("any wiring drift
between record and replay makes every fixture miss on lookup"). Kept in
``tests/integration/`` (not ``src/mylonite/``) because it is test/dev
scaffolding, not anything a library user needs — ``tests/integration`` is
already an importable package (see ``tests/integration/_recorder.py``, the
demo-fixture predecessor of this same pattern) and ``pyproject.toml``'s
``pythonpath = ["."]`` makes ``tests.integration...`` importable from a
plain, repo-root-relative ``python scripts/record_provider_fixtures.py`` too.

The probe itself drives ``scan._llm.litellm_json_call_async`` — the exact
chokepoint the customiser/judge use (T14) — with a trivial "reply with strict
JSON" prompt. It deliberately does NOT exercise ``litellm_tool_call_async``
(the planner's tool-calling chokepoint): tool-schema dialect compatibility
(T15/H4) already has its own fully-offline unit coverage in
``tests/scan/test_schema_sanitise.py`` and doesn't need a live round-trip to
prove; this suite's job is proving basic multi-provider *connectivity and
JSON-mode compliance* through the real chokepoint, not re-testing schema
sanitisation.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ProviderMatrixCase:
    """One named provider/model in the representative matrix.

    ``name`` is both the human-readable id used in test output/parametrize
    ids AND the fixture subdirectory name — kept filesystem-safe (no ``/``)
    precisely so a model string containing a LiteLLM provider prefix (e.g.
    ``"anthropic/claude-haiku-4-5"``) can't turn into a nested/invalid path.
    """

    name: str
    model: str
    note: str


#: The representative matrix named in the remediation plan's §6/H5 design
#: doc: one hosted-Anthropic, one hosted-OpenAI, one hosted-Gemini (STRICT
#: tool-schema dialect), one Bedrock-fronted Anthropic (STRICT dialect + the
#: AWS credential chain instead of a single API key), one self-hosted Ollama,
#: and one generic ``hosted_vllm/...``-style self-hosted vLLM deployment.
PROVIDER_MATRIX: tuple[ProviderMatrixCase, ...] = (
    ProviderMatrixCase(
        name="anthropic-claude-haiku-4-5",
        model="anthropic/claude-haiku-4-5",
        note="hosted, Anthropic-native tool-calling/JSON mode",
    ),
    ProviderMatrixCase(
        name="openai-gpt-4o-mini",
        model="openai/gpt-4o-mini",
        note="hosted, OpenAI-native tool-calling/JSON mode",
    ),
    ProviderMatrixCase(
        name="gemini-2.5-flash",
        model="gemini/gemini-2.5-flash",
        note="hosted, STRICT tool-schema dialect (T15/H4)",
    ),
    ProviderMatrixCase(
        name="bedrock-claude-3-5-haiku",
        model="bedrock/anthropic.claude-3-5-haiku",
        note="AWS-fronted, STRICT dialect + AWS credential-chain auth (not a single API key)",
    ),
    ProviderMatrixCase(
        name="ollama-llama3-3",
        model="ollama/llama3.3",
        note="self-hosted local inference via an api_base, PERMISSIVE dialect",
    ),
    ProviderMatrixCase(
        name="hosted-vllm-example",
        model="hosted_vllm/meta-llama/Llama-3.3-70B-Instruct",
        note="generic self-hosted-vLLM-style prefix, needs api_base",
    ),
)

#: A deliberately trivial, deterministic probe — the same "reply with strict
#: JSON" shape the customiser/judge send, without any target-specific content,
#: so the SAME two messages are sent (and therefore the SAME v2 cache key is
#: computed — see ``demo/_replay.py``'s ``_stable_key_v2``) every time this
#: spec is imported, whether by the recording script or the replay test.
PROBE_SYSTEM = (
    "You are a terse test fixture. Reply with ONLY strict JSON matching the "
    'schema {"body": string}. No prose, no markdown fence.'
)
PROBE_PROMPT = 'Reply with strict JSON: {"body": "provider-matrix-ok"}.'
PROBE_EXPECTED_KEYS: frozenset[str] = frozenset({"body"})
PROBE_FALLBACK: dict[str, str] = {"body": "fallback"}
#: The ``caller=`` label this probe uses — deliberately distinct from
#: "customiser"/"judge"/"planner"/"gate_mitigation" (see
#: ``tests/scan/test_llm_capability_contract.py``'s caller-label
#: cross-reference) since this is dev/test scaffolding, not a production
#: scan call site.
PROBE_CALLER = "provider_matrix_probe"


def fixtures_root() -> Path:
    """``tests/integration/fixtures/provider_matrix`` — never shipped in the
    wheel (unlike ``src/mylonite/demo/fixtures``); this is CI/test-only
    scaffolding, committed to the repo but not packaged."""
    return Path(__file__).resolve().parent / "fixtures" / "provider_matrix"


def fixture_dir_for(case: ProviderMatrixCase) -> Path:
    """Where ``case``'s recorded fixture (if any) lives."""
    return fixtures_root() / case.name


def has_recorded_fixture(case: ProviderMatrixCase) -> bool:
    """True once a maintainer has actually run ``scripts/record_provider_fixtures.py``
    for ``case`` — i.e. its fixture directory exists and holds at least one
    ``*.json`` fixture file (excluding the ``_meta.json`` sidecar). Never
    ``True`` by construction in this repo until that real, keyed, maintainer
    run happens — there is nothing in this module that fabricates one."""
    directory = fixture_dir_for(case)
    if not directory.is_dir():
        return False
    return any(p.name != "_meta.json" for p in directory.glob("*.json"))


__all__ = [
    "PROBE_CALLER",
    "PROBE_EXPECTED_KEYS",
    "PROBE_FALLBACK",
    "PROBE_PROMPT",
    "PROBE_SYSTEM",
    "PROVIDER_MATRIX",
    "ProviderMatrixCase",
    "fixture_dir_for",
    "fixtures_root",
    "has_recorded_fixture",
]
