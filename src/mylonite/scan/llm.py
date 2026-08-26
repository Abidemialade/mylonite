"""Public name for the LLM chokepoint.

Every model call in Mylonite routes through one place -- the LiteLLM transport
wrapper that owns budget counting (:class:`LiteLLMCallCounter`) and the active
:class:`~mylonite.scan.llm_policy.LLMPolicy`. That wrapper lived only in the
private ``mylonite.scan._llm`` module, so "all LLM access flows through here" was
a convention with no public surface to point at.

This module is that public name. Import the transport entry points and the
call-budget scope from here. A direct ``litellm.completion``/``acompletion`` call
anywhere else in ``src/`` is a bypass -- it would skip budget counting and the
policy, silently changing what the oracle measures -- and
``tests/test_llm_chokepoint_boundary.py`` fails if one is introduced.
"""

from __future__ import annotations

from mylonite.scan._llm import (
    DEFAULT_LLM_CALL_TIMEOUT_S,
    FALLBACK_CALL_RAISED,
    FALLBACK_UNPARSEABLE,
    BudgetExceededError,
    LiteLLMCallCounter,
    NonRecoverableProviderError,
    active_counter,
    active_policy,
    build_response_format,
    litellm_json_call,
    litellm_json_call_async,
    litellm_text_call,
    litellm_tool_call_async,
    llm_scope,
    pop_fallback_cause,
)

__all__ = [
    "DEFAULT_LLM_CALL_TIMEOUT_S",
    "FALLBACK_CALL_RAISED",
    "FALLBACK_UNPARSEABLE",
    "BudgetExceededError",
    "LiteLLMCallCounter",
    "NonRecoverableProviderError",
    "active_counter",
    "active_policy",
    "build_response_format",
    "litellm_json_call",
    "litellm_json_call_async",
    "litellm_text_call",
    "litellm_tool_call_async",
    "llm_scope",
    "pop_fallback_cause",
]
