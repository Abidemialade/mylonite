"""``LLMPolicy`` — the per-call kwargs the differential oracle depends on.

Every field here is load-bearing, not tuning (see the module-level rationale
below); a call site that skips it silently changes what the oracle is
measuring. ``api_base``/``api_key``/``api_version`` are also where first-class
self-hosted/proxy support lands: LiteLLM's wiring for Ollama/vLLM/a corporate
proxy/gateway is a provider prefix PLUS ``api_base`` — a per-call kwarg, not a
routing decision — so any command that resolves a model must also be able to
resolve (and validate) an ``api_base`` for it.

Why each field is load-bearing:

* ``temperature=0.0`` — the differential oracle measures a RATE GAP between
  the vulnerable and guarded legs (``min_rate_gap``/``max_guard_leak``). A
  provider's default temperature (often 0.7-1.0) changes the variance of both
  legs, so those thresholds would mean something different per provider.
* ``max_tokens=2048`` — a low default truncates the judge's JSON verdict,
  which degrades to ``FALLBACK_UNPARSEABLE`` (see ``scan._llm``) — a SILENT
  false negative, not a loud failure.
* ``drop_params=True`` — without it, a ``response_format`` LiteLLM sends to a
  provider that doesn't actually support it raises, defeating
  ``build_response_format``'s own degrade-to-``None`` logic.
* ``timeout`` — the per-call socket-level bound. Distinct from (and a
  backstop under) any OUTER wall-clock bound a caller wraps around a
  multi-call sequence (DCR-0011/DCR-0018).
* ``num_retries=2`` — without retries, a merely rate-limited provider trips
  ``provider_failure_threshold`` and aborts the whole scan as
  ``provider_unreachable`` instead of a genuinely-unreachable one.
* ``seed=0`` — deterministic sampling where the provider honours it, so a
  replay/demo fixture recorded against one run stays reproducible.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlsplit

#: Query-parameter names that (case-insensitively) signal an embedded
#: credential in a URL, e.g. ``?api_key=sk-...`` or ``?token=...``. Not
#: exhaustive by design (an allowlist here would silently miss a new
#: provider's naming) — combined with the userinfo (``user:pass@host``) check
#: in :func:`validate_api_base`, this catches the two shapes an ``api_base``
#: actually leaks a secret in practice.
_CREDENTIAL_QUERY_KEYS = frozenset(
    {"api_key", "apikey", "key", "token", "access_token", "auth", "secret", "password"}
)


class CredentialedApiBaseError(ValueError):
    """Raised when an ``api_base`` embeds a credential (userinfo or a key-shaped
    query parameter) instead of naming an env var for it.

    ``mylonite.yaml`` is a COMMITTED file (unlike ``target.yaml``, which
    ``mylonite._redaction.redact_target_yaml`` covers) — a credentialed
    ``api_base`` written there would leak straight into version control. The
    fix is to refuse to construct anything that carries one at all (both
    :class:`~mylonite.config.RunConfig` and :class:`LLMPolicy` validate on
    construction) rather than silently stripping the credential (which would
    hide a real misconfiguration) or silently allowing it (which would ship
    the leak).
    """

    def __init__(self, api_base: str) -> None:
        self.api_base = api_base
        msg = (
            f"api_base {api_base!r} appears to embed a credential (userinfo, e.g. "
            "'https://user:pass@host', or a key-shaped query parameter, e.g. "
            "'?api_key=...'). Refusing to proceed -- mylonite.yaml is a COMMITTED "
            "file and this would leak the secret into version control. Put the "
            "credential in an env var instead: your provider's own key var (e.g. "
            "ANTHROPIC_API_KEY / OPENAI_API_KEY), or MYLONITE_API_BASE for a "
            "credential-free base URL plus a separate --api-key-file/--env-file "
            "for the key, or your proxy/gateway's own credential env var if it "
            "authenticates itself."
        )
        super().__init__(msg)


def validate_api_base(api_base: str | None) -> None:
    """Raise :class:`CredentialedApiBaseError` if ``api_base`` embeds a credential.

    A no-op for ``None``/empty. Checks both leak shapes: userinfo
    (``scheme://user:pass@host``) and a key-shaped query parameter
    (``?api_key=...`` and siblings — see :data:`_CREDENTIAL_QUERY_KEYS`).
    """
    if not api_base:
        return
    parts = urlsplit(api_base)
    if parts.username or parts.password:
        raise CredentialedApiBaseError(api_base)
    query = parse_qs(parts.query)
    for key in query:
        if key.lower() in _CREDENTIAL_QUERY_KEYS:
            raise CredentialedApiBaseError(api_base)


@dataclass(frozen=True)
class LLMPolicy:
    """The kwargs every LiteLLM completion call in the scan/gate/validate/
    ablate path is made with — see the module docstring for why each default
    is load-bearing, not tuning.

    Constructed once per run (from CLI flags / ``mylonite.yaml`` / flat
    ``MYLONITE_*`` env vars — see ``config.RunConfig``) and activated for the
    duration via ``scan._llm.llm_scope``. Every call site
    (``litellm_json_call``/``_async``, ``litellm_tool_call_async``,
    ``litellm_text_call``) reads the active policy via
    ``scan._llm.active_policy()``, which returns a default ``LLMPolicy()``
    when nothing is scoped — so the load-bearing defaults above apply even to
    a call site that never explicitly touches this module.
    """

    api_base: str | None = None
    api_key: str | None = None
    api_version: str | None = None
    max_tokens: int = 2048
    temperature: float = 0.0
    timeout: float = 120.0
    num_retries: int = 2
    drop_params: bool = True
    seed: int | None = 0

    def __post_init__(self) -> None:
        # Defense in depth: even if a caller builds an LLMPolicy directly
        # (bypassing RunConfig's own field validator), a credentialed
        # api_base can never reach a live LiteLLM call — this is the ONE
        # chokepoint every policy, from every source, passes through.
        validate_api_base(self.api_base)

    def kwargs(self) -> dict[str, Any]:
        """The dict to spread into a ``litellm.completion``/``acompletion`` call."""
        out: dict[str, Any] = {
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "timeout": self.timeout,
            "num_retries": self.num_retries,
            "drop_params": self.drop_params,
        }
        if self.seed is not None:
            out["seed"] = self.seed
        if self.api_base is not None:
            out["api_base"] = self.api_base
        if self.api_key is not None:
            out["api_key"] = self.api_key
        if self.api_version is not None:
            out["api_version"] = self.api_version
        return out
