"""``ModelRef`` -- one model string, provider derived from it (H1).

Before this module, every command that took a model resolved TWO
independently-settable pieces of state: ``--model`` and ``--provider``, glued
together at each call site with its own ad-hoc ``provider or "anthropic"``
default. Nothing forced those two to stay consistent -- and `mylonite
validate` proved it, by being the one model-taking command that skipped BOTH
``_validate_model_string`` and the provider-routing step entirely.

``ModelRef`` collapses that to one field a caller can't forget to populate:
``raw`` is exactly the string handed to LiteLLM (``litellm.completion(model=
ref.raw, ...)``); ``provider`` is DERIVED from it (an explicit
``provider_hint`` -- fed by mylonite.yaml's ``provider:`` key, a
``MYLONITE_PROVIDER`` env var, or ``demo``'s still-live ``--provider`` flag
(the CLI ``--provider`` flag on every OTHER command was removed in 0.7.10;
see ``mylonite.cli._warn_deprecated_provider_config``) -- wins when given,
then a ``provider/`` prefix already on the model, then LiteLLM's own model
registry). A model LiteLLM can't route, with no hint and no prefix, raises
rather than silently assuming Anthropic -- the same "loud failure over a
silently-wrong default" rule the rest of this release ladder applies (see
``NOT_TESTED_OUTCOMES`` in T1).
"""

from __future__ import annotations

from dataclasses import dataclass

from mylonite.scan.providers import provider_from_model, required_env_vars


def route_model(provider_hint: str | None, model: str) -> str:
    """Apply LiteLLM ``provider/model`` prefixing when ``provider_hint`` is
    set and ``model`` doesn't already carry a ``provider/`` prefix.

    LiteLLM routes by model-string prefix; some Anthropic aliases (e.g.
    ``claude-3-5-haiku-latest``) aren't auto-routed and fail with "LLM
    Provider NOT provided". When a caller passes an explicit provider hint
    (see :mod:`mylonite.scan.model_ref`'s module docstring for the
    remaining, deprecated sources of one) and the model carries no
    ``provider/`` prefix yet, prefix it so the alias routes. With no hint the
    model is left untouched, preserving LiteLLM's own auto-routing for the
    common case.

    The single source of truth for this prefixing: :meth:`ModelRef.parse`
    uses it to build ``.raw``, and ``mylonite.cli._route_model`` is a thin
    backward-compat wrapper delegating here (existing callers/tests that
    import ``_route_model`` directly keep working unchanged).
    """
    if provider_hint and "/" not in model:
        return f"{provider_hint}/{model}"
    return model


@dataclass(frozen=True)
class ModelRef:
    """A model string exactly as it goes to LiteLLM, plus its derived provider.

    ``provider`` is diagnostics/report-field/env-lookup metadata ONLY --
    never re-derive it independently of ``raw`` at a call site (that's the
    exact two-fields-that-can-drift-apart shape this type exists to close
    off). Construct via :meth:`parse`, not the constructor directly, so the
    derivation rules (hint > prefix > LiteLLM registry) are always applied.
    """

    raw: str
    provider: str | None

    @classmethod
    def parse(cls, model: str, *, provider_hint: str | None = None) -> ModelRef:
        """Parse ``model`` (bare or ``provider/model``), honouring an explicit
        ``provider_hint`` (see the module docstring for its remaining,
        deprecated sources) if given.

        Raises ``ValueError`` for a blank model, or a bare model with no hint
        and no ``provider/`` prefix that LiteLLM's own registry doesn't
        recognise either -- deliberately, so an unroutable model fails at CLI
        argument time with an actionable message instead of silently being
        stamped ``anthropic`` and only failing later, mid-scan, against the
        live LiteLLM call.
        """
        if not model or not model.strip():
            raise ValueError(f"invalid model {model!r}: must be a non-empty model id.")
        provider = provider_from_model(model, declared=provider_hint)
        if provider is None:
            raise ValueError(
                f"can't determine a provider for model {model!r}: it has no "
                "'<provider>/' prefix, no provider hint was given, and LiteLLM "
                "doesn't recognise it as a known model id. Use a "
                "provider-prefixed model string instead (e.g. "
                "'anthropic/claude-haiku-4-5')."
            )
        return cls(raw=route_model(provider_hint, model), provider=provider)

    def env_vars(self) -> tuple[str, ...]:
        """Env var name(s) this model's provider needs -- the API key plus
        anything else LiteLLM reads for it (e.g. Azure's endpoint + API
        version). See :func:`mylonite.scan.providers.required_env_vars`.
        """
        return required_env_vars(self.provider)
