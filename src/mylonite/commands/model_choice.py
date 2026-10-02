"""How the CLI makes sure a model was chosen, and that it is well formed.

There is no default provider or model. ``scan``, ``validate``, ``gate`` and
``ablate`` resolve ``--model``, mylonite.yaml's ``model:`` and
``MYLONITE_MODEL`` first, then call :func:`require_model_chosen_or_exit`.
"""

from __future__ import annotations

import typer

from mylonite._cli_io import echo_err
from mylonite.exit_codes import EXIT_CONFIG, EXIT_PROVIDER


def require_model_chosen_or_exit(model: str | None) -> str:
    """Return ``model``, or exit with the approved-provider list.

    With ``--model``, mylonite.yaml's ``model:`` and ``MYLONITE_MODEL`` all
    unset there is nothing to fall back to. Exits ``EXIT_PROVIDER`` (the same
    code a live command uses when the provider it was given is unreachable)
    with one line naming the approved providers, built from the registry --
    never a hardcoded default, and never a traceback.

    No-LLM paths (``scan --scaffold``, ``check``) never call this; they pass a
    model straight through, possibly ``None``, to an adapter whose
    ``describe()`` makes no LLM call.
    """
    if model is not None:
        return model
    from mylonite.scan.providers import no_model_configured_message

    echo_err(no_model_configured_message())
    raise typer.Exit(code=EXIT_PROVIDER)


def validate_model_string(model: str) -> None:
    """Reject obviously malformed model ids before they reach LiteLLM.

    Examples in the message are drawn from the registry at call time, never
    a literal here: a single bare, unprefixed id reads as an implicit "use
    this provider" and is the form :mod:`mylonite.scan.model_ref` warns may
    fail to route.
    """
    if not model or not model.strip() or model != model.strip():
        from mylonite.providers.registry import PROVIDERS

        examples = ", ".join(
            info.example_model for info in PROVIDERS.values() if info.example_model
        )
        echo_err(
            f"invalid --model {model!r}: must be a non-empty model id with no "
            f"surrounding whitespace, prefixed with its provider (e.g. {examples})."
        )
        raise typer.Exit(code=EXIT_CONFIG)
