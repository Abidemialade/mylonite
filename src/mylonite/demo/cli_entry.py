"""The body of ``mylonite demo``, kept out of ``cli.py``.

``cli.py`` is the CLI composition root: Typer signatures and wiring, not domain
logic (see ``tests/test_cli_size.py``). Everything the demo command does beyond
declaring its three options lives here.

REPLAY INVARIANT - read before adding anything to this module.
==============================================================
The v2 replay cache key folds in ``api_base`` (see
``mylonite._replay._KEY_V2_IDENTITY_KWARGS``). ``api_base`` reaches a LiteLLM
call only through an ``LLMPolicy`` activated by ``scan._llm.llm_scope(policy=)``,
and every such call site builds that policy from CLI flags, ``mylonite.yaml``, or
``MYLONITE_*`` environment variables.

The demo deliberately builds none. ``scan.wiring.build_scan`` never touches the
policy and the engine scopes only a call counter, so replay runs under a default
``LLMPolicy()`` with ``api_base=None``.

That is what stops a stray ``./mylonite.yaml``, or an exported
``MYLONITE_API_BASE`` (entirely plausible for a reader who also runs a local
model), from re-keying every lookup and missing 100% of the fixtures on the first
command a newcomer ever runs. Do not call ``_discover_run_config`` or
``llm_scope`` from this module or from ``cli.demo``.
``tests/demo/test_replay_invariants.py`` fails if either appears.
"""

from __future__ import annotations

import asyncio

import typer
from rich.console import Console

from mylonite._cli_io import echo_err, echo_exc
from mylonite.exit_codes import EXIT_BUDGET, EXIT_CONFIG, EXIT_PROVIDER, EXIT_SUCCESS


def run_demo_command(*, live: bool, provider: str | None, model: str | None) -> None:
    """Run the demo and exit with the appropriate code. Always raises ``typer.Exit``."""
    from mylonite.cli import _exit_if_missing_kitchen_sink
    from mylonite.demo import CorruptFixtureError, MissingFixtureError
    from mylonite.demo.render import render_demo

    # The runner import transitively pulls in mcp_kitchen_sink (runner ->
    # reference_target_adapter -> mcp_kitchen_sink._store), which installs
    # separately via the `[demo]` extra. Map its absence to the friendly exit-2
    # message at import time, before any of the imported symbols are referenced.
    try:
        from mylonite.demo.runner import DEMO_MODEL, DEMO_PROVIDER, DemoFixtureError, run_demo
    except (ModuleNotFoundError, ImportError) as exc:
        _exit_if_missing_kitchen_sink(exc)
        raise

    # Replay is pinned to the recorded provider/model. Never silently drop the
    # override flags - a user who passed them deserves to know they did nothing.
    if not live and (provider is not None or model is not None):
        echo_err(
            "warning: --provider/--model are ignored in replay mode - the demo "
            f"replays fixtures recorded against {DEMO_PROVIDER}/{DEMO_MODEL}. "
            "Pass --live to use a different provider/model."
        )

    try:
        result = asyncio.run(run_demo(live=live, provider=provider, model=model))
    except (MissingFixtureError, DemoFixtureError) as exc:
        # A fixture miss does NOT propagate on its own (the _llm fallback chain
        # and the adapter's skip-conversion swallow completion_fn exceptions -
        # see the mylonite._replay module docstring). It reaches here only
        # because runner._check_replay_recorder inspects recorder state after
        # each variant and raises. Without that inspection this except clause
        # would never fire and the demo would render the vulnerable twin as
        # CLEAN. Do not "simplify" the runner by trusting exceptions here.
        echo_exc(
            "demo fixtures missing or stale - reinstall mylonite, or run "
            "`mylonite demo --live` with a provider configured",
            exc,
        )
        raise typer.Exit(code=EXIT_CONFIG) from exc
    except CorruptFixtureError as exc:
        echo_exc("demo", exc)
        raise typer.Exit(code=EXIT_CONFIG) from exc
    except (ModuleNotFoundError, ImportError) as exc:
        _exit_if_missing_kitchen_sink(exc)
        raise

    # A fresh Console, not cli.py's module-level one: that was constructed at
    # import time, before the root callback reconfigured stdout to UTF-8, and the
    # weakness table renders non-ASCII glyphs that crash a cp1252 console.
    render_demo(
        result.vulnerable,
        result.guarded,
        mode=result.mode,
        elapsed_s=result.elapsed_s,
        console=Console(),
    )

    # A --live run can abort cleanly (the engine returns rather than raises), so
    # surface those as distinct exit codes. Replay never aborts this way.
    for variant in (result.vulnerable, result.guarded):
        if variant.report.aborted == "provider_unreachable":
            echo_err(
                "no provider reachable - set ANTHROPIC_API_KEY, or pass "
                "--provider/--model for another LiteLLM provider."
            )
            raise typer.Exit(code=EXIT_PROVIDER)
        if variant.report.aborted == "budget_exceeded":
            echo_err(
                "demo budget exceeded before both variants completed "
                "(max_llm_calls=100 per variant)."
            )
            raise typer.Exit(code=EXIT_BUDGET)

    raise typer.Exit(code=EXIT_SUCCESS)
