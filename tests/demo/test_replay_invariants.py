"""Drift guards for the two properties that keep offline replay actually offline.

Both failures these pin are SILENT. Neither raises, neither shows up as a test
error elsewhere, and both produce a demo that renders a confident, wrong answer
on the first command a newcomer ever runs. That is why they get their own file
rather than an assertion buried in a behavioural test.

Same convention as ``tests/scan/test_weakness_single_source.py`` and
``tests/test_twin_fidelity_single_source.py``: inspect the source so the guard
holds even when the risky path is not otherwise exercised.

These match on the AST rather than on raw text, deliberately. ``demo``'s body
carries a comment *explaining* the invariant, and that comment necessarily names
``llm_scope`` and ``_discover_run_config`` — a substring guard would fire on its
own documentation. Matching call nodes means the guard tracks what the code
does, not what it says about itself.
"""

from __future__ import annotations

import ast
import inspect
import textwrap

import mylonite.demo
import mylonite.demo.cli_entry
import mylonite.demo.runner
from mylonite import cli


def _called_names(func: object) -> set[str]:
    """Every function name actually invoked in ``func``'s body.

    Covers both bare calls (``llm_scope(...)``) and attribute calls
    (``mod.llm_scope(...)``), so aliasing the import does not slip past.
    """
    tree = ast.parse(textwrap.dedent(inspect.getsource(func)))  # type: ignore[arg-type]
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        target = node.func
        if isinstance(target, ast.Name):
            names.add(target.id)
        elif isinstance(target, ast.Attribute):
            names.add(target.attr)
    return names


def _demo_command_call_names() -> set[str]:
    """Names called across the whole demo command path.

    ``cli.demo`` is only the Typer signature; the body lives in
    ``demo.cli_entry.run_demo_command`` (``cli.py`` is a composition root, see
    ``tests/test_cli_size.py``). Checking only one of the two would let the
    invariant be broken in the half that is not inspected, which is precisely
    what happened to the fixture-staleness guard when the demo was first
    deleted.
    """
    return _called_names(cli.demo) | _called_names(mylonite.demo.cli_entry.run_demo_command)


def test_demo_never_scopes_an_llm_policy() -> None:
    """``demo`` must not build or activate an ``LLMPolicy``.

    The v2 replay cache key folds in ``api_base``
    (``mylonite._replay._KEY_V2_IDENTITY_KWARGS``). ``api_base`` reaches a
    LiteLLM call only through an ``LLMPolicy`` activated by
    ``llm_scope(policy=...)``, and every such call site builds that policy from
    CLI flags, ``mylonite.yaml``, or ``MYLONITE_*`` env vars.

    So if ``demo`` ever scopes one, a reader with ``MYLONITE_API_BASE`` exported
    (entirely plausible for someone also running a local model) or a stray
    ``./mylonite.yaml`` in the working directory re-keys every lookup and misses
    100% of the fixtures. ``demo`` deliberately scopes nothing and therefore runs
    under a default ``LLMPolicy()`` with ``api_base=None``.
    """
    called = _demo_command_call_names()
    assert "llm_scope" not in called, (
        "mylonite demo must not activate an LLMPolicy: api_base is part of the "
        "v2 replay cache key, so a policy built from env/mylonite.yaml would "
        "re-key every fixture lookup and miss all of them."
    )
    assert "LLMPolicy" not in called, (
        "mylonite demo must not construct an LLMPolicy; the default one "
        "(api_base=None) is what makes replay independent of the environment."
    )


def test_demo_never_discovers_a_run_config() -> None:
    """``demo`` must not read ``mylonite.yaml``.

    Same failure as above, one step upstream: run-config discovery is what
    supplies an ``api_base`` in the first place. The demo is the zero-config
    entry point and must behave identically regardless of what happens to sit in
    the working directory.
    """
    called = _demo_command_call_names()
    assert "_discover_run_config" not in called, (
        "mylonite demo must not discover a run config: an auto-discovered "
        "./mylonite.yaml could supply an api_base and silently invalidate every "
        "recorded fixture."
    )


def test_demo_does_not_import_a_second_replay_core() -> None:
    """The record/replay core stays single-sourced at ``mylonite._replay``.

    It was promoted out of ``mylonite.demo`` in 0.8.0 precisely because the
    testkit, the reference validator and the ``scripts/record_*`` family all
    depend on it. A restored ``mylonite.demo._replay`` would fork it, and the
    two copies would drift on exactly the cache-key logic that decides whether a
    fixture hits.
    """
    for module in (mylonite.demo, mylonite.demo.runner, mylonite.demo.cli_entry):
        tree = ast.parse(inspect.getsource(module))
        offenders = [
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module == "mylonite.demo._replay"
        ]
        assert not offenders, (
            f"{module.__name__} imports the record/replay core from "
            "mylonite.demo._replay; import it from mylonite._replay instead so "
            "there is only one copy of the cache-key logic."
        )
