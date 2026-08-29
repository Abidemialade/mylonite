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
from pathlib import Path

import pytest

import mylonite.demo
import mylonite.demo.cli_entry
import mylonite.demo.runner
import mylonite.scan.wiring
from mylonite import cli
from mylonite.demo import runner as runner_mod


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


def test_build_scan_passes_attack_modules_explicitly() -> None:
    """No environment input may change which payloads the demo sends.

    ``MYLONITE_ATTACK_MODULES`` (added alongside this work) lets an operator add
    third-party attack modules to a scan. That must never reach the demo: extra
    modules mean extra payloads, extra payloads mean ``(model, messages)`` pairs
    that were never recorded, and an unrecorded pair is a cache miss. The demo
    would then refuse to run -- but only for users who happen to have that
    variable exported, which is the worst kind of bug to receive a report about.

    Today ``wiring.build_scan`` passes ``attack_modules=`` explicitly, so
    ``assembly.build_scan_engine`` never calls ``discover_attack_modules`` and
    the variable is inert on this path. This pins that. A refactor that "unifies
    the demo with normal discovery" fails here rather than in the wild.
    """
    source = inspect.getsource(mylonite.scan.wiring.build_scan)
    tree = ast.parse(textwrap.dedent(source))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "build_scan_engine":
            assert any(kw.arg == "attack_modules" for kw in node.keywords), (
                "wiring.build_scan must pass attack_modules= explicitly; otherwise "
                "build_scan_engine falls back to entry-point discovery and "
                "MYLONITE_ATTACK_MODULES can inject payloads the fixtures never recorded."
            )
            return
    raise AssertionError("no build_scan_engine(...) call found in wiring.build_scan")


def test_replay_mode_label_degrades_instead_of_crashing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A malformed sidecar must cost provenance, never the demo itself.

    ``json.loads`` succeeds on any valid JSON, so a sidecar containing ``null``
    or ``2`` binds a non-dict. Reading ``.get`` off that outside the suppressed
    block raises ``AttributeError``, which ``cli_entry`` does not catch -- an
    unhandled traceback on the first command a newcomer ever runs, for a purely
    cosmetic field.
    """
    for payload in ("null", "2", '"text"', "[]", "{not json", ""):
        for variant in ("vulnerable", "guarded"):
            d = tmp_path / variant
            d.mkdir(parents=True, exist_ok=True)
            (d / "_meta.json").write_text(payload, encoding="utf-8")
        monkeypatch.setattr(runner_mod, "packaged_fixture_dir", lambda: tmp_path)
        assert runner_mod._replay_mode_label() == "replay (offline)", (
            f"sidecar payload {payload!r} must degrade to the bare label"
        )


def test_replay_mode_label_reports_the_older_date(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Mismatched variants report the OLDER date, never the newer one.

    A partial re-record is permitted, so one variant can be stamped today while
    the other still holds months-old responses. Reporting the newer date would
    overstate how fresh the replayed evidence is, which is the direction that
    actually misleads.
    """
    for variant, date in (("vulnerable", "2026-08-28"), ("guarded", "2026-01-02")):
        d = tmp_path / variant
        d.mkdir(parents=True, exist_ok=True)
        (d / "_meta.json").write_text(
            f'{{"model": "m", "recorded_at": "{date}"}}', encoding="utf-8"
        )
    monkeypatch.setattr(runner_mod, "packaged_fixture_dir", lambda: tmp_path)
    assert "recorded 2026-01-02" in runner_mod._replay_mode_label()


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
