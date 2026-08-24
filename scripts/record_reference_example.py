"""Record the committed reference-validation example (dev-time, run-once-with-a-key).

What this is
------------
A development-time tool that performs the *one* set of real LLM calls the
walking-skeleton offline proof replays forever after. It produces a committed
``examples/reference_validation/`` example: an ``exploit_<pattern_id>.json``
discovered against the LIVE vulnerable twin, the recorded ``fixtures/`` (plus a
``_meta.json`` sidecar) for the GUARDED twin, and the emitted
``test_security_<slug>.py``. Once committed, that test replays the recorded
reproduction against the guarded twin entirely OFFLINE — no API key at the gate.

It reuses :func:`mylonite.scan.wiring.build_scan` and
:func:`mylonite.scan.wiring.note_id_counter` — the single source of scan-wiring
truth, exactly as ``scripts/record_demo_fixtures.py`` reuses the same pair — so
the recorded ``(model, messages)`` keys are byte-for-byte the ones the offline
replay path (``mylonite.testkit.assert_guard_holds``) looks up. It does NOT
re-wire the adapter, customiser, judge, or attack modules: any wiring drift
between record and replay makes every fixture miss on lookup and the gate
silently degrades to a finding-free run.

Seed choice
-----------
The example is pinned to the W2 ``indirect-injection-note-body-direct`` seed: a
deterministic-predicate-backed weakness (``send_email_to_attacker``) that fires
reliably on the vulnerable twin and resists reliably on the guarded twin — the
cleanest possible differential for the committed offline proof.

When to (re-)record
-------------------
The recorded ``exploit_*.json`` + ``fixtures/`` + ``_meta.json`` +
``test_security_*.py`` are committed to the repo and then replay offline
forever. Re-record ONLY when something that changes the recorded
``(model, messages)`` pairs changes — i.e. the planner / judge / customiser
prompts, the reference adapter's tool schemas, or the model below. A normal
code change does NOT need a re-record.

How to run
----------
The provider key is read from the environment via LiteLLM's normal mechanism
(``ANTHROPIC_API_KEY``). Never hardcode or print keys.

bash::

    ANTHROPIC_API_KEY=… python scripts/record_reference_example.py

PowerShell::

    $env:ANTHROPIC_API_KEY="…"; python scripts/record_reference_example.py

After recording, eyeball the written ``exploit_*.json`` and ``fixtures/`` for
accidental secrets before committing them.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from mylonite._replay import LiteLLMRecorder
from mylonite.plugins._reference.reference_pytest_generator import ReferencePytestGenerator
from mylonite.scan.wiring import build_scan, note_id_counter
from mylonite.testkit import FIXTURE_FORMAT_VERSION

#: Provider/model for the example — Haiku discipline, matching the demo and the
#: DifferentialValidator default so the recorded keys line up with the live
#: validation path.
EXAMPLE_PROVIDER = "anthropic"
EXAMPLE_MODEL = "claude-haiku-4-5-20251001"

#: The deterministic-predicate-backed W2 seed the example is pinned to. Fires on
#: the vulnerable twin, resists on the guarded twin.
EXAMPLE_PATTERN_ID = "indirect-injection-note-body-direct"

#: Where the committed example lives in the source tree. Created here so the
#: intent is captured even before a maintainer runs the script with a key.
EXAMPLE_DIR = Path("examples/reference_validation")


async def _record_vulnerable_exploit(example_dir: Path) -> str:
    """Run a LIVE vulnerable scan, write the W2 exploit JSON, return its pattern_id."""
    engine = build_scan(
        "vulnerable",
        completion_fn=None,  # live litellm.acompletion
        note_id_factory=note_id_counter(),
        provider=EXAMPLE_PROVIDER,
        model=EXAMPLE_MODEL,
    )
    result = await engine.run()
    exploit = next(
        (e for e in result.exploits if e.pattern_id == EXAMPLE_PATTERN_ID),
        None,
    )
    if exploit is None:
        fired = sorted(e.pattern_id for e in result.exploits)
        raise SystemExit(
            f"vulnerable scan did not fire the pinned seed {EXAMPLE_PATTERN_ID!r}; "
            f"got {fired or '<none>'}. Re-run, or revisit the seed choice."
        )
    exploit_path = example_dir / f"exploit_{exploit.pattern_id}.json"
    exploit_path.write_text(
        json.dumps(exploit.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"[vulnerable] wrote {exploit_path} (pattern_id={exploit.pattern_id})")
    return exploit.pattern_id


async def _record_guarded_fixtures(example_dir: Path, pattern_id: str) -> int:
    """Run a LIVE guarded scan in RECORD mode, capture fixtures + _meta.json.

    Returns the number of fixtures written.
    """
    fixtures_dir = example_dir / "fixtures"
    recorder = LiteLLMRecorder(fixtures_dir, mode="record")
    engine = build_scan(
        "guarded",
        completion_fn=recorder,
        note_id_factory=note_id_counter(),
        provider=EXAMPLE_PROVIDER,
        model=EXAMPLE_MODEL,
    )
    await engine.run()
    # `format_version` is testkit's own field (per-exploit fixture-isolation
    # SCOPE); `cache_key_version` is the UNRELATED _replay.LiteLLMRecorder
    # cache-key algorithm field — read off `recorder.key_version` (not a
    # locally hardcoded literal) so the sidecar can never drift from what the
    # recorder actually used to key the files just written above. The two
    # fields share this one sidecar file but are independent axes; see
    # mylonite._replay.CACHE_KEY_VERSION_FIELD's docstring.
    meta_path = fixtures_dir / "_meta.json"
    meta_path.write_text(
        json.dumps(
            {
                "format_version": FIXTURE_FORMAT_VERSION,
                "cache_key_version": recorder.key_version,
                "model": EXAMPLE_MODEL,
                "pattern_id": pattern_id,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    fixture_count = len(list(fixtures_dir.glob("*.json"))) - 1  # exclude _meta.json
    print(f"[guarded] recorded {fixture_count} fixture(s) -> {fixtures_dir}")
    print(f"[guarded] wrote {meta_path}")
    return fixture_count


def _emit_test(example_dir: Path, exploit_path: Path) -> Path:
    """Emit the regression test from the recorded exploit and write it into the example."""
    from mylonite.testkit import load_exploit

    exploit = load_exploit(exploit_path)
    generated = ReferencePytestGenerator().emit(exploit)
    test_path = example_dir / generated.filename
    test_path.write_text(generated.source, encoding="utf-8")
    print(f"[generate] wrote {test_path}")
    return test_path


async def _main() -> None:
    example_dir = EXAMPLE_DIR
    example_dir.mkdir(parents=True, exist_ok=True)
    print(f"Recording reference example with {EXAMPLE_PROVIDER}/{EXAMPLE_MODEL}")
    print(f"Example dir: {example_dir.resolve()}")

    pattern_id = await _record_vulnerable_exploit(example_dir)
    fixture_count = await _record_guarded_fixtures(example_dir, pattern_id)
    exploit_path = example_dir / f"exploit_{pattern_id}.json"
    _emit_test(example_dir, exploit_path)

    print("\n=== Recording summary ===")
    print(f"  pattern_id      {pattern_id}")
    print(f"  guarded fixtures {fixture_count}")
    print(f"  example dir      {example_dir}")
    print(
        "\nReminder: eyeball the written exploit_*.json and fixtures/ for "
        "accidental secrets before committing them."
    )


if __name__ == "__main__":
    asyncio.run(_main())
