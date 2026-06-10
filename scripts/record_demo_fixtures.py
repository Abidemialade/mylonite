"""Record the offline ``mylonite demo`` LiteLLM fixtures (dev-time, run-once-with-a-key).

What this is
------------
A development-time tool that performs the *one* set of real LLM calls the offline
demo replays forever after. It reuses :func:`mylonite.demo.runner._build_scan` —
the single source of demo wiring truth — so the ``(model, messages)`` keys it
records are byte-for-byte the ones the replay path looks up. It does NOT re-wire
the adapter, customiser, judge, or attack modules: any wiring drift between record
and replay makes every fixture miss on lookup and the demo silently lies.

For each reference variant (``vulnerable``, ``guarded``) it builds a
record-mode :class:`~mylonite.demo._replay.LiteLLMRecorder` over
``src/mylonite/demo/fixtures/<variant>/`` and runs the real scan once, writing one
JSON fixture per unique ``(model, messages)`` pair. The same deterministic
per-variant note-id factory the replay path uses is reset per variant, so the
recorded note IDs (``n_demo_0001`` …) match replay exactly.

When to (re-)record
-------------------
The recorded fixtures are committed to the repo and shipped inside the wheel.
Re-record ONLY when something that changes the recorded ``(model, messages)``
pairs changes — i.e. the planner / judge / customiser prompts, the reference
adapter's tool schemas, or ``DEMO_MODEL``. A normal code change does NOT need a
re-record.

How to run
----------
The provider key is read from the environment via LiteLLM's normal mechanism
(e.g. ``ANTHROPIC_API_KEY``). Never hardcode or print keys.

bash::

    ANTHROPIC_API_KEY=… python scripts/record_demo_fixtures.py

PowerShell::

    $env:ANTHROPIC_API_KEY="…"; python scripts/record_demo_fixtures.py

After recording, eyeball the written fixtures for accidental secrets before
committing them.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from mylonite.demo._replay import LiteLLMRecorder
from mylonite.demo.runner import (
    DEMO_MODEL,
    DEMO_PROVIDER,
    _build_scan,
    _note_id_counter,
)

try:
    from mylonite.demo.runner import _VARIANTS
except ImportError:  # pragma: no cover - _VARIANTS is exported today
    _VARIANTS = ("vulnerable", "guarded")

#: Where the per-variant fixture subdirectories live in the source tree. Record
#: mode requires a real ``pathlib.Path`` (the recorder enforces this) and will
#: ``mkdir`` parents.
FIXTURES_ROOT = Path("src/mylonite/demo/fixtures")


async def _record_variant(variant: str) -> tuple[int, int]:
    """Record one variant's fixtures; return (fixture_count, findings_count)."""
    variant_dir = FIXTURES_ROOT / variant
    recorder = LiteLLMRecorder(variant_dir, mode="record")
    engine = _build_scan(
        variant,
        completion_fn=recorder,
        note_id_factory=_note_id_counter(),
        provider=DEMO_PROVIDER,
        model=DEMO_MODEL,
    )
    result = await engine.run()
    fixture_count = len(list(variant_dir.glob("*.json")))
    findings_count = result.report.findings_count
    print(
        f"[{variant}] recorded {fixture_count} fixture(s) -> "
        f"{variant_dir} | findings_count={findings_count}"
    )
    return fixture_count, findings_count


async def _main() -> None:
    print(f"Recording demo fixtures with {DEMO_PROVIDER}/{DEMO_MODEL}")
    print(f"Fixtures root: {FIXTURES_ROOT.resolve()}")
    counts: dict[str, tuple[int, int]] = {}
    for variant in _VARIANTS:
        counts[variant] = await _record_variant(variant)

    print("\n=== Recording summary ===")
    for variant in _VARIANTS:
        fixture_count, findings_count = counts[variant]
        print(f"  {variant:<11} fixtures={fixture_count}  findings_count={findings_count}")

    vuln_findings = counts.get("vulnerable", (0, 0))[1]
    guard_findings = counts.get("guarded", (0, 0))[1]
    if vuln_findings < 1:
        print(f"  ⚠ expected the vulnerable variant to yield >=1 finding, got {vuln_findings}")
    if guard_findings > 0:
        print(f"  ⚠ expected the guarded variant to yield 0 findings, got {guard_findings}")

    print("\nReminder: eyeball the written fixtures for accidental secrets before committing.")


if __name__ == "__main__":
    asyncio.run(_main())
