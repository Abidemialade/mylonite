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
JSON fixture per unique ``(model, messages, ...)`` pair. The same deterministic
per-variant note-id factory the replay path uses is reset per variant, so the
recorded note IDs (``n_demo_0001`` …) match replay exactly.

Cache-key format (T8)
----------------------
The CURRENTLY COMMITTED fixtures under ``src/mylonite/demo/fixtures/{vulnerable,
guarded}/`` predate the ``_meta.json`` sidecar entirely and were recorded with
the v1 key (``(model, messages)`` only) — :mod:`mylonite.demo._replay` keeps
replaying them correctly (v1 is the documented default for a sidecar-less
directory in replay mode). A FRESH re-record (an EMPTY ``variant_dir``, as
happens the first time this script targets a variant) defaults to the v2 key
(folds in ``tools``/``tool_choice``/``response_format``/``api_base``) and this
script then stamps ``_meta.json`` with ``format_version: 2`` afterwards, so a
later replay of the freshly-recorded directory resolves the SAME v2 key rather
than silently falling back to v1 (which would ignore ``tools=`` and miss every
lookup). Re-recording an EXISTING v1 directory in place is NOT supported by
this script as written — delete the stale ``*.json`` fixtures (but not this
script's newly-written ``_meta.json``, which won't exist yet either) before
re-running, so the directory starts genuinely empty and the whole variant is
recorded under one consistent key version.

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
import json
from pathlib import Path

from mylonite.demo._replay import LiteLLMRecorder
from mylonite.demo.runner import (
    DEMO_MODEL,
    DEMO_PROVIDER,
    _build_scan,
    _note_id_counter,
)

#: The v2 cache-key format this script always records freshly-empty variant
#: directories with (see the module docstring's "Cache-key format" section).
_FIXTURE_FORMAT_VERSION = 2

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
        # Demo determinism: the live customiser AND the LLM-judge fallback are
        # non-deterministic LLM calls whose output makes fixtures unreproducible
        # (same key, different content; varying findings). The demo drives raw
        # seed bodies judged by deterministic predicates — what it always
        # effectively did before the JSON-fence parse fix. Record + replay must
        # stay in lock-step on this flag.
        llm_assist=False,
    )
    result = await engine.run()
    # Stamp the _meta.json sidecar so a LATER replay of this directory resolves
    # the same v2 key the recorder just used (a sidecar-less directory defaults
    # to v1 on replay — see the module docstring's "Cache-key format" section).
    meta_path = variant_dir / "_meta.json"
    meta_path.write_text(
        json.dumps(
            {"format_version": _FIXTURE_FORMAT_VERSION, "model": DEMO_MODEL, "variant": variant},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    fixture_count = len(list(variant_dir.glob("*.json"))) - 1  # exclude _meta.json
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
    # Deliberately SEQUENTIAL — not migrated to run_twins (mylonite._concurrency)
    # despite the two variants otherwise looking like an independent twin pair.
    # Unlike the offline demo replay/live paths (mylonite.demo.runner.run_demo),
    # this is a RECORD-mode run: it makes real, non-deterministic LLM calls and
    # writes the resulting (model, messages) -> response pairs to disk as the
    # fixtures every future replay depends on. Running both variants
    # concurrently would fire two live provider call streams at once with
    # nothing to keep them in lock-step, and this script's whole job is
    # producing a byte-stable, reviewable artefact — not wall-clock speed (it
    # is a rare, manual, dev-time tool run once per prompt/schema change, never
    # on any hot or CI path). Keeping it strictly sequential also keeps the
    # per-variant console output ("[vulnerable] recorded ... " then
    # "[guarded] recorded ...") in a predictable order for the human running
    # it. An intentional, documented exception is the correct call for a
    # performance finding whose "fix" would trade determinism for a speedup
    # nobody needs here.
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
