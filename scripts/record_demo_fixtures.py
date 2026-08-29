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
record-mode :class:`~mylonite._replay.LiteLLMRecorder` over
``src/mylonite/demo/fixtures/<variant>/`` and runs the real scan once, writing one
JSON fixture per unique ``(model, messages, ...)`` pair. The same deterministic
per-variant note-id factory the replay path uses is reset per variant, so the
recorded note IDs (``n_demo_0001`` …) match replay exactly.

Cache-key format (T8 / close-the-loop)
---------------------------------------
There are no legacy fixtures left to accommodate. The v1-key set that shipped
through 0.7.8 was deleted along with the demo command in 0.8.0, so every
directory this script writes is a FRESH record and gets ``CACHE_KEY_VERSION``
(currently v2 — folds ``tools``/``tool_choice``/``response_format``/``api_base``
into the key alongside ``(model, messages)``). The script stamps ``_meta.json``
with the matching ``cache_key_version`` BEFORE recording begins (not after — see
:func:`_stamp_meta`'s docstring for why), so a later replay resolves the same
key explicitly rather than depending on any implicit default.

Re-recording an EXISTING directory in place is guarded by
:func:`_check_dir_safe_to_record`: if ``variant_dir`` already holds fixture
files but either has no ``_meta.json`` at all or has a sidecar declaring a
DIFFERENT ``cache_key_version`` than this run would use, the script REFUSES
rather than silently writing a mixed-key-version directory or (if interrupted
before a sidecar existed) leaving one with no sidecar at all — either of which a
later replay could silently mis-key. Delete the stale ``*.json`` fixtures (and
``_meta.json``, if present) under ``variant_dir`` first, so it starts genuinely
empty, then re-run.

When to (re-)record
-------------------
The recorded fixtures are committed to the repo and shipped inside the wheel.
Re-record ONLY when something folded into the v2 cache key changes. The full
trigger set is:

* the planner / customiser / judge prompts,
* the seed bodies,
* the reference adapter's tool schemas (these come from ``mcp_kitchen_sink``,
  a SEPARATE package — which is why the ``[demo]`` extra pins it exactly),
* ``mylonite.scan.schema_sanitise`` (the ``tools`` value is hashed AFTER
  sanitisation),
* the ``LLMPolicy`` kwargs shape (``api_base`` is in the key),
* ``DEMO_MODEL``.

A normal code change does NOT need a re-record. CI carries an input-drift guard
that hashes exactly this set, so drift is caught at PR time rather than by a
user hitting a silent cache miss.

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
from datetime import UTC, datetime
from pathlib import Path

from mylonite._replay import (
    CACHE_KEY_VERSION,
    CACHE_KEY_VERSION_FIELD,
    LiteLLMRecorder,
    _read_meta_cache_key_version,
)
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


def _existing_fixture_count(variant_dir: Path) -> int:
    """Fixture ``*.json`` files already in ``variant_dir``, excluding ``_meta.json``."""
    if not variant_dir.exists():
        return 0
    return len([p for p in variant_dir.glob("*.json") if p.name != "_meta.json"])


def _check_dir_safe_to_record(variant_dir: Path, expected_version: int) -> None:
    """Refuse to record into a directory that could end up mixed-key-version.

    Reproduced directly by code review: this script used to stamp
    ``_meta.json`` only AFTER ``engine.run()`` completed, and never checked
    whether ``variant_dir`` already held pre-existing sidecar-less v1
    fixtures (exactly the shape of the currently-committed
    ``src/mylonite/demo/fixtures/{vulnerable,guarded}/``). Recording a
    ``tools=``-bearing call into such a directory would leave the OLD v1
    file untouched AND write a NEW, differently-keyed v2 file alongside it —
    a genuinely mixed directory — and if the run were interrupted before the
    post-run stamp, the directory would have a v1/v2 mix with NO sidecar at
    all: the next replay now resolves ``CACHE_KEY_VERSION`` (v2) by default
    (the old implicit "no sidecar means v1" fallback was retired), so it
    would silently MISS the leftover v1-keyed file for any tools-bearing
    call it still matched — a confusing "fixture missing" failure for a
    directory that visibly has fixtures in it, rather than the loud, explicit
    refusal below.

    An EMPTY (or not-yet-existing) ``variant_dir`` is always safe. A
    NON-EMPTY one is safe only if its ``_meta.json`` already declares the
    SAME ``cache_key_version`` this run would use (an intentional
    incremental re-record) — anything else refuses with ``SystemExit`` and
    tells the operator to clear the directory first, rather than risk ever
    silently producing (or leaving, if interrupted) an ambiguous mix.
    """
    existing = _existing_fixture_count(variant_dir)
    if existing == 0:
        return
    declared = _read_meta_cache_key_version(variant_dir)
    if declared == expected_version:
        return
    if declared is None:
        raise SystemExit(
            f"refusing to record into {variant_dir}: it already has {existing} fixture "
            "file(s) but no _meta.json sidecar declaring a cache_key_version. These are "
            "almost certainly LEGACY v1 fixtures (recorded before the v2 cache key "
            "existed) — recording new v2-keyed fixtures alongside them would leave a "
            "mixed, confusing directory, and if this script is interrupted before it "
            "can stamp _meta.json, a later replay now defaults to v2 (the old "
            "implicit v1 fallback was retired) and would SILENTLY miss the leftover "
            "v1-keyed fixture for a tools-bearing call. Delete "
            f"the stale *.json files under {variant_dir} first (or move them aside), "
            "then re-run."
        )
    raise SystemExit(
        f"refusing to record into {variant_dir}: its _meta.json declares "
        f"cache_key_version={declared}, but this run would record with "
        f"cache_key_version={expected_version}. Recording into it now would produce a "
        "directory keyed inconsistently. Delete the stale *.json fixtures (and "
        f"_meta.json) under {variant_dir} first, then re-run."
    )


def _stamp_meta(variant_dir: Path, variant: str) -> None:
    """Write the ``_meta.json`` sidecar BEFORE recording begins.

    Stamped up front (not after ``engine.run()``, as an earlier version of
    this script did) so the directory is self-consistent even if the run is
    interrupted midway: any fixture files present after an interruption were
    ALL written by a recorder that had already resolved
    :data:`CACHE_KEY_VERSION` (from this very sidecar), so a later replay
    reads the same sidecar and uses the same key — never silently falls back
    to v1. Combined with :func:`_check_dir_safe_to_record`'s upfront refusal,
    a target directory is either genuinely empty (safe to stamp+record into)
    or already agrees with this sidecar (a deliberate incremental re-record).
    """
    variant_dir.mkdir(parents=True, exist_ok=True)
    meta_path = variant_dir / "_meta.json"
    meta_path.write_text(
        json.dumps(
            {
                CACHE_KEY_VERSION_FIELD: CACHE_KEY_VERSION,
                "model": DEMO_MODEL,
                "variant": variant,
                # Surfaced in the demo's own mode line. A replayed result is not
                # a measurement of today's model, and the output says so on its
                # face rather than only in the docs.
                "recorded_at": datetime.now(UTC).date().isoformat(),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


async def _record_variant(variant: str) -> tuple[int, int]:
    """Record one variant's fixtures; return (fixture_count, findings_count)."""
    variant_dir = FIXTURES_ROOT / variant
    _check_dir_safe_to_record(variant_dir, CACHE_KEY_VERSION)
    _stamp_meta(variant_dir, variant)
    recorder = LiteLLMRecorder(variant_dir, mode="record")
    assert recorder.key_version == CACHE_KEY_VERSION, (
        f"internal error: _stamp_meta declared cache_key_version={CACHE_KEY_VERSION} for "
        f"{variant_dir} but the recorder resolved {recorder.key_version} — "
        "_check_dir_safe_to_record should have refused this directory"
    )
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
