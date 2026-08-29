"""Regression tests for ``scripts/record_demo_fixtures.py``'s safety guards (T8 follow-up).

Code review reproduced a real hazard: the script used to stamp ``_meta.json``
only AFTER ``engine.run()`` completed, and never checked whether the target
directory already held pre-existing sidecar-less v1 fixtures — exactly the
shape of the currently-committed ``src/mylonite/demo/fixtures/{vulnerable,
guarded}/``. Recording a ``tools=``-bearing call into such a directory would
leave the old v1 file untouched AND write a new, differently-keyed v2 file
alongside it (a mixed directory); if interrupted before the post-run stamp,
the directory would have a v1/v2 mix with NO sidecar, and a later replay
would silently default to v1 and could return a stale, wrong response for a
tool-bearing call — no error.

These tests exercise the fix directly: :func:`_check_dir_safe_to_record` (the
preflight guard) and :func:`_record_variant` (which now calls it BEFORE doing
any recording work, and stamps the sidecar BEFORE recording rather than
after). None of these tests make a real LLM call — the refusal happens (or
doesn't) before any provider is ever touched.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from scripts import record_demo_fixtures as m

# --- _check_dir_safe_to_record (the isolated preflight guard) ------------------


def test_empty_dir_is_safe(tmp_path: Path) -> None:
    variant_dir = tmp_path / "vulnerable"  # does not exist yet
    m._check_dir_safe_to_record(variant_dir, m.CACHE_KEY_VERSION)  # must not raise


def test_dir_with_files_but_no_sidecar_refuses(tmp_path: Path) -> None:
    """The exact shape of the currently-shipped fixture directories."""
    variant_dir = tmp_path / "vulnerable"
    variant_dir.mkdir()
    (variant_dir / "deadbeef.json").write_text("{}", encoding="utf-8")

    with pytest.raises(SystemExit, match="no _meta\\.json sidecar"):
        m._check_dir_safe_to_record(variant_dir, m.CACHE_KEY_VERSION)


def test_dir_with_sidecar_declaring_different_version_refuses(tmp_path: Path) -> None:
    variant_dir = tmp_path / "vulnerable"
    variant_dir.mkdir()
    (variant_dir / "deadbeef.json").write_text("{}", encoding="utf-8")
    (variant_dir / "_meta.json").write_text(
        json.dumps({m.CACHE_KEY_VERSION_FIELD: 1}), encoding="utf-8"
    )

    with pytest.raises(SystemExit, match="cache_key_version=1"):
        m._check_dir_safe_to_record(variant_dir, m.CACHE_KEY_VERSION)


def test_dir_with_sidecar_already_agreeing_is_safe(tmp_path: Path) -> None:
    """An intentional incremental re-record: the sidecar already matches."""
    variant_dir = tmp_path / "vulnerable"
    variant_dir.mkdir()
    (variant_dir / "deadbeef.json").write_text("{}", encoding="utf-8")
    (variant_dir / "_meta.json").write_text(
        json.dumps({m.CACHE_KEY_VERSION_FIELD: m.CACHE_KEY_VERSION}), encoding="utf-8"
    )

    m._check_dir_safe_to_record(variant_dir, m.CACHE_KEY_VERSION)  # must not raise


# --- _record_variant (the reviewer's literal reproduction scenario) ------------


async def test_record_variant_refuses_on_prepopulated_sidecar_less_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The literal reviewer repro: record-with-tools into a pre-populated,
    sidecar-less directory must now refuse — not silently produce a mix.

    Points the script at a fresh FIXTURES_ROOT pre-populated with one stale,
    sidecar-less fixture (simulating the real committed
    ``src/mylonite/demo/fixtures/vulnerable/`` shape) and calls
    ``_record_variant`` directly. The refusal must happen in the preflight
    check, BEFORE any scan/LLM machinery runs — proven by asserting the stale
    file is untouched, no `_meta.json` was written, and no NEW fixture
    appeared, without needing to mock litellm/the scan engine at all.
    """
    fixtures_root = tmp_path / "fixtures"
    variant_dir = fixtures_root / "vulnerable"
    variant_dir.mkdir(parents=True)
    stale = variant_dir / "deadbeef.json"
    stale.write_text('{"choices": []}', encoding="utf-8")

    monkeypatch.setattr(m, "FIXTURES_ROOT", fixtures_root)

    with pytest.raises(SystemExit, match="LEGACY v1 fixtures"):
        await m._record_variant("vulnerable")

    # Refused before doing anything: no sidecar written, stale file untouched,
    # directory still holds exactly the one pre-existing fixture.
    assert not (variant_dir / "_meta.json").exists()
    assert stale.read_text(encoding="utf-8") == '{"choices": []}'
    assert [p.name for p in variant_dir.glob("*.json")] == ["deadbeef.json"]


# --- _stamp_meta writes the NEW, distinct field name ---------------------------


def test_stamp_meta_writes_cache_key_version_field(tmp_path: Path) -> None:
    variant_dir = tmp_path / "guarded"
    m._stamp_meta(variant_dir, "guarded")

    meta = json.loads((variant_dir / "_meta.json").read_text(encoding="utf-8"))
    assert meta[m.CACHE_KEY_VERSION_FIELD] == m.CACHE_KEY_VERSION
    assert meta["variant"] == "guarded"
    # Never the OLD, unrelated testkit field name — this sidecar is written by
    # a DIFFERENT subsystem (mylonite.demo, not mylonite.testkit) and must not
    # accidentally claim to speak testkit.FIXTURE_FORMAT_VERSION's meaning.
    assert "format_version" not in meta


def test_stamp_meta_records_provenance(tmp_path: Path) -> None:
    """The sidecar must carry model + record date, because the OUTPUT claims it does.

    ``mylonite demo``'s mode line reads "recorded <date> against <model>", and
    README / ROADMAP / quarry / the changelog all state it does. Those claims are
    held up by exactly two fields written here. ``_replay_mode_label`` degrades
    silently to the bare label when they are absent -- correct behaviour for a
    cosmetic field, but it means dropping them breaks four documents without
    breaking anything that shouts. This test is what shouts.
    """
    variant_dir = tmp_path / "vulnerable"
    m._stamp_meta(variant_dir, "vulnerable")

    meta = json.loads((variant_dir / "_meta.json").read_text(encoding="utf-8"))
    assert meta["model"] == m.DEMO_MODEL
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", meta["recorded_at"]), (
        f"recorded_at must be a plain ISO date for the mode line, got {meta['recorded_at']!r}"
    )
