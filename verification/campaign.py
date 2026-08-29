"""Run a full verification campaign and write a versioned, committable result set.

WHY THIS EXISTS
---------------
Until now no verification result recorded which Mylonite produced it. The
published scorecard dates from June 2026 and has aged across fifteen releases
with nothing to signal the drift, so "show the improvement between releases" was
impossible by construction rather than by omission. This writes a stamped,
committed result set per release, which is what makes a trend line possible.

THE SILO
--------
A campaign measures the PUBLISHED artifact, never the working tree. Mylonite uses
a src/ layout, so ``import mylonite`` fails from the repo root unless installed:
running this inside a venv holding ``mylonite==<version>`` from PyPI therefore
resolves imports to the published wheel, while ``verification`` still resolves
from the checkout. :func:`~verification._provenance.assert_siloed` refuses to
proceed otherwise, because numbers stamped ``0.9.0`` that actually measure
uncommitted code are worse than no numbers at all.

This is also why a campaign can only run AFTER a tag is published. That ordering
is a feature: tag, publish, then measure the published thing.

DIVISION OF LABOUR
------------------
Layer 2 runs end to end here. Layers 1 and 3 do not, and that is not a shortcut:
the existing harness already requires the operator to drive those scans
themselves (``layer1 score --reports``, ``layer3 score --scan``) because Layer 1
executes ten deliberately-vulnerable third-party servers and Layer 3 needs a scan
of a chosen target. Pass the artefacts in with ``--layer1-reports`` /
``--layer3-scan`` and they are folded in; omit them and they are recorded as
``not-run``.

A layer that did not run is NEVER absent from ``meta.json`` and never a zero. The
project's rule is that NOT-TESTED is not clean, and a missing layer that reads as
0% recall would be a false claim about coverage.

SAFETY
------
Everything written here passes through :func:`~verification._sanitise.scrub_tree`
and a per-layer field allowlist before it touches disk. Committed results must
carry no local-machine information, and an allowlist is what holds when someone
adds a field later -- a denylist only catches what its author thought of.
"""

from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from verification import _sanitise
from verification._provenance import assert_siloed, build_meta

#: Result filenames. Must match ``verification.trends._LAYER_FILES``; a test
#: pins the two together so a rename cannot silently orphan the trend table.
LAYER_FILES = {
    "layer1": "layer1-recall.json",
    "layer2-agentdojo": "layer2-agentdojo.json",
    "layer2-injecagent": "layer2-injecagent.json",
    "layer3": "layer3-precision.json",
}

_ALLOWLISTS = {
    "layer1": _sanitise.LAYER1_FIELDS,
    "layer2-agentdojo": _sanitise.LAYER2_FIELDS,
    "layer2-injecagent": _sanitise.LAYER2_FIELDS,
    "layer3": _sanitise.LAYER3_FIELDS,
}


class CampaignError(RuntimeError):
    """A campaign could not produce an honest result set."""


def _rev_parse(rev: str) -> str:
    """Short sha for ``rev``, or ``"unknown"``.

    Never raises: a campaign that dies because ``git`` is missing, or because a
    tag is not fetched locally, would be a worse outcome than provenance that
    says ``unknown`` out loud.
    """
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", rev],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    return out.stdout.strip() or "unknown"


def measured_sha(version: str) -> str:
    """The commit that produced the artifact being measured.

    Resolves the RELEASE TAG (``v<version>^{}``), not ``HEAD``.

    This distinction is the whole point of recording two shas. A campaign can
    only run after the tag is published -- the silo needs an installed wheel --
    so by then ``HEAD`` has usually moved on, and often onto commits that are
    themselves part of the verification work. Recording ``HEAD`` for both fields
    made them always identical, which quietly turned "distinguish the tool from
    the scorer" into a promise the data could not keep.

    Falls back to ``HEAD`` when the tag cannot be resolved (an unfetched tag, a
    campaign re-run against an unreleased build), because a sha that is merely
    less precise beats no provenance at all -- but the two fields going equal is
    then itself the signal that the tag was not found.
    """
    tagged = _rev_parse(f"v{version}^{{}}")
    return tagged if tagged != "unknown" else _rev_parse("HEAD")


def _write_layer(results_dir: Path, layer: str, payload: dict[str, Any]) -> None:
    """Scrub, validate against the layer's allowlist, then write.

    Order matters. Scrub first so a path inside a free-text ``detail`` is gone
    before anything else looks at it; validate second so a field nobody reviewed
    cannot reach disk even though it is now scrubbed. Both run before the write,
    never after -- a file that exists for even a moment with a local path in it
    is a file that can be committed by an unlucky ``git add``.
    """
    cleaned = _sanitise.scrub_tree(payload)
    if not isinstance(cleaned, dict):  # pragma: no cover - scrub_tree preserves shape
        raise CampaignError(f"{layer}: scrubbing did not preserve a mapping")
    _sanitise.validate_fields(cleaned, allowed=_ALLOWLISTS[layer], where=LAYER_FILES[layer])
    path = results_dir / LAYER_FILES[layer]
    path.write_text(json.dumps(cleaned, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def prepare_results_dir(results_root: Path, version: str, *, force: bool) -> Path:
    """Create ``<results_root>/<version>/``, refusing to clobber an existing set.

    Mirrors ``scripts/record_demo_fixtures.py``'s ``_check_dir_safe_to_record``:
    a half-overwritten result set is worse than either a clean one or none, and
    silently merging a new run into an old directory would produce a version
    stamp covering two different measurements.
    """
    results_dir = results_root / version
    if results_dir.exists() and any(results_dir.iterdir()) and not force:
        raise CampaignError(
            f"{results_dir} already holds a result set. Re-running would mix two "
            "measurements under one version stamp. Pass --force to replace it, or "
            "delete the directory first."
        )
    results_dir.mkdir(parents=True, exist_ok=True)
    return results_dir


def fold_in_prebuilt(results_dir: Path, layer: str, report_path: Path) -> str:
    """Fold an operator-produced Layer 1/3 report into the result set.

    Returns ``"ran"`` on success. A malformed or missing report is reported as a
    hard error rather than quietly downgraded to ``not-run``: the operator said
    they ran it, so silence here would hide a broken artefact behind a status
    that looks deliberate.
    """
    try:
        payload = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CampaignError(f"{layer}: could not read {report_path.name}: {exc}") from exc
    if not isinstance(payload, dict):
        raise CampaignError(f"{layer}: {report_path.name} is not a JSON object")
    _write_layer(results_dir, layer, payload)
    return "ran"


def finalise(
    results_dir: Path,
    *,
    version: str,
    model: str,
    layers: dict[str, str],
    harness_sha: str | None = None,
) -> Path:
    """Write ``meta.json``. Call this LAST, after every layer has settled.

    Written last on purpose: the file is the campaign's own claim about what ran,
    so it must not exist until that claim is true. An interrupted campaign leaves
    a directory with no ``meta.json``, which the freshness gate treats as absent
    -- the safe reading.
    """
    meta = build_meta(
        mylonite_version=version,
        # The tagged commit that produced the measured wheel...
        git_sha=measured_sha(version),
        # ...versus the checkout that ran the scorer. Usually different, and the
        # difference is what lets a trend distinguish "the tool changed" from
        # "we changed how we measure".
        harness_sha=harness_sha or _rev_parse("HEAD"),
        model=model,
        recorded_at=datetime.now(UTC).date().isoformat(),
        layers=layers,
    )
    cleaned = _sanitise.scrub_tree(meta)
    _sanitise.validate_fields(cleaned, allowed=_sanitise.META_FIELDS, where="meta.json")
    path = results_dir / "meta.json"
    path.write_text(json.dumps(cleaned, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def start(version: str) -> None:
    """Assert the silo before any measurement happens.

    Deliberately the first thing a campaign does. Checking afterwards would mean
    discovering that a completed run measured the wrong artifact, and the natural
    response to that -- relabel it -- is exactly the dishonesty this guards.
    """
    assert_siloed(expected_version=version)
