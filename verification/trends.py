"""Render committed verification results into a human-readable trend table.

``verification/results/<version>/`` holds one directory per release that ran
the verification campaign: a ``meta.json`` (schema_version, mylonite_version,
mylonite_origin, harness_sha, model, recorded_at, and a ``layers`` map of
``"ran" | "not-run"``) plus a per-layer summary JSON named after the layer key
(``layer1.json``, ``layer2.json``, ``layer3.json`` -- the same
``build_recall_report`` / ``build_report`` / ``precision_report`` shapes
``verification/layer1_runnable/run.py``, ``verification/report.py`` and
``verification/layer3_production/run.py`` already write).

This module turns that history into one Markdown table -- did recall/judge-F1/
FPR move release over release, and did any layer simply stop being measured.

Two correctness rules are load-bearing, not stylistic:

- A layer recorded ``not-run`` renders the literal ``not run``, never a blank
  and never ``0``. Silently rendering a missing measurement as ``0`` would
  read as "this release scored zero", which is a false claim about a number
  that was never taken.
- Layer 2's F1 is only meaningful when ``judge_agreement_exercised`` is true.
  ``verification/report.py`` already explains why: at zero recorded positives
  the judge never sees a positive case to classify, so precision/recall/F1
  are mechanically vacuous, not "good" or "bad". This module renders that
  case as ``vacuous`` rather than the (misleadingly numeric) F1 value, for the
  same reason ``report.py`` refuses to headline it.

Malformed or unreadable result directories are skipped, but never silently --
each skip is listed in the output so a broken commit is visible in the table
itself, not just in a build log nobody reads later.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

_HEADER = "| Version | Date | Model | Layer 1 recall | Layer 2 judge F1 | Layer 3 FPR |"
_SEPARATOR = "| --- | --- | --- | --- | --- | --- |"

#: Per-layer summary filename, keyed by the same layer name meta.json's
#: ``layers`` mapping uses.
#: Result filenames, matching what the campaign writes. Layer 2 produces TWO
#: reports from two different sources, so it cannot be a single file:
#:
#: * AgentDojo scores Mylonite's judge against RELEASED third-party trajectories
#:   that already contain successful attacks. That is the judge-agreement number
#:   worth trending, because its positive class is real and not ours.
#: * InjecAgent requires recording a model run first, and on a well-aligned model
#:   that run can resist every case -- leaving no positives, which makes any
#:   resulting F1 vacuous (the report flags this itself).
#:
#: So the trend's judge column reads AgentDojo. InjecAgent is still recorded and
#: committed; it just is not the number to plot.
_LAYER_FILES = {
    "layer1": "layer1-recall.json",
    "layer2-agentdojo": "layer2-agentdojo.json",
    "layer2-injecagent": "layer2-injecagent.json",
    "layer3": "layer3-precision.json",
}

_SEMVER_RE = re.compile(r"^(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)$")

#: The command that regenerates TRENDS.md, quoted verbatim in its own header
#: so "how do I refresh this" never requires reading this module's source.
_REGENERATE_COMMAND = "python -m verification.trends"


def _semver_key(version: str) -> tuple[int, int, int] | None:
    """Sortable ``(major, minor, patch)``, or ``None`` if not ``X.Y.Z``.

    Must NOT be a string sort: ``"0.10.0" < "0.9.0"`` lexicographically (``1``
    sorts before ``9``), which would place a newer minor release before an
    older one in the table.
    """
    match = _SEMVER_RE.match(version)
    if match is None:
        return None
    return (int(match["major"]), int(match["minor"]), int(match["patch"]))


def _load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} must be a JSON object, got {type(data).__name__}")
    return data


def _layer_status(meta: dict[str, Any], layer: str) -> str:
    layers = meta.get("layers")
    if not isinstance(layers, dict):
        return "unknown"
    return str(layers.get(layer, "unknown"))


def _fmt_ratio(value: Any) -> str:
    """Render a 0..1 fraction as a percentage; ``error`` if it isn't numeric.

    ``error`` (rather than raising, and rather than a silent blank) keeps one
    corrupt field from either crashing the whole table render or from being
    mistaken for a real 0% measurement.
    """
    if isinstance(value, bool) or not isinstance(value, int | float):
        return "error"
    return f"{value * 100:.1f}%"


def _render_layer1(version_dir: Path, meta: dict[str, Any]) -> str:
    if _layer_status(meta, "layer1") != "ran":
        return "not run"
    try:
        data = _load_json(version_dir / _LAYER_FILES["layer1"])
        return _fmt_ratio(data["recall"])
    except (OSError, json.JSONDecodeError, ValueError, KeyError):
        return "error"


def _render_layer2(version_dir: Path, meta: dict[str, Any]) -> str:
    """Judge agreement, read from the AgentDojo report -- see ``_LAYER_FILES``."""
    if _layer_status(meta, "layer2-agentdojo") != "ran":
        return "not run"
    try:
        data = _load_json(version_dir / _LAYER_FILES["layer2-agentdojo"])
        # Vacuous check FIRST: a False here means the F1 field below is not a
        # real measurement no matter what number it holds.
        if not data.get("judge_agreement_exercised", False):
            return "vacuous"
        agreement = data["judge_agreement"]
        if not isinstance(agreement, dict):
            return "error"
        return _fmt_ratio(agreement["f1"])
    except (OSError, json.JSONDecodeError, ValueError, KeyError):
        return "error"


def _render_layer3(version_dir: Path, meta: dict[str, Any]) -> str:
    if _layer_status(meta, "layer3") != "ran":
        return "not run"
    try:
        data = _load_json(version_dir / _LAYER_FILES["layer3"])
        return _fmt_ratio(data["false_positive_rate"])
    except (OSError, json.JSONDecodeError, ValueError, KeyError):
        return "error"


def _render_date(meta: dict[str, Any]) -> str:
    recorded = meta.get("recorded_at")
    if not isinstance(recorded, str) or not recorded:
        return "?"
    return recorded.split("T", 1)[0]


def render_trends(results_root: Path) -> str:
    """A Markdown table, one row per version directory, ascending by semver.

    Reads only what is committed under ``results_root``; never writes.
    """
    rows: list[tuple[tuple[int, int, int], str]] = []
    notes: list[str] = []

    entries = sorted(results_root.iterdir()) if results_root.exists() else []
    for entry in entries:
        if not entry.is_dir():
            continue
        meta_path = entry / "meta.json"
        try:
            meta = _load_json(meta_path)
        except FileNotFoundError:
            notes.append(f"- skipped `{entry.name}`: no meta.json")
            continue
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            notes.append(f"- skipped `{entry.name}`: unreadable meta.json ({exc})")
            continue

        version = meta.get("mylonite_version")
        if not isinstance(version, str):
            notes.append(f"- skipped `{entry.name}`: meta.json has no mylonite_version")
            continue
        key = _semver_key(version)
        if key is None:
            notes.append(
                f"- skipped `{entry.name}`: mylonite_version {version!r} is not X.Y.Z semver"
            )
            continue

        model = str(meta.get("model", "?"))
        row = (
            f"| {version} | {_render_date(meta)} | {model} "
            f"| {_render_layer1(entry, meta)} | {_render_layer2(entry, meta)} "
            f"| {_render_layer3(entry, meta)} |"
        )
        rows.append((key, row))

    rows.sort(key=lambda item: item[0])
    lines = [_HEADER, _SEPARATOR, *(row for _, row in rows)]
    if notes:
        lines.append("")
        lines.append("Skipped (malformed or unreadable):")
        lines.extend(notes)
    return "\n".join(lines) + "\n"


def write_trends(results_root: Path, out: Path) -> None:
    """Write ``out`` (normally ``verification/TRENDS.md``) from ``results_root``."""
    header = (
        "<!-- GENERATED FILE. Do not edit by hand. -->\n"
        f"<!-- Regenerate with: {_REGENERATE_COMMAND} -->\n\n"
        "# Verification trends\n\n"
    )
    out.write_text(header + render_trends(results_root), encoding="utf-8", newline="\n")


def main(argv: list[str] | None = None) -> int:
    default_root = Path(__file__).with_name("results")
    default_out = Path(__file__).with_name("TRENDS.md")
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else "")
    parser.add_argument("results_root", nargs="?", type=Path, default=default_root)
    parser.add_argument("out", nargs="?", type=Path, default=default_out)
    args = parser.parse_args(argv)
    write_trends(args.results_root, args.out)
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
