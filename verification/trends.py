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

_HEADER = (
    "| Version | Date | Model | Layer 1 recall | Layer 2 judge F1 (AgentDojo) "
    "| InjecAgent dh F1 | InjecAgent ds F1 | Layer 3 FPR |"
)
_SEPARATOR = "| --- | --- | --- | --- | --- | --- | --- | --- |"

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
    # BOTH splits, never one. dh (direct harm) and ds (data stealing) gave
    # F1 1.000 and 0.400 respectively on the same run -- recording either
    # alone would be cherry-picking, and the gap between them is the finding.
    "layer2-injecagent-dh": "layer2-injecagent-dh.json",
    "layer2-injecagent-ds": "layer2-injecagent-ds.json",
    "layer3": "layer3-precision.json",
}

#: Layers whose committed number is known to be unreliable for a reason that
#: has nothing to do with what the release actually measured -- a harness
#: defect discovered after the fact. Rendered as this annotation instead of
#: the (technically present, but misleading) number, so the table cannot be
#: read as "this release measured a clean 0%" when the real story is that the
#: harness could not have told a miss from an untested challenge, or (0.9.0's
#: case) could not have told what a challenge found even when it fired.
#:
#: Keyed by ``(mylonite_version, layer_key)``. Remove an entry once the
#: affected layer has been RE-MEASURED with the fixed harness and a new
#: result is committed that supersedes it -- this is a record of a known-bad
#: historical number, not a permanent asterisk.
_KNOWN_DEFECTIVE: dict[tuple[str, str], str] = {
    ("0.9.0", "layer1"): "unmeasured (harness defect, see FINDINGS.md)",
    # The AgentDojo adapter read the upstream `security` label backwards (it
    # mapped security==False to "attack succeeded"; upstream's own docstring
    # says the opposite). Every committed result through 0.11.0 was scored
    # against that inverted label. 41.2% is what was published; 81.1% is the
    # same 27 recorded judge verdicts recomputed under the corrected label
    # (no new model call) -- see FINDINGS.md.
    ("0.9.0", "layer2-agentdojo"): "41.2% (label inverted; corrected 81.1%, see FINDINGS.md)",
    ("0.10.0", "layer2-agentdojo"): "41.2% (label inverted; corrected 81.1%, see FINDINGS.md)",
    ("0.11.0", "layer2-agentdojo"): "41.2% (label inverted; corrected 81.1%, see FINDINGS.md)",
}

_SEMVER_RE = re.compile(r"^(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)$")

#: The command that regenerates TRENDS.md, quoted verbatim in its own header
#: so "how do I refresh this" never requires reading this module's source.
_REGENERATE_COMMAND = "python -m verification.trends"

#: The third-party campaign (``verification/PREREG_THIRD_PARTY_2026_10.md``) is a
#: different kind of evidence than layer1/2/3's academic benchmarks: six real MCP/
#: agent systems Mylonite had never run against, scored against a pre-registered
#: rule rather than a released dataset's own labels. It is committed one directory
#: level deeper (``<version>/third-party/results.json``), so a version directory
#: that holds ONLY this evidence has no top-level ``meta.json`` -- that must never
#: render as a "skipped: no meta.json" note (which would read as a broken commit),
#: so it gets its own short table instead, right after the main one.
_THIRD_PARTY_SUBDIR = "third-party"
_THIRD_PARTY_RESULTS_FILE = "results.json"
_THIRD_PARTY_HEADER = (
    "| Version | Date | Targets KEPT (bar met) | Product defects (open issues) | Spend |"
)
_THIRD_PARTY_SEPARATOR = "| --- | --- | --- | --- | --- |"

#: The committed prereg, target files and workflow already use these `tpv-`
#: family names in public `--authorize` values, so they are not a new leak --
#: but the upstream project name reads better in a trend table meant for a
#: reader skimming release history. Unknown ids fall back to the raw name
#: (see the `.get` call below), so a future target that forgets to register
#: here never disappears from the table.
_THIRD_PARTY_DISPLAY_NAMES: dict[str, str] = {
    "tpv-server-memory": "server-memory",
    "tpv-mcp-redis": "mcp-redis",
    "tpv-streamablehttp": "simple-streamablehttp",
    "tpv-server-everything": "server-everything",
    "tpv-go-memory": "go-sdk memory",
    "tpv-agents-sdk-ollama": "agents-sdk-ollama",
}


def _third_party_summary(results_path: Path) -> dict[str, Any] | None:
    """The fields :func:`_render_third_party_row` needs, or ``None`` if the file
    is missing or unreadable -- caught, never raised, the same posture
    ``render_trends`` already takes toward a malformed ``meta.json``."""
    try:
        return _load_json(results_path)
    except (OSError, json.JSONDecodeError, ValueError):
        return None


def _render_third_party_row(version: str, data: dict[str, Any]) -> str:
    """One summary row from a committed ``third-party/results.json``.

    Deliberately coarse -- this table exists to show WHETHER a version shipped
    live third-party evidence and its shape at a glance, not to duplicate that
    directory's own ``README.md``, which is the full per-cell write-up.
    """
    rollups = data.get("rollups", {})
    kept = sorted(
        {
            key.split("/", 1)[0]
            for key, r in rollups.items()
            if isinstance(r, dict) and r.get("result") == "KEPT" and r.get("met_bar")
        }
    )
    kept_cell = (
        ", ".join(f"`{_THIRD_PARTY_DISPLAY_NAMES.get(name, name)}`" for name in kept)
        if kept
        else "none"
    )

    issues = data.get("product_issues", [])
    open_issues = [i for i in issues if isinstance(i, dict) and i.get("state") == "open"]
    defects_cell = f"{len(issues)} ({len(open_issues)} open)" if issues else "0"

    spend = data.get("spend_counted_usd", {})
    spend_parts = []
    for provider in sorted(spend):
        entry = spend[provider]
        if isinstance(entry, dict) and "cost_usd" in entry:
            spend_parts.append(f"{provider} ${entry['cost_usd']:.2f}")
    spend_cell = ", ".join(spend_parts) if spend_parts else "?"

    date = str(data.get("recorded_at", "?"))
    return f"| {version} | {date} | {kept_cell} | {defects_cell} | {spend_cell} |"


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


def _render_layer1(version_dir: Path, meta: dict[str, Any], version: str) -> str:
    known_defective = _KNOWN_DEFECTIVE.get((version, "layer1"))
    if known_defective is not None:
        return known_defective
    if _layer_status(meta, "layer1") != "ran":
        return "not run"
    try:
        data = _load_json(version_dir / _LAYER_FILES["layer1"])
        return _fmt_ratio(data["recall"])
    except (OSError, json.JSONDecodeError, ValueError, KeyError):
        return "error"


def _render_judge_f1(version_dir: Path, meta: dict[str, Any], layer_key: str, version: str) -> str:
    """Judge-agreement F1 from one layer-2 report.

    Parameterised over the layer so the table can show all three columns. It
    used to read AgentDojo only, and the table had one "Layer 2 judge F1" cell.
    AgentDojo is still the number worth *trending* for the reason recorded at
    ``_LAYER_FILES`` -- its positive class is released third-party trajectories
    that really do contain successful attacks -- and it stays the headline.

    But publishing it alone hid the rest of the same run. On 0.9.0 the
    InjecAgent splits scored F1 1.000 (direct harm) and 0.400 at recall 0.25
    (data stealing), both genuinely exercised. ``_LAYER_FILES``' own comment
    calls that gap "the finding"; it was committed to JSON and absent from the
    only human-readable view of it. Both now have columns, so a reader sees the
    good number and the bad one together -- which is the standard the README
    sets for itself ("published for the same reason the wins are").

    Checked against ``_KNOWN_DEFECTIVE`` first, same as ``_render_layer1``: a
    harness/labelling defect discovered after the fact must never render as a
    clean number just because the field is technically present.
    """
    known_defective = _KNOWN_DEFECTIVE.get((version, layer_key))
    if known_defective is not None:
        return known_defective
    if _layer_status(meta, layer_key) != "ran":
        return "not run"
    try:
        data = _load_json(version_dir / _LAYER_FILES[layer_key])
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
    third_party_rows: list[tuple[tuple[int, int, int] | str, str]] = []

    entries = sorted(results_root.iterdir()) if results_root.exists() else []
    for entry in entries:
        if not entry.is_dir():
            continue

        # Checked independently of the academic meta.json below -- a version
        # can carry third-party evidence, academic evidence, both, or neither.
        third_party_path = entry / _THIRD_PARTY_SUBDIR / _THIRD_PARTY_RESULTS_FILE
        if third_party_path.is_file():
            data = _third_party_summary(third_party_path)
            if data is not None:
                key = _semver_key(entry.name)
                third_party_rows.append(
                    (
                        key if key is not None else entry.name,
                        _render_third_party_row(entry.name, data),
                    )
                )
            else:
                notes.append(f"- skipped `{entry.name}`: unreadable {third_party_path.name}")

        meta_path = entry / "meta.json"
        if not meta_path.is_file():
            # No academic campaign for this version -- not a defect by itself
            # (it may carry only third-party evidence, already handled above).
            if not third_party_path.is_file():
                notes.append(f"- skipped `{entry.name}`: no meta.json")
            continue
        try:
            meta = _load_json(meta_path)
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
            f"| {_render_layer1(entry, meta, version)} "
            f"| {_render_judge_f1(entry, meta, 'layer2-agentdojo', version)} "
            f"| {_render_judge_f1(entry, meta, 'layer2-injecagent-dh', version)} "
            f"| {_render_judge_f1(entry, meta, 'layer2-injecagent-ds', version)} "
            f"| {_render_layer3(entry, meta)} |"
        )
        rows.append((key, row))

    rows.sort(key=lambda item: item[0])
    lines = [_HEADER, _SEPARATOR, *(row for _, row in rows)]

    if third_party_rows:
        # Mixed key types (a semver tuple, or the raw directory name when it
        # isn't one) aren't comparable against each other in Python 3, so
        # normalise to a (0, tuple) / (1, name) pair -- semver-named
        # directories sort first, by version; anything else sorts after, by
        # name.
        def _tp_sort_key(item: tuple[tuple[int, int, int] | str, str]) -> tuple[int, Any]:
            key = item[0]
            return (0, key) if isinstance(key, tuple) else (1, key)

        third_party_rows.sort(key=_tp_sort_key)
        lines.append("")
        lines.append("## Third-party verification campaigns")
        lines.append("")
        lines.append(
            "Live-in-CI runs against real third-party systems, scored against a "
            "pre-registered rule rather than a released dataset's own labels -- see "
            "each version's own `third-party/README.md` for the full write-up. "
            "`met_bar` KEPT cells only; a candidate (`FOUND_UNVALIDATED`) or a smoke "
            "pass never counts as KEPT here."
        )
        lines.append("")
        lines.append(_THIRD_PARTY_HEADER)
        lines.append(_THIRD_PARTY_SEPARATOR)
        lines.extend(row for _, row in third_party_rows)

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
