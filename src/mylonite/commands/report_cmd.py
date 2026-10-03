"""The `mylonite report` command body: render a saved scan/validation as a trust panel.

Extracted out of ``cli.py`` (#91/#197 follow-up) to keep the composition
root thin. See ``tests/test_cli_size.py``.

``cli.py`` keeps the Typer-facing decorator, the full signature (so the
help text Typer builds `--help` from stays inline there) and the
docstring, and calls straight into ``report_body`` below.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.markup import escape as rich_escape
from rich.table import Table

from mylonite._cli_io import console_print, echo, echo_err, echo_exc
from mylonite.exit_codes import EXIT_CONFIG, EXIT_SUCCESS
from mylonite.generate.wiring import _map_compliance
from mylonite.report.render import _render_validation_report


def _render_recommendation_panel(rec: Any, console: Console | None = None) -> None:
    """Render a structural recommendation (PR7) as a Rich table.

    Every attacker-influenced cell — a tool NAME, an argument VALUE, and a
    prescription HEADLINE (which interpolates evidence values directly, e.g.
    W3's "reached an off-allowlist destination (`<the attacker's URL>`)") —
    is redact()-ed AND rich_escape()'d before add_row. This is NOT redundant
    with console_print's own markup=False: that only helps a bare STRING
    renderable printed directly; a Table's cells parse Rich markup at
    construction time regardless of how the table is later printed (see
    console_print's own docstring, and _render_validation_report's identical
    handling of outcome.detail above) — so a value shaped like `[/bold]`
    would otherwise raise rich.errors.MarkupError, and a value containing a
    style tag could otherwise inject formatting into a terminal a developer
    is about to screenshot.
    """
    from mylonite._redaction import redact

    if console is None:
        console = Console()

    def _safe(text: str) -> str:
        return rich_escape(redact(text))

    header = Table.grid(padding=(0, 1))
    header.add_column(style="bold")
    header.add_column()
    header.add_row("recommendation for:", _safe(rec.weakness_class))
    header.add_row("confidence:", _safe(f"{rec.confidence} ({rec.confidence_reason})"))
    header.add_row("proven:", _safe(f"{rec.proven} (layer: {rec.proven_layer})"))
    if rec.degraded:
        header.add_row("degraded:", _safe("; ".join(rec.degraded)))
    console_print(console, header)

    if rec.evidence:
        ev_table = Table(title="evidence", title_justify="left", show_lines=False)
        ev_table.add_column("tool", no_wrap=True)
        ev_table.add_column("argument", no_wrap=True)
        ev_table.add_column("value")
        ev_table.add_column("executed", no_wrap=True)
        for ev in rec.evidence:
            ev_table.add_row(
                _safe(ev.tool),
                _safe(ev.argument or "-"),
                _safe(ev.value or "-"),
                "yes" if ev.executed else "no",
            )
        console_print(console, ev_table)

    ctl_table = Table(title="recommended controls", title_justify="left", show_lines=True)
    ctl_table.add_column("tier", no_wrap=True)
    ctl_table.add_column("control")
    for p in rec.prescriptions:
        ctl_table.add_row(p.tier, _safe(p.headline))
    console_print(console, ctl_table)


def _compliance_tags_line(compliance: Any) -> str:
    """One-line compliance summary from a ComplianceTags (OWASP/ATLAS/NIST)."""
    parts = []
    if compliance.owasp_llm:
        parts.append("OWASP-LLM " + ", ".join(compliance.owasp_llm))
    if compliance.owasp_asi:
        parts.append("OWASP-ASI " + ", ".join(compliance.owasp_asi))
    if compliance.mitre_atlas:
        parts.append("MITRE ATLAS " + ", ".join(compliance.mitre_atlas))
    if compliance.nist_ai_rmf:
        parts.append("NIST " + ", ".join(compliance.nist_ai_rmf))
    return " | ".join(parts) if parts else "(no compliance tags)"


def _locate_report_artefact(target: Path) -> tuple[str, Path]:
    """Resolve a ``report`` TARGET to a ('validation'|'scan', path) pair.

    Prefers a persisted ``validation_report.json`` (the oracle verdict + evidence)
    over a ``scan_report.json`` when a dir holds both. Exits 2 with guidance when
    nothing loadable is found.
    """
    if target.is_file():
        if target.name == "validation_report.json":
            return "validation", target
        if target.name == "scan_report.json":
            return "scan", target
        echo_err(
            f"don't know how to report on {target.name}. Pass a scan dir, a "
            "generated/validated dir, or a scan_report.json / validation_report.json."
        )
        raise typer.Exit(code=EXIT_CONFIG)
    if target.is_dir():
        vr = target / "validation_report.json"
        if vr.is_file():
            return "validation", vr
        sr = target / "scan_report.json"
        if sr.is_file():
            return "scan", sr
        echo_err(
            f"no validation_report.json or scan_report.json found in {target}. "
            "Run `mylonite scan` or `mylonite validate` first."
        )
        raise typer.Exit(code=EXIT_CONFIG)
    echo_err(f"path not found: {target}. Pass a scan/validated dir or a report JSON.")
    raise typer.Exit(code=EXIT_CONFIG)


def _target_context_for_artefact_dir(artefact_dir: Path) -> Any | None:
    """PR7: reconstruct a TargetContext from an already-completed run's saved
    directory, for `mylonite report` — the offline counterpart to gate's own
    live target_context wiring (PR2).

    Reads the co-located, REDACTED `target.yaml` (written by `scan`/`gate` for
    a custom target) purely as DATA — `build_target_spec` constructs a
    TargetSpec without launching anything, so redacted credential fields
    (env/headers replaced with `${VAR}` refs) are harmless: none of them
    factor into a TargetContext. Enriches with the `tool_surface.json`
    sidecar (PR7) when present. Returns `None` (never raises) for a reference
    target, a directory with no co-located target.yaml, or any load failure —
    every caller must degrade to the class-level fix, not crash `report`.
    """
    target_yaml = artefact_dir / "target.yaml"
    if not target_yaml.is_file():
        return None
    try:
        from mylonite.plugins._mcp.target_file import (
            build_target_spec,
            load_target_file,
            target_context_for,
        )
        from mylonite.scan.artefacts import read_tool_surface

        tf = load_target_file(target_yaml)
        spec = build_target_spec(tf)
        tools = read_tool_surface(artefact_dir) or ()
        target_id = f"mcp:{tf.family}" + (f":{tf.scope}" if tf.scope else "")
        return target_context_for(spec, target_id=target_id, tools=tools, framework=tf.framework)
    except Exception as exc:
        echo_exc(f"warning: could not reconstruct target context from {target_yaml}", exc)
        return None


def report_body(
    target: Path,
    sarif: Path | None,
    json_bundle: Path | None,
) -> None:
    """Body of `mylonite report` -- see `mylonite.cli.report` for the Typer signature and help text."""
    from rich.console import Console as _Console

    kind, path = _locate_report_artefact(target)
    console = _Console()

    # PR7: reconstruct a TargetContext from this artefact dir's co-located
    # target.yaml + tool_surface.json sidecar (both optional — a reference
    # target, or a directory from before PR7, simply gets None here and every
    # consumer below degrades to the class-level fix, exactly as build_pr_body
    # already does for target=None).
    target_context = _target_context_for_artefact_dir(path.parent)

    # Captured for the machine-readable exports below (SARIF / JSON bundle),
    # enriched so NIST is present everywhere.
    vreport: Any = None
    sreport: Any = None
    dashboard_exploit: Any = None
    dashboard_exploits: list[Any] = []
    # A1: the exit code for a `kind == "scan"` artefact. Defaults to success;
    # overwritten below from `ScanOutcome.from_report(sreport)` once loaded --
    # the same single "did this scan actually work" authority `scan`/`gate`
    # already go through (mylonite.scan.coverage). Before this, `report`
    # rendered "aborted: <reason>" in its own output text and then STILL fell
    # through to `raise typer.Exit(code=EXIT_SUCCESS)` unconditionally --
    # exactly the silent fail-open this release exists to close. A validation
    # artefact has no comparable "did this actually run" signal to re-derive
    # (any persisted validation_report.json already reflects a completed run;
    # `kept=False` is a genuine verdict, not an infra abort), so it keeps
    # EXIT_SUCCESS unconditionally.
    exit_code = EXIT_SUCCESS

    if kind == "validation":
        from mylonite import testkit
        from mylonite.contracts import ValidationReport

        try:
            vreport = ValidationReport.model_validate_json(path.read_text(encoding="utf-8"))
        except Exception as exc:
            echo_exc(f"could not load {path}", exc)
            raise typer.Exit(code=EXIT_CONFIG) from exc
        _render_validation_report(vreport, console=console)
        # Compliance tags from the co-located exploit, if present.
        exploit_matches = sorted(path.parent.glob("exploit_*.json"))
        if exploit_matches:
            try:
                # Enrich on read (derive NIST from the OWASP cross-refs) so the
                # report's compliance line matches the emitted test's marks even
                # for artefacts whose persisted exploit predates enrichment. Captured
                # for the dashboard renderer.
                dashboard_exploit = _map_compliance(testkit.load_exploit(exploit_matches[0]))
                console_print(
                    console, f"compliance: {_compliance_tags_line(dashboard_exploit.compliance)}"
                )
                console_print(
                    console,
                    f"target: {dashboard_exploit.target_id}  "
                    f"pattern: {dashboard_exploit.pattern_id}",
                )
                if target_context is not None:
                    from mylonite.gate.recommend import recommend as _recommend

                    _render_recommendation_panel(
                        _recommend(dashboard_exploit, vreport, target=target_context),
                        console=console,
                    )
            except (FileNotFoundError, ValueError) as exc:
                # DCR-0003: don't silently degrade to an empty --sarif/--json
                # bundle. `dashboard_exploit` stays None below, which zeroes
                # the findings list in `to_sarif`/`to_bundle` -- a
                # REJECTED/vulnerable validation would otherwise show ZERO
                # findings in GitHub code scanning with no diagnostic that
                # compliance data was actually missing. Warn and keep going
                # (degraded but honest), never crash the command over it.
                echo_exc(
                    f"warning: could not load compliance data from {exploit_matches[0]} "
                    "-- --sarif/--json output for this artefact will omit the finding",
                    exc,
                )
        console_print(console, f"artefacts: {path.parent}")
    else:
        from mylonite import testkit
        from mylonite.contracts import ScanReport
        from mylonite.scan.artefacts import read_verdicts_calibration, render_summary
        from mylonite.scan.engine import ScanResult

        try:
            sreport = ScanReport.model_validate_json(path.read_text(encoding="utf-8"))
        except Exception as exc:
            echo_exc(f"could not load {path}", exc)
            raise typer.Exit(code=EXIT_CONFIG) from exc

        from mylonite.scan.coverage import ScanOutcome

        # Code-quality review of the A1 fix (43dc63b): a legacy-version or
        # hand-edited/corrupted scan_report.json can carry an `aborted` value
        # outside the current AbortReason enum -- `ScanOutcome.from_report`
        # raises ValueError for exactly that case. Left uncaught, that
        # surfaces as a bare traceback (exit 1, empty output) -- strictly
        # worse than the silent-exit-0 bug this branch exists to fix.
        # Degrade the same way the sibling try/except above (unparseable
        # report) already does: a clear message, no traceback, EXIT_CONFIG.
        #
        # 0.7.10: `ScanReport.aborted` is now `AbortReason | None` (a real
        # Pydantic enum), so an unrecognised value is normally already
        # rejected above, at `ScanReport.model_validate_json()` -- this
        # try/except is now defense-in-depth for a report that reached this
        # point via a path that bypasses Pydantic validation (e.g.
        # `model_construct()`), rather than the primary guard it used to be.
        try:
            exit_code = ScanOutcome.from_report(sreport).exit_code
        except ValueError as exc:
            echo_exc(f"could not classify {path}", exc)
            raise typer.Exit(code=EXIT_CONFIG) from exc

        result = ScanResult(sreport, [], calibration=read_verdicts_calibration(path.parent))
        # render_summary already returns a fully-rendered, ASCII-aware string.
        console_print(console, render_summary(result), markup=False)
        # Compliance tags aggregated across the co-located exploit files, enriched
        # on read (derive NIST from the OWASP cross-refs) so the report matches the
        # emitted test's marks even for scan dirs whose persisted exploits predate
        # enrichment.
        tags: set[str] = set()
        target_id = sreport.target_id
        from mylonite.plugins._reference.reference_compliance_mapper import (
            ReferenceComplianceMapper,
        )

        # Built once, reused for every exploit file (DCR-0014 perf) — a scan dir
        # with many findings would otherwise construct + import a fresh mapper
        # per finding in this loop.
        compliance_mapper = ReferenceComplianceMapper()
        for exploit_file in sorted(path.parent.glob("exploit_*.json")):
            try:
                exploit = _map_compliance(testkit.load_exploit(exploit_file), compliance_mapper)
            except (FileNotFoundError, ValueError, OSError):
                continue
            dashboard_exploits.append(exploit)
            c = exploit.compliance
            for ids in (c.owasp_llm, c.owasp_asi, c.mitre_atlas, c.nist_ai_rmf):
                tags.update(ids)
        if tags:
            console_print(console, f"compliance: {', '.join(sorted(tags))}")
        console_print(console, f"target: {target_id}  artefacts: {path.parent}")
        if target_context is not None and dashboard_exploits:
            from mylonite.gate.recommend import recommend as _recommend

            for exploit in dashboard_exploits:
                _render_recommendation_panel(
                    _recommend(exploit, None, target=target_context), console=console
                )

    if sarif is not None or json_bundle is not None:
        import json as _json

        # The same finding set feeds both machine-readable exports: a validation
        # carries its differential-proof report; a scan has exploits with no report.
        if kind == "validation":
            findings = [(dashboard_exploit, vreport)] if dashboard_exploit is not None else []
        else:
            findings = [(e, None) for e in dashboard_exploits]

        if sarif is not None:
            from mylonite.report import to_sarif

            sarif.write_text(
                _json.dumps(to_sarif(findings, target=target_context), indent=2) + "\n",
                encoding="utf-8",
            )
            echo(f"Wrote SARIF (GitHub code scanning): {sarif}")
        if json_bundle is not None:
            from mylonite.report import to_bundle

            json_bundle.write_text(
                _json.dumps(to_bundle(findings, target=target_context), indent=2) + "\n",
                encoding="utf-8",
            )
            echo(f"Wrote JSON finding bundle: {json_bundle}")
    raise typer.Exit(code=exit_code)
