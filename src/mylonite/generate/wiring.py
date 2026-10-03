"""Generate-command helpers: resolving exploit inputs, compliance enrichment,
the compat bridge into ``TestGenerator.emit``, and emitting one regression
test (+ co-located exploit/fixtures/target) per finding.

Moved out of ``cli.py`` (#91 thin-shell refactor) verbatim -- these are also
called from ``mylonite.cli``'s ``report`` and ``gate`` commands, which import
them back from here so a single implementation backs all three commands.
"""

from __future__ import annotations

import inspect
from pathlib import Path
from typing import Any

import typer

from mylonite._cli_io import _exit_if_missing_target_file, echo, echo_err, echo_exc
from mylonite._paths import path_for_shell, quote_for_shell, safe_slug
from mylonite.contracts.exec_context import ExecContext
from mylonite.exit_codes import EXIT_CONFIG


def _slugify_pattern(pattern_id: str) -> str:
    """Filesystem-safe slug for a default ``--out`` dir (mirrors the generator)."""
    return "".join(ch if ch.isalnum() else "_" for ch in pattern_id).strip("_") or "exploit"


def _exploits_in_dir(scan_dir: Path) -> list[Path]:
    """All (sorted) ``exploit_*.json`` inside ``scan_dir``."""
    return sorted(scan_dir.glob("exploit_*.json"))


def _resolve_exploit_paths(scan_path: Path | None, latest: bool, scans_root: Path) -> list[Path]:
    """Resolve ALL exploit JSONs to generate from (F1 — no path archaeology).

    Precedence: an explicit ``scan_path`` (an ``exploit_*.json`` file *or* a scan
    dir), else ``--latest`` (newest scan dir under ``scans_root``). A scan dir
    yields *every* ``exploit_*.json`` it contains — so a multi-finding scan emits
    one test per finding instead of silently dropping all but the
    alphabetically-first. Exits 2 with actionable guidance when nothing resolves.
    """
    if scan_path is not None:
        if scan_path.is_file():
            return [scan_path]
        if scan_path.is_dir():
            found = _exploits_in_dir(scan_path)
            if found:
                return found
            echo_err(
                f"no exploit_*.json found in {scan_path}. "
                "Run `mylonite scan <target>` first, or pass an exploit_*.json directly."
            )
            raise typer.Exit(code=EXIT_CONFIG)
        echo_err(
            f"path not found: {scan_path}. Pass a scan dir or an exploit_*.json, "
            "or run `mylonite scan <target>` first."
        )
        raise typer.Exit(code=EXIT_CONFIG)

    if latest:
        from mylonite.scan.artefacts import find_latest_scan_dir, warn_if_scan_is_stale

        scan_dir = find_latest_scan_dir(scans_root)
        if scan_dir is None:
            echo_err(f"no scans found under {scans_root}. Run `mylonite scan <target>` first.")
            raise typer.Exit(code=EXIT_CONFIG)
        # `--latest` picks by directory NAME with no age check: say which.

        echo(f"generate --latest: using {scan_dir}")
        warn_if_scan_is_stale(scan_dir, emit=echo_err)
        found = _exploits_in_dir(scan_dir)
        if not found:
            echo_err(
                f"the latest scan ({scan_dir}) found no exploits — nothing to generate. "
                "A no-finding scan is a PASS, not an error: it usually means the target "
                "is clean or guarded. To generate from an earlier scan that DID find "
                "something, pass that scan dir explicitly, e.g. "
                "`mylonite generate .mylonite/scans/<earlier-run>`."
            )
            raise typer.Exit(code=EXIT_CONFIG)
        return found

    echo_err(
        "no input given. Pass a SCAN_PATH (an exploit_*.json or a scan dir), or "
        "--latest to use the newest scan under .mylonite/scans/. Run "
        "`mylonite scan <target>` first if you have no scans yet."
    )
    raise typer.Exit(code=EXIT_CONFIG)


def _map_compliance(exploit: Any, mapper: Any | None = None) -> Any:
    """Enrich a finding's compliance tags via the reference mapper (derives NIST
    from the OWASP tags using the bundled taxonomy cross-refs).

    ``mapper``, when supplied, is reused instead of constructing a fresh
    ``ReferenceComplianceMapper()`` — a caller looping over many findings (e.g.
    ``report``'s per-exploit-file loop) can build one and pass it in (DCR-0014
    perf) instead of paying construction + import overhead per finding.
    """
    if mapper is None:
        from mylonite.plugins._reference.reference_compliance_mapper import (
            ReferenceComplianceMapper,
        )

        mapper = ReferenceComplianceMapper()
    return exploit.model_copy(update={"compliance": mapper.map(exploit)})


def _backfill_scan_report(
    source_report: Path,
    out_dir: Path,
    *,
    json_mod: Any,
    trimmed_cache: dict[Path, dict[str, str] | None] | None = None,
) -> None:
    """T12 back-fill: co-locate a TRIMMED ``scan_report.json`` next to a
    ``generate``-emitted custom-target test.

    ``scan`` writes ``scan_report.json`` into the SCAN dir (``exploit_path.parent``
    in :func:`_emit_generated_test`), but ``generate`` writes its output into a
    DIFFERENT directory (``layout.generated_for(slug)``, e.g.
    ``.mylonite/generated/<slug>/``). Without this, an exploit with no embedded
    ``mylonite.exec.*`` execution-context metadata (e.g. one scanned before this
    release) has no sibling report for ``testkit._resolve_exec_context`` to
    back-fill from once co-located there — the back-fill safety net is dead in
    practice against the real CLI-produced layout.

    Writes ONLY ``{"model": ..., "provider": ...}`` — never a verbatim copy.
    Unlike ``target.yaml`` (redacted before copying, see the caller), a raw
    ``ScanReport``'s ``attempts`` can carry unredacted target/judge free text,
    and ``out_dir`` is a directory this project tells the operator to commit.
    A no-op (nothing written, no error) when ``source_report`` is absent,
    unparseable, or doesn't carry both fields — this is a best-effort back-fill,
    not a hard requirement (``testkit`` raises its own loud error at test-run
    time if nothing ever supplied a usable model/provider).

    ``trimmed_cache``, when supplied, memoises the trimmed result per resolved
    ``source_report`` path — a multi-finding scan dir invokes this once per
    exploit, all against the SAME scan dir's ``scan_report.json``, so re-reading
    and re-parsing the identical file on every finding is pure overhead
    (mirrors ``validated_target_files`` below). Absent (``None``), every call
    re-reads independently.
    """
    resolved_source = source_report.resolve()
    if trimmed_cache is not None and resolved_source in trimmed_cache:
        trimmed = trimmed_cache[resolved_source]
    else:
        trimmed = None
        if source_report.is_file():
            try:
                report_data = json_mod.loads(source_report.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                report_data = None
            if isinstance(report_data, dict):
                candidate = {
                    key: report_data[key]
                    for key in ("model", "provider")
                    if isinstance(report_data.get(key), str)
                }
                # Only useful to testkit's back-fill if BOTH fields are present —
                # a partial trim (e.g. model only) would silently mask that the
                # source report itself was incomplete.
                trimmed = candidate if {"model", "provider"} <= candidate.keys() else None
        if trimmed_cache is not None:
            trimmed_cache[resolved_source] = trimmed

    if trimmed is None:
        return

    colocated_report = out_dir / "scan_report.json"
    colocated_report.write_text(
        json_mod.dumps(trimmed, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    echo(f"Wrote report:  {colocated_report} (model/provider back-fill only)")


def _dispatch_emit(generator: Any, exploit: Any, context: ExecContext | None) -> Any:
    """Call ``generator.emit()``, passing ``context=`` only if the generator
    actually accepts it.

    ``TestGenerator.CONTRACT_VERSION`` moved 0.1.0 -> 0.2.0 in 0.7.10 to add
    an optional ``context: ExecContext | None = None`` parameter to ``emit``
    (see ``contracts/test_generator.py``). A third-party plugin still built
    against 0.1.x only defines ``emit(self, exploit)`` — unconditionally
    calling ``generator.emit(exploit, context=context)`` would raise
    ``TypeError: emit() got an unexpected keyword argument 'context'`` for
    such a plugin.

    This is a TEMPORARY compat bridge for pre-0.2.0 third-party
    ``TestGenerator`` plugins: inspect the plugin's ``emit`` signature
    BEFORE calling it (rather than wrapping the call in a broad
    ``except TypeError``, which could just as easily mask a real bug
    *inside* a conforming ``emit()`` implementation and misattribute it to
    this bridge), and only pass ``context=`` when the signature declares it
    (by name or via ``**kwargs``).
    """
    try:
        sig = inspect.signature(generator.emit)
    except (TypeError, ValueError):
        # Signature couldn't be introspected (e.g. a non-Python callable) —
        # be conservative and use the pre-0.2.0 call shape.
        return generator.emit(exploit)
    accepts_context = "context" in sig.parameters or any(
        p.kind is inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()
    )
    if accepts_context:
        return generator.emit(exploit, context=context)
    return generator.emit(exploit)


def _emit_generated_test(
    exploit: Any,
    exploit_path: Path,
    out_dir: Path,
    target_file: Path | None,
    *,
    json_mod: Any,
    validated_target_files: set[Path] | None = None,
    scan_report_cache: dict[Path, dict[str, str] | None] | None = None,
    redacted_target_cache: dict[Path, str] | None = None,
    proven_by: Path | None = None,
) -> None:
    """Emit one regression test (+ co-located exploit/fixtures/target) for one
    exploit, echoing the per-test ``Wrote …`` lines and next-step guidance.

    Factored out of :func:`generate` so a multi-finding scan dir can emit one
    test per finding into per-pattern subdirs. The single-exploit output is
    unchanged.

    ``validated_target_files``, when supplied, is a cache of target-file paths
    already loaded+validated (by this call or an earlier one in the same
    multi-finding loop) — a multi-finding scan dir re-invokes this once per
    exploit, all typically against the SAME target file, so re-parsing and
    re-validating the identical YAML on every finding is pure overhead
    (DCR-0013/0009 perf). Absent (``None``), every call validates independently
    — the original, always-correct behaviour.

    ``scan_report_cache`` is the same style of cache for
    :func:`_backfill_scan_report`'s trimmed ``scan_report.json`` read.

    ``redacted_target_cache`` (DCR-0013) is the same style of cache for the
    target file's REDACTED text written into each finding's ``target.yaml``
    below: ``validated_target_files`` only remembers "already validated"
    (a boolean), so before this the identical file was still re-read from
    disk and re-run through ``redact_target_yaml`` on every finding in a
    multi-finding scan dir sharing one target file. Absent (``None``), every
    call reads+redacts independently — the original, always-correct
    behaviour.

    The test gets the UNVALIDATED header, and a line saying so is printed,
    unless ``proven_by`` names a KEPT test it matches exactly (see
    :mod:`mylonite.generate.provenance`).
    """
    from mylonite._redaction import redact_target_yaml, redact_value
    from mylonite._target_env import echo_env_notice
    from mylonite.generate.provenance import (
        announce_unvalidated,
        source_is_proven,
        stamp_unvalidated,
    )
    from mylonite.plugins._reference.reference_pytest_generator import (
        ReferencePytestGenerator,
    )

    # Enrich compliance ONCE (derives NIST from the OWASP cross-refs) and use the
    # SAME enriched record for both the emitted test's marks and the co-located
    # exploit JSON. Writing the raw record here left the persisted exploit (what
    # `mylonite report` reads) without the NIST tags the marks carried — the
    # marks-vs-report inconsistency from the v0.7.0 assessment.
    enriched = _map_compliance(exploit)
    # T12/0.7.10: build the exec context from the exploit's stamped
    # mylonite.exec.* metadata and pass it explicitly rather than relying on
    # the generator to re-derive it — see ExecContext.from_metadata's and
    # TestGenerator.emit's docstrings. _dispatch_emit is the compat bridge
    # for any pre-0.2.0 third-party generator that doesn't accept `context`.
    exec_ctx = ExecContext.from_metadata(enriched.payload.metadata)
    generated = _dispatch_emit(ReferencePytestGenerator(), enriched, exec_ctx)
    out_dir.mkdir(parents=True, exist_ok=True)

    test_path = out_dir / generated.filename
    # Compared before the write: regenerating in place overwrites the proven test.
    unvalidated = not source_is_proven(generated.source, proven_by)
    source = stamp_unvalidated(generated.source) if unvalidated else generated.source
    test_path.write_text(source, encoding="utf-8")

    # Co-locate the exploit under the exact name the emitted test loads
    # (`load_exploit(here / "exploit_<pattern_id>.json")`).
    # Never write the exploit's captured response/payload verbatim into a
    # directory we tell the operator to commit — a successful exfiltration
    # attack can carry a live secret in raw_response (DCR-0002 companion).
    # Mirrors the redact_target_yaml() treatment applied to colocated_target
    # a few lines below.
    colocated_exploit = out_dir / f"exploit_{safe_slug(enriched.pattern_id)}.json"
    colocated_exploit.write_text(
        json_mod.dumps(redact_value(enriched.model_dump(mode="json")), indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )

    fixtures_dir = out_dir / "fixtures"
    fixtures_dir.mkdir(parents=True, exist_ok=True)

    echo(f"Wrote test:    {test_path}")
    echo(f"Wrote exploit: {colocated_exploit}")
    echo(f"Fixtures dir:  {fixtures_dir}")

    # A custom-target test re-drives the REAL app, so it needs the target YAML
    # co-located as target.yaml. Co-locate it when given; otherwise warn loudly
    # (the test would fail at runtime without it). Reference tests replay the
    # bundled twin and need no target file.
    is_custom = not exploit.target_id.startswith("reference:")

    # T12 back-fill (see _backfill_scan_report's docstring): only applies to
    # custom targets — a reference-target test replays the bundled twin via
    # assert_guard_holds, which takes no model/provider kwargs and has no use
    # for a co-located scan_report.json at all.
    if is_custom:
        _backfill_scan_report(
            exploit_path.parent / "scan_report.json",
            out_dir,
            json_mod=json_mod,
            trimmed_cache=scan_report_cache,
        )

    # Auto-resolve the target YAML co-located with the scan (written by `scan`) so
    # the operator needn't re-pass --target-file at every step. An explicit
    # --target-file always wins.
    if target_file is None and is_custom:
        candidate = exploit_path.parent / "target.yaml"
        if candidate.is_file():
            target_file = candidate
            echo(f"Using target:  {candidate} (from the scan dir)")
    if target_file is not None:
        resolved_target_file = target_file.resolve()
        if validated_target_files is None or resolved_target_file not in validated_target_files:
            from mylonite.plugins._mcp.target_file import build_target_spec, load_target_file

            try:
                build_target_spec(load_target_file(target_file))  # validate before copying
            except Exception as exc:
                # Defensive: callers of _emit_generated_test already validate this
                # exact target_file up front (generate's pre-loop check below, or
                # the caller passing an already-validated `validated_target_files`
                # cache), so FileNotFoundError should not reach here in practice.
                _exit_if_missing_target_file(exc, target_file)
                echo_exc(f"invalid --target-file {target_file}", exc)
                raise typer.Exit(code=EXIT_CONFIG) from exc
            if validated_target_files is not None:
                validated_target_files.add(resolved_target_file)
        colocated_target = out_dir / "target.yaml"
        # Never copy a target file verbatim into a directory we tell the operator
        # to commit: request.headers and env may carry live credentials (DCR-0010).
        # DCR-0013: read + redact at most once per unique target file, cached
        # across every finding in a multi-finding loop (see the cache's
        # docstring above) instead of redoing this on every single finding.
        cached = (redacted_target_cache or {}).get(resolved_target_file)
        if cached is not None:
            redacted_target_text = cached
        else:
            redacted_target_text = redact_target_yaml(target_file.read_text(encoding="utf-8"))
            if redacted_target_cache is not None:
                redacted_target_cache[resolved_target_file] = redacted_target_text
        colocated_target.write_text(redacted_target_text, encoding="utf-8")
        echo(f"Wrote target:  {colocated_target}")
        if cached is None:  # one notice per target file, not one per finding
            echo_env_notice(redacted_target_text, colocated_target)
    elif is_custom:
        echo("")
        echo_err(
            f"warning: {exploit.target_id} is a custom target - the emitted test re-drives "
            "your real app and needs a co-located target.yaml. Re-run with "
            "`--target-file <your-target>.yaml`, or copy your scan's target YAML into "
            f"{out_dir} as target.yaml. Without it the test errors at runtime."
        )

    echo("")
    authorize_value: str | None = None
    if is_custom:
        from mylonite._authz import authorize_value_for_target_file
        from mylonite.scan.providers import api_key_hint

        # validate auto-resolves the co-located target.yaml — no --target-file
        # needed, but the LIVE authorize gate (DCR-0009) still requires the
        # exact scope this target.yaml declares: --authorize must be in the
        # printed command, not just in the docs, or it is refused as printed
        # (`mylonite validate` would otherwise exit 2: "--authorize must
        # equal ... got None").
        authorize_value = (
            authorize_value_for_target_file(target_file) if target_file is not None else None
        )
        authorize_flag = (
            f" --authorize {quote_for_shell(authorize_value)}" if authorize_value else ""
        )

        # The custom test is LIVE (gated behind MYLONITE_LIVE_TARGET=1): it needs
        # pytest, a provider key, a runnable MCP server, and the co-located YAML.
        echo("Next - this is a LIVE custom-target test. To run it you need:")
        echo("  - pytest + mylonite installed in the consuming environment")
        echo(f"  - {api_key_hint(exec_ctx.provider if exec_ctx is not None else None)} set")
        echo("  - your target's MCP server runnable, and target.yaml co-located")
        echo("Then:")
        echo(f"  MYLONITE_LIVE_TARGET=1 pytest {path_for_shell(out_dir)}")
        echo(f"  mylonite validate {path_for_shell(out_dir)}{authorize_flag}")
    else:
        echo(f"Next: mylonite validate {path_for_shell(out_dir)}")
    if unvalidated:
        announce_unvalidated(out_dir, authorize=authorize_value)


def _tag_control_for_generate(exploit: Any) -> Any:
    """Stamp ``synthetic_control`` so the generator emits an ``assert_control_holds``
    test (``generate --prove-control``), turning the control-efficacy oracle's
    verdict into a committable CI gate.

    Passes the exploit through unchanged (with a notice) for a reference target or
    a weakness with no boundary control — those can't be emitted as a committable
    custom-target control test. Mirrors the tagging ``gate`` does by default.
    """
    from mylonite.gate.mitigation import weakness_class_for
    from mylonite.scan.control_shim import make_control

    if exploit.target_id.startswith("reference:"):
        echo_err(
            f"--prove-control: {exploit.pattern_id} targets a reference twin; emitting "
            "the standard guard test instead."
        )
        return exploit
    cw = weakness_class_for(exploit)
    try:
        make_control(cw)
    except ValueError:
        echo_err(
            f"--prove-control: no boundary control for weakness {cw!r} "
            f"({exploit.pattern_id}); emitting the standard target-resists test instead."
        )
        return exploit
    meta = {**exploit.payload.metadata, "synthetic_control": cw}
    return exploit.model_copy(
        update={"payload": exploit.payload.model_copy(update={"metadata": meta})}
    )
