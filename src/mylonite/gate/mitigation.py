"""PR-body builder for the gating PR (deterministic + opt-in LLM enrichment)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from mylonite._redaction import redact
from mylonite._twin_fidelity import PROOF_CLAIM_SERVER, guarded_twin_layer
from mylonite._verdict import KEPT, verdict_label, verdict_reason
from mylonite.contracts import ExploitRecord, ValidationReport
from mylonite.gate.localize import localize
from mylonite.mitigations import snippet as _snippet
from mylonite.scan.llm_types import CompletionFn
from mylonite.scan.seeds import SEED_CATALOGUE
from mylonite.scan.weakness import WEAKNESS_CLASSES

_PATTERN_TO_WEAKNESS = {s.pattern_id: s.weakness for s in SEED_CATALOGUE}

# Fallback when the pattern_id isn't a bundled seed: infer the class from the
# strongest compliance signal. ASI01 goal-hijack / ASI06 memory-poison ride with
# indirect injection (W2); ASI02 tool-misuse with description smuggling (W1);
# LLM06 excessive agency with the egress/unconfirmed-action families (W3/W4).
_ASI_TO_WEAKNESS = {"ASI01": "W2", "ASI06": "W2", "ASI02": "W1", "ASI05": "W3"}
_LLM_TO_WEAKNESS = {"LLM05": "W2", "LLM06": "W4"}

_GUARDED_TWIN = "reference_targets/mcp_kitchen_sink/src/mcp_kitchen_sink/server_guarded.py"

#: Fallback for the "How this is gated" section's directory mention when a
#: caller has no real one to pass (GT15) — matches `gate`'s own CLI default
#: for `--out`, so a bare `build_pr_body(...)` call (a test, or a library
#: user with no gate_dir) still reads as a real-looking path.
_DEFAULT_GATE_DIR_LABEL = ".mylonite/gate/"


def _gate_dir_label(gate_dir: Path | str | None) -> str:
    """Render ``gate_dir`` as the backtick-quoted path fragment the PR body
    names in its "How this is gated" section, e.g. ``.mylonite/gate/``.

    ``gate_dir`` is the directory the run actually wrote to (``gate``'s
    resolved ``--out``), not a hardcoded literal — a run with a non-default
    ``--out`` used to tell the reader the test lives under `.mylonite/gate/`
    regardless of where it was actually written.
    """
    if gate_dir is None:
        return _DEFAULT_GATE_DIR_LABEL
    return f"{Path(gate_dir).as_posix().rstrip('/')}/"


def commits_as_pending(exploit: ExploitRecord) -> bool:
    """Whether ``gate`` commits this finding's test as a pending fix.

    True for a finding on the user's own target that has no control-efficacy
    differential: its committed test re-drives the attack on the user's app,
    which still lets it through, so a plain test would be red the moment the
    gate PR lands. A reference-twin test and a control-efficacy test both pass
    on the current build, so neither is pending.
    """
    if exploit.target_id.startswith("reference:"):
        return False
    return not exploit.payload.metadata.get("synthetic_control")


def weakness_class_for(exploit: ExploitRecord) -> str:
    """Return the W1-W4 class for an exploit, or 'generic' if unknown.

    Prefers the exploit's own stamped ``payload.metadata["weakness"]`` — set by
    the attack module at scan time, and the ground truth for a pattern_id the
    bundled seed catalogue doesn't recognise (an adaptively-synthesised seed,
    or a custom-target pattern_id that happens to collide with a bundled one).
    Falls back to the bundled seed catalogue (authoritative for reference/
    bundled patterns); then the exploit's compliance tags; finally 'generic'.

    A4: ``report/bundle.py`` already applied this precedence independently
    (stamped metadata over inference); this function did not, so
    ``build_pr_body`` (and every other caller here) could disagree with the
    JSON bundle about which weakness class the same finding belongs to.
    """
    stamped = exploit.payload.metadata.get("weakness")
    if stamped in WEAKNESS_CLASSES:
        return stamped
    if exploit.pattern_id in _PATTERN_TO_WEAKNESS:
        return _PATTERN_TO_WEAKNESS[exploit.pattern_id]
    for asi in exploit.compliance.owasp_asi:
        if asi in _ASI_TO_WEAKNESS:
            return _ASI_TO_WEAKNESS[asi]
    for llm in exploit.compliance.owasp_llm:
        if llm in _LLM_TO_WEAKNESS:
            return _LLM_TO_WEAKNESS[llm]
    return "generic"


def _guarded_is_server_layer(
    report: ValidationReport, guarded_is_server_layer: bool | None
) -> bool:
    """Whether the guarded twin was the REAL server-side control.

    A thin bool-returning adapter over the shared resolver in
    ``mylonite._twin_fidelity``, which owns the marker literal and the
    default-to-boundary rule. Kept because this module's callers pass and read a
    plain bool.
    """
    return guarded_twin_layer(report, guarded_is_server_layer) == "server"


def _evidence_lines(report: ValidationReport) -> str:
    # ``detail`` is free text that can carry a credential the target echoed
    # (#223). The PR body is committed and sent to GitHub, so it gets the same
    # ``redact()`` pass ``validation_report.json`` gets before it is written.
    rows = [
        f"- **{o.stage}**: {'pass' if o.passed else 'FAIL'} — {redact(o.detail)}"
        for o in report.outcomes
    ]
    # The differential-oracle evidence (PR2): the gate with live per-leg marks,
    # the fires/resists counts, and the per-seed kill matrix — so the PR shows
    # WHY this test is trustworthy, not just that it was kept.
    # str() the stage key so indexing with gating_legs (list[str]) type-checks
    # against the Literal-keyed outcome stages.
    legs_by_stage = {str(o.stage): o for o in report.outcomes}
    if report.gating_legs:
        rendered = " AND ".join(
            f"{leg} {'✓' if legs_by_stage[leg].passed else '✗'}"
            for leg in report.gating_legs
            if leg in legs_by_stage
        )
        rows.append(f"- **gate**: kept = {rendered} => **{verdict_label(report)}**")
    repro = report.reproducibility
    if repro is not None:
        if repro.guard_resisted is not None:
            rows.append(
                f"- **reproducibility**: vulnerable fired {repro.vuln_fired}/{repro.iterations}, "
                f"guarded resisted {repro.guard_resisted}/{repro.iterations}"
            )
        else:
            rows.append(
                f"- **reproducibility**: reproduced {repro.vuln_fired}/{repro.iterations} "
                "against the real target"
            )
    if report.mutation_score is not None:
        rows.append(f"- **mutation score**: {report.mutation_score:.2f}")
    if report.mutation_matrix:
        killed = sum(1 for s in report.mutation_matrix if s.killed)
        cells = ", ".join(
            f"{s.weakness}:{s.pattern_id} {'✓' if s.killed else '✗'}"
            for s in report.mutation_matrix
        )
        rows.append(f"- **kill matrix** ({killed}/{len(report.mutation_matrix)}): {cells}")
    rows.append(f"- **kept**: {report.kept}")
    return "\n".join(rows)


def _compliance_line(exploit: ExploitRecord) -> str:
    c = exploit.compliance
    parts = []
    if c.owasp_llm:
        parts.append("OWASP-LLM " + ", ".join(c.owasp_llm))
    if c.owasp_asi:
        parts.append("OWASP-ASI " + ", ".join(c.owasp_asi))
    if c.mitre_atlas:
        parts.append("MITRE ATLAS " + ", ".join(c.mitre_atlas))
    if c.nist_ai_rmf:
        parts.append("NIST " + ", ".join(c.nist_ai_rmf))
    return " · ".join(parts) if parts else "(no compliance tags)"


def build_pr_body(
    exploit: ExploitRecord,
    report: ValidationReport,
    *,
    llm_enrich: bool = False,
    completion_fn: CompletionFn | None = None,
    system_prompt: str | None = None,
    model: str | None = None,
    guarded_is_server_layer: bool | None = None,
    target: Any | None = None,
    gate_dir: Path | str | None = None,
) -> str:
    """Assemble the gating PR description (deterministic; opt-in LLM enrichment).

    ``system_prompt`` (the target's ingested prompt, when available) lets the
    locus line pin a system-prompt finding to an exact line (R4). ``model`` is
    the enrichment model used when ``llm_enrich=True`` (T14) — ``gate``
    threads its own resolved ``--model`` through here so the enrichment call
    is a real, configurable, budget-counted/policy-kwarg'd LiteLLM call
    instead of the hardcoded literal this used to be.

    ``guarded_is_server_layer`` (A3): a caller with direct access to
    ``TwinPlan.guarded_is_server_layer`` may pass it explicitly; otherwise it
    is derived from ``report.notes``'s ``[guarded-twin=...]`` marker (see
    :func:`_guarded_is_server_layer`). This used to be conflated with
    ``is_control`` — every control-efficacy finding was captioned "(proxy)"
    even when the differential toggled the target's REAL server-side control
    (a declared ``control_env``), mislabelling the strongest possible result
    as the weakest.

    ``target`` (PR2, Workstream D): an optional
    ``mylonite.gate.recommend.TargetContext``. Typed ``Any`` here rather than
    imported at module scope to avoid a needless import when a caller has none
    to pass — ``recommend()`` handles ``target=None`` gracefully by design
    (degraded evidence, lower confidence, never a crash).

    ``gate_dir`` (GT15): the directory this run actually wrote to (``gate``'s
    resolved ``--out``), so the "How this is gated" section names the real
    path instead of a hardcoded ``.mylonite/gate/`` that drifted from a
    non-default ``--out``. Defaults to that literal when omitted.

    PR11 (deliberate compat event): the fix section always renders
    :func:`mylonite.gate.recommend.render_markdown`'s target-specific,
    evidence-anchored recommendation now, for every target including a
    reference one — the fixed, illustrative ``gate/fixes/{wc}.md`` diff this
    used to fall back to on ``target=None`` is retired. The class-level
    ``mitigations/{wc}.md`` background prose (:func:`_snippet`, now
    ``mylonite.mitigations.snippet``) stays — it is still true and still useful
    context regardless of target.
    """
    wc = weakness_class_for(exploit)
    is_reference = exploit.target_id.startswith("reference:")
    control = exploit.payload.metadata.get("synthetic_control") or ""
    is_control = bool(control)
    server_layer = _guarded_is_server_layer(report, guarded_is_server_layer)
    loc = localize(exploit, system_prompt=system_prompt)
    # Only a KEPT verdict (a passing build and a passing differential or effect
    # leg) earns a claim. A STABLE, NOT PROVEN or REJECTED report gets its label
    # and the reason instead, the same rule SARIF and the JSON bundle follow.
    label = verdict_label(report)
    proven = label == KEPT
    not_proven_line = f"**Verdict: {label}:** {verdict_reason(report)}"

    if is_control and not proven:
        repro = report.reproducibility
        if repro is not None and repro.iterations:
            stat = (
                f"Attack `{exploit.pattern_id}` fired {repro.vuln_fired}/{repro.iterations} "
                f"against your app; control **{control}** was applied on the guarded side."
            )
        else:
            stat = f"Control **{control}** was tested for `{exploit.pattern_id}`."
        head = [
            "## Control efficacy not proven",
            stat,
            "",
            not_proven_line,
            "",
            f"**Compliance:** {_compliance_line(exploit)}",
            f"**Attack tier:** {exploit.payload.metadata.get('attack_tier', 'static')}",
            "",
            "**Validation evidence:**",
            _evidence_lines(report),
        ]
    elif is_control:
        repro = report.reproducibility
        if repro is not None and repro.iterations:
            raw_rate = (repro.vuln_fired or 0) / repro.iterations
            guard_rate = (repro.guard_fired or 0) / repro.iterations
            gap = repro.rate_gap if repro.rate_gap is not None else raw_rate - guard_rate
            stat = (
                f"With your model held constant, attack `{exploit.pattern_id}` **succeeds** "
                f"against your app ({raw_rate:.0%}) and is **resisted** when control "
                f"**{control}** is applied at the boundary ({guard_rate:.0%} leak); control "
                f"contribution **{gap:+.0%}**."
            )
        else:
            stat = (
                f"Control **{control}** is verified load-bearing for `{exploit.pattern_id}` "
                f"against `{exploit.target_id}` (model held constant)."
            )
        if server_layer:
            layer_caveat = (
                "> **Server-layer control verified.** Mylonite disabled and re-enabled your "
                "REAL server-side control (declared via `control_env`) — not a synthetic "
                "boundary shim. This differential proves your actual implementation is what "
                "carries the security, not a canonical stand-in for it."
            )
        else:
            layer_caveat = (
                "> **Boundary-validated control (proxy).** Mylonite enforced this control at the "
                "adapter boundary, not in your server. Implement it server-side for a production "
                "fix (see the mitigation below), then re-point the committed test at your real "
                "implementation."
            )
        # The claim must match the twin that produced it. On a synthetic boundary
        # twin the guarded side is Mylonite's canonical shim, so the run measured
        # the control CLASS, not the operator's implementation -- stating the
        # strong claim here and qualifying it two lines later put the overclaim
        # in the headline, where it is what actually gets read.
        claim = (
            f"This proves that {PROOF_CLAIM_SERVER}."
            if server_layer
            else (
                "This proves the attack is **real** and that a canonical "
                f"**{control}** control closes it, with your model held constant. "
                "It does **not** yet prove your own implementation carries the "
                "security - see below."
            )
        )
        head = [
            "## Control efficacy verified",
            stat,
            "",
            claim,
            "",
            layer_caveat,
            "",
            f"**Compliance:** {_compliance_line(exploit)}",
            f"**Attack tier:** {exploit.payload.metadata.get('attack_tier', 'static')}",
            "",
            "**Validation evidence:**",
            _evidence_lines(report),
        ]
    else:
        found = (
            f"A validated weakness (`{exploit.pattern_id}`) against `{exploit.target_id}`."
            if proven
            else f"A weakness (`{exploit.pattern_id}`) against `{exploit.target_id}`. "
            + not_proven_line
        )
        head = [
            "## What Mylonite found",
            found,
            "",
            f"**Compliance:** {_compliance_line(exploit)}",
            f"**Attack tier:** {exploit.payload.metadata.get('attack_tier', 'static')}",
            "",
            "**Validation evidence:**",
            _evidence_lines(report),
        ]

    sections = [
        *head,
        "",
        "## Suggested mitigation",
        "_Human-applied — Mylonite proves and gates the weakness; it does not patch your code._",
        "",
        f"**Located at:** {loc.label}. {loc.why}",
        "",
        _snippet(wc),
        "",
    ]
    from mylonite.gate.recommend import recommend, render_markdown

    rec = recommend(exploit, report, target=target)
    sections += [
        (
            "**Proven fix** — implement the control the differential verified load-bearing, "
            "server-side, then re-point the committed test at it:"
            if is_control and proven
            else "**Recommended fix** — implement this control server-side, then re-point the "
            "committed test at your implementation:"
        ),
        "",
        render_markdown(rec).rstrip(),
    ]
    if is_reference:
        sections += [
            "",
            f"See the guarded reference twin for a concrete fix: `{_GUARDED_TWIN}`.",
        ]
    if llm_enrich:
        # The model's reply is pasted into a committed PR body; it can echo
        # anything it was shown, so it is redacted like the evidence lines.
        extra = redact(_llm_suggestion(exploit, completion_fn=completion_fn, model=model) or "")
        if extra:
            sections += [
                "",
                "> **Unverified LLM suggestion** (not validated by the oracle — review before applying):",
                "> " + extra.replace("\n", "\n> "),
            ]
    gate_dir_label = _gate_dir_label(gate_dir)
    if is_control and not proven:
        gating_desc = (
            f"`{report.test_filename}` (under `{gate_dir_label}`) re-drives the attack with and "
            f"without control **{control}**. This run has not yet shown that the control stops "
            "the attack, so a passing check does not show it either; re-run `mylonite validate` "
            "until the verdict is KEPT before relying on this gate."
        )
    elif is_control:
        gating_desc = (
            f"`{report.test_filename}` (under `{gate_dir_label}`) re-drives the attack with and "
            f"without control **{control}** and asserts it fires on the raw target but is "
            "resisted with the control applied. The committed per-PR workflow runs it on every "
            "PR; if the control stops carrying the security, the check fails."
        )
    elif commits_as_pending(exploit):
        gating_desc = (
            f"`{report.test_filename}` (under `{gate_dir_label}`) re-drives this attack and "
            "asserts your agent resists it. Your agent does not resist it yet, so the test is "
            "committed as a pending fix (`@testkit.pending_fix`): it is an expected failure "
            "and the per-PR check stays green. Once your fix lands the test passes and fails "
            "the check on purpose, with a message telling you to delete the "
            "`@testkit.pending_fix(...)` line. From then on it is a regular gate, and a "
            "regression fails the check."
        )
    else:
        gating_desc = (
            f"`{report.test_filename}` (under `{gate_dir_label}`) re-drives this attack and "
            "asserts your agent resists it. The committed per-PR workflow runs it on every PR; "
            "a regression fails the check."
        )
    sections += ["", "## How this is gated", gating_desc]
    return "\n".join(sections) + "\n"


def build_gate_pr_body(
    kept: list[tuple[ExploitRecord, ValidationReport]],
    rejected: list[tuple[ExploitRecord, str]],
    *,
    llm_enrich: bool = False,
    completion_fn: CompletionFn | None = None,
    system_prompt: str | None = None,
    model: str | None = None,
    guarded_is_server_layer: bool | None = None,
    target: Any | None = None,
    gate_dir: Path | str | None = None,
) -> str:
    """Thin wrapper (#202): join each KEPT finding's :func:`build_pr_body`
    section, then list the REJECTED findings with their reason.

    ``build_pr_body`` itself stays per-finding — unchanged, and still the only
    thing that knows how to render one finding's evidence/recommendation. For
    the single-kept/no-rejected case (today's only shape) this returns
    ``build_pr_body``'s output byte-for-byte, so a one-finding gate PR is
    unaffected by this wrapper existing. A run with several kept findings, or
    any rejected ones, gets one ``## Finding N: <pattern_id>`` section per kept
    finding plus a trailing "Other findings" section naming what was rejected
    and why — so a finding the oracle could not confirm is never silently
    dropped from the PR the way it used to be dropped from the gate entirely.

    ``gate_dir`` (GT15) is forwarded to every :func:`build_pr_body` call
    unchanged, so every finding's "How this is gated" section names the same
    real output directory.
    """
    if len(kept) == 1 and not rejected:
        exploit, report = kept[0]
        return build_pr_body(
            exploit,
            report,
            llm_enrich=llm_enrich,
            completion_fn=completion_fn,
            system_prompt=system_prompt,
            model=model,
            guarded_is_server_layer=guarded_is_server_layer,
            target=target,
            gate_dir=gate_dir,
        )

    sections = [f"# Mylonite gate: {len(kept)} finding(s) kept, {len(rejected)} rejected", ""]
    for i, (exploit, report) in enumerate(kept, start=1):
        sections.append(f"## Finding {i}: `{exploit.pattern_id}`")
        sections.append("")
        sections.append(
            build_pr_body(
                exploit,
                report,
                llm_enrich=llm_enrich,
                completion_fn=completion_fn,
                system_prompt=system_prompt,
                model=model,
                guarded_is_server_layer=guarded_is_server_layer,
                target=target,
                gate_dir=gate_dir,
            )
        )
        sections.append("")
    if rejected:
        sections.append("## Other findings (not gated)")
        sections.append(
            "_The scan turned up more than this PR gates. Each of these did not make it "
            "into a kept, committed test — see the reason next to each. Re-run "
            "`mylonite generate` + `mylonite validate` on the scan directory to inspect "
            "one directly._"
        )
        sections.append("")
        for exploit, reason in rejected:
            sections.append(f"- `{exploit.pattern_id}`: {reason}")
        sections.append("")
    return "\n".join(sections)


def _llm_suggestion(
    exploit: ExploitRecord,
    *,
    completion_fn: CompletionFn | None = None,
    model: str | None = None,
) -> str | None:
    """A short, app-specific remediation idea. Best-effort; labelled unverified.

    Routed through ``_llm.litellm_text_call`` — the same chokepoint the
    customiser/judge/planner use — rather than a bare ``litellm.completion``
    call, so it is a real, configurable, budget-counted/policy-kwarg'd call
    with a model the CALLER supplies (``gate`` threads its own resolved
    ``--model`` through ``build_pr_body``/``build_gate_pr_body``). There is
    no default provider or model: with no ``model``, enrichment is skipped
    -- but LOUDLY, with one warning line (a caller asked for
    ``llm_enrich=True`` and got no enrichment; silence there would read as
    "nothing to add" rather than "couldn't run it"), not silently.
    ``completion_fn`` is still the offline test seam (passed straight
    through); any failure (call exception, empty response) also returns
    ``None`` — enrichment must never break body assembly.
    """
    if model is None:
        from mylonite._cli_io import echo_err

        echo_err(
            "warning: --llm-enrich was requested but no model is configured -- "
            "skipping the LLM suggestion (the rest of the PR body is unaffected)."
        )
        return None
    prompt = (
        "You are a security engineer. In 2-3 sentences, suggest a concrete, "
        "human-applied mitigation for this AI-agent weakness. Do not include "
        "code unless trivial. Weakness pattern: "
        f"{exploit.pattern_id}; reason: {redact(exploit.success_reason)}."
    )
    from mylonite.scan._llm import litellm_text_call

    return litellm_text_call(
        model=model,
        prompt=prompt,
        caller="gate_mitigation",
        completion_fn=completion_fn,
    )
