"""PR-body builder for the gating PR (deterministic + opt-in LLM enrichment)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from mylonite._markdown import code_span
from mylonite._redaction import redact
from mylonite._twin_fidelity import PROOF_CLAIM_SERVER, guarded_twin_layer
from mylonite._verdict import (
    KEPT,
    STABILITY_STAGES,
    stability_measured,
    stability_not_measured,
    verdict_label,
    verdict_reason,
)
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


#: One deterministic, plain-language sentence per weakness class: what an
#: attacker gets, in words a non-specialist reads in one pass. Keyed on the
#: class alone (not the finding) so the same class always reads the same way
#: across every PR — a developer who has seen one W2 finding already knows
#: what the next one means before reading the evidence.
_IMPACT_BY_WEAKNESS: dict[str, str] = {
    "W1": (
        "A tool's own description can quietly direct your agent to take an action your "
        "user never asked for and never sees requested."
    ),
    "W2": (
        "Anyone who can place text your agent reads — a note, an email, a web page, a "
        "retrieved document — can redirect it to act on their instructions instead of "
        "your user's, including sending what it read to them."
    ),
    "W3": (
        "An attacker can make your agent fetch or send data to a host of their choosing, "
        "turning your agent into a channel out of your network."
    ),
    "W4": (
        "An attacker, or ordinary text your agent reads, can make it take a real, "
        "hard-to-reverse action — send an email, create a record, move money — with no "
        "human ever approving it."
    ),
}
_IMPACT_GENERIC = (
    "This weakness lets an attacker change what your agent does without your user's "
    "knowledge or approval."
)


def impact_sentence(weakness: str) -> str:
    """One deterministic sentence on what an attacker gains from this class.

    Class-level, not finding-level: it does not read the trace, so it never
    needs degraded evidence or a confidence tier the way
    :mod:`mylonite.gate.recommend` does. Every caller gets the same sentence
    for the same class, by design.
    """
    return _IMPACT_BY_WEAKNESS.get(weakness, _IMPACT_GENERIC)


#: Lower rank sorts first — a reviewer with several kept findings in one gate
#: PR sees the one that matters most at the top.
_SEVERITY_RANK: dict[str, int] = {"High": 0, "Medium": 1, "Low": 2}


def severity_for_exploit(exploit: ExploitRecord) -> str:
    """The exploit's severity, by the same rule the SARIF and JSON exports use.

    Severity was computed for those two exports and nowhere else; the gate PR
    body stated no severity at all, so a reviewer had to go read a machine
    export to learn how bad a kept finding was.

    ``mylonite.report.severity`` is imported here, not at module scope:
    ``mylonite.report`` imports ``mylonite.report.bundle``, which imports
    ``weakness_class_for`` from this module, so importing the severity rule
    up front would be circular.
    """
    from mylonite.report.severity import severity_for

    effect = str(getattr(exploit.response, "metadata", {}).get("effect_confirmed", "unprobed"))
    return severity_for(weakness_class_for(exploit), effect)


def _severity_sort_key(exploit: ExploitRecord) -> tuple[int, str]:
    """Most-severe-first, tie-broken by ``pattern_id`` — the single ordering
    every severity-sorted surface (the gate PR body, `scan`'s end-of-run
    findings) uses, so they agree on which finding is "first"."""
    return (
        _SEVERITY_RANK.get(severity_for_exploit(exploit), len(_SEVERITY_RANK)),
        exploit.pattern_id,
    )


def severity_sort_kept(
    kept: list[tuple[ExploitRecord, ValidationReport]], kept_dirs: list[Path]
) -> tuple[list[tuple[ExploitRecord, ValidationReport]], list[Path]]:
    """Order kept findings by severity (most severe first), tie-broken by
    ``pattern_id`` for a reproducible order.

    ``kept_dirs`` is reordered by the exact same permutation, so the PR body,
    the per-finding layout table and the git-add list all agree on which
    finding is "first" in a multi-finding gate PR.
    """
    if not kept:
        return kept, kept_dirs
    paired = sorted(
        zip(kept, kept_dirs, strict=True),
        key=lambda item: _severity_sort_key(item[0][0]),
    )
    new_kept, new_dirs = zip(*paired, strict=True)
    return list(new_kept), list(new_dirs)


def sort_exploits_by_severity(exploits: list[ExploitRecord]) -> list[ExploitRecord]:
    """The same most-severe-first order as :func:`severity_sort_kept`, for a
    plain list of exploits (`scan`'s end-of-run findings)."""
    return sorted(exploits, key=_severity_sort_key)


def finding_block(
    exploit: ExploitRecord,
    report: ValidationReport | None = None,
    *,
    target: Any | None = None,
) -> list[str]:
    """Severity, impact and suggested-fix lines for one finding.

    The same facts the gate PR body opens with — reused here, not
    re-derived, so every surface that shows a finding states them the same
    way: `scan`'s end-of-run summary (one block per FOUND exploit, no
    ``report`` yet) and `validate`'s verdict panel (under a KEPT verdict
    only, with its ``report``). ``recommend()`` already degrades gracefully
    with ``report=None`` — see its own ``report is not None`` checks — so
    this never needs a special case for the scan-time call.

    The fix is always introduced as a *suggestion*: "Mylonite proves and
    gates the weakness; it does not patch your code" is the same disclaimer
    the PR body states, so neither surface ever reads as "Mylonite fixed
    this". ``render_markdown(rec)`` states what to implement (confidence,
    evidence, the tiered prescriptions); it never claims "your own
    safeguard stops it" either way — that claim is made only in the gate PR
    body's control-efficacy framing, gated there on a proven server-layer
    ``control_env``, and is not repeated here.
    """
    wc = weakness_class_for(exploit)
    from mylonite.gate.recommend import recommend, render_markdown

    rec = recommend(exploit, report, target=target)
    return [
        f"Severity: {severity_for_exploit(exploit)}",
        f"Impact: {impact_sentence(wc)}",
        "",
        "Suggested fix (Mylonite proves and gates the weakness; it does not patch your code):",
        "",
        render_markdown(rec).rstrip(),
    ]


def _own_seed_pattern_id(report: ValidationReport) -> str | None:
    """The bank seed this report's own test was generated for, if it can be
    told from the committed test's file name.

    Mirrors ``mylonite.report.render``'s ``_own_seed_id``: the generator
    names the test ``test_security_<slug(pattern_id)>.py``, so the seed whose
    slug matches ``report.test_filename`` is the one this test actually
    drives. Every other row in ``mutation_matrix`` was never run by this
    test — the differential attacks with the test's own seed only — so the
    kill matrix below renders those rows as "not run", not as a miss.
    """
    from mylonite.plugins._reference.reference_pytest_generator import _slugify

    filename = report.test_filename or ""
    for seed in report.mutation_matrix:
        if filename == f"test_security_{_slugify(seed.pattern_id)}.py":
            return str(seed.pattern_id)
    return None


#: Shown once, directly under the kill matrix, so a reviewer who has not read
#: the validation docs still knows a "not run" cell is not a missed catch.
_KILL_MATRIX_LEGEND = (
    "legend: ✓ = killed (fired on the vulnerable side, resisted on the guarded side) "
    "· ✗ = ran but not killed · - = not run by this test"
)


def _kill_matrix_lines(report: ValidationReport) -> list[str]:
    """The per-seed kill matrix row(s) plus its legend, for ``_evidence_lines``.

    When the report's own seed can be told from the test file name, every
    other bank seed is marked "not run" rather than given the same ``x`` a
    seed that actually ran and failed to discriminate would get — the
    differential drives one seed per test, so a whole-bank x/kill count was
    never a true count of what this test checked.
    """
    matrix = report.mutation_matrix
    if not matrix:
        return []
    killed = sum(1 for s in matrix if s.killed)
    own = _own_seed_pattern_id(report)
    if own is None:
        joined = ", ".join(
            f"{s.weakness}:{s.pattern_id} {'✓' if s.killed else '✗'}" for s in matrix
        )
        return [
            f"- **kill matrix** ({killed}/{len(matrix)}): {joined}",
            f"  - {_KILL_MATRIX_LEGEND}",
        ]
    not_run = sum(1 for s in matrix if s.pattern_id != own and not s.killed)
    cells: list[str] = []
    for s in matrix:
        name = f"{s.weakness}:{s.pattern_id}"
        if s.pattern_id == own:
            cells.append(f"{name} {'✓' if s.killed else '✗'}")
        elif s.killed:
            cells.append(f"{name} ✓")
        else:
            cells.append(f"{name} -")
    return [
        f"- **kill matrix** (this test's own seed; {not_run}/{len(matrix)} not run): "
        + ", ".join(cells),
        f"  - {_KILL_MATRIX_LEGEND}",
    ]


def _runs_and_rates_line(report: ValidationReport) -> str:
    """One plain sentence on the reproducibility evidence, for the reviewer
    checklist — the same counts ``_evidence_lines`` states, repeated here so
    the checklist is a self-contained reading, not a cross-reference."""
    repro = report.reproducibility
    if repro is None or not repro.iterations:
        return "no reproducibility evidence was recorded for this run."
    if repro.guard_resisted is not None:
        return (
            f"fired {repro.vuln_fired}/{repro.iterations} on the unguarded side, resisted "
            f"{repro.guard_resisted}/{repro.iterations} on the guarded side."
        )
    return f"reproduced {repro.vuln_fired}/{repro.iterations} against the real target."


def _proof_level_checklist_line(label: str, *, proven: bool, server_layer: bool) -> str:
    """What the verdict actually showed, worded so "your safeguard stops it"
    is only ever said when a real ``control_env`` was the guarded side."""
    if not proven:
        return f"{label} — not proven yet; do not rely on this gate as a fix."
    if server_layer:
        return (
            f"{label} — your own control (declared via `control_env`) was shown to stop the attack."
        )
    return f"{label} — a canonical stand-in control stopped the attack; your own implementation is not yet proven."


def _reviewer_checklist(
    report: ValidationReport,
    *,
    proven: bool,
    server_layer: bool,
    model: str | None,
    system_prompt: str | None,
) -> list[str]:
    """A short checklist: what a reviewer should confirm before merging
    this gate PR, not a claim Mylonite makes on their behalf."""
    label = verdict_label(report)
    prompt_line = (
        "the system prompt supplied to this run — confirm it matches your agent's real prompt."
        if system_prompt
        else (
            "Mylonite's generic default (no system prompt was supplied to this run) — "
            "confirm it matches your agent's real prompt."
        )
    )
    return [
        "Before merging, confirm each of these for your own app:",
        "",
        f"- [ ] **Proof level:** {_proof_level_checklist_line(label, proven=proven, server_layer=server_layer)}",
        f"- [ ] **Planner model:** `{model or 'not recorded'}` — confirm this is the model "
        "(or one no weaker than it) your production agent actually runs.",
        f"- [ ] **Prompt used:** {prompt_line}",
        f"- [ ] **Runs and rates:** {_runs_and_rates_line(report)}",
    ]


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
    # (#223), or other target-echoed content entirely (a tool result, an
    # error message the target raised -- e.g. calibration.py's
    # ``f"{recall.name!r} returned an error: {_quote(content)}"``). The PR
    # body is committed and sent to GitHub, so it first gets the same
    # ``redact()`` pass ``validation_report.json`` gets before it is
    # written, THEN ``code_span()`` (F9): a bare backtick, a Markdown
    # link/image, or an embedded newline in the target's own text would
    # otherwise render as live Markdown in the committed, GitHub-rendered PR
    # body, exactly as an unescaped tool name would.
    # A repeat-run leg resting on one run per build measured nothing, so it
    # reads "not measured", never pass or a check mark (see
    # _verdict.stability_measured). Enough runs render as before.
    unmeasured: set[str] = (
        set() if stability_measured(report) else {str(s) for s in STABILITY_STAGES}
    )

    def _result(o: Any) -> str:
        if str(o.stage) in unmeasured and o.passed and not o.report_only:
            return stability_not_measured(report)
        return "pass" if o.passed else "FAIL"

    rows = [
        f"- **{o.stage}**: {_result(o)} — {code_span(redact(o.detail))}" for o in report.outcomes
    ]
    # The differential-oracle evidence (PR2): the gate with live per-leg marks,
    # the fires/resists counts, and the per-seed kill matrix — so the PR shows
    # WHY this test is trustworthy, not just that it was kept.
    # str() the stage key so indexing with gating_legs (list[str]) type-checks
    # against the Literal-keyed outcome stages.
    legs_by_stage = {str(o.stage): o for o in report.outcomes}
    if report.gating_legs:
        rendered = " AND ".join(
            f"{leg} (not measured)"
            if leg in unmeasured and legs_by_stage[leg].passed
            else f"{leg} {'✓' if legs_by_stage[leg].passed else '✗'}"
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
    # The seed kill matrix: which of the bank's seeds this test actually
    # discriminated, with the ones it never ran named as such (see
    # _kill_matrix_lines) rather than lumped in with a genuine miss.
    rows.extend(_kill_matrix_lines(report))
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

    ``guarded_is_server_layer``: a caller with direct access to
    ``TwinPlan.guarded_is_server_layer`` may pass it explicitly; otherwise it
    is derived from ``report.notes``'s ``[guarded-twin=...]`` marker (see
    :func:`_guarded_is_server_layer`). Conflating this with ``is_control``
    would caption every control-efficacy finding "(proxy)" even when the
    differential toggled the target's REAL server-side control (a declared
    ``control_env``), mislabelling the strongest possible result as the
    weakest — so "your safeguard stops it" is said only when this is true.

    ``target``: an optional ``mylonite.gate.recommend.TargetContext``. Typed
    ``Any`` here rather than imported at module scope to avoid a needless
    import when a caller has none to pass — ``recommend()`` handles
    ``target=None`` gracefully by design (degraded evidence, lower
    confidence, never a crash).

    ``gate_dir``: the directory this run actually wrote to (``gate``'s
    resolved ``--out``), so the "How this is gated" section names the real
    path instead of a hardcoded ``.mylonite/gate/`` that drifted from a
    non-default ``--out``. Defaults to that literal when omitted.

    The fix section always renders :func:`mylonite.gate.recommend.render_markdown`'s
    target-specific, evidence-anchored recommendation, for every target
    including a reference one. The class-level ``mitigations/{wc}.md``
    background prose (:func:`_snippet`, now ``mylonite.mitigations.snippet``)
    stays alongside it — it is still true and still useful context
    regardless of target. Neither one is a patch Mylonite applied: the
    heading says "suggested"/"recommended", never "fixed".

    Every finding below is laid out in one order — **verdict, impact, fix,
    proof** — so the facts a reviewer needs most (is this real, what does it
    cost, how do I close it, what showed it) read top to bottom instead of
    being scattered across the PR body by finding shape. A severity line and
    a one-sentence, class-level impact statement sit right under the
    verdict; a reviewer checklist and the "how this is gated" explanation
    follow the proof, as supporting detail rather than the headline.
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
    # Shown once, uniformly, for every verdict — not only when unproven — so
    # the PR body always opens on a verdict line, the first of the four.
    label = verdict_label(report)
    proven = label == KEPT
    verdict_line = f"**Verdict: {label}:** {verdict_reason(report)}"
    severity = severity_for_exploit(exploit)
    impact = impact_sentence(wc)

    # ``claim``/``layer_caveat`` are set only for a PROVEN control-efficacy
    # finding; they belong in the proof section below (what the differential
    # actually showed), not in the opening verdict/impact block.
    claim = ""
    layer_caveat = ""

    if is_control and not proven:
        repro = report.reproducibility
        if repro is not None and repro.iterations:
            stat = (
                f"Attack `{exploit.pattern_id}` fired {repro.vuln_fired}/{repro.iterations} "
                f"against your app; control **{control}** was applied on the guarded side."
            )
        else:
            stat = f"Control **{control}** was tested for `{exploit.pattern_id}`."
        heading = "## Control efficacy not proven"
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
        heading = "## Control efficacy verified"
    else:
        stat = (
            f"A validated weakness (`{exploit.pattern_id}`) against `{exploit.target_id}`."
            if proven
            else f"A weakness (`{exploit.pattern_id}`) against `{exploit.target_id}`."
        )
        heading = "## What Mylonite found"

    sections = [
        heading,
        verdict_line,
        "",
        f"**Severity:** {severity}",
        "",
        f"**Impact:** {impact}",
        "",
        stat,
        "",
        f"**Compliance:** {_compliance_line(exploit)}",
        f"**Attack tier:** {exploit.payload.metadata.get('attack_tier', 'static')}",
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

    # Proof: what the run actually measured, fourth and last of the four —
    # the control-efficacy claim/caveat (only when proven) plus the full
    # evidence trail, including the per-seed kill matrix and its legend.
    sections += ["", "## Proof"]
    if is_control and proven:
        sections += [claim, "", layer_caveat, ""]
    sections += ["**Validation evidence:**", _evidence_lines(report)]

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

    checklist = _reviewer_checklist(
        report,
        proven=proven,
        server_layer=server_layer,
        model=model,
        system_prompt=system_prompt,
    )
    sections += ["", "## Reviewer checklist", *checklist]
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
