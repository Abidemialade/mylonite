"""PR-body builder for the gating PR (deterministic + opt-in LLM enrichment)."""

from __future__ import annotations

import importlib.resources as _ir
from collections.abc import Callable
from typing import Any

from mylonite.contracts._types import ExploitRecord, ValidationReport
from mylonite.scan.seeds import SEED_CATALOGUE

_PATTERN_TO_WEAKNESS = {s.pattern_id: s.weakness for s in SEED_CATALOGUE}

# Fallback when the pattern_id isn't a bundled seed: infer the class from the
# strongest compliance signal. ASI01 goal-hijack / ASI06 memory-poison ride with
# indirect injection (W2); ASI02 tool-misuse with description smuggling (W1);
# LLM06 excessive agency with the egress/unconfirmed-action families (W3/W4).
_ASI_TO_WEAKNESS = {"ASI01": "W2", "ASI06": "W2", "ASI02": "W1", "ASI05": "W3"}
_LLM_TO_WEAKNESS = {"LLM05": "W2", "LLM06": "W4"}

_GUARDED_TWIN = "reference_targets/mcp_kitchen_sink/src/mcp_kitchen_sink/server_guarded.py"


def weakness_class_for(exploit: ExploitRecord) -> str:
    """Return the W1-W4 class for an exploit, or 'generic' if unknown.

    Prefers the bundled seed catalogue (authoritative); falls back to the
    exploit's compliance tags; finally 'generic'.
    """
    if exploit.pattern_id in _PATTERN_TO_WEAKNESS:
        return _PATTERN_TO_WEAKNESS[exploit.pattern_id]
    for asi in exploit.compliance.owasp_asi:
        if asi in _ASI_TO_WEAKNESS:
            return _ASI_TO_WEAKNESS[asi]
    for llm in exploit.compliance.owasp_llm:
        if llm in _LLM_TO_WEAKNESS:
            return _LLM_TO_WEAKNESS[llm]
    return "generic"


def _snippet(weakness_class: str) -> str:
    base = _ir.files("mylonite.gate") / "mitigations"
    return (base / f"{weakness_class}.md").read_text(encoding="utf-8").strip()


def _fix_block(weakness_class: str) -> str:
    """The concrete, reviewable fix (a fenced diff) for a weakness class (R3).

    Parallel to ``_snippet`` (prose rationale) but actionable: it renders the
    server-side change that implements the boundary control the differential
    proved load-bearing, so the PR carries "here's the fix we proved works", not
    a guess. Class-keyed (W1-W4/generic) — the control name rides in the prose.
    """
    base = _ir.files("mylonite.gate") / "fixes"
    return (base / f"{weakness_class}.md").read_text(encoding="utf-8").strip()


def _evidence_lines(report: ValidationReport) -> str:
    rows = [
        f"- **{o.stage}**: {'pass' if o.passed else 'FAIL'} — {o.detail}" for o in report.outcomes
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
        verdict = "KEPT" if report.kept else "REJECTED"
        rows.append(f"- **gate**: kept = {rendered} => **{verdict}**")
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
    completion_fn: Callable[..., Any] | None = None,
) -> str:
    """Assemble the gating PR description (deterministic; opt-in LLM enrichment)."""
    wc = weakness_class_for(exploit)
    is_reference = exploit.target_id.startswith("reference:")
    control = exploit.payload.metadata.get("synthetic_control") or ""
    is_control = bool(control)

    if is_control:
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
        head = [
            "## Control efficacy verified",
            stat,
            "",
            "This proves the **safeguard** - not the model - carries the security.",
            "",
            "> **Boundary-validated control (proxy).** Mylonite enforced this control at the "
            "adapter boundary, not in your server. Implement it server-side for a production "
            "fix (see the mitigation below), then re-point the committed test at your real "
            "implementation.",
            "",
            f"**Compliance:** {_compliance_line(exploit)}",
            f"**Attack tier:** {exploit.payload.metadata.get('attack_tier', 'static')}",
            "",
            "**Validation evidence:**",
            _evidence_lines(report),
        ]
    else:
        head = [
            "## What Mylonite found",
            f"A validated weakness (`{exploit.pattern_id}`) against `{exploit.target_id}`.",
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
        _snippet(wc),
        "",
        (
            "**Proven fix** — implement the control the differential verified load-bearing, "
            "server-side, then re-point the committed test at it:"
            if is_control
            else "**Recommended fix** — implement this control server-side, then re-point the "
            "committed test at your implementation:"
        ),
        "",
        _fix_block(wc),
    ]
    if is_reference:
        sections += [
            "",
            f"See the guarded reference twin for a concrete fix: `{_GUARDED_TWIN}`.",
        ]
    if llm_enrich:
        extra = _llm_suggestion(exploit, completion_fn=completion_fn)
        if extra:
            sections += [
                "",
                "> **Unverified LLM suggestion** (not validated by the oracle — review before applying):",
                "> " + extra.replace("\n", "\n> "),
            ]
    if is_control:
        gating_desc = (
            f"`{report.test_filename}` (under `.mylonite/gate/`) re-drives the attack with and "
            f"without control **{control}** and asserts it fires on the raw target but is "
            "resisted with the control applied. The committed per-PR workflow runs it on every "
            "PR; if the control stops carrying the security, the check fails."
        )
    else:
        gating_desc = (
            f"`{report.test_filename}` (under `.mylonite/gate/`) re-drives this attack and "
            "asserts your agent resists it. The committed per-PR workflow runs it on every PR; "
            "a regression fails the check."
        )
    sections += ["", "## How this is gated", gating_desc]
    return "\n".join(sections) + "\n"


def _llm_suggestion(
    exploit: ExploitRecord, *, completion_fn: Callable[..., Any] | None = None
) -> str | None:
    """A short, app-specific remediation idea. Best-effort; labelled unverified.

    Uses the injected ``completion_fn`` when given (the offline test seam);
    otherwise routes through litellm. Any failure returns ``None`` — enrichment
    must never break body assembly.
    """
    prompt = (
        "You are a security engineer. In 2-3 sentences, suggest a concrete, "
        "human-applied mitigation for this AI-agent weakness. Do not include "
        "code unless trivial. Weakness pattern: "
        f"{exploit.pattern_id}; reason: {exploit.success_reason}."
    )
    messages = [{"role": "user", "content": prompt}]
    try:
        if completion_fn is not None:
            resp = completion_fn(model="enrich", messages=messages)
        else:  # pragma: no cover - live path
            import litellm

            resp = litellm.completion(model="claude-haiku-4-5-20251001", messages=messages)
        text = resp.choices[0].message.content
        return text.strip() if text else None
    except Exception:  # broad catch intentional — enrichment must never break body assembly
        return None
