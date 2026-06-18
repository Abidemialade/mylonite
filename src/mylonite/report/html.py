"""Self-contained HTML report renderer (no JS, no CDN, no web fonts).

Renders a ``ScanReport``+exploits or a ``ValidationReport``+exploit into a single
HTML page with an executive summary, per-finding severity badges, compliance
tags, and collapsible raw evidence (native ``<details>`` — interactivity with
zero JavaScript). Everything is inline so the page screenshots cleanly in CI and
needs no network: there are no external assets or URLs of any kind.
"""

from __future__ import annotations

from html import escape
from typing import Any

# System font stack only — no web fonts (keeps the page fully self-contained).
_FONT = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif"
_MONO = "ui-monospace, SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace"

# Severity palette (inline; no external stylesheet).
_SEV_COLORS = {
    "High": ("#b3261e", "#fdecea"),
    "Medium": ("#9a6700", "#fff8e1"),
    "Low": ("#1a7f37", "#e9f7ec"),
}

_STYLE = f"""
  :root {{ color-scheme: light dark; }}
  body {{ font-family: {_FONT}; margin: 0; padding: 0 1.5rem 3rem;
          color: #1a1a1a; background: #fafafa; line-height: 1.5; }}
  header.exec {{ padding: 1.5rem 0 1rem; border-bottom: 2px solid #e3e3e3; }}
  header.exec h1 {{ margin: 0 0 .25rem; font-size: 1.5rem; }}
  .meta {{ color: #555; font-size: .85rem; font-family: {_MONO}; }}
  .verdict {{ display: inline-block; margin-top: .75rem; padding: .4rem .8rem;
              border-radius: 6px; font-weight: 600; }}
  .verdict.pass {{ background: #e9f7ec; color: #1a7f37; }}
  .verdict.fail {{ background: #fdecea; color: #b3261e; }}
  .trust {{ color: #444; max-width: 60ch; }}
  section.findings {{ margin-top: 1.5rem; }}
  h2 {{ font-size: 1.05rem; margin: 1.5rem 0 .5rem; }}
  article.finding {{ background: #fff; border: 1px solid #e3e3e3; border-left-width: 5px;
                     border-radius: 8px; padding: .85rem 1rem; margin: .75rem 0; }}
  .fhead {{ display: flex; align-items: center; gap: .6rem; flex-wrap: wrap; }}
  .fhead b {{ font-size: 1rem; }}
  .weakness {{ font-family: {_MONO}; font-size: .8rem; color: #555;
               background: #f0f0f0; padding: .1rem .4rem; border-radius: 4px; }}
  .badge {{ font-size: .75rem; font-weight: 700; padding: .15rem .5rem;
            border-radius: 999px; text-transform: uppercase; letter-spacing: .03em; }}
  .compliance {{ margin: .5rem 0; font-size: .8rem; color: #444; font-family: {_MONO}; }}
  .compliance span {{ background: #eef2ff; color: #3949ab; padding: .1rem .4rem;
                      border-radius: 4px; margin-right: .3rem; display: inline-block; }}
  .reason {{ margin: .4rem 0; }}
  details {{ margin-top: .5rem; }}
  summary {{ cursor: pointer; font-size: .85rem; color: #3949ab; }}
  pre {{ background: #1e1e1e; color: #e6e6e6; padding: .75rem; border-radius: 6px;
         overflow-x: auto; font-family: {_MONO}; font-size: .8rem; white-space: pre-wrap;
         word-break: break-word; }}
  table.kv {{ border-collapse: collapse; font-size: .85rem; margin: .5rem 0; }}
  table.kv td {{ padding: .2rem .8rem .2rem 0; vertical-align: top; }}
  table.kv td.k {{ color: #555; font-family: {_MONO}; white-space: nowrap; }}
  footer {{ margin-top: 2.5rem; padding-top: 1rem; border-top: 1px solid #e3e3e3;
            color: #888; font-size: .8rem; }}
"""


def severity_for(
    weakness: str, effect_confirmed: str = "unprobed", *, situational: bool = False
) -> str:
    """Derive a finding's severity.

    * **High** — a consequential action materialized (effect probe confirmed) or
      the weakness is an exfil / egress / excessive-agency class that landed
      (W2/W3/W4 as a finding).
    * **Medium** — the weakness fires but no damaging effect landed (e.g. W1
      tool-description smuggling).
    * **Low** — a situational finding that does not reproduce on a cold run.
    """
    if situational:
        return "Low"
    if effect_confirmed == "true":
        return "High"
    if weakness in {"W2", "W3", "W4"}:
        return "High"
    if weakness == "W1":
        return "Medium"
    return "Medium"


def _badge(severity: str) -> str:
    fg, bg = _SEV_COLORS.get(severity, ("#444", "#eee"))
    return f'<span class="badge" style="color:{fg};background:{bg}">{escape(severity)}</span>'


def _compliance_row(compliance: Any) -> str:
    chips: list[str] = []
    for label, ids in (
        ("OWASP-LLM", getattr(compliance, "owasp_llm", []) or []),
        ("OWASP-ASI", getattr(compliance, "owasp_asi", []) or []),
        ("ATLAS", getattr(compliance, "mitre_atlas", []) or []),
        ("NIST", getattr(compliance, "nist_ai_rmf", []) or []),
    ):
        for tag in ids:
            chips.append(f"<span>{escape(label)} {escape(str(tag))}</span>")
    return f'<div class="compliance">{"".join(chips) or "(no compliance tags)"}</div>'


def _page(title: str, body: str) -> str:
    return (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{escape(title)}</title><style>{_STYLE}</style></head><body>"
        f"{body}"
        "<footer>Generated by Mylonite — self-contained (no scripts, fonts, or "
        "network assets). Re-generate with <code>mylonite report</code>.</footer>"
        "</body></html>\n"
    )


def _finding_card(exploit: Any) -> str:
    meta = getattr(exploit.payload, "metadata", {}) or {}
    weakness = str(meta.get("weakness", "") or "")
    effect = str(getattr(exploit.response, "metadata", {}).get("effect_confirmed", "unprobed"))
    sev = severity_for(weakness, effect)
    tool_calls = list(getattr(exploit.response, "tool_calls", []) or [])
    tier = str(meta.get("attack_tier", "") or "")
    head = (
        '<div class="fhead">'
        f"{_badge(sev)}"
        f"<b>{escape(exploit.pattern_id)}</b>"
        + (f'<span class="weakness">{escape(weakness)}</span>' if weakness else "")
        + (f'<span class="weakness">{escape(tier)}</span>' if tier else "")
        + "</div>"
    )
    evidence = escape(
        "tool calls: " + (", ".join(tool_calls) or "(none)") + "\n\n"
        "final response:\n" + str(getattr(exploit.response, "raw_response", ""))[:1200]
    )
    return (
        f'<article class="finding" style="border-left-color:{_SEV_COLORS.get(sev, ("#444",))[0]}">'
        f"{head}"
        f"{_compliance_row(exploit.compliance)}"
        f'<div class="reason">{escape(str(exploit.success_reason))}</div>'
        f"<details><summary>Evidence (tool trace + response)</summary><pre>{evidence}</pre></details>"
        "</article>"
    )


def render_scan_html(report: Any, exploits: list[Any]) -> str:
    """Render a scan report + its exploits as a self-contained HTML dashboard."""
    n = len(exploits)
    verdict_cls = "fail" if n else "pass"
    verdict_txt = f"{n} finding{'s' if n != 1 else ''}" if n else "No findings — clean"
    meta = (
        f"Target: {escape(report.target_id)} · Model: {escape(report.model)} · "
        f"Provider: {escape(report.provider)} · {escape(f'{report.elapsed_seconds:.1f}s')} · "
        f"mylonite {escape(getattr(report, 'mylonite_version', '') or '')}"
    )
    aborted = getattr(report, "aborted", None)
    trust = (
        "Every finding below fired on the target and is backed by its tool trace. "
        "A finding is never &ldquo;the agent did something&rdquo; — only a weakness the "
        "scan reproduced."
    )
    body = [
        '<header class="exec"><h1>Mylonite security report</h1>',
        f'<div class="meta">{meta}</div>',
        f'<div class="verdict {verdict_cls}">{escape(verdict_txt)}</div>',
        f'<p class="trust">{trust}</p>',
    ]
    if aborted:
        body.append(
            f'<div class="verdict fail">scan aborted: {escape(str(aborted))} '
            "(results are partial)</div>"
        )
    body.append("</header>")
    if exploits:
        order = {"High": 0, "Medium": 1, "Low": 2}
        cards = sorted(
            exploits,
            key=lambda e: order.get(
                severity_for(
                    str((getattr(e.payload, "metadata", {}) or {}).get("weakness", "")),
                    str(getattr(e.response, "metadata", {}).get("effect_confirmed", "unprobed")),
                ),
                1,
            ),
        )
        body.append('<section class="findings"><h2>Findings</h2>')
        body.extend(_finding_card(e) for e in cards)
        body.append("</section>")
    else:
        body.append(
            '<section class="findings"><p>The scan completed with no findings. '
            "For a guarded/clean target this is the expected PASS.</p></section>"
        )
    return _page(f"Mylonite report — {report.target_id}", "".join(body))


def render_validation_html(report: Any, exploit: Any | None = None) -> str:
    """Render a validation report (the differential-oracle verdict) as HTML."""
    kept = bool(getattr(report, "kept", False))
    verdict_cls = "pass" if kept else "fail"
    verdict_txt = "KEPT — test gates CI" if kept else "REJECTED — not committed"
    repro = getattr(report, "reproducibility", None)
    rows: list[str] = [
        f'<tr><td class="k">test</td><td>{escape(str(getattr(report, "test_filename", "")))}</td></tr>',
    ]
    if getattr(report, "gating_formula", None):
        rows.append(
            f'<tr><td class="k">gate</td><td>{escape(str(report.gating_formula))}</td></tr>'
        )
    if repro is not None:
        iters = getattr(repro, "iterations", None)
        vf = getattr(repro, "vuln_fired", None)
        gr = getattr(repro, "guard_resisted", None)
        rows.append(
            f'<tr><td class="k">reproducibility</td><td>vulnerable fired {escape(str(vf))}/'
            f"{escape(str(iters))} · guarded resisted {escape(str(gr))}/{escape(str(iters))}</td></tr>"
        )
    if getattr(report, "mutation_score", None) is not None:
        rows.append(
            f'<tr><td class="k">metamorphic</td><td>{escape(str(report.mutation_score))}</td></tr>'
        )
    if getattr(report, "notes", None):
        rows.append(f'<tr><td class="k">notes</td><td>{escape(str(report.notes))}</td></tr>')
    body = [
        '<header class="exec"><h1>Mylonite validation report</h1>',
        f'<div class="verdict {verdict_cls}">{escape(verdict_txt)}</div>',
        f'<table class="kv">{"".join(rows)}</table>',
        "</header>",
    ]
    if exploit is not None:
        body.append('<section class="findings"><h2>Validated finding</h2>')
        body.append(_finding_card(exploit))
        body.append("</section>")
    return _page(f"Mylonite validation — {getattr(report, 'test_filename', '')}", "".join(body))
