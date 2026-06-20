"""Stakeholder-facing report rendering (HTML dashboards).

The terminal/trust-panel rendering lives in ``mylonite.scan.artefacts`` and the
``mylonite report`` command; this package adds a structured, self-contained HTML
dashboard (exec summary, per-finding severity + compliance, collapsible
evidence) that is screenshot-friendly for CI and shareable with stakeholders.
"""

from mylonite.report.bundle import to_bundle
from mylonite.report.html import render_scan_html, render_validation_html, severity_for
from mylonite.report.sarif import to_sarif

__all__ = [
    "render_scan_html",
    "render_validation_html",
    "severity_for",
    "to_bundle",
    "to_sarif",
]
