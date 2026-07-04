"""Machine-readable report exports (SARIF + JSON bundle).

The terminal/trust-panel rendering lives in ``mylonite.scan.artefacts`` and the
``mylonite report`` command. This package adds the two machine-readable exports
teams consume — SARIF 2.1.0 for GitHub code scanning and a self-contained JSON
finding bundle for dashboards / SIEM / bots — sharing one ``severity_for`` rule.
"""

from mylonite.report.bundle import to_bundle
from mylonite.report.sarif import to_sarif
from mylonite.report.severity import severity_for

__all__ = [
    "severity_for",
    "to_bundle",
    "to_sarif",
]
