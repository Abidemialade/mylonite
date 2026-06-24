"""Finding-severity rule, shared by the SARIF and JSON-bundle exports.

This is the one piece of the former HTML dashboard worth keeping: a single,
deterministic severity derivation so every machine-readable export (SARIF for
GitHub code scanning, the JSON finding bundle) agrees on a finding's severity.
"""

from __future__ import annotations


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
