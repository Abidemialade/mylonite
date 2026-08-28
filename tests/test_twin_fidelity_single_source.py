"""The guarded-twin claim has exactly one definition, and it stays that way.

Mylonite's pitch is that it does not overclaim, so the one place it *did* was the
cheapest thing an adversarial reader could lead with. 0.8.5 made every verdict
surface distinguish a server-layer twin (the operator's own control, toggled) from
a synthetic boundary twin (Mylonite's canonical shim) — and missed two:

* ``report/sarif.py`` printed the server-layer claim for any differential. It is
  the artefact uploaded to GitHub code scanning, so it is the worst one to miss.
* ``plugins/_mcp/twins.py``'s run banner made the strong claim on the SYNTHETIC
  path and withheld it on the server-layer path — exactly inverted.

Both were possible because the marker literal and the claim sentence were
re-spelled in five modules. They now live in ``mylonite._twin_fidelity``; these
tests fail if a literal is reintroduced, or if a surface renders a verdict without
resolving the fidelity first.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

from mylonite._twin_fidelity import (
    MARKER_SERVER_LAYER,
    MARKER_SYNTHETIC,
    PROOF_CLAIM_BOUNDARY,
    PROOF_CLAIM_SERVER,
    format_marker,
    guarded_twin_layer,
    proof_claim,
)

_SRC = Path(__file__).resolve().parent.parent / "src" / "mylonite"

#: The affirmative strong claim, in any of the punctuations the codebase has used
#: ("safeguard, not the model, carries" / "**safeguard** - not the model - carries").
_STRONG_CLAIM = re.compile(r"not the model\s*[-,—]?\s*carries the security")

#: The marker body, however it is spelled or bracketed.
_MARKER_LITERAL = re.compile(r"guarded-twin\s*=")

#: Modules that render a per-finding verdict. `cli.py` is exempt: its two matches
#: are `--fast` help text and a code comment describing what the differential leg
#: is FOR in general ("skipping it means the kept test no longer proves ..."), not
#: a claim about any particular result.
_VERDICT_DIRS = ("report", "gate", "plugins")


def _rendered_strings(path: Path) -> list[str]:
    """Every string literal in ``path`` that could reach output.

    Comments and docstrings are excluded deliberately: prose *explaining* the
    fidelity mechanism is exactly what this module wants people to write, and
    several such comments are load-bearing documentation. Only a literal that can
    be rendered is an overclaim risk.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    docstrings = {
        id(node.body[0].value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Module | ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef)
        and node.body
        and isinstance(node.body[0], ast.Expr)
        and isinstance(node.body[0].value, ast.Constant)
        and isinstance(node.body[0].value.value, str)
    }
    return [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in docstrings
    ]


def test_no_verdict_surface_spells_the_strong_claim_itself() -> None:
    offenders = [
        str(p.relative_to(_SRC))
        for d in _VERDICT_DIRS
        for p in (_SRC / d).rglob("*.py")
        if any(_STRONG_CLAIM.search(s) for s in _rendered_strings(p))
    ]
    assert not offenders, (
        "these modules spell the server-layer claim inline instead of importing "
        f"PROOF_CLAIM_SERVER from mylonite._twin_fidelity: {offenders}. A surface "
        "that spells it cannot narrow it for a synthetic boundary twin."
    )


def test_no_module_spells_the_marker_literal_itself() -> None:
    offenders = [
        str(p.relative_to(_SRC))
        for p in _SRC.rglob("*.py")
        if p.name != "_twin_fidelity.py"
        and any(_MARKER_LITERAL.search(s) for s in _rendered_strings(p))
    ]
    assert not offenders, (
        "these modules spell the [guarded-twin=...] marker inline instead of using "
        f"format_marker / MARKER_* from mylonite._twin_fidelity: {offenders}"
    )


def test_marker_round_trips_through_the_resolver() -> None:
    """What the validator writes is what every reader resolves."""
    assert guarded_twin_layer(_FakeReport(format_marker(server_layer=True))) == "server"
    assert guarded_twin_layer(_FakeReport(format_marker(server_layer=False))) == "boundary"
    assert MARKER_SERVER_LAYER in format_marker(server_layer=True)
    assert MARKER_SYNTHETIC in format_marker(server_layer=False)


def test_an_unresolvable_report_under_claims() -> None:
    """The failure mode of a missing/None marker must be an under-claim.

    Every caller inherits this default, so it is the single decision that stops a
    new surface from over-claiming by omission.
    """
    assert guarded_twin_layer(None) == "boundary"
    assert guarded_twin_layer(_FakeReport(None)) == "boundary"
    assert guarded_twin_layer(_FakeReport("no marker here")) == "boundary"
    # An explicit flag still wins over the notes.
    assert guarded_twin_layer(_FakeReport(format_marker(server_layer=False)), True) == "server"


def test_the_two_claims_are_actually_different() -> None:
    assert proof_claim("server") == PROOF_CLAIM_SERVER
    assert proof_claim("boundary") == PROOF_CLAIM_BOUNDARY
    # The boundary claim must not contain the strong claim as a substring, or
    # narrowing it would be cosmetic.
    assert not _STRONG_CLAIM.search(PROOF_CLAIM_BOUNDARY)
    # ...and it must name what was NOT measured, which is the part a reader would
    # otherwise assume in Mylonite's favour.
    assert "does not establish" in PROOF_CLAIM_BOUNDARY


class _FakeReport:
    def __init__(self, notes: str | None) -> None:
        self.notes = notes


def _finding() -> tuple[Any, Any]:
    from mylonite.contracts._types import (
        AdapterResponse,
        ComplianceTags,
        ExploitRecord,
        Payload,
        ReproducibilityEvidence,
        ValidationReport,
    )

    pid = "finding-w2"
    exploit = ExploitRecord(
        target_id="mcp:myapp",
        pattern_id=pid,
        payload=Payload(
            pattern_id=pid,
            channel="tool-result",
            body="x",
            # `synthetic_control` is what puts build_pr_body on its control-efficacy
            # branch — the branch that carries the claim under test.
            metadata={"weakness": "W2", "synthetic_control": "W2"},
        ),
        response=AdapterResponse(
            payload_pattern_id=pid,
            raw_response="the agent followed the injection",
            tool_calls=["read_note", "send_email"],
            metadata={"effect_confirmed": "true"},
        ),
        success_reason="W2 weakness reproduced on the target",
        compliance=ComplianceTags(owasp_llm=["LLM01"]),
    )

    def report(server_layer: bool) -> Any:
        return ValidationReport(
            test_filename="test_security_finding.py",
            kept=True,
            notes=f"custom target: reproduced 5/5. {format_marker(server_layer=server_layer)}",
            reproducibility=ReproducibilityEvidence(
                iterations=5, vuln_fired=5, guard_resisted=5, guard_fired=0, rate_gap=1.0
            ),
        )

    return exploit, report


def _rendered_surfaces(exploit: Any, report: Any) -> dict[str, str]:
    """Every surface that renders a KEPT verdict to a human or a machine."""
    import json

    from mylonite.gate.mitigation import build_pr_body
    from mylonite.report.bundle import to_bundle
    from mylonite.report.sarif import to_sarif

    return {
        "sarif": json.dumps(to_sarif([(exploit, report)])),
        "bundle": json.dumps(to_bundle([(exploit, report)])),
        "pr_body": build_pr_body(exploit, report),
    }


def test_every_verdict_surface_narrows_the_claim_on_a_synthetic_twin() -> None:
    """The behavioural half: a synthetic-twin PASS must not read as a server-layer one.

    Parameterised over the surfaces rather than asserted once in SARIF, because the
    original bug was precisely that one surface drifted from the other three.
    """
    exploit, report = _finding()
    for name, text in _rendered_surfaces(exploit, report(False)).items():
        assert not _STRONG_CLAIM.search(text), f"{name} over-claims on a synthetic boundary twin"


def test_every_verdict_surface_still_makes_the_earned_claim() -> None:
    """The other half: narrowing must not have silently disarmed the strong claim
    where it IS earned. A test that only checks the negative passes trivially if a
    surface stops making any claim at all."""
    exploit, report = _finding()
    surfaces = _rendered_surfaces(exploit, report(True))
    assert _STRONG_CLAIM.search(surfaces["sarif"]), "sarif dropped the earned claim"
    assert _STRONG_CLAIM.search(surfaces["pr_body"]), "pr_body dropped the earned claim"
