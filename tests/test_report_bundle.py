"""R5: machine-readable JSON finding bundle (dashboards / SIEM / bots)."""

from __future__ import annotations

import json
from typing import Any


def _exploit(
    weakness: str, *, effect: str = "unprobed", metadata: dict[str, str] | None = None
) -> Any:
    from mylonite.contracts._types import AdapterResponse, ComplianceTags, ExploitRecord, Payload

    pid = f"finding-{weakness.lower()}"
    md = {"weakness": weakness}
    md.update(metadata or {})
    return ExploitRecord(
        target_id="mcp:myapp",
        pattern_id=pid,
        payload=Payload(pattern_id=pid, channel="tool-result", body="x", metadata=md),
        response=AdapterResponse(
            payload_pattern_id=pid,
            raw_response="the agent followed the injection",
            tool_calls=["read_note", "send_email"],
            metadata={"effect_confirmed": effect},
        ),
        success_reason=f"{weakness} weakness reproduced on the target",
        compliance=ComplianceTags(owasp_llm=["LLM01"], nist_ai_rmf=["MEASURE-2.7"]),
    )


def _proven_outcomes() -> list[Any]:
    """A passing build and differential leg: what a KEPT label needs beyond ``kept``."""
    from mylonite.contracts._types import ValidationOutcome

    return [
        ValidationOutcome(stage="build", passed=True, detail="built"),
        ValidationOutcome(stage="differential", passed=True, detail="discriminates"),
    ]


def _report(*, kept: bool = True) -> Any:
    from mylonite.contracts._types import ReproducibilityEvidence, ValidationReport

    return ValidationReport(
        test_filename="test_security_finding.py",
        kept=kept,
        outcomes=_proven_outcomes() if kept else [],
        reproducibility=ReproducibilityEvidence(iterations=5, vuln_fired=5, guard_resisted=5),
    )


def test_bundle_structure_and_reuses_finding_data() -> None:
    from mylonite.report.bundle import to_bundle

    bundle = to_bundle([(_exploit("W2", effect="true"), _report())])
    assert bundle["schema_version"]
    assert bundle["tool"]["name"] == "Mylonite" and bundle["tool"]["version"]
    f = bundle["findings"][0]
    assert f["pattern_id"] == "finding-w2"
    assert f["target_id"] == "mcp:myapp"
    assert f["weakness_class"] == "W2"
    assert f["severity"] == "High"  # W2 + confirmed effect
    # compliance reused verbatim
    assert "LLM01" in f["compliance"]["owasp_llm"]
    assert "MEASURE-2.7" in f["compliance"]["nist_ai_rmf"]
    # localization (R4) — the implicated tool/field
    assert f["localization"]["tool"] == "read_note"
    assert f["localization"]["kind"] == "data"
    # differential proof (R2)
    assert f["proof"]["vuln_fired"] == 5 and f["proof"]["iterations"] == 5
    assert f["proof"]["kept"] is True
    json.dumps(bundle)  # fully serialisable


def test_bundle_carries_proven_control_and_attack_shape() -> None:
    from mylonite.report.bundle import to_bundle

    ex = _exploit("W2", metadata={"synthetic_control": "W2", "attack_shape": "static"})
    f = to_bundle([(ex, _report())])["findings"][0]
    assert f["proven_control"] == "W2"
    assert f["attack_shape"] == "static"


def test_bundle_without_report_has_null_proof() -> None:
    from mylonite.report.bundle import to_bundle

    f = to_bundle([(_exploit("W1"), None)])["findings"][0]
    assert f["proof"] is None
    assert f["proven_control"] is None
    assert f["attack_shape"] == "static"  # default when unstamped


def test_bundle_recommendation_absent_without_a_target() -> None:
    """PR6: additive — every existing (target-less) caller keeps getting
    recommendation: null, not a missing key that would break strict parsers."""
    from mylonite.report.bundle import to_bundle

    f = to_bundle([(_exploit("W3"), _report())])["findings"][0]
    assert f["recommendation"] is None


def test_bundle_recommendation_present_with_a_target() -> None:
    """The bundle's recommendation is the SAME shape build_pr_body renders —
    both go through recommend.to_dict, so they cannot describe one finding
    two different ways."""
    from mylonite.gate.recommend import TargetContext, recommend, to_dict
    from mylonite.report.bundle import to_bundle

    ex = _exploit("W2")
    report = _report()
    target = TargetContext(target_id="mcp:myapp")
    f = to_bundle([(ex, report)], target=target)["findings"][0]
    assert f["recommendation"] == to_dict(recommend(ex, report, target=target))
    json.dumps(f)  # still fully serialisable with the recommendation present


def test_bundle_schema_version_tracks_additive_keys() -> None:
    """1.1 added "recommendation"; 1.2 added "guarded_twin_layer" and "proof.claim";
    1.3 added "proof_level"; 1.4 added "proof.verdict" and "proof.status"."""
    from mylonite.report.bundle import SCHEMA_VERSION, to_bundle

    assert SCHEMA_VERSION == "1.4"
    assert to_bundle([])["schema_version"] == "1.4"


def _fidelity_report(
    *,
    server_layer: bool,
    guard_resisted: int | None = 5,
    kept: bool = True,
    vuln_fired: int = 5,
    proven: bool = True,
) -> Any:
    from mylonite._twin_fidelity import format_marker
    from mylonite.contracts._types import ReproducibilityEvidence, ValidationReport

    return ValidationReport(
        test_filename="test_security_finding.py",
        kept=kept,
        outcomes=_proven_outcomes() if proven else [],
        notes=format_marker(server_layer=server_layer),
        reproducibility=ReproducibilityEvidence(
            iterations=5, vuln_fired=vuln_fired, guard_resisted=guard_resisted
        ),
    )


def test_bundle_states_a_boundary_guarded_side() -> None:
    from mylonite._twin_fidelity import PROOF_CLAIM_BOUNDARY
    from mylonite.report.bundle import to_bundle

    f = to_bundle([(_exploit("W2"), _fidelity_report(server_layer=False))])["findings"][0]
    assert f["guarded_twin_layer"] == "boundary"
    assert f["proof"]["claim"] == PROOF_CLAIM_BOUNDARY


def test_bundle_states_a_server_layer_guarded_side() -> None:
    from mylonite._twin_fidelity import PROOF_CLAIM_SERVER
    from mylonite.report.bundle import to_bundle

    f = to_bundle([(_exploit("W2"), _fidelity_report(server_layer=True))])["findings"][0]
    assert f["guarded_twin_layer"] == "server"
    assert f["proof"]["claim"] == PROOF_CLAIM_SERVER


def test_bundle_makes_no_differential_claim_without_a_guarded_twin() -> None:
    """A stability-only run (``guard_resisted is None``) had no guarded side, so it
    carries neither a layer nor a claim -- mirroring SARIF's "no guarded twin" text."""
    from mylonite.report.bundle import to_bundle

    report = _fidelity_report(server_layer=False, guard_resisted=None)
    f = to_bundle([(_exploit("W2"), report)])["findings"][0]
    assert f["guarded_twin_layer"] is None
    assert f["proof"]["claim"] is None


def test_bundle_rejected_finding_makes_no_claim_and_says_what_was_shown() -> None:
    """A rejection where the attack never fired proved nothing about a safeguard,
    even though a guarded twin ran and resisted every time."""
    from mylonite.report.bundle import to_bundle

    report = _fidelity_report(server_layer=True, kept=False, vuln_fired=0, proven=False)
    proof = to_bundle([(_exploit("W2"), report)])["findings"][0]["proof"]
    assert proof["verdict"] == "REJECTED"
    assert proof["claim"] is None
    assert proof["status"] == "not reproduced on this model"


def test_bundle_rejected_after_reproducing_reads_as_rejected() -> None:
    from mylonite.report.bundle import to_bundle

    report = _fidelity_report(server_layer=True, kept=False, vuln_fired=5, proven=False)
    proof = to_bundle([(_exploit("W2"), report)])["findings"][0]["proof"]
    assert proof["claim"] is None
    assert proof["status"] == "rejected"


def test_bundle_stable_not_proven_makes_no_claim() -> None:
    from mylonite.report.bundle import to_bundle

    report = _fidelity_report(server_layer=True, proven=False)
    proof = to_bundle([(_exploit("W2"), report)])["findings"][0]["proof"]
    assert proof["verdict"] == "STABLE, NOT PROVEN"
    assert proof["claim"] is None
    assert proof["status"] == "stable, not proven"


def test_bundle_scan_only_finding_carries_no_layer() -> None:
    from mylonite.report.bundle import to_bundle

    f = to_bundle([(_exploit("W2"), None)])["findings"][0]
    assert f["guarded_twin_layer"] is None
    assert f["proof"] is None


def test_bundle_empty() -> None:
    from mylonite.report.bundle import to_bundle

    assert to_bundle([])["findings"] == []


def test_bundle_redacts_secret_shaped_success_reason() -> None:
    """Mirrors the sarif.py DCR-0021 fix: this bundle is written to disk
    unconditionally (report --json / gate), and a real exfil finding's
    success_reason can narrate the exfiltrated value itself."""
    from mylonite.contracts._types import AdapterResponse, ComplianceTags, ExploitRecord, Payload
    from mylonite.report.bundle import to_bundle

    secret = "sk-live" + "abcdefghijklmnopqrstuvwxyz"
    pid = "finding-w3"
    ex = ExploitRecord(
        target_id="mcp:myapp",
        pattern_id=pid,
        payload=Payload(
            pattern_id=pid, channel="tool-result", body="x", metadata={"weakness": "W3"}
        ),
        response=AdapterResponse(
            payload_pattern_id=pid, raw_response="ok", tool_calls=["fetch"], metadata={}
        ),
        success_reason=f"exfiltrated {secret} to the attacker endpoint",
        compliance=ComplianceTags(owasp_llm=["LLM01"]),
    )
    f = to_bundle([(ex, None)])["findings"][0]
    assert secret not in f["success_reason"]


def test_bundle_shows_the_findings_proof_level() -> None:
    from mylonite.report.bundle import to_bundle

    exploit = _exploit("W4", metadata={"proof_level": "dispatched-tool-linked"})
    assert to_bundle([(exploit, None)])["findings"][0]["proof_level"] == "dispatched-tool-linked"


def test_bundle_proof_level_is_null_without_a_trace() -> None:
    from mylonite.report.bundle import to_bundle

    assert to_bundle([(_exploit("W4"), None)])["findings"][0]["proof_level"] is None


def test_an_errored_or_deferred_probe_reads_like_an_unprobed_one() -> None:
    """Only a confirmed effect raises severity: an errored or deferred probe
    confirmed nothing."""
    from mylonite.report.bundle import to_bundle

    for effect in ("errored", "deferred", "unprobed"):
        finding = to_bundle([(_exploit("W1", effect=effect), None)])["findings"][0]
        assert finding["severity"] == "Medium", effect


def test_bundle_validation_with_no_runs_keeps_its_verdict() -> None:
    """A validation that recorded no iterations is still a validation: proof
    carries its verdict and status, with null counts, rather than null."""
    from mylonite.contracts._types import ValidationReport
    from mylonite.report.bundle import to_bundle

    report = ValidationReport(test_filename="test_security_finding.py", kept=False)
    proof = to_bundle([(_exploit("W2"), report)])["findings"][0]["proof"]
    assert proof is not None
    assert proof["verdict"] == "REJECTED"
    assert proof["status"] == "rejected"
    assert proof["iterations"] is None and proof["vuln_fired"] is None
    assert proof["claim"] is None
