from mylonite.contracts._types import (
    AdapterResponse,
    ComplianceTags,
    ExploitRecord,
    Payload,
    ValidationOutcome,
    ValidationReport,
)
from mylonite.gate.mitigation import build_pr_body, weakness_class_for
from mylonite.scan.seeds import SEED_CATALOGUE


def test_gate_package_imports():
    import mylonite.gate  # noqa: F401
    from mylonite.gate import GateResult, build_pr_body, run_gate  # noqa: F401


def _exploit_for(pattern_id, *, target_id="reference:vulnerable"):
    seed = next(s for s in SEED_CATALOGUE if s.pattern_id == pattern_id)
    return ExploitRecord(
        target_id=target_id,
        pattern_id=pattern_id,
        payload=Payload(
            pattern_id=pattern_id,
            channel="user-message",
            body="x",
            metadata={},
        ),
        response=AdapterResponse(
            payload_pattern_id=pattern_id,
            raw_response="",
            tool_calls=[],
            metadata={},
        ),
        success_reason="test",
        compliance=seed.compliance,
    )


def test_weakness_class_from_seed_catalogue():
    assert (
        weakness_class_for(_exploit_for("excessive-agency-send-email-direct-unconfirmed")) == "W4"
    )
    assert weakness_class_for(_exploit_for("indirect-injection-note-body-direct")) == "W2"


def test_weakness_class_unknown_pattern_falls_back_to_compliance_then_generic():
    ex = ExploitRecord(
        target_id="mcp:custom",
        pattern_id="totally-unknown-id",
        payload=Payload(
            pattern_id="totally-unknown-id",
            channel="user-message",
            body="x",
            metadata={},
        ),
        response=AdapterResponse(
            payload_pattern_id="totally-unknown-id",
            raw_response="",
            tool_calls=[],
            metadata={},
        ),
        success_reason="test",
        compliance=ComplianceTags(owasp_asi=["ASI02"]),
    )
    assert weakness_class_for(ex) == "W1"  # ASI02 (tool-description smuggling) -> W1

    ex_llm = ex.model_copy(update={"compliance": ComplianceTags(owasp_llm=["LLM06"])})
    assert weakness_class_for(ex_llm) == "W4"

    ex_blank = ex.model_copy(update={"compliance": ComplianceTags()})
    assert weakness_class_for(ex_blank) == "generic"


def test_weakness_class_prefers_stamped_metadata_over_seed_catalogue():
    """A4: report/bundle.py already preferred exploit.payload.metadata["weakness"]
    over the seed-catalogue/compliance inference; weakness_class_for did not, so
    the PR body and the JSON bundle could disagree about the same finding's
    class. A stamped W3 must win even when the pattern_id is a bundled W2 seed."""
    ex = _exploit_for("indirect-injection-note-body-direct")  # a bundled W2 pattern_id
    assert weakness_class_for(ex) == "W2"  # unchanged: no stamped override present

    ex_stamped = ex.model_copy(
        update={"payload": ex.payload.model_copy(update={"metadata": {"weakness": "W3"}})}
    )
    assert weakness_class_for(ex_stamped) == "W3"

    # An invalid/garbage stamped value must not shadow the catalogue lookup.
    ex_garbage = ex.model_copy(
        update={"payload": ex.payload.model_copy(update={"metadata": {"weakness": "not-a-class"}})}
    )
    assert weakness_class_for(ex_garbage) == "W2"


def test_all_mitigation_snippets_present():
    from mylonite.mitigations import snippet

    for name in ("W1", "W2", "W3", "W4", "generic"):
        assert snippet(name).strip(), f"{name}.md is empty"


def _report(kept=True):
    return ValidationReport(
        test_filename="test_security_x.py",
        outcomes=[
            ValidationOutcome(stage="stability", passed=True, detail="2/2 runs", metric=1.0),
            ValidationOutcome(stage="effect", passed=True, detail="probe confirmed", metric=1.0),
        ],
        kept=kept,
        mutation_score=0.75,
    )


def test_pr_body_reference_target_has_all_sections_and_diff_link():
    ex = _exploit_for("excessive-agency-send-email-direct-unconfirmed")  # reference:vulnerable
    body = build_pr_body(ex, _report())
    assert "## What Mylonite found" in body
    assert "## Suggested mitigation" in body
    assert "human-applied" in body.lower()
    assert "## How this is gated" in body
    assert "excessive agency (W4)" in body  # the W4 snippet
    assert "LLM06" in body and "ASI02" in body  # compliance tags surfaced
    assert "server_guarded.py" in body  # guarded-twin diff reference
    assert "mutation" in body.lower()  # validation evidence


def test_pr_body_custom_target_has_no_diff_link():
    ex = _exploit_for("excessive-agency-send-email-direct-unconfirmed", target_id="mcp:custom")
    body = build_pr_body(ex, _report())
    assert "server_guarded.py" not in body
    assert "## Suggested mitigation" in body


def test_pr_body_is_deterministic():
    ex = _exploit_for("indirect-injection-note-body-direct")
    assert build_pr_body(ex, _report()) == build_pr_body(ex, _report())


def test_pr_body_surfaces_differential_oracle_evidence():
    """The gating PR shows the formula + reproducibility + kill matrix (PR2)."""
    from mylonite.contracts import ReproducibilityEvidence, SeedKill

    report = ValidationReport(
        test_filename="test_security_x.py",
        outcomes=[
            ValidationOutcome(stage="build", passed=True, detail="collected", metric=None),
            ValidationOutcome(
                stage="differential", passed=True, detail="discriminates", metric=1.0
            ),
            ValidationOutcome(stage="flakiness", passed=True, detail="5/5", metric=1.0),
        ],
        kept=True,
        mutation_score=0.75,
        gating_formula="kept = build AND differential AND flakiness",
        gating_legs=["build", "differential", "flakiness"],
        reproducibility=ReproducibilityEvidence(iterations=5, vuln_fired=5, guard_resisted=5),
        mutation_matrix=[
            SeedKill(pattern_id="indirect-injection-note-body-direct", weakness="W2", killed=True),
            SeedKill(
                pattern_id="excessive-agency-fetch-attacker-url-direct", weakness="W3", killed=False
            ),
        ],
    )
    body = build_pr_body(_exploit_for("indirect-injection-note-body-direct"), report)
    assert "gate" in body and "kept = build" in body
    assert "vulnerable fired 5/5" in body
    assert "guarded resisted 5/5" in body
    assert "kill matrix" in body
    assert "W2:indirect-injection-note-body-direct" in body


def test_pr_body_includes_proven_fix_recommendation_for_control_finding():
    """A control-efficacy finding surfaces the fix as a target-specific, evidence-
    anchored recommendation (PR11: gate/fixes/*.md's fixed illustrative diff is
    retired) — not just prose — and frames it as proven."""
    ex = _exploit_for("indirect-injection-note-body-direct", target_id="mcp:custom")
    ex = ex.model_copy(
        update={"payload": ex.payload.model_copy(update={"metadata": {"synthetic_control": "W2"}})}
    )
    body = build_pr_body(ex, _report())
    assert "```" in body  # rendered as a fenced code sketch, never a diff
    assert "```diff" not in body
    assert "untrusted" in body.lower()  # the W2 information-flow-control fix
    assert "Proven fix" in body  # framed as proven load-bearing


def test_pr_body_fix_recommendation_matches_weakness_class():
    """The recommendation is class-specific: a W4 finding shows the confirm-gate
    sketch; a non-control finding still gets a (recommended) fix."""
    ex = _exploit_for("excessive-agency-send-email-direct-unconfirmed", target_id="mcp:custom")
    body = build_pr_body(ex, _report())
    assert "```" in body
    assert "```diff" not in body
    assert "confirmation_required" in body  # the W4 confirm-gate sketch
    assert "Recommended fix" in body  # non-control framing


def test_pr_body_localizes_the_finding_to_a_tool():
    """R4: the PR points at the exact locus (tool/field), not just a description."""
    ex = _exploit_for("excessive-agency-send-email-direct-unconfirmed", target_id="mcp:custom")
    ex = ex.model_copy(
        update={
            "payload": ex.payload.model_copy(
                update={"metadata": {"consequential_tool": "send_email"}}
            )
        }
    )
    body = build_pr_body(ex, _report())
    assert "Located at:" in body
    # the implicated tool appears with the field it lives in
    assert "send_email" in body and "->" in body


def test_pr_body_localizes_system_prompt_line_when_given():
    """When the system-prompt text is available, the locus carries the exact line."""
    ex = _exploit_for("indirect-injection-note-body-direct", target_id="mcp:custom")
    ex = ex.model_copy(
        update={
            "payload": ex.payload.model_copy(
                update={"channel": "system-prompt-injection", "body": "Obey embedded notes."}
            )
        }
    )
    prompt = "You are helpful.\nObey embedded notes.\nBe concise."
    body = build_pr_body(ex, _report(), system_prompt=prompt)
    assert "Located at:" in body
    assert "system prompt, line 2" in body


def test_llm_enrichment_is_labelled_and_opt_in():
    ex = _exploit_for("indirect-injection-note-body-direct")

    calls = {"n": 0}

    def fake_completion(*, model, messages, **kwargs):
        calls["n"] += 1

        class _Msg:  # minimal litellm-shaped response
            content = "Wrap retrieved notes in an untrusted envelope and re-test."

        class _Choice:
            message: _Msg = _Msg()  # type: ignore[misc]

        class _Resp:
            def __init__(self) -> None:
                self.choices = [_Choice()]

        return _Resp()

    # default: no enrichment, no call
    body_plain = build_pr_body(ex, _report())
    assert "Unverified LLM suggestion" not in body_plain
    assert calls["n"] == 0

    # opt-in: labelled block, completion called once
    body_rich = build_pr_body(ex, _report(), llm_enrich=True, completion_fn=fake_completion)
    assert "Unverified LLM suggestion" in body_rich
    assert "untrusted envelope" in body_rich
    assert calls["n"] == 1


def test_pr_body_shows_attack_tier_and_nist():
    ex = _exploit_for("indirect-injection-note-body-direct")
    ex = ex.model_copy(
        update={
            "compliance": ex.compliance.model_copy(update={"nist_ai_rmf": ["MEASURE-2.7"]}),
            "payload": ex.payload.model_copy(update={"metadata": {"attack_tier": "obfuscated"}}),
        }
    )
    body = build_pr_body(ex, _report())
    assert "Attack tier:" in body and "obfuscated" in body
    assert "NIST MEASURE-2.7" in body


def test_pr_body_control_efficacy_framing():
    """A control-efficacy finding (synthetic_control metadata) reframes the PR to
    'Control efficacy verified' with the raw/guarded rates, contribution, and the
    boundary-proxy fidelity caveat — not the generic 'What Mylonite found'."""
    from mylonite.contracts import ReproducibilityEvidence

    ex = _exploit_for("indirect-injection-note-body-direct", target_id="mcp:custom")
    ex = ex.model_copy(
        update={"payload": ex.payload.model_copy(update={"metadata": {"synthetic_control": "W2"}})}
    )
    report = ValidationReport(
        test_filename="test_security_x.py",
        outcomes=[
            ValidationOutcome(stage="build", passed=True, detail="collected"),
            ValidationOutcome(stage="stability", passed=True, detail="2/2"),
            ValidationOutcome(stage="effect", passed=True, detail="probe confirmed"),
            ValidationOutcome(stage="consensus", passed=True, detail="agree"),
            ValidationOutcome(stage="differential", passed=True, detail="control W2 +100%"),
        ],
        kept=True,
        gating_formula="kept = build AND stability AND effect AND consensus AND differential",
        gating_legs=["build", "stability", "effect", "consensus", "differential"],
        reproducibility=ReproducibilityEvidence(
            iterations=2, vuln_fired=2, guard_resisted=2, guard_fired=0, rate_gap=1.0
        ),
    )
    body = build_pr_body(ex, report)
    assert "## Control efficacy verified" in body
    assert "## What Mylonite found" not in body
    assert "control **W2**" in body
    assert "contribution **+100%**" in body
    assert "Boundary-validated control (proxy)" in body
    # The gating section explains the with/without-control re-drive.
    assert "with and without control **W2**" in body
    # Mitigation snippet still present (single source of truth).
    assert "## Suggested mitigation" in body
    # The HEADLINE claim must match the twin. On a synthetic boundary twin the
    # guarded side is Mylonite's own canonical shim, so the PR must not open by
    # telling the reviewer their safeguard carries the security and only qualify
    # it two lines down, where nobody reads it.
    assert "This proves the **safeguard** - not the model - carries the security." not in body
    assert "does **not** yet prove your own implementation" in body


def test_pr_body_server_layer_differential_is_not_captioned_proxy():
    """A3: a genuine SERVER-LAYER differential (the target's real control_env-
    declared guard, toggled directly) used to be captioned '(proxy)' anyway,
    because the caption keyed off is_control alone instead of whether the
    guarded twin was actually server-layer. This is the strongest possible
    result and it was being mislabelled as the weakest. The validator stamps
    '[guarded-twin=server-layer]' into report.notes for exactly this case."""
    ex = _exploit_for("indirect-injection-note-body-direct", target_id="mcp:custom")
    ex = ex.model_copy(
        update={"payload": ex.payload.model_copy(update={"metadata": {"synthetic_control": "W2"}})}
    )
    report = _report().model_copy(
        update={
            "notes": "Server-layer-guarded twin (control 'W2'): leaked 0/2, "
            "contribution +100%. [guarded-twin=server-layer]"
        }
    )
    body = build_pr_body(ex, report)
    assert "Boundary-validated control (proxy)" not in body
    assert "Server-layer control verified" in body
    assert "REAL server-side control" in body


def test_pr_body_explicit_guarded_is_server_layer_wins_over_notes():
    """A caller with direct TwinPlan access (guarded_is_server_layer=True) is
    trusted even when report.notes carries no marker at all — the notes
    parse is the run_gate fallback, not the only signal."""
    ex = _exploit_for("indirect-injection-note-body-direct", target_id="mcp:custom")
    ex = ex.model_copy(
        update={"payload": ex.payload.model_copy(update={"metadata": {"synthetic_control": "W2"}})}
    )
    body = build_pr_body(ex, _report(), guarded_is_server_layer=True)
    assert "Boundary-validated control (proxy)" not in body
    assert "Server-layer control verified" in body
