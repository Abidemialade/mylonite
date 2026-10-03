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
    # A passing build leg plus a passing effect leg: a KEPT verdict, the only one
    # the PR body states a claim for.
    return ValidationReport(
        test_filename="test_security_x.py",
        outcomes=[
            ValidationOutcome(stage="build", passed=True, detail="collected"),
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


def test_pr_body_gating_section_names_the_default_gate_dir_when_unset():
    """No ``gate_dir`` passed -- falls back to the literal default, not a crash."""
    ex = _exploit_for("indirect-injection-note-body-direct")
    body = build_pr_body(ex, _report())
    assert "under `.mylonite/gate/`" in body


def test_pr_body_gating_section_names_the_real_out_dir():
    """A non-default ``--out`` must show up here, not the hardcoded default (GT15)."""
    ex = _exploit_for("indirect-injection-note-body-direct")
    body = build_pr_body(ex, _report(), gate_dir="build/ci-gate")
    assert "under `build/ci-gate/`" in body
    assert ".mylonite/gate" not in body


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
    body_rich = build_pr_body(
        ex, _report(), llm_enrich=True, completion_fn=fake_completion, model="stub"
    )
    assert "Unverified LLM suggestion" in body_rich
    assert "untrusted envelope" in body_rich
    assert calls["n"] == 1


def test_llm_enrich_with_no_model_warns_instead_of_silently_skipping(capsys):
    """Review follow-up: there is no default model, so `--llm-enrich` with
    none configured must say so -- a bare silent skip reads as "nothing to
    add" rather than "couldn't run it"."""
    ex = _exploit_for("indirect-injection-note-body-direct")

    body = build_pr_body(ex, _report(), llm_enrich=True, model=None)
    assert "Unverified LLM suggestion" not in body

    err = capsys.readouterr().err
    assert "llm-enrich" in err.lower()
    assert "no model" in err.lower()


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


def _control_finding():
    ex = _exploit_for("indirect-injection-note-body-direct", target_id="mcp:custom")
    return ex.model_copy(
        update={"payload": ex.payload.model_copy(update={"metadata": {"synthetic_control": "W2"}})}
    )


def _unproven_report(*, kept: bool, vuln_fired: int):
    """A server-layer differential that proved nothing: kept with no passing
    differential or effect leg, or rejected."""
    from mylonite.contracts import ReproducibilityEvidence

    return ValidationReport(
        test_filename="test_security_x.py",
        outcomes=[
            ValidationOutcome(stage="build", passed=True, detail="collected"),
            ValidationOutcome(stage="stability", passed=True, detail="2/2 runs", metric=1.0),
        ],
        kept=kept,
        notes="[guarded-twin=server-layer]",
        reproducibility=ReproducibilityEvidence(
            iterations=3, vuln_fired=vuln_fired, guard_resisted=3, guard_fired=0
        ),
    )


def test_pr_body_states_no_claim_for_a_stable_not_proven_report():
    body = build_pr_body(_control_finding(), _unproven_report(kept=True, vuln_fired=3))
    assert "carries the security" not in body
    assert "Control efficacy verified" not in body
    assert "Server-layer control verified" not in body
    assert "Proven fix" not in body
    assert "## Control efficacy not proven" in body
    assert "**Verdict: STABLE, NOT PROVEN:**" in body
    assert "stops carrying the security" not in body
    assert "has not yet shown that the control stops the attack" in body


def test_pr_body_states_no_claim_for_a_rejected_report():
    body = build_pr_body(_control_finding(), _unproven_report(kept=False, vuln_fired=0))
    assert "carries the security" not in body
    assert "Proven fix" not in body
    assert "**Verdict: REJECTED:**" in body


def test_pr_body_non_control_finding_names_an_unproven_verdict():
    ex = _exploit_for("excessive-agency-send-email-direct-unconfirmed", target_id="mcp:custom")
    body = build_pr_body(ex, _unproven_report(kept=True, vuln_fired=3))
    assert "A validated weakness" not in body
    assert "**Verdict: STABLE, NOT PROVEN:**" in body


def test_pr_body_evidence_lines_redact_validator_detail():
    """#223: validator detail can carry a live key echoed by the target; the PR
    body is committed and sent to GitHub, so it must be redacted like
    validation_report.json is."""
    fake_key = "sk-live-abcdefghijklmnopqrstuvwxyz"  # pragma: allowlist secret
    report = ValidationReport(
        test_filename="test_security_x.py",
        outcomes=[
            ValidationOutcome(stage="build", passed=True, detail="collected"),
            ValidationOutcome(
                stage="effect", passed=True, detail=f"probe saw token={fake_key}", metric=1.0
            ),
        ],
        kept=True,
    )
    ex = _exploit_for("excessive-agency-send-email-direct-unconfirmed")
    body = build_pr_body(ex, report)
    assert fake_key not in body
    assert "- **effect**: pass — probe saw token=***REDACTED***" in body


def test_llm_suggestion_and_its_prompt_are_redacted():
    """#223: the opt-in LLM suggestion is pasted into the committed PR body,
    and its prompt quotes success_reason; neither may carry a key."""
    fake_key = "sk-live-abcdefghijklmnopqrstuvwxyz"  # pragma: allowlist secret
    ex = _exploit_for("indirect-injection-note-body-direct")
    ex = ex.model_copy(update={"success_reason": f"agent leaked {fake_key}"})
    prompts: list[str] = []

    def fake_completion(*, model, messages, **kwargs):
        prompts.append(str(messages))

        class _Msg:
            content = f"Rotate the key {fake_key} and wrap notes."

        class _Choice:
            message: _Msg = _Msg()  # type: ignore[misc]

        class _Resp:
            def __init__(self) -> None:
                self.choices = [_Choice()]

        return _Resp()

    body = build_pr_body(
        ex, _report(), llm_enrich=True, completion_fn=fake_completion, model="stub"
    )
    assert prompts and fake_key not in prompts[0]
    assert "Unverified LLM suggestion" in body
    assert fake_key not in body
    assert "Rotate the key ***REDACTED***" in body


def test_pr_body_says_a_custom_target_test_is_committed_as_a_pending_fix():
    from mylonite.gate.mitigation import commits_as_pending

    ex = _exploit_for("indirect-injection-note-body-direct", target_id="mcp:custom")
    assert commits_as_pending(ex)
    body = build_pr_body(ex, _report())
    gated = body.split("## How this is gated", 1)[1]
    assert "pending fix" in gated
    assert "@testkit.pending_fix" in gated


def test_pr_body_reference_target_is_not_pending():
    from mylonite.gate.mitigation import commits_as_pending

    ex = _exploit_for("indirect-injection-note-body-direct")  # reference:vulnerable
    assert not commits_as_pending(ex)
    assert "pending_fix" not in build_pr_body(ex, _report())


def test_control_finding_is_not_pending():
    from mylonite.gate.mitigation import commits_as_pending

    assert not commits_as_pending(_control_finding())


def test_pr_body_follows_the_verdict_impact_fix_proof_order():
    """A3/SV3/RP2: one result template, verdict -> impact -> fix -> proof, so
    the facts a reviewer needs most read top to bottom instead of landing at
    the bottom of the PR or not appearing at all."""
    ex = _exploit_for("excessive-agency-send-email-direct-unconfirmed")
    body = build_pr_body(ex, _report())
    verdict_at = body.index("**Verdict: KEPT:**")
    impact_at = body.index("**Impact:**")
    fix_at = body.index("## Suggested mitigation")
    proof_at = body.index("## Proof")
    assert verdict_at < impact_at < fix_at < proof_at


def test_pr_body_shows_severity_and_a_deterministic_impact_sentence():
    """SV1 (severity shown) + SV3 (a deterministic, plain-language impact
    sentence per weakness class)."""
    from mylonite.gate.mitigation import impact_sentence

    ex = _exploit_for("excessive-agency-send-email-direct-unconfirmed")  # W4
    body = build_pr_body(ex, _report())
    assert "**Severity:** High" in body
    assert f"**Impact:** {impact_sentence('W4')}" in body
    # Deterministic and attacker-focused: the sentence names what the
    # attacker gets, and is identical for any W4 finding.
    assert impact_sentence("W4") == impact_sentence("W4")
    for wc in ("W1", "W2", "W3", "W4"):
        assert impact_sentence(wc).strip()
    assert impact_sentence("not-a-class") == impact_sentence("generic-anything-else")


def test_pr_body_recommend_shown_under_a_kept_finding():
    """A3: the deterministic fix must not be exclusive to a validated
    directory or an export -- it is already rendered under every KEPT gate
    PR finding, proven or control-efficacy, via recommend()/render_markdown()."""
    ex = _exploit_for("excessive-agency-send-email-direct-unconfirmed")
    body = build_pr_body(ex, _report())
    assert "Recommended fix" in body or "Proven fix" in body
    assert "confirmation_required" in body  # the W4 recommend() sketch rendered


def test_pr_body_has_a_reviewer_checklist():
    """T5: a short reviewer checklist naming the proof level, the planner
    model, the prompt used, and the runs/rates -- for the reviewer to
    confirm against their own app, not a claim Mylonite makes for them."""
    ex = _exploit_for("indirect-injection-note-body-direct")
    body = build_pr_body(
        ex, _report(), model="claude-haiku-4-5-20251001", system_prompt="be helpful"
    )
    checklist = body.split("## Reviewer checklist", 1)[1]
    assert "Proof level" in checklist
    assert "Planner model" in checklist
    assert "claude-haiku-4-5-20251001" in checklist
    assert "Prompt used" in checklist
    assert "the system prompt supplied to this run" in checklist
    assert "Runs and rates" in checklist


def test_pr_body_checklist_names_the_default_prompt_and_missing_model():
    ex = _exploit_for("indirect-injection-note-body-direct")
    body = build_pr_body(ex, _report())
    checklist = body.split("## Reviewer checklist", 1)[1]
    assert "`not recorded`" in checklist
    assert "Mylonite's generic default" in checklist


def test_pr_body_checklist_never_claims_the_safeguard_for_a_boundary_proof():
    """ "your safeguard stops it" (or any equivalent claim) is said only when
    the guarded side was a real control_env, never for Mylonite's boundary
    stand-in."""
    ex = _control_finding()
    body = build_pr_body(ex, _report())  # no server-layer marker -> boundary
    checklist = body.split("## Reviewer checklist", 1)[1]
    assert "your own control" not in checklist
    assert "stand-in" in checklist


def test_pr_body_kill_matrix_marks_unrun_seeds_and_carries_a_legend():
    """Carried from the validator track: the PR-body kill matrix must show a
    seed the differential never ran as "not run", not as an indistinguishable
    miss, and a legend explains what each mark means."""
    from mylonite.contracts import SeedKill
    from mylonite.plugins._reference.reference_pytest_generator import _slugify

    own_id = "indirect-injection-note-body-direct"
    report = ValidationReport(
        test_filename=f"test_security_{_slugify(own_id)}.py",
        outcomes=[ValidationOutcome(stage="build", passed=True, detail="collected")],
        kept=True,
        mutation_matrix=[
            SeedKill(pattern_id=own_id, weakness="W2", killed=True),
            SeedKill(
                pattern_id="excessive-agency-fetch-attacker-url-direct",
                weakness="W3",
                killed=False,
            ),
        ],
    )
    body = build_pr_body(_exploit_for(own_id), report)
    assert "this test's own seed; 1/2 not run" in body
    assert f"W2:{own_id} ✓" in body
    assert "W3:excessive-agency-fetch-attacker-url-direct -" in body
    assert "legend:" in body
    assert "not run by this test" in body


def test_pr_body_kill_matrix_falls_back_when_the_own_seed_is_unknown():
    """A report whose test file doesn't match any bank seed's slug (a hand-
    built report, or an older report shape) keeps the plain killed/not-killed
    rendering -- it never guesses which seed is "its own"."""
    from mylonite.contracts import SeedKill

    report = ValidationReport(
        test_filename="test_security_x.py",
        outcomes=[ValidationOutcome(stage="build", passed=True, detail="collected")],
        kept=True,
        mutation_matrix=[
            SeedKill(pattern_id="indirect-injection-note-body-direct", weakness="W2", killed=True),
            SeedKill(
                pattern_id="excessive-agency-fetch-attacker-url-direct",
                weakness="W3",
                killed=False,
            ),
        ],
    )
    body = build_pr_body(_exploit_for("indirect-injection-note-body-direct"), report)
    assert "this test's own seed" not in body
    assert "W3:excessive-agency-fetch-attacker-url-direct ✗" in body
    assert "legend:" in body


def test_severity_sort_kept_orders_most_severe_first_and_keeps_dirs_parallel():
    from pathlib import Path

    from mylonite.gate.mitigation import severity_sort_kept

    w1 = _exploit_for("tool-description-summary-smuggle")  # Medium (W1)
    w4 = _exploit_for("excessive-agency-send-email-direct-unconfirmed")  # High (W4)
    kept = [(w1, _report()), (w4, _report())]
    kept_dirs = [Path("a"), Path("b")]
    new_kept, new_dirs = severity_sort_kept(kept, kept_dirs)
    assert [e.pattern_id for e, _ in new_kept] == [
        "excessive-agency-send-email-direct-unconfirmed",
        "tool-description-summary-smuggle",
    ]
    assert new_dirs == [Path("b"), Path("a")]


def test_severity_sort_kept_is_stable_for_equal_severity():
    from pathlib import Path

    from mylonite.gate.mitigation import severity_sort_kept

    a = _exploit_for("indirect-injection-note-body-direct")
    b = _exploit_for("indirect-injection-note-body-roleplay")
    kept = [(a, _report()), (b, _report())]
    kept_dirs = [Path("a"), Path("b")]
    new_kept, _ = severity_sort_kept(kept, kept_dirs)
    # Both W2 -> same (High) severity -> tie-broken by pattern_id, alphabetical.
    assert [e.pattern_id for e, _ in new_kept] == [
        "indirect-injection-note-body-direct",
        "indirect-injection-note-body-roleplay",
    ]


def test_severity_sort_kept_handles_empty_input():
    from mylonite.gate.mitigation import severity_sort_kept

    assert severity_sort_kept([], []) == ([], [])


def test_sort_exploits_by_severity_orders_most_severe_first():
    """SV1: the same most-severe-first order `scan`'s end-of-run findings
    use, for a plain list of exploits (no ValidationReport yet)."""
    from mylonite.gate.mitigation import sort_exploits_by_severity

    w1 = _exploit_for("tool-description-summary-smuggle")  # Medium
    w4 = _exploit_for("excessive-agency-send-email-direct-unconfirmed")  # High
    assert [e.pattern_id for e in sort_exploits_by_severity([w1, w4])] == [
        "excessive-agency-send-email-direct-unconfirmed",
        "tool-description-summary-smuggle",
    ]


def test_finding_block_is_verdict_free_severity_impact_then_suggested_fix():
    """A3: the same facts the gate PR body opens with (severity, the
    deterministic impact sentence, then recommend()'s suggestion), reused
    rather than re-derived, for a surface (scan, with no ValidationReport
    yet) that has no KEPT/REJECTED verdict to show at all."""
    from mylonite.gate.mitigation import finding_block, impact_sentence

    ex = _exploit_for("excessive-agency-send-email-direct-unconfirmed")  # W4
    lines = finding_block(ex)
    block = "\n".join(lines)
    assert lines[0] == "Severity: High"
    assert lines[1] == f"Impact: {impact_sentence('W4')}"
    assert (
        "Suggested fix (Mylonite proves and gates the weakness; it does not patch your code):"
        in block
    )
    assert "confirmation_required" in block  # the W4 recommend() sketch, rendered
    # Never overclaims a fix, and never claims the safeguard without a
    # proven control_env (finding_block never calls recommend() with a
    # KEPT control-efficacy report, so that claim text cannot appear here).
    assert "we fixed" not in block.lower()
    assert "carries the security" not in block
    severity_at = block.index("Severity:")
    impact_at = block.index("Impact:")
    fix_at = block.index("Suggested fix")
    assert severity_at < impact_at < fix_at


def test_finding_block_degrades_gracefully_with_no_report_or_target():
    """``recommend()`` already handles ``report=None``/``target=None``; this
    just confirms ``finding_block`` passes both straight through instead of
    requiring either."""
    from mylonite.gate.mitigation import finding_block

    ex = _exploit_for("indirect-injection-note-body-direct")
    lines = finding_block(ex, None, target=None)
    assert lines  # never raises, never empty
