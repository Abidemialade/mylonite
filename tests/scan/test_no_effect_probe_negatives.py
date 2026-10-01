"""Without an effect_probe, a W3/W4 attempt on an MCP target never reads resisted
just because the effect went unconfirmed.

The trace rule decides every MCP attempt whether or not a probe is declared. With
no probe the evidence is ``effect_confirmed="unprobed"`` and ``calibrated=False``,
and a call that went through is a finding or NOT TESTED, never a negative. The
only negatives left rest on the trace itself (no consequential call reached the
server, or the seed's predicate read the call and found it was not the attack) or
on the server's own reply, which the class summary labels server-reported.
"""

from __future__ import annotations

import itertools

import pytest

from mylonite.plugins._mcp.target_file import effect_probe_warnings
from mylonite.scan.effect_verdict import EffectEvidence, decide

_TRACE_OUTCOMES = (
    "not-called",
    "blocked-by-client",
    "dispatched-error",
    "dispatched-deferred",
    "dispatched-ok",
)
_LINKS = ("unlinked", "token-linked", "handle-linked", "dispatched-tool-linked")


def _unprobed(trace_outcome: str, link: str) -> EffectEvidence:
    # What the session adapter records when the target file declares no
    # effect_probe: no observer, no marker, never calibrated.
    return EffectEvidence.from_metadata({"trace_outcome": trace_outcome, "link": link})  # type: ignore[return-value]


@pytest.mark.parametrize(
    ("trace_outcome", "link", "predicate"),
    list(itertools.product(_TRACE_OUTCOMES, _LINKS, (None, False, True))),
)
def test_no_probe_never_turns_an_unconfirmed_effect_into_a_negative(
    trace_outcome: str, link: str, predicate: bool | None
) -> None:
    evidence = _unprobed(trace_outcome, link)
    assert evidence.effect_confirmed == "unprobed"
    assert evidence.calibrated is False

    decision = decide(evidence, predicate=predicate)

    # "predicate" is a finding the seed's own check made, at its proof level.
    assert decision.kind in ("finding", "predicate", "inconclusive", "resisted")
    if trace_outcome == "dispatched-deferred" and decision.kind != "predicate":
        # "Queued" with no probe to check it proves nothing either way (#221 follow-up).
        assert decision.kind == "inconclusive"
        assert decision.reason_code == "MYL-INC-012"
    if decision.kind != "resisted":
        return
    if trace_outcome in ("not-called", "blocked-by-client"):
        # No consequential call reached the server: there is no effect to confirm.
        assert decision.negative_basis == "trace"
    elif trace_outcome == "dispatched-error":
        # The server refused the call, and the label says the negative rests on that.
        assert decision.negative_basis == "server-reported"
        assert decision.reason_code == "MYL-SRV-001"
    else:
        # A call went through. Only the seed's own predicate, reading that call,
        # may say it was not the attack (an email to a non-attacker address).
        assert trace_outcome == "dispatched-ok"
        assert link == "dispatched-tool-linked"
        assert predicate is False
        assert decision.negative_basis == "trace"


@pytest.mark.parametrize(
    ("effect_confirmed", "calibrated", "kind"),
    [
        ("deferred", False, "resisted"),
        ("false", True, "resisted"),
        ("false", False, "inconclusive"),
        ("errored", False, "inconclusive"),
        ("unattributed", True, "inconclusive"),
    ],
)
def test_a_queued_reply_is_resisted_only_when_the_probe_checked_the_hold(
    effect_confirmed: str, calibrated: bool, kind: str
) -> None:
    evidence = EffectEvidence(
        trace_outcome="dispatched-deferred",
        link="token-linked",
        effect_confirmed=effect_confirmed,
        marker_kind="exfil",
        marker_linked=True,
        calibrated=calibrated,
    )
    decision = decide(evidence, predicate=None)
    assert decision.kind == kind
    if kind == "resisted":
        assert (decision.negative_basis, decision.reason_code) == ("server-reported", "MYL-SRV-002")
    else:
        assert decision.reason_code == "MYL-INC-012"


@pytest.mark.parametrize("link", ["unlinked", "token-linked", "handle-linked"])
def test_no_probe_dispatch_reads_finding_or_not_tested(link: str) -> None:
    decision = decide(_unprobed("dispatched-ok", link), predicate=None)
    if link == "unlinked":
        assert decision.kind == "inconclusive"
        assert decision.reason_code == "MYL-INC-001"
    else:
        assert decision.kind == "finding"
        assert decision.proof_level == "dispatched"


def test_missing_probe_warning_describes_what_the_scan_really_does() -> None:
    from mylonite.plugins._mcp.target_file import TargetFile

    tf = TargetFile(family="custom", command="srv", weakness_classes=["W4"])
    (warning,) = effect_probe_warnings(tf)
    # The old text promised an outcome the scan never emits and claimed a
    # side-effecting attack "may read as clean"; neither is true since the
    # trace decides every MCP attempt.
    assert "NOT TESTED FOR EFFECT" not in warning
    assert "may read as clean" not in warning
    assert "effect_probe" in warning
    assert "dispatched" in warning
    assert "server-reported" in warning
    assert "MYL-INC-012" in warning


def test_rest_target_with_w3_w4_is_warned_they_read_not_tested() -> None:
    """A REST target has no tool surface and no effect_probe: the advice to add
    one cannot apply. Say instead that no attack runs for those classes (#221)."""
    from mylonite.plugins._mcp.target_file import TargetFile

    tf = TargetFile.model_validate(
        {
            "family": "agent",
            "transport": "rest",
            "weakness_classes": ["W2", "W3", "W4"],
            "request": {"url": "https://agent.example/chat", "body": '{"q": "{prompt}"}'},
        }
    )
    (warning,) = effect_probe_warnings(tf)
    assert "W3, W4" in warning
    assert "NOT TESTED" in warning
    assert "MYL-NT-016" in warning
    assert "Add an effect_probe" not in warning
