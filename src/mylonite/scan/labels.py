"""Two-axis information-flow labels, following FIDES.

``InformationFlowControl``'s docstring has always cited "the pattern Microsoft
ships as FIDES" (``agent_framework.security``, Costa et al.,
https://arxiv.org/abs/2505.23643). It implemented a strictly cruder subset: a
single session-wide boolean ``_tainted``, monotonic and terminal, with the only
escape being a per-sink exemption that switches the control off for that sink.

Measured consequence: **every** read-then-act workflow was refused, benign or
not. ``read_note -> send_email`` refused; ``list_files -> write_file`` refused.
Declaring ``read_tool_names`` precisely (the "T1" configuration the project's
own plan predicted was "where the tool earns its claim") did not help — only
``accepts_untrusted`` did, and that just disables the control. So a guarded twin
scored `attack_gap = 1.0` with `benign_retention = 0.0`: it discriminated
workflow SHAPE, not attack from legitimate work, which is what
``GUARD_DENIES_ALL`` in the verification scorecard actually means.

What was missing is the second axis. In FIDES's own canonical example the
exfiltration is caught by CONFIDENTIALITY — ``post_comment`` caps at ``public``
and the context went ``private`` after reading ``.env`` — not by integrity. With
only an integrity axis, integrity has to catch everything, which forces the
blanket deny. With both, ``read public doc -> post public comment`` succeeds
while ``read private secret -> post public`` is refused.

Microsoft documents the remaining conservatism as FIDES's own limitation:
"Most-restrictive-wins propagation can be conservative. Once an untrusted issue
body enters the context, the rest of the run is untrusted unless you explicitly
drop it." That is a known, accepted property of the model — not a reason to
collapse the two axes back into one.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol

IntegrityLabel = Literal["trusted", "untrusted"]
ConfidentialityLabel = Literal["public", "private", "user_identity"]

#: Enforcement posture, mirroring FIDES's three modes. ``observe`` is the one
#: that resolves the "reference control vs measurement instrument" tension: it
#: propagates labels and records what WOULD be blocked without blocking
#: anything, which is simultaneously the differential oracle's measurement
#: instrument and the "what would break if I adopted this?" mode a user needs
#: before turning enforcement on.
EnforcementMode = Literal["observe", "approve", "block"]

_CONFIDENTIALITY_RANK: dict[str, int] = {"public": 0, "private": 1, "user_identity": 2}


@dataclass(frozen=True)
class ContentLabel:
    """Provenance of a piece of content, on two independent axes.

    Defaults are the safe reading of developer-controlled data: ``trusted`` +
    ``public``. Note this is the default for content whose provenance is KNOWN;
    an unlabelled TOOL RESULT is treated as untrusted by
    :class:`InformationFlowControl`, matching FIDES's secure-by-default
    ``default_integrity=UNTRUSTED``.
    """

    integrity: IntegrityLabel = "trusted"
    confidentiality: ConfidentialityLabel = "public"

    def is_untrusted(self) -> bool:
        return self.integrity == "untrusted"

    def rank(self) -> int:
        return _CONFIDENTIALITY_RANK[self.confidentiality]


def combine_labels(*labels: ContentLabel) -> ContentLabel:
    """Most-restrictive-wins, per axis independently (FIDES ``combine_labels``).

    Integrity: ``untrusted`` beats ``trusted``.
    Confidentiality: ``user_identity`` > ``private`` > ``public``.
    """
    if not labels:
        return ContentLabel()
    integrity: IntegrityLabel = (
        "untrusted" if any(label.is_untrusted() for label in labels) else "trusted"
    )
    worst = max(labels, key=lambda label: label.rank())
    return ContentLabel(integrity=integrity, confidentiality=worst.confidentiality)


@dataclass(frozen=True)
class SinkPolicy:
    """What context a sink tool is willing to run in (FIDES's two knobs).

    ``accepts_untrusted`` — may this tool run while untrusted content is in
    scope? Mirrors FIDES's ``accepts_untrusted``; False is the guarded default
    for anything with a side effect.

    ``max_allowed_confidentiality`` — the most sensitive context this tool may
    run in. Mirrors FIDES's ``max_allowed_confidentiality``. ``public`` for
    anything that publishes externally; this is the knob that catches
    exfiltration WITHOUT blocking ordinary read-then-act work.
    """

    accepts_untrusted: bool = False
    max_allowed_confidentiality: ConfidentialityLabel = "public"

    def violated_by(self, context: ContentLabel) -> str | None:
        """Why ``context`` is not allowed to drive this sink, or None if it is."""
        if context.is_untrusted() and not self.accepts_untrusted:
            return (
                "untrusted content is in scope this session and this sink does not "
                "accept untrusted context (W2 information-flow control)"
            )
        cap = _CONFIDENTIALITY_RANK[self.max_allowed_confidentiality]
        if context.rank() > cap:
            return (
                f"context is {context.confidentiality!r} but this sink accepts at most "
                f"{self.max_allowed_confidentiality!r} — refusing to let more sensitive "
                "data leave through a less sensitive channel"
            )
        return None


@dataclass(frozen=True)
class ApprovalRequest:
    """An out-of-band decision a control needs before a call may proceed.

    Replaces the in-band confirm token ``ConfirmGateControl`` used to mint. That
    design required the MODEL to carry the security protocol: extract a 16-char
    HMAC from an ``isError`` refusal string and re-supply it as a
    ``confirm_token`` argument the advertised schema never declared (and which
    ``additionalProperties: false`` forbids). Measured result: 0/6 completions
    across two frontier models, while a byte-identical programmatic retry
    succeeded — the mechanism was sound and simply unreachable.

    FIDES routes this the other way: a violation raises a function-approval
    request the FRAMEWORK (or a human) answers. The model never sees a token,
    so there is nothing for it to fail to thread.
    """

    tool: str
    arguments: dict[str, object]
    context: ContentLabel
    reason: str


ApprovalDecision = Literal["approve", "deny"]


class ApprovalPolicy(Protocol):
    """Decides an :class:`ApprovalRequest` out of band."""

    def decide(self, request: ApprovalRequest) -> ApprovalDecision: ...


class DenyAll:
    """Refuse every consequential action. The safe default when nobody is
    available to approve — and the correct ATTACK-side policy: a user would not
    approve the exfiltration an injected instruction is asking for."""

    def decide(self, request: ApprovalRequest) -> ApprovalDecision:
        return "deny"


class ApproveWhenTrusted:
    """Approve only when no untrusted content is in scope.

    The deterministic reading of "did the USER ask for this, or did ingested
    content?" — which is what excessive agency (W4) is actually about. It is
    also what makes ``benign_retention`` meaningful for a confirm gate for the
    first time: a confirm gate is SUPPOSED to stop an unconfirmed benign action
    too, so the benign leg has to complete THROUGH the confirmation flow rather
    than around it. A benign task (no untrusted content in scope) is approved as
    a real user would approve it; an injection-driven one is not.
    """

    def decide(self, request: ApprovalRequest) -> ApprovalDecision:
        return "deny" if request.context.is_untrusted() else "approve"
