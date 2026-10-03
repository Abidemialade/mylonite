"""Stable reason codes for every result that is not a verdict.

A scan attempt that was never exercised, a scan that aborted, a pre-flight
refusal, and an effect check that could not be trusted each carry one code from
this registry. The code is what the operator sees in the output (``[MYL-NT-005]``)
and what they look up in ``docs/reason-codes.md``, where each code has its own
section with the fix.

Rules:

* A code never changes meaning once shipped. ``tests/fixtures/
  reason_codes.snapshot.json`` freezes each code's category and summary, and a
  test fails if either changes or a code disappears. Retire a code by leaving it
  in place, never by reusing its number.
* The ``fix`` text is the single source for the remedy. The operator messages in
  ``scan/coverage.py`` and ``plugins/cli_targets.py`` read it from here.
* Codes do not change exit codes.

This module is a dependency-free leaf, like ``exit_codes``: ``scan``, ``plugins``
and the CLI all import it without inverting any layering. Keys that name other
modules' values (cause buckets, ``AbortReason`` values) are plain strings, and
tests check them against the real enums.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final

#: The docs page every anchor points into, relative to ``docs/``.
DOCS_PAGE: Final = "reason-codes.md"

CATEGORY_NOT_TESTED: Final = "not-tested"
CATEGORY_ABORT: Final = "abort"
CATEGORY_PREFLIGHT: Final = "pre-flight"
CATEGORY_INCONCLUSIVE: Final = "inconclusive"
CATEGORY_SERVER_REPORTED: Final = "server-reported"

#: The code prefix (``MYL-<prefix>-NNN``) for each category.
CATEGORY_BY_PREFIX: Final[dict[str, str]] = {
    "NT": CATEGORY_NOT_TESTED,
    "ABT": CATEGORY_ABORT,
    "PRE": CATEGORY_PREFLIGHT,
    "INC": CATEGORY_INCONCLUSIVE,
    "SRV": CATEGORY_SERVER_REPORTED,
}


@dataclass(frozen=True)
class ReasonCode:
    """One documented reason a result is not a verdict."""

    #: ``MYL-<prefix>-NNN``. Never reused, never renumbered.
    code: str
    #: One of the ``CATEGORY_*`` values; matches the code's prefix.
    category: str
    #: One line: what happened.
    summary: str
    #: What to do about it. Operator messages embed this text verbatim.
    fix: str
    #: ``reason-codes.md#<code>``: the section that documents this code.
    anchor: str


def _rc(code: str, summary: str, fix: str) -> ReasonCode:
    prefix = code.split("-")[1]
    return ReasonCode(
        code=code,
        category=CATEGORY_BY_PREFIX[prefix],
        summary=summary,
        fix=fix,
        anchor=f"{DOCS_PAGE}#{code.lower()}",
    )


# --- NOT TESTED: an attempt that proved nothing about the target ---------------
#
# One code per cause bucket in ``scan/coverage.py`` (``_not_tested_cause_bucket``).
# These ``fix`` strings are sentence fragments on purpose: the incomplete-coverage
# message reads "N of M untested attempt(s) <what happened> — <fix>, then re-run."

NT_LAUNCH_FAILURE: Final = "MYL-NT-001"
NT_PLANNER_FAILURE: Final = "MYL-NT-002"
NT_PLANNER_NO_ENGAGEMENT: Final = "MYL-NT-003"
NT_NOT_APPLICABLE: Final = "MYL-NT-004"
NT_NO_SEED_ARM: Final = "MYL-NT-005"
NT_PAYLOAD_NOT_DELIVERED: Final = "MYL-NT-006"
NT_PROVIDER_ERROR: Final = "MYL-NT-007"
NT_GENERIC_ERROR: Final = "MYL-NT-008"
NT_EFFECT_PROBE_ERRORED: Final = "MYL-NT-009"
NT_UNPARSEABLE_JUDGE_OUTPUT: Final = "MYL-NT-010"
NT_NO_ADJUDICATOR: Final = "MYL-NT-011"
NT_UNDECIDED: Final = "MYL-NT-012"
NT_INVALID_METADATA: Final = "MYL-NT-013"
NT_UNKNOWN_SEED: Final = "MYL-NT-014"
NT_MODULE_LOAD_FAILED: Final = "MYL-NT-015"
NT_NO_ATTACK_EMITTED: Final = "MYL-NT-016"
NT_EFFECT_UNCONFIRMABLE: Final = "MYL-NT-017"

_NOT_TESTED: Final[tuple[ReasonCode, ...]] = (
    _rc(
        NT_LAUNCH_FAILURE,
        "The target's command never started, so nothing was tested.",
        "check the target file's command:/args: and that the server actually starts",
    ),
    _rc(
        NT_PLANNER_FAILURE,
        "The planner failed before the attack could be delivered.",
        "check the target/model connectivity",
    ),
    _rc(
        NT_PLANNER_NO_ENGAGEMENT,
        "The agent never called the tool this attack targets.",
        "check the target's purpose/system_prompt and that the planner model is tool-capable",
    ),
    _rc(
        NT_NOT_APPLICABLE,
        "The seed needs a capability this target's tool surface does not expose.",
        "the seed doesn't fit this target; check weakness_classes and the target's tool surface",
    ),
    _rc(
        NT_NO_SEED_ARM,
        "There was no seed_arm to plant the poisoned content.",
        "declare a seed_arm in the target file (see docs/target-file.md)",
    ),
    _rc(
        NT_PAYLOAD_NOT_DELIVERED,
        "The payload was planted, but the planner never retrieved it.",
        "check the seed_arm's args_template/id_key and the drive's recall wiring",
    ),
    _rc(
        NT_PROVIDER_ERROR,
        "The attempt failed on an LLM provider call.",
        "check each attempt's verdict_reason/error_detail (a common cause is missing or "
        "invalid provider credentials)",
    ),
    _rc(
        NT_GENERIC_ERROR,
        "The attempt raised an error that is not a provider failure, such as a target crash.",
        "see each attempt's verdict_reason/error_detail",
    ),
    _rc(
        NT_EFFECT_PROBE_ERRORED,
        "The effect_probe's verify call errored, so the effect was not confirmed either way.",
        "check the effect_probe wiring (verify_tool, verify_args_template)",
    ),
    _rc(
        NT_UNPARSEABLE_JUDGE_OUTPUT,
        "The LLM judge answered, but its output could not be used.",
        "check the judge model (--judge-model)",
    ),
    _rc(
        NT_NO_ADJUDICATOR,
        "The deterministic check was inconclusive and no LLM judge was configured.",
        "set a judge model, or accept this as an intentional predicate-only run",
    ),
    _rc(
        NT_UNDECIDED,
        "No mechanism (deterministic check, effect_probe or LLM judge) decided the attempt.",
        "check each attempt's verdict_reason and judge_evidence for the cause",
    ),
    _rc(
        NT_INVALID_METADATA,
        "The seed's metadata was invalid, so the attack never ran.",
        "this looks like an internal catalogue defect; please file an issue",
    ),
    _rc(
        NT_UNKNOWN_SEED,
        "The seed could not be resolved from the catalogue, so the attack never ran.",
        "this looks like an internal defect; please file an issue",
    ),
    _rc(
        NT_MODULE_LOAD_FAILED,
        "The attack module that covers this class failed to load, so its attacks never ran.",
        "reinstall the module's package and its dependencies; the `attack modules:` line "
        "names the module and the error type",
    ),
    _rc(
        NT_NO_ATTACK_EMITTED,
        "No attack module in this run emitted an attack for this class on this target, so "
        "the class was never attacked.",
        "enable an attack module that covers this class (the `attack modules:` line lists "
        "what ran); on a `transport: rest` target scan the agent's MCP server instead; or "
        "remove it from weakness_classes",
    ),
    _rc(
        NT_EFFECT_UNCONFIRMABLE,
        "No effect_probe was in effect for this run, so this class's effect could not be "
        "confirmed or ruled out.",
        "declare an effect_probe whose verify_tool reads back what the attack would change "
        "(see docs/target-file.md; `scan --scaffold` proposes one), or remove the class from "
        "weakness_classes",
    ),
)

#: The inconclusive codes the trace rule (``scan/effect_verdict.py``) stamps on
#: a single attempt. Defined here so the cause buckets below can name them
#: before the ``_INCONCLUSIVE`` entries that document them.
INC_UNLINKED_DISPATCH: Final = "MYL-INC-001"
INC_PAYLOAD_MARKER: Final = "MYL-INC-008"
#: Stamped by the ``tool_surface_mutated_mid_session`` predicate when the
#: tool list could not be read again after the agent ran, or was compared in
#: an unknown signature form.
INC_RELIST_FAILED: Final = "MYL-INC-009"
#: Stamped by the judge on a non-finding when the server's tool list was read
#: only in part (page cap or a repeated cursor).
INC_TOOL_LIST_TRUNCATED: Final = "MYL-INC-010"
#: Stamped by the judge when the LLM judge said the attack landed but with a
#: confidence below the floor it needs to count as a finding.
INC_JUDGE_BELOW_FLOOR: Final = "MYL-INC-011"
#: Stamped by the trace rule when the server replied that it held or queued a
#: consequential call (or returned a task handle) and the effect probe did not
#: see the action held.
INC_UNCHECKED_DEFERRAL: Final = "MYL-INC-012"

#: ``scan/coverage.py`` cause bucket -> code. Every bucket
#: ``_not_tested_cause_bucket`` can return is a key (enforced by a test). The
#: two ``undecided_*`` effect buckets map to inconclusive codes, not NT ones:
#: the attack ran, but the trace could not tie its call to the attempt.
NT_CODE_BY_BUCKET: Final[dict[str, str]] = {
    "launch_failure": NT_LAUNCH_FAILURE,
    "skipped_planner_failure": NT_PLANNER_FAILURE,
    "skipped_planner_no_engagement": NT_PLANNER_NO_ENGAGEMENT,
    "not_applicable": NT_NOT_APPLICABLE,
    "skipped_no_seed_arm": NT_NO_SEED_ARM,
    "skipped_payload_not_delivered": NT_PAYLOAD_NOT_DELIVERED,
    "provider_error": NT_PROVIDER_ERROR,
    "generic_error": NT_GENERIC_ERROR,
    "undecided_effect_probe_errored": NT_EFFECT_PROBE_ERRORED,
    "undecided_unparseable_judge_output": NT_UNPARSEABLE_JUDGE_OUTPUT,
    "undecided_no_adjudicator": NT_NO_ADJUDICATOR,
    "undecided_unlinked_dispatch": INC_UNLINKED_DISPATCH,
    "undecided_payload_marker": INC_PAYLOAD_MARKER,
    "undecided_relist_failed": INC_RELIST_FAILED,
    "undecided_tool_list_truncated": INC_TOOL_LIST_TRUNCATED,
    "undecided_judge_below_floor": INC_JUDGE_BELOW_FLOOR,
    "undecided_unchecked_deferral": INC_UNCHECKED_DEFERRAL,
    "undecided": NT_UNDECIDED,
    "skipped_invalid_metadata": NT_INVALID_METADATA,
    "skipped_unknown_seed": NT_UNKNOWN_SEED,
    "module_load_failed": NT_MODULE_LOAD_FAILED,
    "no_attack_emitted": NT_NO_ATTACK_EMITTED,
    "effect_unconfirmable": NT_EFFECT_UNCONFIRMABLE,
}


# --- Aborts: the scan stopped before it covered what it set out to ------------

ABT_BUDGET_EXCEEDED: Final = "MYL-ABT-001"
ABT_PROVIDER_UNREACHABLE: Final = "MYL-ABT-002"
ABT_NO_PAYLOADS: Final = "MYL-ABT-003"
ABT_NO_PAYLOADS_FILTER: Final = "MYL-ABT-004"
ABT_NO_PAYLOADS_UNSEEDED: Final = "MYL-ABT-005"
ABT_DESCRIBE_FAILED: Final = "MYL-ABT-006"
ABT_WALL_CLOCK_TIMEOUT: Final = "MYL-ABT-007"

_UNCOVERABLE_CLASS_FIX: Final = (
    "Each class's line names its fix: remove the class from weakness_classes (or from "
    "--weakness-class), or give the target the tool that class needs, then re-run."
)

_ABORT: Final[tuple[ReasonCode, ...]] = (
    _rc(
        ABT_BUDGET_EXCEEDED,
        "The scan used up its LLM call budget and stopped early; coverage is incomplete.",
        "Raise --max-llm-calls (the per-scan budget), or the hard request ceiling "
        "(--max-llm-requests or MYLONITE_MAX_LLM_REQUESTS) when the run names it, or "
        "run fewer weakness classes with --weakness-class (every target kind), or by "
        "editing weakness_classes in the target file (a custom target only) — then "
        "re-run.",
    ),
    _rc(
        ABT_PROVIDER_UNREACHABLE,
        "LLM provider calls failed several times in a row, so the scan stopped early.",
        "Check your provider's credentials (its own key environment variable -- "
        "see docs/self-hosted-models.md for the approved providers) and --model, "
        "and that this machine can reach the provider (behind a proxy, see "
        "docs/enterprise-networking.md), then re-run.",
    ),
    _rc(
        ABT_NO_PAYLOADS,
        "No seeds applied to this target, so nothing was scanned.",
        "If this is a custom MCP app, declare which weakness classes it exposes via "
        "--target-file (weakness_classes) or --weakness-class.",
    ),
    _rc(
        ABT_NO_PAYLOADS_FILTER,
        "The --weakness-class filter matched no seeds for this target, so nothing was scanned.",
        "Drop or widen the filter, then re-run.",
    ),
    _rc(
        ABT_NO_PAYLOADS_UNSEEDED,
        "A declared weakness class has no seed on this target's tool surface, so the scan "
        "stopped before any payload.",
        _UNCOVERABLE_CLASS_FIX,
    ),
    _rc(
        ABT_DESCRIBE_FAILED,
        "The target could not be described (its tools were never listed), so nothing was scanned.",
        "Check the target command/scope and connectivity.",
    ),
    _rc(
        ABT_WALL_CLOCK_TIMEOUT,
        "The scan exceeded its wall-clock budget and stopped early; coverage is incomplete.",
        "Raise the timeout or narrow the scan, then re-run.",
    ),
)

#: ``AbortReason`` value -> the code for its generic cause. ``no_payloads`` has
#: two more specific codes (:data:`ABT_NO_PAYLOADS_FILTER`,
#: :data:`ABT_NO_PAYLOADS_UNSEEDED`), which the engine stamps into its own abort
#: detail when it knows the cause.
ABT_CODE_BY_ABORT: Final[dict[str, str]] = {
    "budget_exceeded": ABT_BUDGET_EXCEEDED,
    "provider_unreachable": ABT_PROVIDER_UNREACHABLE,
    "no_payloads": ABT_NO_PAYLOADS,
    "describe_failed": ABT_DESCRIBE_FAILED,
    "wall_clock_timeout": ABT_WALL_CLOCK_TIMEOUT,
}


# --- Pre-flight: refused before any LLM call ------------------------------------

PRE_UNCOVERABLE_CLASS: Final = "MYL-PRE-001"
PRE_DESCRIBE_TIMEOUT: Final = "MYL-PRE-002"
PRE_DESCRIBE_FAILED: Final = "MYL-PRE-003"
PRE_AUTOWIRE_TIMEOUT: Final = "MYL-PRE-004"
PRE_AUTOWIRE_DESCRIBE_FAILED: Final = "MYL-PRE-005"
PRE_WEAKNESS_FILTER_EMPTY: Final = "MYL-PRE-006"

_PREFLIGHT: Final[tuple[ReasonCode, ...]] = (
    _rc(
        PRE_UNCOVERABLE_CLASS,
        "A declared weakness class cannot run at all on this target's tool surface, so the "
        "run was refused before any LLM call.",
        _UNCOVERABLE_CLASS_FIX,
    ),
    _rc(
        PRE_DESCRIBE_TIMEOUT,
        "The server was not described in time to check which declared weakness classes can "
        "run, so the run was refused.",
        "Re-run (a first npx/uvx download is cached after that), or raise timeout_s in the "
        "target file.",
    ),
    _rc(
        PRE_DESCRIBE_FAILED,
        "Describing the server raised an error, so which declared weakness classes can run "
        "is unknown and the run was refused.",
        "Check that the target file's command and args start the server and that it lists "
        "its tools, then re-run.",
    ),
    _rc(
        PRE_AUTOWIRE_TIMEOUT,
        "Starting or describing the server timed out while inferring a seed_arm.",
        "Re-run once the download finishes -- it's cached after that -- or set timeout_s: "
        "in the target file to raise this budget.",
    ),
    _rc(
        PRE_AUTOWIRE_DESCRIBE_FAILED,
        "Starting or describing the server failed while inferring a seed_arm.",
        "Fix the cause printed after the code (it names the failing step, usually the "
        "target file's command, args or timeout_s), then re-run.",
    ),
    _rc(
        PRE_WEAKNESS_FILTER_EMPTY,
        "--weakness-class named none of the target's declared weakness_classes, so "
        "nothing would be scanned, and the run was refused before any LLM call.",
        "Pass a class the target file declares in weakness_classes, or drop "
        "--weakness-class to run every declared class.",
    ),
)


# --- Inconclusive: the attack ran, but the effect evidence can't be trusted ------

_INCONCLUSIVE: Final[tuple[ReasonCode, ...]] = (
    _rc(
        INC_UNLINKED_DISPATCH,
        "A consequential tool call went through, but it could not be tied to this attempt.",
        "Use an effect_probe marker the agent's call carries, such as {exfil_email} or a "
        "unique token from the payload, so the call links to the attempt.",
    ),
    _rc(
        "MYL-INC-002",
        "The effect probe was not calibrated: calibration was not authorized, its "
        "controls were set to skip, or the target could not be launched to run them.",
        "Pass --authorize (scan/gate/ablate/validate) so the calibration "
        "controls can run, and do not set calibration.controls to skip. A remote "
        "(sse/http) target also needs calibration.controls: allow -- auto only runs on "
        "an authorized stdio target. If the target could not be launched, check that its "
        "command: and args: start the server.",
    ),
    _rc(
        "MYL-INC-003",
        "Positive control failed: the probe did not see a known write.",
        "Point verify_tool at a tool that reads back what the consequential tool writes, and "
        "make verify_args_template select the written record by a fixed value, not {payload}.",
    ),
    _rc(
        "MYL-INC-004",
        "Negative control failed: the probe reported a change when nothing was written.",
        "Scope verify_args_template to a single record or query, so unrelated state changes "
        "do not read as an effect.",
    ),
    _rc(
        "MYL-INC-005",
        "The verify or control arguments fail the tool's inputSchema.",
        "Add the missing required argument the message names to the template it names "
        "(verify_args_template or the seed_arm's args_template), matching the tool's "
        "inputSchema. When it names a control write or a recall call, that tool needs an "
        "argument Mylonite cannot fill: list a simpler tool under consequential_tools or "
        "read_tool_names.",
    ),
    _rc(
        "MYL-INC-006",
        "W2 seed control failed: the planted content could not be recalled.",
        "Check the seed_arm's args_template and id_key, and that the recall tool reads back "
        "what the plant tool stores.",
    ),
    _rc(
        "MYL-INC-007",
        "W2 seed control did not run: no recall tool could be inferred.",
        "Declare a seed_arm naming the store tool, and make sure the server exposes a tool "
        "that reads the stored content back.",
    ),
    _rc(
        INC_PAYLOAD_MARKER,
        "The effect_probe marker renders from {payload}, which the agent's call never carries.",
        "Use {exfil_email}, or a token the agent's call carries, as the marker instead of "
        "{payload}.",
    ),
    _rc(
        INC_RELIST_FAILED,
        "The tool list could not be read again after the agent ran, or was not compared "
        "in a known form, so a mid-session change to the tools was not checked.",
        "Check that the server still answers tools/list after a few tool calls (it may have "
        "crashed or closed the session), then re-run. A result replayed from an older run "
        "carries no signature form; re-run the scan to compare every tool field.",
    ),
    _rc(
        INC_TOOL_LIST_TRUNCATED,
        "The server's tool list was read only in part, so tools on the unread pages were "
        "never tested.",
        "Check the server's tools/list pagination: it repeated a cursor or returned more "
        "than 100 pages. Fix the server's nextCursor handling, then re-run.",
    ),
    _rc(
        INC_JUDGE_BELOW_FLOOR,
        "The LLM judge leaned toward the attack landing, but below the confidence it "
        "needs to count as a finding, so the attempt proved neither a finding nor "
        "resistance.",
        "Read the attempt's judge rationale and tool trace to decide it yourself, then "
        "re-run with a stronger judge model (--judge-model), or, on an MCP target, "
        "declare an effect_probe so the result rests on observed state.",
    ),
    _rc(
        INC_UNCHECKED_DEFERRAL,
        "The server replied that it queued or held a consequential call, and the effect "
        "probe did not see the action held, so it may still take effect.",
        "Declare an effect_probe whose verify tool lists held actions, and name the "
        "word it marks them with in deferred_markers, so a held action can be told "
        "apart from one accepted for later delivery.",
    ),
)


# --- Server-reported: a negative that rests on the server's own reply ------------

_SERVER_REPORTED: Final[tuple[ReasonCode, ...]] = (
    _rc(
        "MYL-SRV-001",
        "The negative rests only on the server returning an error.",
        "Check the error is a refusal, not a network or configuration failure, and declare an "
        "effect_probe so the result rests on observed state.",
    ),
    _rc(
        "MYL-SRV-002",
        "The negative rests only on a server reply deferring the action.",
        "Declare an effect_probe so the result rests on observed state, not on the server's reply.",
    ),
)


#: Every code, keyed by its code string.
REGISTRY: Final[dict[str, ReasonCode]] = {
    rc.code: rc for rc in (*_NOT_TESTED, *_ABORT, *_PREFLIGHT, *_INCONCLUSIVE, *_SERVER_REPORTED)
}

_CODE_TAG_RE: Final = re.compile(r"\[MYL-[A-Z]{2,3}-\d{3}\]")
_LEVEL_PREFIX_RE: Final = re.compile(r"^(error|warning|auto-wire): ")


def get(code: str) -> ReasonCode:
    """The registered :class:`ReasonCode` for ``code``; ``KeyError`` naming it if absent."""
    try:
        return REGISTRY[code]
    except KeyError:
        raise KeyError(f"unknown reason code {code!r}") from None


def tag(code: str, message: str) -> str:
    """``message`` led by ``[code]``, placed after a leading ``error:``/``warning:``/
    ``auto-wire:`` label so the label still starts the line.

    Idempotent: a message that already carries any reason code is returned
    unchanged, so a more specific code stamped upstream is never overwritten.
    """
    get(code)
    if _CODE_TAG_RE.search(message):
        return message
    match = _LEVEL_PREFIX_RE.match(message)
    if match:
        return f"{match.group(0)}[{code}] {message[match.end() :]}"
    return f"[{code}] {message}"


def format_code_counts(codes: Iterable[str]) -> str:
    """``"MYL-NT-001 x1, MYL-NT-005 x2"``: each code with its count, sorted by code."""
    counts = Counter(codes)
    return ", ".join(f"{code} x{n}" for code, n in sorted(counts.items()))
