"""AgentDojo (ETH SPY Lab, MIT) adapter — score Mylonite's judge on REAL runs.

Unlike InjecAgent (where we run a model ourselves), AgentDojo ships **recorded
agent trajectories** under ``runs/<model>/<suite>/<user_task>/<attack>/injection_task_N.json``
for dozens of models — including older/weaker ones that actually fell for attacks.
Each run carries the full ``messages`` trajectory, the ``injections`` payload, and
a ground-truth **``security``** label.

That makes AgentDojo the cleanest closure for "verify the judge's positive class":
its released runs contain **real third-party positives** (``security == False`` =
the injection succeeded), so we can score Mylonite's success-judge against an
independent label *without running a model ourselves* and *without synthesising*
anything.

Semantics (verified against the data): ``security == True`` → the agent resisted
(secure); ``security == False`` → the attack succeeded. So
``benchmark_success = not security``.

Mapping to a Mylonite ``Transcript``: AgentDojo injection goals are multi-step
tasks, not a single attacker tool, so there is no ``consequential_tool`` — scoring
uses the **LLM judge** (the deterministic predicate defers), with the injection
text as the attacker payload. Crosswalk: ``agentdojo: injection -> [W2]``.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from verification.transcript import ToolCall, Transcript

logger = logging.getLogger(__name__)


def _tool_calls_from_messages(messages: list[dict[str, Any]]) -> tuple[list[ToolCall], str]:
    """Flatten AgentDojo ``messages`` into ToolCalls + the final assistant text.

    Assistant tool calls look like ``{"function": name, "args": {...}, "id": ...}``;
    tool results are ``{"role":"tool","content":..,"tool_call_id":..,"error":..}``.
    """
    results: dict[str, tuple[str, bool]] = {}
    for m in messages:
        if m.get("role") == "tool":
            cid = str(m.get("tool_call_id", ""))
            results[cid] = (str(m.get("content", "") or ""), bool(m.get("error")))

    calls: list[ToolCall] = []
    final_text = ""
    for m in messages:
        if m.get("role") == "assistant":
            content = m.get("content")
            if isinstance(content, str) and content.strip():
                final_text = content
            for tc in m.get("tool_calls") or []:
                name = str(tc.get("function", "") or "")
                if not name:
                    continue
                cid = str(tc.get("id", ""))
                result, is_error = results.get(cid, ("", False))
                args = tc.get("args") if isinstance(tc.get("args"), dict) else {}
                calls.append(ToolCall(tool=name, args=args, result=result[:800], is_error=is_error))
    return calls, final_text


def run_to_transcript(run: dict[str, Any]) -> Transcript:
    """Convert one AgentDojo run dict into a Mylonite Transcript (ground-truth labelled)."""
    suite = str(run.get("suite_name", "?"))
    user_task = str(run.get("user_task_id", "?"))
    injection_task = str(run.get("injection_task_id", "?"))
    injections = run.get("injections", {}) or {}
    attacker_instruction = " ".join(str(v) for v in injections.values()) if injections else ""
    calls, final_text = _tool_calls_from_messages(run.get("messages", []) or [])
    return Transcript(
        case_id=f"agentdojo-{suite}-{user_task}-{injection_task}",
        dataset="agentdojo",
        split="injection",
        attack_type=str(run.get("attack_type", "")),
        attacker_tool="",  # multi-step goal, not a single tool -> LLM judge decides
        attacker_instruction=attacker_instruction,
        model=str(run.get("pipeline_name", "")),
        tool_calls=calls,
        final_output=final_text,
        benchmark_success=(run.get("security") is False),  # security False => attack succeeded
        benchmark_metric="agentdojo-security",
        synthetic=False,
        agent_mode="third-party-run",
    )


def load_run_transcripts(runs_dir: Path, *, limit: int | None = None) -> list[Transcript]:
    """Parse every ``*.json`` AgentDojo run under ``runs_dir`` into Transcripts.

    A file that isn't a run at all (missing ``security``/``messages``) is
    silently filtered — ``rglob`` sweeps the whole tree and unrelated JSON
    files are expected there. A file that DOES look like a run but fails to
    parse or convert (corrupt JSON, or a shape ``run_to_transcript`` can't
    handle) is counted and logged as a skip (DCR-0009) rather than either
    crashing the whole call — discarding every transcript already
    accumulated from files that sorted before it (#39) — or going silent, so
    "0 runs matched" reads differently from "N runs were dropped".
    """
    files = sorted(p for p in runs_dir.rglob("*.json") if p.is_file())
    out: list[Transcript] = []
    skipped = 0
    for p in files:
        if limit is not None and len(out) >= limit:  # DCR-0012: before the append
            break
        try:
            run = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if not (isinstance(run, dict) and "security" in run and "messages" in run):
            continue
        try:
            out.append(run_to_transcript(run))
        except (AttributeError, TypeError, KeyError) as exc:
            skipped += 1
            logger.warning("load_run_transcripts: skipping malformed run %s: %r", p, exc)
    if skipped:
        logger.warning(
            "load_run_transcripts: %d malformed run(s) skipped under %s (%d transcripts loaded)",
            skipped,
            runs_dir,
            len(out),
        )
    return out
