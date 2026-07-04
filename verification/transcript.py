"""Transcript schema — the boundary between the ``record`` and ``score`` steps.

The ``record`` step runs a real model over a benchmark's attack scenarios and
emits ``Transcript`` rows (one per case): the agent's tool calls, its final
output, and ``benchmark_success`` — the benchmark's OWN success rule applied to
that run (third-party ground truth). The ``score`` step is hermetic: it replays
these transcripts through Mylonite's success-judge and compares the judge's
verdict to ``benchmark_success``. Persisting the transcript makes scoring
reproducible with no model and no network.

Transcripts serialise as JSONL (one ``Transcript`` JSON object per line).
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

from pydantic import BaseModel


class ToolCall(BaseModel):
    """One tool invocation in an agent trajectory.

    Field names match what Mylonite's effect-trace machinery reads
    (``tool``/``args``/``result``/``is_error``), so a list of these serialises
    straight into ``AdapterResponse.metadata['effect_trace']``.
    """

    tool: str
    args: dict[str, Any] = {}
    result: str = ""
    is_error: bool = False


class Transcript(BaseModel):
    """One benchmark case as actually run by a model, plus the benchmark verdict."""

    case_id: str
    dataset: str  # "injecagent" | "agentdojo"
    split: str  # crosswalk label, e.g. "dh" | "ds" | "injection"
    attack_type: str = ""  # the benchmark's fine-grained type, for reporting
    attacker_tool: str  # the tool a successful attack makes the agent call
    attacker_instruction: str = ""  # the injected payload (for the judge prompt)
    model: str = ""  # model used at record time ("" for synthetic fixtures)
    tool_calls: list[ToolCall] = []  # the agent's actions (the trajectory)
    final_output: str = ""
    benchmark_success: bool  # the benchmark's OWN rule applied at record time
    benchmark_metric: str = "asr-all"  # which rule produced benchmark_success
    synthetic: bool = False  # True for committed illustrative fixtures (not a real run)
    # "faithful" = neutral base agent (fair ASR). "elicit-positives" = a compliant
    # agent used only to manufacture successful attacks for judge verification (ASR
    # NOT fair).
    agent_mode: str = "faithful"


def write_transcripts(path: Path, transcripts: Iterable[Transcript]) -> int:
    """Write transcripts as JSONL; returns the count written."""
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8") as fh:
        for t in transcripts:
            fh.write(t.model_dump_json() + "\n")
            n += 1
    return n


def read_transcripts(path: Path) -> Iterator[Transcript]:
    """Yield ``Transcript`` rows from a JSONL file, skipping blank lines."""
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield Transcript.model_validate(json.loads(line))
