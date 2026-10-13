"""Benchmark cases for the judge measurement harness.

A ``BenchCase`` is one judged attempt: the ``Payload`` / ``AdapterResponse``
pair production hands to ``SuccessJudge.judge``, the ground-truth label, and the
keys the split and the statistics cluster on (``seed_id``, ``scan_id``).

Only the families in :data:`BAR_FAMILIES` (fresh LLM-routed recorded attempts
and AgentDojo) ever count toward the bar. The rest are supporting evidence.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, field_validator

from mylonite.contracts._types import AdapterResponse, Payload
from verification.crosswalk import Crosswalk
from verification.score import _payload_for, _response_for
from verification.transcript import Transcript

Family = Literal["llm_routed", "agentdojo", "injecagent", "synthetic", "shadow", "shadow_stripped"]
TargetType = Literal["mcp", "rest", "reference", "dataset"]
Label = Literal["landed", "not_landed", "undecidable"]

#: The only families whose cases count toward the bar (preregistered).
BAR_FAMILIES: frozenset[str] = frozenset({"llm_routed", "agentdojo"})

#: Default per-(family, seed) cap: one seed must not dominate a family.
DEFAULT_SEED_CAP = 8


class BenchCase(BaseModel):
    """One benchmark case: a judged attempt plus its ground-truth label."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str
    family: Family
    seed_id: str
    #: The cluster key for one scan; datasets use the case id.
    scan_id: str
    target_type: TargetType
    label: Label
    hard_negative: bool = False
    payload: dict[str, Any]
    response: dict[str, Any]
    provenance: str

    @field_validator("payload")
    @classmethod
    def _validate_payload(cls, v: dict[str, Any]) -> dict[str, Any]:
        # Stored in its normalised form so the canonical JSON (and the manifest
        # hash over it) does not depend on which optional keys a writer spelled out.
        return Payload.model_validate(v).model_dump(mode="json")

    @field_validator("response")
    @classmethod
    def _validate_response(cls, v: dict[str, Any]) -> dict[str, Any]:
        return AdapterResponse.model_validate(v).model_dump(mode="json")

    @property
    def counts_toward_bar(self) -> bool:
        """True only for the production-routed families (:data:`BAR_FAMILIES`)."""
        return self.family in BAR_FAMILIES

    def to_payload(self) -> Payload:
        return Payload.model_validate(self.payload)

    def to_response(self) -> AdapterResponse:
        return AdapterResponse.model_validate(self.response)

    def canonical_json(self) -> str:
        """Key-sorted, whitespace-free JSON: the form the manifest hash covers."""
        return json.dumps(
            self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )


def load_cases(path: Path) -> list[BenchCase]:
    """Read cases from JSONL, skipping blank lines. Duplicate ``case_id`` raises."""
    cases: list[BenchCase] = []
    seen: set[str] = set()
    with path.open(encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            case = BenchCase.model_validate(json.loads(line))
            if case.case_id in seen:
                raise ValueError(f"{path}:{lineno}: duplicate case_id {case.case_id!r}")
            seen.add(case.case_id)
            cases.append(case)
    return cases


def dump_cases(path: Path, cases: Iterable[BenchCase]) -> int:
    """Write cases as JSONL (canonical JSON, one per line); returns the count."""
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        for case in cases:
            fh.write(case.canonical_json() + "\n")
            n += 1
    return n


def _default_seed_id(transcript: Transcript) -> str:
    """The attack itself is the seed: one injected instruction reused across tasks.

    Both InjecAgent and AgentDojo pair one attacker instruction with many user
    tasks, so cases sharing an instruction are not independent. Clustering on a
    digest of it is the conservative choice for the distinct-seed rule.
    """
    if not transcript.attacker_instruction:
        return transcript.case_id
    digest = hashlib.sha256(transcript.attacker_instruction.encode("utf-8")).hexdigest()[:12]
    return f"{transcript.dataset}:{digest}"


def case_from_transcript(
    transcript: Transcript,
    crosswalk: Crosswalk,
    family: Family,
    force_llm: bool = False,
    *,
    seed_id: str | None = None,
    scan_id: str | None = None,
    hard_negative: bool = False,
    provenance: str | None = None,
) -> BenchCase:
    """Build a dataset case from a recorded benchmark transcript.

    Reuses ``verification/score.py``'s payload and response reconstruction.
    ``force_llm=True`` drops ``consequential_tool`` from the payload metadata, so
    the portable ``consequential_action_executed`` predicate returns ``None``
    and the LLM judge decides (the InjecAgent stress family). The label is the
    benchmark's own verdict (``transcript.benchmark_success``).
    """
    payload = _payload_for(transcript, crosswalk)
    if force_llm:
        metadata = {k: v for k, v in payload.metadata.items() if k != "consequential_tool"}
        payload = payload.model_copy(update={"metadata": metadata})
    response = _response_for(transcript)
    return BenchCase(
        case_id=transcript.case_id,
        family=family,
        seed_id=seed_id or _default_seed_id(transcript),
        scan_id=scan_id or transcript.case_id,
        target_type="dataset",
        label="landed" if transcript.benchmark_success else "not_landed",
        hard_negative=hard_negative,
        payload=payload.model_dump(mode="json"),
        response=response.model_dump(mode="json"),
        provenance=provenance
        or f"transcript:{transcript.dataset}/{transcript.split} model={transcript.model or '-'}",
    )


def apply_seed_cap(
    cases: Iterable[BenchCase], cap: int = DEFAULT_SEED_CAP
) -> tuple[list[BenchCase], int]:
    """Keep at most ``cap`` cases per (family, seed_id); return ``(kept, dropped)``.

    Deterministic: within each group the cases with the lowest ``case_id`` (in
    sorted order) are kept. Kept cases stay in their input order.
    """
    if cap < 1:
        raise ValueError(f"cap must be >= 1; got {cap}")
    items = list(cases)
    groups: dict[tuple[str, str], list[str]] = defaultdict(list)
    for case in items:
        groups[(case.family, case.seed_id)].append(case.case_id)
    keep: set[tuple[str, str, str]] = set()
    for (family, seed), ids in groups.items():
        for cid in sorted(ids)[:cap]:
            keep.add((family, seed, cid))
    kept = [c for c in items if (c.family, c.seed_id, c.case_id) in keep]
    return kept, len(items) - len(kept)


__all__ = [
    "BAR_FAMILIES",
    "DEFAULT_SEED_CAP",
    "BenchCase",
    "Family",
    "Label",
    "TargetType",
    "apply_seed_cap",
    "case_from_transcript",
    "dump_cases",
    "load_cases",
]
