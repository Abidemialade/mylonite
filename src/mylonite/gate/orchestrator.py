"""Gate orchestration (filled in Task 8)."""

from dataclasses import dataclass


@dataclass
class GateResult:  # pragma: no cover - fields finalised in Task 8
    exit_code: int


def run_gate(*args, **kwargs) -> GateResult:  # pragma: no cover - replaced in Task 8
    raise NotImplementedError
