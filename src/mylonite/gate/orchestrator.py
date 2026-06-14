"""Gate orchestration (filled in Task 8)."""

from dataclasses import dataclass
from typing import Any


@dataclass
class GateResult:  # pragma: no cover - fields finalised in Task 8
    exit_code: int


def run_gate(*args: Any, **kwargs: Any) -> GateResult:  # pragma: no cover - replaced in Task 8
    raise NotImplementedError
