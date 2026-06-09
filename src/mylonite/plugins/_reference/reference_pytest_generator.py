"""Reference pytest generator — emits a placeholder test file."""

from __future__ import annotations

from typing import ClassVar, Literal

from mylonite.contracts import ExploitRecord, GeneratedTest, TestGeneratorBase
from mylonite.contracts.test_generator import CONTRACT_VERSION

_TEMPLATE = '''"""Auto-generated security regression test ({pattern_id}).

Reference plugin output — replace with a real generator before relying on
this for CI gating. Phase 1 ships the real test generator.
"""

import pytest


@pytest.mark.skip(reason="reference generator stub")
def test_security_{slug}():
    """Reproduces exploit {pattern_id} against {target_id}."""
    assert False, "stub — Phase 1 generator replaces this body"
'''


class ReferencePytestGenerator(TestGeneratorBase):
    """Stub generator that emits a pytest file skipping itself."""

    contract_version: ClassVar[str] = CONTRACT_VERSION

    def framework(self) -> Literal["pytest", "jest"]:
        return "pytest"

    def emit(self, exploit: ExploitRecord) -> GeneratedTest:
        slug = exploit.pattern_id.replace("-", "_")
        source = _TEMPLATE.format(
            pattern_id=exploit.pattern_id,
            slug=slug,
            target_id=exploit.target_id,
        )
        return GeneratedTest(
            framework="pytest",
            filename=f"test_security_{slug}.py",
            source=source,
            exploit=exploit,
        )
