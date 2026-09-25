"""Pytest plugin that registers the markers mylonite-emitted tests carry.

Auto-loaded for any pytest invocation in an environment where ``mylonite`` is
installed, via the ``pytest11`` entry point declared in ``pyproject.toml``. Its
sole job is to register — warning-free — the bounded set of markers the
reference pytest generator emits:

* ``mylonite_security`` — flags a Mylonite-generated security regression test.
* ``owasp_llm01`` .. ``owasp_llm10`` — OWASP LLM Top 10 (2025) category.
* ``owasp_asi01`` .. ``owasp_asi10`` — OWASP Agentic Security Initiative (2026).
* ``atlas_<id>`` — one per MITRE ATLAS technique in the bundled taxonomy
  (e.g. ``atlas_aml_t0051``).
* ``nist_<id>`` — one per NIST AI RMF subcategory in the bundled taxonomy
  (e.g. ``nist_measure_2_6``).

Without this registration an emitted test would raise ``PytestUnknownMarkWarning``,
which the project's ``filterwarnings = ["error", ...]`` config promotes to a
failure. The ATLAS / NIST marker namespaces are bounded by the bundled
taxonomy, so they ARE registered here (sanitised via :func:`_marker_name`);
their raw IDs also ride in the emitted test's docstring.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from mylonite.taxonomy import load_atlas_techniques, load_nist_ai_rmf

if TYPE_CHECKING:
    import pytest

#: The base marker every Mylonite-generated test carries.
MYLONITE_SECURITY_MARKER = "mylonite_security"

#: Set to ``"1"`` in the CI job that runs the committed gate to require that the
#: gate actually ran. The scaffolded ``mylonite-gate.yml`` sets it. Unset (the
#: default everywhere else), the plugin only registers markers.
REQUIRE_GATE_RUN_ENV = "MYLONITE_REQUIRE_GATE_RUN"

#: The exact set of OWASP marker names this plugin registers. The generator
#: imports this and emits an ``@pytest.mark.owasp_*`` marker ONLY when its
#: derived name is in this set — so the generator can never emit a marker the
#: plugin doesn't register (which, under ``filterwarnings=error``, would turn a
#: consumer's committed test into a hard collection error). Out-of-range OWASP
#: IDs fall back to the docstring, like out-of-taxonomy ATLAS/NIST IDs.
REGISTERED_OWASP_MARKERS: frozenset[str] = frozenset(
    [f"owasp_llm{n:02d}" for n in range(1, 11)] + [f"owasp_asi{n:02d}" for n in range(1, 11)]
)


def _marker_name(prefix: str, taxonomy_id: str) -> str:
    """Sanitise a taxonomy ID into a ``prefix``-namespaced pytest marker name.

    Non-alphanumeric characters collapse to ``_`` and the whole name lowercases,
    so ``AML.T0051`` → ``atlas_aml_t0051`` and ``MEASURE-2.6`` → ``nist_measure_2_6``.
    Deterministic; used by BOTH this plugin and the reference generator so the
    emitted marker names match the registered set exactly.
    """
    return f"{prefix}_" + "".join(c if c.isalnum() else "_" for c in taxonomy_id).lower()


#: The exact set of MITRE ATLAS marker names this plugin registers, one per
#: technique in the bundled taxonomy. The generator emits ``@pytest.mark.atlas_*``
#: ONLY for names in this set (out-of-taxonomy IDs fall back to the docstring).
REGISTERED_ATLAS_MARKERS: frozenset[str] = frozenset(
    _marker_name("atlas", t.id) for t in load_atlas_techniques()
)

#: The exact set of NIST AI RMF marker names this plugin registers, one per
#: subcategory in the bundled taxonomy. Same registered-set contract as ATLAS.
REGISTERED_NIST_MARKERS: frozenset[str] = frozenset(
    _marker_name("nist", s.id) for s in load_nist_ai_rmf()
)


def pytest_configure(config: pytest.Config) -> None:
    """Register the mylonite-emitted markers so they collect warning-free.

    When :data:`REQUIRE_GATE_RUN_ENV` is ``"1"``, also register the check that
    fails the session if the committed gate did not run (see ``_GateRunCheck``).
    """
    if os.environ.get(REQUIRE_GATE_RUN_ENV) == "1":
        config.pluginmanager.register(_GateRunCheck(), "mylonite-require-gate-run")
    config.addinivalue_line(
        "markers",
        f"{MYLONITE_SECURITY_MARKER}: a Mylonite-generated security regression test",
    )
    for n in range(1, 11):
        config.addinivalue_line(
            "markers",
            f"owasp_llm{n:02d}: OWASP LLM Top 10 (2025) category LLM{n:02d}",
        )
        config.addinivalue_line(
            "markers",
            f"owasp_asi{n:02d}: OWASP Agentic Security Initiative (2026) category ASI{n:02d}",
        )
    for name in sorted(REGISTERED_ATLAS_MARKERS):
        config.addinivalue_line(
            "markers",
            f"{name}: MITRE ATLAS technique (bundled taxonomy)",
        )
    for name in sorted(REGISTERED_NIST_MARKERS):
        config.addinivalue_line(
            "markers",
            f"{name}: NIST AI RMF subcategory (bundled taxonomy)",
        )


class _GateRunCheck:
    """Fail the session when the committed gate did not run.

    Registered only when :data:`REQUIRE_GATE_RUN_ENV` is ``"1"``. A live gate
    test for a custom target is skipped unless ``MYLONITE_LIVE_TARGET=1`` is set,
    which is the right default for a keyless local ``pytest``. In the CI job
    whose purpose is to run that test, a skip means the gate checked nothing, so
    this makes two cases fail the session:

    * a ``mylonite_security`` test was selected but skipped;
    * no ``mylonite_security`` test was selected at all (an empty or moved
      gate directory).

    Tests without the marker are never inspected.
    """

    def __init__(self) -> None:
        self.selected = 0
        self.skipped: list[str] = []

    def pytest_collection_finish(self, session: pytest.Session) -> None:
        self.selected = sum(
            1 for item in session.items if item.get_closest_marker(MYLONITE_SECURITY_MARKER)
        )

    def pytest_runtest_logreport(self, report: pytest.TestReport) -> None:
        if report.skipped and MYLONITE_SECURITY_MARKER in report.keywords:
            self.skipped.append(report.nodeid)

    def _problem(self) -> str | None:
        if self.skipped:
            return (
                f"{len(self.skipped)} Mylonite gate test(s) were skipped, so the gate "
                "checked nothing. Set MYLONITE_LIVE_TARGET=1 (and the provider key) "
                "in this job: " + ", ".join(self.skipped)
            )
        if self.selected == 0:
            return (
                "no Mylonite gate test was collected. Check that pytest is pointed at "
                "the committed gate directory."
            )
        return None

    def pytest_sessionfinish(self, session: pytest.Session, exitstatus: int) -> None:
        import pytest

        if session.config.option.collectonly:
            return
        if self._problem() is not None and exitstatus == pytest.ExitCode.OK:
            session.exitstatus = pytest.ExitCode.TESTS_FAILED

    def pytest_terminal_summary(self, terminalreporter: pytest.TerminalReporter) -> None:
        if terminalreporter.config.option.collectonly:
            return
        problem = self._problem()
        if problem is not None:
            terminalreporter.write_line(f"{REQUIRE_GATE_RUN_ENV}: {problem}", red=True)
