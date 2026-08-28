"""Single source of truth for guarded-twin fidelity: the marker and the two claims.

A KEPT differential means something different depending on what the *guarded* side
of it actually was:

* **Server-layer twin** — the operator's own control, toggled via ``control_env``
  (or the in-repo ``server_guarded.py`` for a reference target). Disabling their
  control let the attack through and re-enabling it stopped it, so their
  implementation is what carries the security. The strong claim is *earned*.
* **Synthetic boundary twin** — Mylonite's own canonical control, applied at the
  adapter boundary by ``scan.control_shim``. The attack is real and this class of
  control closes it, but the operator's implementation was never measured.

``DifferentialValidator`` knows which one it ran and stamps a machine-readable
marker into ``ValidationReport.notes``; every surface that renders a verdict reads
it back. That worked, but the marker literal and the claim sentences were re-spelled
in five modules, so a surface could be added (or edited) without picking up the
distinction -- which is exactly what happened to ``report/sarif.py``, the artefact
uploaded to GitHub code scanning, and to the ``plugins/_mcp/twins.py`` run banner,
which made the strong claim on the *synthetic* path and not on the server-layer one.

Everything that writes or reads the fidelity now goes through here.
``tests/test_twin_fidelity_single_source.py`` fails if a literal is reintroduced
elsewhere in ``src/``.
"""

from __future__ import annotations

from typing import Any, Literal

#: Which build the guarded side of a differential actually was.
TwinLayer = Literal["server", "boundary"]

#: The marker bodies, matched as substrings of ``ValidationReport.notes``. These are
#: the exact strings the readers grepped for before this module existed, so notes
#: written by an older version still resolve correctly.
MARKER_SERVER_LAYER = "guarded-twin=server-layer"
MARKER_SYNTHETIC = "guarded-twin=synthetic-boundary"

#: Earned only by a server-layer twin. Deliberately un-punctuated at the end so a
#: caller can embed it mid-sentence or terminate it as it likes.
PROOF_CLAIM_SERVER = "the safeguard, not the model, carries the security"

#: What a synthetic boundary twin actually proves. It says the attack is real and
#: names what was NOT measured, because that is the part a reader will otherwise
#: assume in Mylonite's favour.
PROOF_CLAIM_BOUNDARY = (
    "a canonical control of this class closes this attack with the model held "
    "constant - the attack is real and this control class stops it. The guarded "
    "side was Mylonite's boundary shim, not your implementation, so this does not "
    "establish that your own control carries the security"
)


def format_marker(*, server_layer: bool) -> str:
    """The bracketed marker to append to ``ValidationReport.notes``.

    Terse and ASCII: ``notes`` is serialized to JSON and read by humans in a
    terminal, so it stays free of anything that needs escaping.
    """
    return f"[{MARKER_SERVER_LAYER if server_layer else MARKER_SYNTHETIC}]"


def guarded_twin_layer(report: Any | None, explicit: bool | None = None) -> TwinLayer:
    """Resolve whether the guarded twin was the operator's REAL server-side control.

    An explicit ``explicit`` (from a caller with direct access to
    ``TwinPlan.guarded_is_server_layer``) always wins. Otherwise fall back to the
    marker :func:`format_marker` stamps into ``report.notes`` -- this is how
    ``run_gate`` gets an honest answer without any new plumbing through the
    orchestrator, since it only ever holds a ``ValidationReport``, never the
    ``TwinPlan`` that produced it.

    Absent either signal, default to ``"boundary"``: a differential must never be
    captioned "server-layer verified" without positive evidence. Every caller
    inherits that default, so the failure mode of a missing marker is an
    *under*-claim, never an over-claim.
    """
    if explicit is not None:
        return "server" if explicit else "boundary"
    notes = getattr(report, "notes", "") or ""
    return "server" if MARKER_SERVER_LAYER in notes else "boundary"


def proof_claim(layer: TwinLayer) -> str:
    """The claim a differential on ``layer`` is entitled to make."""
    return PROOF_CLAIM_SERVER if layer == "server" else PROOF_CLAIM_BOUNDARY
