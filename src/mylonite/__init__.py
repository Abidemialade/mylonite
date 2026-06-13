"""Mylonite — open-source framework for AI-layer security testing.

See ``ROADMAP.md`` for the phased build plan and ``README.md`` for the quickstart.
"""

from __future__ import annotations

import os

# Use litellm's wheel-bundled model-cost map instead of fetching the remote one
# at import time. The remote fetch logs a noisy ``CERTIFICATE_VERIFY_FAILED``
# warning on a TLS-inspecting-proxy machine (it runs before any truststore is
# injected) and needs the network at all. This only affects cost/token-accounting
# metadata — never provider routing — and Mylonite never gates on cost. Set as a
# default so a user who wants the remote map can still opt back in. Must run before
# any submodule imports litellm (scan.providers et al. import it at module top).
os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")

from mylonite.version import __version__

__all__ = ["__version__"]
