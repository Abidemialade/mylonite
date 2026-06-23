"""Mylonite third-party verification harness.

A tiered system for checking Mylonite's claims against ground truth Mylonite did
NOT author. Unlike ``mylonite.corpus`` (which scores the in-repo kitchen-sink
twins — ground truth we wrote), this harness scores Mylonite against external,
independently-published sources:

- **Layer 1** — runnable vulnerable targets (DVAA, ...): point Mylonite's full
  pipeline at apps we didn't write and score recall vs their published checks.
- **Layer 2** — academic benchmarks (InjecAgent, AgentDojo): verify Mylonite's
  success-judge against the benchmark's OWN success rule, on transcripts from a
  real model run (record -> score), and report an ASR comparable to their public
  leaderboard.
- **Layer 3** — production-grade sources: precision / false-positive control on
  well-built real servers + real CVEs (largely exploratory).

This package lives OUTSIDE ``src/mylonite`` and is excluded from the wheel — it
consumes the published package as a library. External datasets/targets are
fetched at pinned commits/digests (see ``verification/SOURCE.md``), never
vendored. The one Mylonite-authored artefact is ``crosswalk.yaml`` (external
label -> W-class), isolated so its subjectivity is reviewable.
"""

from __future__ import annotations
