"""Judge measurement harness: score Mylonite's LLM judge against a preregistered bar.

Runs benchmark cases through the real :class:`mylonite.scan.judge.SuccessJudge`,
built exactly as production builds it, and scores the single-call result with
two-sided Wilson 95% intervals, a seed-clustered bootstrap and a frozen
dev/test split. Offline-replayable: recorded judge replies replay keyless and
give byte-identical outcomes.

Modules:

* :mod:`.cases` -- the ``BenchCase`` schema, JSONL I/O, transcript conversion,
  the per-seed cap.
* :mod:`.split` -- the seed/scan-clustered dev/test split and its manifest.
* :mod:`.stats` -- Wilson intervals, the cluster bootstrap, the bar evaluation.
* :mod:`.runner` -- judge one case; run many across models and repeats.
* :mod:`.report` -- the summary dict and its Markdown rendering.

The CLI is ``scripts/measure_judge.py``. Nothing here ships in the wheel.
"""

from __future__ import annotations
