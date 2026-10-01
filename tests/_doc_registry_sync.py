"""Shared Markdown-section parsing for doc <-> registry two-way checks.

`tests/test_docs_consistency.py` (the reason-code heading pin) and
`tests/test_docs_registry_ratchet.py` (the CLI-flag / testkit / reason-code
two-way ratchet) both need to split a docs page into `## <heading>` sections.
This is the one place that parsing lives, so the two tests can never read a
page two different ways -- a prior version had the same `re.split(r"^## ",
...)` inlined twice.

Not named `test_*` so pytest does not try to collect it as a test module.
"""

from __future__ import annotations

import re


def markdown_sections_by_heading(page_text: str, *, marker: str = "## ") -> dict[str, str]:
    """Split ``page_text`` at every line starting with ``marker`` (default an
    H2, ``"## "``) into ``{heading_text: section_body}``.

    ``section_body`` includes the heading's own trailing text as its first
    line and runs up to (not including) the next heading with the SAME
    marker -- a lower-level heading (e.g. `### ` under a `## ` marker) stays
    inside its parent's body rather than starting a new entry. Text before
    the first matching heading is dropped; a caller that needs it should
    slice ``page_text`` itself (``page_text.split(marker, 1)[0]`` would be
    wrong once nested headings are involved, so this function doesn't do it
    for you).
    """
    sections = re.split(rf"^{re.escape(marker)}", page_text, flags=re.MULTILINE)
    return {s.splitlines()[0].strip(): s for s in sections[1:]}


def reason_code_headings(page_text: str) -> set[str]:
    """Every ``MYL-xxx-nnn``-shaped ``## `` heading on a reason-codes-style page."""
    return {h for h in markdown_sections_by_heading(page_text) if h.startswith("MYL-")}
