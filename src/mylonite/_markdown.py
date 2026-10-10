"""Markdown-safe encoding for target-derived text (F9).

Any string a scanned target returns -- a tool name, an argument value, a
free-text detail -- can end up quoted verbatim in the gate PR body, the
SARIF message, or the JSON bundle's ``label`` field. All three are rendered
as Markdown somewhere downstream (GitHub renders the PR body; a SARIF
viewer or the bundle's own consumer may render its text the same way), so a
value containing a backtick can close an inline code span early and let the
rest of the target's text render as structured Markdown -- a link, an
image, bold text or a heading the target chose, not Mylonite.

``code_span()`` is the single place that quotes such a value as an inline
code span the value's own content cannot escape from: the fence is always
longer than the longest backtick run already present (the CommonMark
backtick-fence rule -- a fence of N backticks is only closed by a run of at
least N backticks, so making the fence one longer than anything inside the
value guarantees the value's own backticks can never close it early), and a
value that starts or ends with a backtick gets a single space of padding on
that side so the fence doesn't read as touching the value's own backtick.
"""

from __future__ import annotations

import re
from typing import Any

__all__ = ["code_span", "strip_controls"]

#: C0 controls (0x00-0x1F) and C1 controls / DEL (0x7F-0x9F) -- CR/LF
#: included: a literal newline inside an inline code span ends the span's
#: single line just as surely as an unescaped backtick ends its fence, and
#: a raw C1 control is itself a terminal-escape building block on some
#: renderers. Unlike the terminal-output stripper in ``_cli_io.py``, this
#: one does NOT keep ``\n``/``\t`` -- there is no legitimate multi-line or
#: tab-formatted inline code span in a PR body/SARIF message/bundle label.
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")

_BACKTICK_RUN_RE = re.compile(r"`+")


def strip_controls(value: Any) -> str:
    """Strip CR/LF and C0/C1 control characters from ``value``.

    The control-stripping half of :func:`code_span`, exposed on its own for
    a target-derived value that must NOT be fenced as an inline code span
    (e.g. it is interpolated into a YAML ``config_snippet`` as a literal
    key, where wrapping it in backticks would change the key itself and
    break a consumer that parses the snippet back out) but still must not
    be able to inject a newline that de-indents an indented code block onto
    the surrounding Markdown, or -- combined with a line of backticks of its
    own -- closes a fenced code block early. Stripping the newline alone
    closes both: neither failure mode is reachable without one, since a
    single-line value can never BE a standalone fence-closing line or start
    a new, unindented line.
    """
    return _CONTROL_RE.sub("", str(value))


def code_span(value: Any, *, table: bool = False) -> str:
    """Quote ``value`` as a Markdown inline code span safe against its own content.

    Strips CR/LF and C0/C1 control characters, then fences the result with
    one more backtick than the longest backtick run already in the value,
    padding with a single space on either side the value starts or ends
    with a backtick (so ``` `foo` ``` doesn't visually fuse with the fence).

    ``table=True`` additionally escapes a literal ``|`` -- inside a Markdown
    table cell a bare pipe ends the cell early, the exact same failure mode
    as an unescaped backtick ending the code span.
    """
    text = strip_controls(value)
    if table:
        text = text.replace("|", "\\|")
    longest = max((len(run) for run in _BACKTICK_RUN_RE.findall(text)), default=0)
    fence = "`" * (longest + 1)
    if text.startswith("`") or text.endswith("`"):
        text = f" {text} "
    return f"{fence}{text}{fence}"
