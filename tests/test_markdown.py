"""Unit tests for ``mylonite._markdown.code_span`` (F9).

Each test here FAILED before the fix (there was no ``_markdown`` module; the
call sites quoted target text with a bare, fixed-width ``f"\\`{value}\\`"``)
and PASSES after it.
"""

from __future__ import annotations

from mylonite._markdown import code_span


def test_plain_identifier_renders_byte_identical_to_a_bare_backtick_quote():
    """No backtick, no control char: the output must be exactly what the old
    ``f"\\`{value}\\`"`` call sites produced, so every plain tool-name/value
    rendering stays byte-identical."""
    assert code_span("send_email") == "`send_email`"
    assert code_span("https://example.invalid/x") == "`https://example.invalid/x`"


def test_a_single_backtick_gets_a_longer_fence_and_padding():
    # A naive f"`{value}`" would read as "`` `a` backtick ``" -- the value's
    # own backtick closing the span one character early.
    out = code_span("a `backtick`")
    assert out == "`` a `backtick` ``"
    assert "`a" not in out  # the fence never touches the value unpadded


def test_a_value_with_a_markdown_link_and_image_cannot_escape_the_span():
    evil = (
        "lookup` ![pwned](https://example.invalid/x.png) [click](https://example.invalid/y) `tail"
    )
    out = code_span(evil)
    # The fence must be longer than the longest backtick run already in the
    # value (here: 1), so a double-backtick fence is required.
    assert out.startswith("``")
    assert out.endswith("``")
    # The link/image syntax rides through unparsed, inside the span.
    assert "![pwned](https://example.invalid/x.png)" in out
    assert "[click](https://example.invalid/y)" in out


def test_fence_is_longer_than_the_longest_internal_backtick_run():
    out = code_span("a ``` triple ``` run")
    # longest run inside is 3 backticks -> fence must be (at least) 4.
    assert out.startswith("````")
    assert out.endswith("````")


def test_leading_or_trailing_backtick_gets_padded():
    assert code_span("`leading") == "`` `leading ``"
    assert code_span("trailing`") == "`` trailing` ``"


def test_cr_lf_and_control_bytes_are_stripped():
    # Only the raw control bytes themselves are removed; a bare ESC's
    # printable payload (here "[2J") is not a control byte and is left as
    # literal text -- stripping full ANSI sequences is `_cli_io`'s job for
    # terminal output, not this Markdown-quoting helper's.
    out = code_span("line1\r\nline2\x07\x1b[2J")
    assert "\r" not in out
    assert "\n" not in out
    assert "\x07" not in out
    assert "\x1b" not in out
    assert out == "`line1line2[2J`"


def test_table_mode_escapes_a_literal_pipe():
    out = code_span("a|b", table=True)
    assert out == r"`a\|b`"


def test_non_table_mode_does_not_touch_a_pipe():
    assert code_span("a|b") == "`a|b`"
