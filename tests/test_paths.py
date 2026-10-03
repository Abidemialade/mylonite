from __future__ import annotations

import shlex
from pathlib import Path, PureWindowsPath

import pytest

from mylonite._paths import (
    PathEscapesBase,
    path_for_shell,
    quote_for_shell,
    resolve_contained,
    safe_slug,
)


def test_resolves_relative_path_inside_base(tmp_path: Path) -> None:
    (tmp_path / "prompt.txt").write_text("hi", encoding="utf-8")
    assert (
        resolve_contained("prompt.txt", base=tmp_path, label="system_prompt_file")
        == (tmp_path / "prompt.txt").resolve()
    )


def test_rejects_dotdot_escape(tmp_path: Path) -> None:
    with pytest.raises(PathEscapesBase):
        resolve_contained("../../../../etc/passwd", base=tmp_path, label="system_prompt_file")


def test_rejects_absolute_path_outside_base(tmp_path: Path) -> None:
    with pytest.raises(PathEscapesBase):
        resolve_contained("/etc/passwd", base=tmp_path, label="system_prompt_file")


def test_rejects_symlink_pointing_outside_base(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    link = tmp_path / "link.txt"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable on this platform/user")
    with pytest.raises(PathEscapesBase):
        resolve_contained("link.txt", base=tmp_path, label="system_prompt_file")


def test_safe_slug_strips_path_and_quote_characters() -> None:
    assert "/" not in safe_slug('../../evil"; exec()')
    assert safe_slug("") == "unknown"


def test_quote_for_shell_leaves_a_plain_posix_path_unquoted() -> None:
    assert (
        quote_for_shell("/home/alice/.mylonite/generated/x") == "/home/alice/.mylonite/generated/x"
    )


def test_quote_for_shell_leaves_a_safe_value_unchanged() -> None:
    # Letters, digits and `_-./:@+=` never need quoting in cmd, PowerShell,
    # bash or Git Bash -- a forward-slash path or a scope/family value made
    # only of these is the common case this covers.
    safe = "my-app_v2.1:scope@host+tag=value/.mylonite/generated/x"
    assert quote_for_shell(safe) == safe


def test_quote_for_shell_does_not_treat_a_backslash_as_safe() -> None:
    # A raw backslash is NOT in the safe set (even though every real path
    # reaching this function has already gone through `path_for_shell` and
    # so never carries one) -- an unquoted backslash is an escape character
    # to the POSIX shell `journey.sh` runs via `eval`, which would silently
    # eat it rather than merely splitting the command on a space.
    value = r"C:\Users\alice\gen"
    assert quote_for_shell(value) != value


def test_quote_for_shell_quotes_a_space_with_windows_double_quotes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("mylonite._paths.os.name", "nt")
    # Unquoted, a printed command built from this path would split into two
    # shell words and run with the wrong argument. `"..."` parses correctly
    # in cmd, PowerShell AND Git Bash for a value with no `"`, `$` or `` ` ``.
    quoted = quote_for_shell("C:\\Users\\My Name\\gen")
    assert quoted == '"C:\\Users\\My Name\\gen"'


def test_quote_for_shell_quotes_a_space_with_posix_quoting_off_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("mylonite._paths.os.name", "posix")
    quoted = quote_for_shell("/home/alice/My Documents/gen")
    assert quoted == "'/home/alice/My Documents/gen'"


def test_quote_for_shell_falls_back_to_posix_quoting_on_windows_for_a_dollar_sign(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("mylonite._paths.os.name", "nt")
    # `"..."` can't make this safe: bash (what Git Bash runs) still expands
    # `$...` inside double quotes, so this falls back to the POSIX form,
    # with a note that this one line is POSIX-quoted even on Windows.
    quoted = quote_for_shell("C:\\Users\\$alice\\gen")
    assert quoted.startswith(shlex.quote("C:\\Users\\$alice\\gen"))
    assert "POSIX" in quoted


def test_quote_for_shell_escapes_an_embedded_single_quote_on_posix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("mylonite._paths.os.name", "posix")
    quoted = quote_for_shell("/home/o'brien/gen")
    assert quoted == "'/home/o'\"'\"'brien/gen'"


# --- path_for_shell: every printed next-step command's own path, rendered
# with forward slashes on EVERY platform before quote_for_shell ever sees
# it, so a native Windows path's backslashes never reach a POSIX `eval`
# (`verification/rehearsal/journey.sh`) unquoted and never get eaten. ---


def test_path_for_shell_renders_a_windows_style_path_with_forward_slashes() -> None:
    # `PureWindowsPath`, not a plain backslash string or the host's own
    # `Path`: it always parses backslash as a separator, on every platform
    # that runs this test (including a Linux/macOS CI runner, where a bare
    # `Path(r"C:\...")` would treat the whole string as one literal POSIX
    # filename and never convert it) -- the same thing a real Windows run
    # of `generate`/`validate`/`scan --scaffold` hands this function.
    windows_path = PureWindowsPath(r"C:\Users\alice\.mylonite\generated\x")
    assert path_for_shell(windows_path) == "C:/Users/alice/.mylonite/generated/x"


def test_path_for_shell_needs_no_quoting_for_the_common_case() -> None:
    windows_path = PureWindowsPath(r"C:\Users\alice\.mylonite\generated\x")
    rendered = path_for_shell(windows_path)
    assert rendered == quote_for_shell(rendered)  # already safe -- quoting is a no-op


def test_path_for_shell_still_quotes_a_space(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("mylonite._paths.os.name", "nt")
    windows_path = PureWindowsPath(r"C:\Users\My Name\gen")
    assert path_for_shell(windows_path) == '"C:/Users/My Name/gen"'


def test_path_for_shell_parses_intact_through_a_real_bash_eval_stand_in() -> None:
    # The scenario the round-0 test caught: a native Windows path's
    # backslashes, left unquoted, are silently eaten by `shlex.split` (a
    # stand-in for the real bash `eval` in `journey.sh`) before `validate`
    # ever sees the path. Forward slashes round-trip intact instead.
    windows_path = PureWindowsPath(r"C:\Users\alice\.mylonite\generated\x")
    line = f"mylonite validate {path_for_shell(windows_path)} --authorize scope"
    assert shlex.split(line) == [
        "mylonite",
        "validate",
        "C:/Users/alice/.mylonite/generated/x",
        "--authorize",
        "scope",
    ]
