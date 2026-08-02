from __future__ import annotations

from pathlib import Path

import pytest

from mylonite._paths import PathEscapesBase, resolve_contained, safe_slug


def test_resolves_relative_path_inside_base(tmp_path: Path) -> None:
    (tmp_path / "prompt.txt").write_text("hi", encoding="utf-8")
    assert resolve_contained("prompt.txt", base=tmp_path, label="system_prompt_file") == (
        tmp_path / "prompt.txt"
    ).resolve()


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
