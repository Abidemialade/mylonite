"""Silo guard + provenance stamp tests -- hermetic (no network, no API key).

The dev checkout is itself an editable/working-tree install, so these tests can
never rely on the ambient interpreter to represent a "good" install. Every case
substitutes ``_resolve_mylonite_file`` / ``_installed_version`` instead, which is
also the point of those two seams existing.
"""

from __future__ import annotations

import pytest

from verification import _provenance

SiloViolation = _provenance.SiloViolation
assert_siloed = _provenance.assert_siloed
build_meta = _provenance.build_meta
safe_install_origin = _provenance.safe_install_origin

_SITE_PACKAGES = r"C:\Users\someone\envs\verify\Lib\site-packages\mylonite\__init__.py"
_WORKING_TREE = r"C:\Users\someone\Projects\Mylonite\src\mylonite\__init__.py"
_POSIX_SITE_PACKAGES = "/home/someone/venv/lib/python3.11/site-packages/mylonite/__init__.py"


def _install(monkeypatch, module_file: str | None, version: str | None) -> None:
    monkeypatch.setattr(_provenance, "_resolve_mylonite_file", lambda: module_file)
    monkeypatch.setattr(_provenance, "_installed_version", lambda: version)


def test_siloed_install_passes(monkeypatch) -> None:
    _install(monkeypatch, _SITE_PACKAGES, "0.9.0")
    assert_siloed("0.9.0")  # must not raise


def test_siloed_install_passes_on_posix_layout(monkeypatch) -> None:
    _install(monkeypatch, _POSIX_SITE_PACKAGES, "0.9.0")
    assert_siloed("0.9.0")


def test_working_tree_install_raises(monkeypatch) -> None:
    _install(monkeypatch, _WORKING_TREE, "0.9.0")
    with pytest.raises(SiloViolation) as excinfo:
        assert_siloed("0.9.0")
    message = str(excinfo.value)
    assert "working tree" in message
    assert "pip install mylonite==0.9.0" in message


def test_violation_message_never_leaks_the_path(monkeypatch) -> None:
    """The fix hint must be actionable without naming the machine it ran on."""
    _install(monkeypatch, _WORKING_TREE, "0.9.0")
    with pytest.raises(SiloViolation) as excinfo:
        assert_siloed("0.9.0")
    message = str(excinfo.value)
    assert "Users" not in message
    assert "someone" not in message
    assert "\\" not in message
    assert "Mylonite\\src" not in message


def test_unrecognised_origin_raises(monkeypatch) -> None:
    _install(monkeypatch, "/opt/vendored/mylonite/__init__.py", "0.9.0")
    with pytest.raises(SiloViolation, match="unrecognised location"):
        assert_siloed("0.9.0")


def test_missing_module_file_raises(monkeypatch) -> None:
    _install(monkeypatch, None, "0.9.0")
    with pytest.raises(SiloViolation):
        assert_siloed("0.9.0")


def test_missing_distribution_metadata_raises(monkeypatch) -> None:
    _install(monkeypatch, _SITE_PACKAGES, None)
    with pytest.raises(SiloViolation, match="no distribution metadata"):
        assert_siloed("0.9.0")


def test_version_mismatch_raises(monkeypatch) -> None:
    _install(monkeypatch, _SITE_PACKAGES, "0.8.6")
    with pytest.raises(SiloViolation) as excinfo:
        assert_siloed("0.9.0")
    message = str(excinfo.value)
    assert "0.9.0" in message
    assert "0.8.6" in message


def test_version_check_skipped_when_not_requested(monkeypatch) -> None:
    _install(monkeypatch, _SITE_PACKAGES, "0.8.6")
    assert_siloed()  # no expected_version -> origin check only


def test_venv_inside_the_repo_still_counts_as_siloed(monkeypatch) -> None:
    """Innermost marker wins: a repo-local venv is still a real install."""
    _install(
        monkeypatch,
        "/home/someone/src/Mylonite/.venv/lib/site-packages/mylonite/__init__.py",
        "0.9.0",
    )
    assert safe_install_origin() == "site-packages"


@pytest.mark.parametrize(
    "module_file",
    [_SITE_PACKAGES, _WORKING_TREE, _POSIX_SITE_PACKAGES, "/opt/vendored/mylonite/x.py", None],
)
def test_safe_install_origin_never_identifies_the_machine(monkeypatch, module_file) -> None:
    _install(monkeypatch, module_file, "0.9.0")
    origin = safe_install_origin()
    assert origin in {"site-packages", "working-tree", "unknown"}
    assert "/" not in origin
    assert "\\" not in origin
    assert "Users" not in origin


def test_build_meta_has_exactly_the_expected_keys(monkeypatch) -> None:
    _install(monkeypatch, _SITE_PACKAGES, "0.9.0")
    meta = build_meta(
        mylonite_version="0.9.0",
        git_sha="deadbee",
        harness_sha="abc1234",
        model="claude-haiku-4-5-20251001",
        recorded_at="2026-08-28T00:00:00Z",
        layers={"layer1": "ran", "layer2": "ran", "layer3": "not-run"},
    )
    assert set(meta) == {
        "schema_version",
        "mylonite_version",
        "mylonite_origin",
        "git_sha",
        "harness_sha",
        "model",
        "recorded_at",
        "layers",
    }
    assert meta["schema_version"] == "1.0"
    assert meta["mylonite_version"] == "0.9.0"
    assert meta["mylonite_origin"] == "site-packages"
    # git_sha and harness_sha are deliberately DISTINCT. The campaign runs after
    # the tag (the silo needs an installed artifact), so "what tree was measured"
    # and "what scorer measured it" are separate questions -- and if the scorer
    # changes, numbers move with no Mylonite change at all.
    assert meta["git_sha"] == "deadbee"
    assert meta["harness_sha"] == "abc1234"
    assert meta["model"] == "claude-haiku-4-5-20251001"
    assert meta["recorded_at"] == "2026-08-28T00:00:00Z"
    assert meta["layers"] == {"layer1": "ran", "layer2": "ran", "layer3": "not-run"}


def test_build_meta_records_a_skipped_layer_as_not_run(monkeypatch) -> None:
    _install(monkeypatch, _SITE_PACKAGES, "0.9.0")
    meta = build_meta(
        mylonite_version="0.9.0",
        git_sha="deadbee",
        harness_sha="abc1234",
        model="m",
        recorded_at="2026-08-28T00:00:00Z",
        layers={"layer1": "ran", "layer3": "not-run"},
    )
    assert meta["layers"]["layer3"] == "not-run"
    # A layer that did not run must still be PRESENT: an absent layer reads as a
    # zero, and a zero reads as "clean".
    assert "layer3" in meta["layers"]


def test_build_meta_fails_closed_on_an_unknown_layer_state(monkeypatch) -> None:
    _install(monkeypatch, _SITE_PACKAGES, "0.9.0")
    meta = build_meta(
        mylonite_version="0.9.0",
        git_sha="deadbee",
        harness_sha="abc1234",
        model="m",
        recorded_at="2026-08-28T00:00:00Z",
        layers={"layer2": "crashed", "layer1": "RAN"},
    )
    assert meta["layers"] == {"layer2": "not-run", "layer1": "not-run"}


def test_build_meta_ignores_unvetted_caller_keys(monkeypatch) -> None:
    """``layers`` is rebuilt, not spliced -- no caller can widen the payload."""
    _install(monkeypatch, _SITE_PACKAGES, "0.9.0")
    layers = {"layer1": "ran"}
    meta = build_meta(
        mylonite_version="0.9.0",
        git_sha="deadbee",
        harness_sha="abc1234",
        model="m",
        recorded_at="2026-08-28T00:00:00Z",
        layers=layers,
    )
    layers["layer2"] = "ran"  # mutating the caller's dict must not reach the payload
    assert meta["layers"] == {"layer1": "ran"}
