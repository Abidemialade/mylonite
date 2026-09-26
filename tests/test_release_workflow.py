from pathlib import Path

import yaml


def _load_release_workflow() -> dict:
    return yaml.safe_load(Path(".github/workflows/release.yml").read_text(encoding="utf-8"))


def test_pypi_smoke_job_runs_the_demo_from_the_published_package():
    """After publish-pypi, a matrix job installs the just-released version
    from PyPI (not the checkout) and runs the demo, on both operating
    systems -- the post-release check the launch-floor milestone requires."""
    doc = _load_release_workflow()
    job = doc["jobs"]["pypi-smoke"]

    assert job["needs"] == "publish-pypi"
    assert job["permissions"] == {"contents": "read"}

    os_matrix = job["strategy"]["matrix"]["os"]
    assert set(os_matrix) == {"ubuntu-latest", "windows-latest"}

    steps_blob = yaml.dump(job["steps"])
    assert "mylonite[demo]==" in steps_blob
    assert '.[demo]"' not in steps_blob  # must come from PyPI, not the checkout


def test_pypi_smoke_never_blocks_the_github_release():
    """github-release still depends only on publish-pypi: the smoke check
    reports on its own and a slow or flaky PyPI index must not hold up the
    release notes."""
    doc = _load_release_workflow()
    assert doc["jobs"]["github-release"]["needs"] == "publish-pypi"
