"""Write the gating workflow templates into a target repo's .github/workflows/."""

from __future__ import annotations

import importlib.resources as ir
from collections.abc import Sequence
from pathlib import Path

from mylonite.layout import DEFAULT_LAYOUT
from mylonite.version import __version__

_TEMPLATES = ("mylonite-gate.yml", "mylonite-discovery.yml")


def _target_secrets_env_block(target_env_vars: Sequence[str]) -> str:
    """The gate job's own ``env:`` block (it has none today): one entry per
    ``${MYLONITE_TARGET_...}`` variable the redacted target file references,
    mapped to the repository secret of the same name. Empty when the target
    declares no secrets, so the token line collapses to a blank line."""
    if not target_env_vars:
        return ""
    lines = ["        env:"]
    lines.extend(f"          {var}: ${{{{ secrets.{var} }}}}" for var in target_env_vars)
    return "\n".join(lines)


def _target_secrets_env_lines(target_env_vars: Sequence[str]) -> str:
    """Same idea as :func:`_target_secrets_env_block`, for the discovery
    workflow's step — which already declares its own ``env:`` (for
    ``MYLONITE_AUTHORIZE``), so only the extra entries are needed here."""
    return "\n".join(f"          {var}: ${{{{ secrets.{var} }}}}" for var in target_env_vars)


def write_workflows(
    repo_root: Path,
    *,
    runs_on: str = "ubuntu-latest",
    gate_dir: Path = DEFAULT_LAYOUT.gate,
    target_env_vars: Sequence[str] = (),
) -> list[Path]:
    """Render both workflow templates into ``repo_root/.github/workflows/``.

    A token MAP is substituted into each template (rather than a single
    string-replace) so the scaffolded workflows can reference the ACTUAL
    configured gate directory instead of a hardcoded default baked into the
    YAML:

    * ``__RUNS_ON__`` -> ``runs_on`` — a self-hosted label (e.g.
      ``"[self-hosted, linux]"``) for in-perimeter enterprise runners.
    * ``__GATE_DIR__`` -> ``gate_dir`` (posix-style) — the ``gate --out``
      directory the committed test / target.yaml actually live under;
      defaults to :data:`mylonite.layout.DEFAULT_LAYOUT`'s gate dir.
    * ``__MYLONITE_VERSION__`` -> this package's ``__version__``, so the
      workflows install the release that wrote them rather than whatever PyPI
      serves on the day the job runs.
    * ``__TARGET_SECRETS_ENV__`` / ``__TARGET_SECRETS_ENV_LINES__`` ->
      (#185) an ``env:`` entry per ``${MYLONITE_TARGET_...}`` placeholder in
      the redacted ``target.yaml`` this run co-writes, mapped to
      ``${{ secrets.<NAME> }}``, so the workflow's own ``load_target_file``
      call doesn't fail on an undefined variable in CI. Pass the variable
      names read back from the written target file via
      :func:`mylonite._redaction.target_env_refs`; empty (the default) for a
      target with no secrets, or a reference/bundled target with none to
      write at all.

    Returns the written paths.
    """
    tokens = {
        "__RUNS_ON__": runs_on,
        "__GATE_DIR__": Path(gate_dir).as_posix(),
        "__MYLONITE_VERSION__": __version__,
        # The templates spell these as full-line YAML comments
        # (``#__TARGET_SECRETS_ENV__``) so the RAW, unsubstituted template
        # stays valid YAML on its own (see test_workflows.py's
        # test_templates_are_valid_yaml_and_ship_as_package_data) — a bare
        # unindented token broke the surrounding block's indentation.
        "#__TARGET_SECRETS_ENV__": _target_secrets_env_block(target_env_vars),
        "#__TARGET_SECRETS_ENV_LINES__": _target_secrets_env_lines(target_env_vars),
    }
    dest = repo_root / ".github" / "workflows"
    dest.mkdir(parents=True, exist_ok=True)
    base = ir.files("mylonite.gate") / "templates"
    written: list[Path] = []
    for name in _TEMPLATES:
        text = (base / name).read_text(encoding="utf-8")
        for token, value in tokens.items():
            text = text.replace(token, value)
        out = dest / name
        out.write_text(text, encoding="utf-8")
        written.append(out)
    return written
