"""Write the gating workflow templates into a target repo's .github/workflows/."""

from __future__ import annotations

import importlib.resources as ir
import re
from collections.abc import Sequence
from pathlib import Path

from mylonite.gate.pr import GatePrError
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


def _target_secrets_check_step(target_env_vars: Sequence[str]) -> str:
    """A step that fails the job, naming the secret, when any target secret
    is empty. GitHub renders a missing ``${{ secrets.X }}`` as an empty
    string, and an empty value counts as set when the target file is
    expanded, so without this the target launches with an empty credential
    and the gate can pass for the wrong reason. Runs before the step that
    uses the secrets. Empty when the target declares no secrets."""
    if not target_env_vars:
        return ""
    lines = [
        "      - name: Check the target secrets are set",
        "        env:",
        *(f"          {var}: ${{{{ secrets.{var} }}}}" for var in target_env_vars),
        # `[ -n ... ]` is POSIX shell; pin bash so this doesn't parse as
        # pwsh on a self-hosted Windows runner (a documented `runs-on`
        # option) and fail with the wrong message.
        "        shell: bash",
        "        run: |",
        *(
            f'          [ -n "${var}" ] || {{ echo "::error::secret {var} is empty - '
            f'add it under repository secrets"; exit 1; }}'
            for var in target_env_vars
        ),
    ]
    return "\n".join(lines)


def _relative_gate_dir(repo_root: Path, gate_dir: Path) -> Path:
    """``gate_dir`` as rendered into a workflow: always relative to
    ``repo_root``, never a machine-local absolute path. ``resolve_gate_out_dir`` anchors ``--out`` at the repo root as
    an ABSOLUTE path so file writes land in the right place regardless of the
    operator's cwd — but that same absolute path, rendered verbatim into
    ``run: pytest <path>``, only ever worked on the machine that wrote it.
    GitHub Actions checks out a FRESH clone at the repo root every run,
    so the path a committed workflow needs is repo-root-relative.

    Raises :class:`GatePrError` (exit 8, the same code every other
    repo-boundary failure in this package uses) when ``gate_dir`` is an
    absolute path that isn't actually under ``repo_root`` — an operator-
    supplied ``--out`` outside the repository, which ``resolve_gate_out_dir``
    does not touch (it only anchors the DEFAULT relative layout).
    """
    gate_dir = Path(gate_dir)
    if not gate_dir.is_absolute():
        return gate_dir
    try:
        return gate_dir.relative_to(repo_root)
    except ValueError as exc:
        raise GatePrError(
            f"gate output directory {gate_dir} is not inside the repository root "
            f"{repo_root} — cannot scaffold a workflow that references it."
        ) from exc


def write_workflows(
    repo_root: Path,
    *,
    model: str,
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
    * ``__GATE_DIR__`` -> ``gate_dir``, relativized against ``repo_root`` and
      rendered posix-style — the ``gate --out`` directory the committed test /
      target.yaml actually live under, defaulting to
      :data:`mylonite.layout.DEFAULT_LAYOUT`'s gate dir. Always relative in
      the rendered workflow (see :func:`_relative_gate_dir`): CI checks out a
      fresh clone, so an absolute path baked in at scaffold time would only
      ever resolve on the machine that ran ``gate --workflows``.
    * ``__MYLONITE_VERSION__`` -> this package's ``__version__``, so the
      workflows install the release that wrote them rather than whatever PyPI
      serves on the day the job runs.
    * ``__MYLONITE_MODEL__`` -> ``model`` -- the exact model THIS gate run
      resolved (no default provider or model: ``gate`` always has a real one
      by the time it writes workflows, see
      ``cli._require_model_chosen_or_exit``). Rendered as
      ``${{ vars.MYLONITE_MODEL || '<model>' }}`` in both templates, so the
      scaffolded workflow never needs a model chosen for it at CI time (the
      literal fallback keeps it working out of the box) while a repository
      variable lets an operator change models later without editing the
      file.
    * ``__TARGET_SECRETS_ENV__`` / ``__TARGET_SECRETS_ENV_LINES__`` ->
      (#185) an ``env:`` entry per ``${MYLONITE_TARGET_...}`` placeholder in
      the redacted ``target.yaml`` this run co-writes, mapped to
      ``${{ secrets.<NAME> }}``, so the workflow's own ``load_target_file``
      call doesn't fail on an undefined variable in CI. Pass the variable
      names read back from the written target file via
      :func:`mylonite._redaction.target_env_refs`; empty (the default) for a
      target with no secrets, or a reference/bundled target with none to
      write at all.
    * ``__TARGET_SECRETS_CHECK_STEP__`` -> a step, before the one that runs
      the gate, that fails the job naming each target secret that is empty
      (see :func:`_target_secrets_check_step`); removed when there are none.

    Returns the written paths.
    """
    posix_gate_dir = _relative_gate_dir(repo_root, Path(gate_dir)).as_posix()
    inline_tokens = {
        "__RUNS_ON__": runs_on,
        "__GATE_DIR__": posix_gate_dir,
        "__MYLONITE_VERSION__": __version__,
        "__MYLONITE_MODEL__": model,
    }
    # The templates spell these as full-line YAML comments
    # (``#__TARGET_SECRETS_ENV__``) so the RAW, unsubstituted template stays
    # valid YAML on its own (see test_workflows.py's
    # test_templates_are_valid_yaml_and_ship_as_package_data) — a bare
    # unindented token broke the surrounding block's indentation. Handled
    # separately from ``inline_tokens`` (rather than one flat dict) because an
    # EMPTY value here must remove the whole line, newline included — a plain
    # substring replace would leave a blank line behind, which is a real
    # byte-for-byte regression against the pre-existing (no-secrets) render.
    line_tokens = {
        "#__TARGET_SECRETS_ENV__": _target_secrets_env_block(target_env_vars),
        "#__TARGET_SECRETS_ENV_LINES__": _target_secrets_env_lines(target_env_vars),
        "#__TARGET_SECRETS_CHECK_STEP__": _target_secrets_check_step(target_env_vars),
    }
    dest = repo_root / ".github" / "workflows"
    dest.mkdir(parents=True, exist_ok=True)
    base = ir.files("mylonite.gate") / "templates"
    written: list[Path] = []
    for name in _TEMPLATES:
        text = (base / name).read_text(encoding="utf-8")
        for token, value in inline_tokens.items():
            text = text.replace(token, value)
        for token, value in line_tokens.items():
            text = text.replace(token, value) if value else text.replace(token + "\n", "")
        out = dest / name
        out.write_text(text, encoding="utf-8")
        written.append(out)
    return written


_PIN = re.compile(r"mylonite==([0-9][0-9A-Za-z.+!-]*)")


def stale_workflow_pins(gate_dir: Path, *, version: str = __version__) -> list[str]:
    """One warning line per committed gate workflow that pins an older mylonite.

    The workflows ``gate --workflows`` scaffolds install ``mylonite==<the
    version that wrote them>``. An older pin may not replay what a newer
    ``gate`` records (recordings made by this version are named by a short
    key prefix older versions do not look for), so the new tests would fail
    in CI on their first run. Looks in the nearest ``.github/workflows/``
    at or above ``gate_dir``. A warning, never a refusal: the user may bump
    the pin in the same commit.
    """
    from packaging.version import InvalidVersion, Version

    try:
        running = Version(version)
    except InvalidVersion:
        return []
    start = Path(gate_dir).absolute()
    for folder in (start, *start.parents):
        workflows = folder / ".github" / "workflows"
        if workflows.is_dir():
            break
    else:
        return []
    lines: list[str] = []
    for name in _TEMPLATES:
        path = workflows / name
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        for pinned in sorted(set(_PIN.findall(text))):
            try:
                older = Version(pinned) < running
            except InvalidVersion:
                continue
            if older:
                lines.append(
                    f"warning: {path} installs mylonite=={pinned}, older than this "
                    f"mylonite ({version}), which may not replay the recordings this run "
                    f"wrote. Re-run gate with --workflows, or change the pin to "
                    f"mylonite=={version}."
                )
    return lines
