"""Write the gating workflow templates into a target repo's .github/workflows/."""

from __future__ import annotations

import importlib.resources as ir
import re
from collections.abc import Sequence
from pathlib import Path

from mylonite.gate.pr import GatePrError
from mylonite.layout import DEFAULT_LAYOUT
from mylonite.providers.registry import PROVIDERS
from mylonite.version import __version__

_TEMPLATES = ("mylonite-gate.yml", "mylonite-discovery.yml")

#: Launch commands that need a runtime setup step before the target can be
#: spawned — a hosted runner has neither Node nor uv preinstalled the way it
#: has Python, so a target launched with npx/uvx/node/uv otherwise fails to
#: launch in CI with no clearer message than "command not found".
_NODE_COMMANDS = frozenset({"npx", "node"})
_UV_COMMANDS = frozenset({"uvx", "uv"})


def _llm_key_env_var(model: str) -> str:
    """The credential env var name for ``model``'s provider — read from the
    approved-provider registry rather than always assuming one provider: the
    scaffolded workflow used to map the gate secret to a single hardcoded
    provider's key variable unconditionally, so a different provider's user
    had their gate job fail in CI with no useful message, and a finding made
    with a local model re-drove it on a runner that has none.

    Raises :class:`GatePrError` when the model's provider is local
    (:attr:`~mylonite.providers.registry.ProviderInfo.local`, e.g. Ollama/
    vLLM) — there is no key to map, and a hosted GitHub runner can't reach a
    local server anyway, so scaffolding a workflow for it would only produce
    CI that can never pass. Also raises when the provider is unrecognised
    (no registry row at all) or needs more than one credential variable
    (Bedrock's access-key pair) — a single ``MYLONITE_API_KEY`` secret can't
    express either case; such a target needs a hand-written workflow instead
    of the scaffolded one.
    """
    from mylonite.scan.providers import env_vars_for, provider_from_model

    provider = provider_from_model(model)
    info = PROVIDERS.get(provider) if provider else None
    if info is not None and info.local:
        raise GatePrError(
            f"can't scaffold a CI workflow for the local model {model!r} "
            f"(provider {provider!r} has no credential — it runs on this "
            "machine, not a hosted GitHub runner). Point the target at a "
            "CI-reachable backend and gate with a non-local model, or write "
            "the CI workflow by hand for a self-hosted runner that has it."
        )
    key_vars = env_vars_for(provider)
    if len(key_vars) != 1:
        reason = "no registered credential" if not key_vars else f"needs {key_vars}, not one var"
        raise GatePrError(
            f"can't scaffold a CI workflow for model {model!r} (provider "
            f"{provider!r} {reason}) — a scaffolded workflow maps exactly "
            "one MYLONITE_API_KEY secret to one credential variable. Write "
            "the CI workflow by hand for this provider instead."
        )
    return key_vars[0]


def _llm_extra_env_lines(model: str) -> str:
    """Repository-**variable** env lines for every credential-adjacent
    variable ``model``'s provider needs BEYOND its bare key — Azure's
    endpoint + API version, read from the registry's
    :attr:`~mylonite.providers.registry.ProviderInfo.extra_env`: a
    provider can pass :func:`_llm_key_env_var`'s "exactly one key variable"
    check and still need more than the key to actually route a call, and
    silently dropping those left Azure scaffolding a workflow that could
    never pass (the missing endpoint fails every re-drive). Emitted as
    repository ``vars.*`` rather than secrets — an endpoint URL or an API
    version string isn't secret-shaped. Empty for every provider with no
    ``extra_env`` (every one but Azure/Vertex today; Vertex is refused
    earlier by :func:`_llm_key_env_var` for having no bare key at all).
    """
    from mylonite.scan.providers import provider_from_model

    provider = provider_from_model(model)
    info = PROVIDERS.get(provider) if provider else None
    if info is None or not info.extra_env:
        return ""
    return "\n".join(f"          {var}: ${{{{ vars.{var} }}}}" for var in info.extra_env)


def _runtime_setup_step(command: str | None) -> str:
    """A step that installs the runtime ``command`` needs, inserted before
    the step that installs/runs mylonite — empty (nothing emitted) when the
    target launches with ``python`` or its command is unknown, since the
    Python ``actions/setup-python`` already set up is enough: a target
    launched via `npx`/`node` or `uvx`/`uv` otherwise has nothing on the
    runner to launch it with.

    ``command`` is reduced to its basename first: ``load_target_file(
    ...).command`` can be an absolute path (``/usr/bin/npx``), which a bare
    ``in _NODE_COMMANDS`` membership test would miss.
    """
    if command:
        command = Path(command).name
    if command in _NODE_COMMANDS:
        lines = [
            "      - name: Set up Node (the target launches with npx/node)",
            "        uses: actions/setup-node@a0853c24544627f65ddf259abe73b1d18a591444 # v5.0.0",
            "        with:",
            '          node-version: "22"',
        ]
    elif command in _UV_COMMANDS:
        lines = [
            "      - name: Install uv (the target launches with uvx/uv)",
            "        run: pip install uv -c .github/workflows/mylonite-constraints.txt",
        ]
    else:
        return ""
    return "\n".join(lines)


def _target_secrets_env_lines(target_env_vars: Sequence[str]) -> str:
    """One extra ``env:`` entry per ``${MYLONITE_TARGET_...}`` variable the
    redacted target file references, mapped to the repository secret of
    the same name — appended inside the step's OWN existing ``env:`` block
    (both templates now scope the LLM credential/model vars to the one
    step that makes a live call, so that step always has an ``env:`` key
    of its own by the time this is rendered; a bare ``return ""`` for no
    secrets just removes the comment line, never a stray empty mapping)."""
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
    target_command: str | None = None,
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
    * ``__TARGET_SECRETS_ENV_LINES__`` -> (#185) an ``env:`` entry per
      ``${MYLONITE_TARGET_...}`` placeholder in the redacted ``target.yaml``
      this run co-writes, mapped to ``${{ secrets.<NAME> }}``, appended
      inside the step's own existing ``env:`` block (both templates scope
      the LLM credential/model vars to the one step that makes a live
      call, so that step always has an ``env:`` key already) so the
      workflow's own ``load_target_file`` call doesn't fail on an
      undefined variable in CI. Pass the variable names read back from the
      written target file via :func:`mylonite._redaction.target_env_refs`;
      empty (the default) for a target with no secrets, or a reference/
      bundled target with none to write at all.
    * ``__TARGET_SECRETS_CHECK_STEP__`` -> a step, before the one that runs
      the gate, that fails the job naming each target secret that is empty
      (see :func:`_target_secrets_check_step`); removed when there are none.
    * ``__LLM_KEY_ENV__`` -> the credential env var for ``model``'s provider
      (see :func:`_llm_key_env_var`) — never hardcoded to Anthropic's.
    * ``__LLM_EXTRA_ENV__`` -> one repository-variable line per extra
      credential-adjacent var ``model``'s provider needs beyond its bare
      key (Azure's endpoint + API version; see :func:`_llm_extra_env_lines`);
      empty for a provider with none.
    * ``__RUNTIME_SETUP_STEP__`` -> a Node/uv setup step when
      ``target_command`` needs one (see :func:`_runtime_setup_step`);
      removed when the target launches with Python or ``target_command`` is
      unknown (``None`` — a reference/bundled target, or a caller that
      doesn't have it).

    Returns the written paths.
    """
    posix_gate_dir = _relative_gate_dir(repo_root, Path(gate_dir)).as_posix()
    inline_tokens = {
        "__RUNS_ON__": runs_on,
        "__GATE_DIR__": posix_gate_dir,
        "__MYLONITE_VERSION__": __version__,
        "__MYLONITE_MODEL__": model,
        "__LLM_KEY_ENV__": _llm_key_env_var(model),
    }
    # The templates spell these as full-line YAML comments
    # (``#__TARGET_SECRETS_ENV_LINES__``) so the RAW, unsubstituted template
    # stays valid YAML on its own (see test_workflows.py's
    # test_templates_are_valid_yaml_and_ship_as_package_data) — a bare
    # unindented token broke the surrounding block's indentation. Handled
    # separately from ``inline_tokens`` (rather than one flat dict) because an
    # EMPTY value here must remove the whole line, newline included — a plain
    # substring replace would leave a blank line behind, which is a real
    # byte-for-byte regression against the pre-existing (no-secrets) render.
    line_tokens = {
        "#__TARGET_SECRETS_ENV_LINES__": _target_secrets_env_lines(target_env_vars),
        "#__TARGET_SECRETS_CHECK_STEP__": _target_secrets_check_step(target_env_vars),
        "#__RUNTIME_SETUP_STEP__": _runtime_setup_step(target_command),
        "#__LLM_EXTRA_ENV__": _llm_extra_env_lines(model),
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
    # A pinned, exact-version constraints file both templates' install
    # steps apply (`pip install ... -c mylonite-constraints.txt`) — vendored
    # verbatim (no tokens) so a LiteLLM compromise like 24 Mar 2026's doesn't
    # reach a scaffolded CI run just because PyPI resolved a newer release
    # that same day. Returned alongside the two workflow files so a caller
    # (the git-add step in gate/wiring.py) stages it too.
    constraints_src = base / "constraints.txt"
    constraints_out = dest / "mylonite-constraints.txt"
    constraints_out.write_text(constraints_src.read_text(encoding="utf-8"), encoding="utf-8")
    written.append(constraints_out)
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
