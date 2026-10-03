"""A wrong key stops the run in one line, exit 4, before the target launches.

Each command that drives a target (scan, gate, validate, ablate) sends one
tiny request per role model first. A refused key (HTTP 401) names the key
variable; a key that needs an extra header (HTTP 400) names ``--llm-header``.
Spies on every adapter factory and on the stdio launch prove the target was
never started. The provider is a fake; no request leaves the machine.

The second half covers ``--llm-header`` itself: the value reaches the provider
call and nothing else (not the console, logs or any written artefact).
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import litellm
import pytest
from tests.test_cli import _generated_dir
from typer.testing import CliRunner

from mylonite.cli import app
from mylonite.exit_codes import EXIT_CONFIG, EXIT_PROVIDER
from mylonite.providers.registry import PROVIDERS
from mylonite.scan import auth_preflight
from mylonite.scan.llm_headers import LLM_HEADERS_ENV

runner = CliRunner()

#: Captured at import, before the suite-wide autouse fixture swaps the
#: preflight for a no-op (see tests/conftest.py).
_REAL_PREFLIGHT = auth_preflight.auth_preflight_or_exit

_KEY_VAR = PROVIDERS["anthropic"].key_env[0]
_WORKSPACE_HEADER = PROVIDERS["anthropic"].extra_headers[0]
_SENTINEL = "wrkspc-sentinel-91be4"
_HEADER_400 = f"{_WORKSPACE_HEADER} header is required for this API key"

#: Everything that would construct or launch a target, named where each
#: command looks it up (cli.py binds the adapter factories by name; the rest
#: are imported lazily from their own modules).
_LAUNCH_POINTS = (
    "mylonite.cli._build_adapter_for_reference",
    "mylonite.cli._build_adapter_for_mcp",
    "mylonite.cli._build_adapter_for_custom",
    "mylonite.cli._calibrate_custom_target_now",
    "mylonite.cli._provider_preflight",
    "mylonite.cli._provider_preflight_direct",
    "mylonite.plugins.cli_targets.autowire_seed_arm",
    "mylonite.plugins.cli_targets.refuse_uncoverable_weakness_classes",
    "mylonite.plugins._mcp.stdio_adapter.stdio_client",
    "mylonite.plugins._reference.reference_validator.DifferentialValidator",
    "asyncio.create_subprocess_exec",
)

#: scan constructs (but does not start) the custom adapter before the key
#: check, as it always has; every point that STARTS the target is still spied.
_CONSTRUCTED_BEFORE_PREFLIGHT = {"scan": {"mylonite.cli._build_adapter_for_custom"}}


@pytest.fixture(autouse=True)
def _real_preflight(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(auth_preflight, "auth_preflight_or_exit", _REAL_PREFLIGHT)
    monkeypatch.setenv(_KEY_VAR, "sk-ant-test-not-a-real-key")  # pragma: allowlist secret
    monkeypatch.delenv(LLM_HEADERS_ENV, raising=False)


class _Provider:
    """A fake provider: records each call's kwargs; raises ``error`` if set."""

    def __init__(self, error: BaseException | None = None) -> None:
        self.error = error
        self.calls: list[dict[str, Any]] = []

    def _answer(self, kwargs: dict[str, Any]) -> Any:
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        message = SimpleNamespace(content="ok", tool_calls=None)
        return SimpleNamespace(choices=[SimpleNamespace(message=message)], usage=None)

    async def acompletion(self, **kwargs: Any) -> Any:
        return self._answer(kwargs)

    def completion(self, **kwargs: Any) -> Any:
        return self._answer(kwargs)


@pytest.fixture
def provider(monkeypatch: pytest.MonkeyPatch) -> _Provider:
    fake = _Provider()
    monkeypatch.setattr(litellm, "acompletion", fake.acompletion)
    monkeypatch.setattr(litellm, "completion", fake.completion)
    return fake


def _custom_target(tmp_path: Path) -> Path:
    target = tmp_path / "target.yaml"
    target.write_text(
        "family: myapp-notes\ncommand: echo\nargs: []\nweakness_classes:\n  - W2\n",
        encoding="utf-8",
    )
    return target


def _argv(command: str, tmp_path: Path) -> list[str]:
    if command == "scan":
        target = _custom_target(tmp_path)
        return ["scan", "--target-file", str(target), "--authorize", "myapp-notes"]
    if command == "gate":
        return ["gate", "reference:vulnerable", "--out", str(tmp_path / "g"), "--no-workflows"]
    if command == "gate-custom":
        target = _custom_target(tmp_path)
        return ["gate", "--target-file", str(target), "--authorize", "myapp-notes"]
    if command == "validate":
        return ["validate", str(_generated_dir(tmp_path))]
    if command == "validate-custom":
        return ["validate", str(_custom_generated_dir(tmp_path)), "--authorize", "myapp-notes"]
    target = _custom_target(tmp_path)
    return [
        "ablate",
        "--target-file",
        str(target),
        "--authorize",
        "myapp-notes",
        "--controls",
        "W2",
    ]


def _custom_generated_dir(tmp_path: Path) -> Path:
    """A real `generate` output for a custom target, target.yaml co-located."""
    import json

    from tests.test_cli import _sample_exploit

    exploit = _sample_exploit().model_copy(update={"target_id": "mcp:myapp-notes"})
    exploit_json = tmp_path / "exploit_custom.json"
    exploit_json.write_text(json.dumps(exploit.model_dump(mode="json")), encoding="utf-8")
    out_dir = tmp_path / "gen-custom"
    target = _custom_target(tmp_path)
    argv = ["generate", str(exploit_json), "--out", str(out_dir), "--target-file", str(target)]
    result = runner.invoke(app, argv)
    assert result.exit_code == 0, result.output
    return out_dir


_COMMANDS = ["scan", "gate", "gate-custom", "validate", "validate-custom", "ablate"]


@pytest.fixture
def launch_spies() -> Iterator[dict[str, Any]]:
    with ExitStack() as stack:
        yield {name: stack.enter_context(patch(name)) for name in _LAUNCH_POINTS}


def _assert_target_never_started(command: str, spies: dict[str, Any]) -> None:
    allowed = _CONSTRUCTED_BEFORE_PREFLIGHT.get(command, set())
    for name, spy in spies.items():
        if name not in allowed:
            assert not spy.called, f"{name} ran before the key preflight stopped {command}"


def _one_error_line(output: str) -> str:
    lines = [line for line in output.splitlines() if line.strip().startswith("error:")]
    assert len(lines) == 1, output
    assert "Traceback" not in output
    return lines[0]


@pytest.mark.parametrize("command", _COMMANDS)
def test_a_401_exits_4_naming_the_key_variable_before_the_target_starts(
    command: str, tmp_path: Path, provider: _Provider, launch_spies: dict[str, Any]
) -> None:
    provider.error = litellm.AuthenticationError(
        message="invalid x-api-key", llm_provider="anthropic", model="anthropic/m"
    )
    result = runner.invoke(app, _argv(command, tmp_path))

    assert result.exit_code == EXIT_PROVIDER, result.output
    line = _one_error_line(result.output)
    assert _KEY_VAR in line
    assert "invalid or expired" in line
    assert len(provider.calls) == 1, "one tiny request for the one configured model"
    _assert_target_never_started(command.split("-")[0], launch_spies)


@pytest.mark.parametrize("command", _COMMANDS)
def test_a_400_header_required_exits_4_naming_llm_header_before_the_target_starts(
    command: str, tmp_path: Path, provider: _Provider, launch_spies: dict[str, Any]
) -> None:
    provider.error = litellm.BadRequestError(
        message=_HEADER_400, model="anthropic/m", llm_provider="anthropic"
    )
    result = runner.invoke(app, _argv(command, tmp_path))

    assert result.exit_code == EXIT_PROVIDER, result.output
    line = _one_error_line(result.output)
    assert f"--llm-header {_WORKSPACE_HEADER}=" in line
    assert LLM_HEADERS_ENV in line
    assert "invalid or expired" not in line
    _assert_target_never_started(command.split("-")[0], launch_spies)


@pytest.mark.parametrize("command", _COMMANDS)
def test_no_model_and_no_key_exits_4_before_the_target_starts(
    command: str, tmp_path: Path, provider: _Provider, launch_spies: dict[str, Any]
) -> None:
    argv = _argv(command, tmp_path)
    result = runner.invoke(app, argv, env={"MYLONITE_MODEL": None, _KEY_VAR: None})

    assert result.exit_code == EXIT_PROVIDER, result.output
    assert provider.calls == []
    _assert_target_never_started(command.split("-")[0], launch_spies)


# --- --llm-header: the value reaches the provider and nothing else -----------


def test_a_malformed_header_is_a_usage_error_that_never_echoes_the_value() -> None:
    result = runner.invoke(app, ["--llm-header", f"bad name={_SENTINEL}", "version"])
    assert result.exit_code == EXIT_CONFIG
    assert _SENTINEL not in result.output


@pytest.mark.parametrize("source", ["flag", "env"])
def test_a_curl_style_header_never_reaches_the_console(source: str) -> None:
    """'Name: value=pad' splits at the first '=' into a bogus name that holds
    the secret; the usage error must not print it, from either source."""
    entry = f"x-ws: {_SENTINEL}=pad"
    if source == "flag":
        result = runner.invoke(app, ["--llm-header", entry, "version"])
    else:
        result = runner.invoke(app, ["version"], env={LLM_HEADERS_ENV: entry})
    assert result.exit_code == EXIT_CONFIG
    assert _SENTINEL not in result.output
    assert "x-ws" not in result.output
    assert "NAME=VALUE" in result.output


def test_env_file_loads_the_headers_variable_without_printing_its_value(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The workspace id belongs next to the key in a .env file. The loader
    accepts the variable by its exact name and never echoes the value."""
    from mylonite.scan.llm_headers import configured_llm_headers

    # Registered with monkeypatch so the loader's os.environ write is undone.
    monkeypatch.setenv(LLM_HEADERS_ENV, "")
    env_file = tmp_path / ".env"
    env_file.write_text(f"{LLM_HEADERS_ENV}={_WORKSPACE_HEADER}={_SENTINEL}\n", encoding="utf-8")
    result = runner.invoke(app, ["--env-file", str(env_file), "version"])

    assert result.exit_code == 0, result.output
    assert f"ignored {LLM_HEADERS_ENV}" not in result.output
    assert _SENTINEL not in result.output
    assert configured_llm_headers() == ((_WORKSPACE_HEADER, _SENTINEL),)


def test_a_malformed_env_header_is_a_usage_error_too() -> None:
    result = runner.invoke(app, ["version"], env={LLM_HEADERS_ENV: f"no-equals-{_SENTINEL}"})
    assert result.exit_code == EXIT_CONFIG
    assert _SENTINEL not in result.output


def _all_written_text(root: Path) -> str:
    return "\n".join(
        p.read_bytes().decode("utf-8", errors="replace") for p in root.rglob("*") if p.is_file()
    )


@pytest.mark.parametrize("source", ["flag", "env"])
def test_header_value_reaches_every_call_but_no_output_log_or_artefact(
    source: str,
    tmp_path: Path,
    provider: _Provider,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A full offline scan with the header set: every provider call carries
    it, and the sentinel value appears in no console line, log record or
    file the run wrote anywhere under its working directory -- even when the
    provider echoes it in an error."""
    monkeypatch.chdir(tmp_path)
    provider.error = None
    out = tmp_path / "out"
    header = f"{_WORKSPACE_HEADER}={_SENTINEL}"
    argv = ["scan", "reference:vulnerable", "--output-dir", str(out), "--max-llm-calls", "6"]
    env: dict[str, str | None] = {}
    if source == "flag":
        argv = ["--llm-header", header, *argv]
    else:
        env[LLM_HEADERS_ENV] = header

    real_answer = provider._answer
    seen = {"n": 0}

    def _echoing_answer(kwargs: dict[str, Any]) -> Any:
        seen["n"] += 1
        if seen["n"] == 3:
            # One mid-run call fails and echoes the header back, the way a
            # verbose proxy error might.
            provider.calls.append(kwargs)
            raise RuntimeError(f"upstream said: bad {_WORKSPACE_HEADER} {_SENTINEL}")
        return real_answer(kwargs)

    provider._answer = _echoing_answer  # type: ignore[method-assign]
    with caplog.at_level(logging.DEBUG):
        result = runner.invoke(app, argv, env=env)

    assert provider.calls, result.output
    for call in provider.calls:
        assert call.get("extra_headers") == {_WORKSPACE_HEADER: _SENTINEL}
    assert out.exists(), result.output
    assert _SENTINEL not in result.output
    assert _SENTINEL not in caplog.text
    assert _SENTINEL not in _all_written_text(tmp_path)


def test_scan_prints_each_credential_warning_once_on_the_seed_arm_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """scan's seed_arm branch checks the key early, before the probe, and
    again for every role later; a provider warning (Bedrock's best-effort
    credential note) must still print once."""
    import typer

    from mylonite.plugins._mcp.target_file import load_target_file

    for var in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_PROFILE"):
        monkeypatch.delenv(var, raising=False)
    target = _custom_target(tmp_path)
    tf = load_target_file(target)
    model = f"{PROVIDERS['bedrock'].model_prefix}example-model"
    with (
        patch("mylonite.scan.auth_preflight.auth_preflight_or_exit"),
        patch("mylonite.plugins.cli_targets.autowire_seed_arm", return_value=(tf, False, True)),
        patch(
            "mylonite.plugins.cli_targets.refuse_uncoverable_weakness_classes",
            side_effect=typer.Exit(9),
        ),
    ):
        argv = ["scan", "--target-file", str(target), "--authorize", "myapp-notes"]
        result = runner.invoke(app, [*argv, "--model", model])

    assert result.exit_code == 9, result.output
    warnings = [line for line in result.output.splitlines() if "AWS" in line]
    assert len(warnings) == 1, result.output
