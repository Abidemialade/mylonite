"""Tests for the hidden `mylonite access` command. No test reaches the network."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest
from tests.access.conftest import Route, mock_client
from typer.testing import CliRunner

import mylonite.commands.access as access_cmd
from mylonite.access.github_client import GitHubClient
from mylonite.cli import app
from mylonite.exit_codes import EXIT_CONFIG, EXIT_FINDINGS, EXIT_SUCCESS

ORG = "my-test-org"
APP_SLUG = "coding-agent"
INSTALLATION_ID = 99
APP_ID = 4242

APP_INTENT = f"""\
intent_version: 0
approved_by: owner
approved_on: 2026-11-20
organisation: {ORG}
environment: test
identity:
  kind: github_app
  app_slug: {APP_SLUG}
repositories:
  - name: {ORG}/service-a
    access: write
permissions:
  contents: write
  metadata: read
"""

CLASSIC_INTENT = f"""\
intent_version: 0
approved_by: owner
approved_on: 2026-11-20
organisation: {ORG}
environment: test
identity:
  kind: classic_token
repositories:
  - name: {ORG}/service-a
    access: write
scopes: [repo]
"""


def ARGS(intent: Path) -> list[str]:
    return [
        "access",
        "--intent",
        str(intent),
        "--authorize",
        ORG,
        "--owner-token-env",
        "OWNER_TOKEN",
    ]


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MYLONITE_EXPERIMENTAL", "1")
    monkeypatch.setenv("OWNER_TOKEN", "ghp_" + "o" * 36)


@pytest.fixture
def intent_file(tmp_path: Path) -> Path:
    path = tmp_path / "intent.yaml"
    path.write_text(APP_INTENT, encoding="utf-8")
    return path


@pytest.fixture
def classic_intent_file(tmp_path: Path) -> Path:
    path = tmp_path / "classic-intent.yaml"
    path.write_text(CLASSIC_INTENT, encoding="utf-8")
    return path


@pytest.fixture
def unapproved_intent_file(tmp_path: Path) -> Path:
    path = tmp_path / "unapproved.yaml"
    path.write_text(APP_INTENT.replace("approved_on: 2026-11-20\n", ""), encoding="utf-8")
    return path


def _install(
    monkeypatch: pytest.MonkeyPatch, routes: dict[tuple[str, str], Route]
) -> list[tuple[str, bool]]:
    """Route every client the command builds to ``routes``; record what was built."""
    built: list[tuple[str, bool]] = []

    def factory(token: str, *, bearer_is_jwt: bool = False) -> GitHubClient:
        built.append((token, bearer_is_jwt))
        return mock_client(routes, token, bearer_is_jwt=bearer_is_jwt)

    monkeypatch.setattr(access_cmd, "_make_client", factory)
    return built


def _app_routes(repos: list[str], permissions: dict[str, str]) -> dict[tuple[str, str], Route]:
    routes: dict[tuple[str, str], Route] = {
        ("GET", f"/orgs/{ORG}/installations"): httpx.Response(
            200,
            json={
                "installations": [
                    {
                        "id": INSTALLATION_ID,
                        "app_id": APP_ID,
                        "app_slug": APP_SLUG,
                        "permissions": permissions,
                        "repository_selection": "selected",
                    }
                ]
            },
        ),
        ("GET", f"/user/installations/{INSTALLATION_ID}/repositories"): httpx.Response(
            200,
            json={
                "repositories": [
                    {"full_name": name, "private": True, "owner": {"login": ORG}} for name in repos
                ]
            },
        ),
        ("GET", f"/orgs/{ORG}"): httpx.Response(200, json={"plan": {"name": "team"}}),
    }
    for name in repos:
        routes[("GET", f"/repos/{name}/rulesets")] = httpx.Response(200, json=[])
    return routes


@pytest.fixture
def matching_github(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, bool]]:
    return _install(
        monkeypatch,
        _app_routes([f"{ORG}/service-a"], {"contents": "write", "metadata": "read"}),
    )


@pytest.fixture
def over_granted_github(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, bool]]:
    return _install(
        monkeypatch,
        _app_routes(
            [f"{ORG}/service-a", f"{ORG}/payroll"], {"contents": "write", "metadata": "read"}
        ),
    )


@pytest.fixture
def github_401(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, bool]]:
    refused = httpx.Response(401, json={"message": "Bad credentials"})
    return _install(
        monkeypatch,
        {("GET", f"/orgs/{ORG}/installations"): refused, ("GET", f"/orgs/{ORG}"): refused},
    )


class _Recorder:
    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(500)


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> _Recorder:
    recorder = _Recorder()

    def factory(token: str, *, bearer_is_jwt: bool = False) -> GitHubClient:
        return GitHubClient(
            token, transport=httpx.MockTransport(recorder.handler), bearer_is_jwt=bearer_is_jwt
        )

    monkeypatch.setattr(access_cmd, "_make_client", factory)
    monkeypatch.setattr(
        access_cmd, "_drill_transport", lambda: httpx.MockTransport(recorder.handler)
    )
    return recorder


# -- the order of refusals -----------------------------------------------------


def test_refuses_without_the_experimental_flag(runner, monkeypatch):
    monkeypatch.delenv("MYLONITE_EXPERIMENTAL", raising=False)
    assert runner.invoke(app, ["access", "--intent", "i.yaml", "--authorize", "x"]).exit_code == (
        EXIT_CONFIG
    )


def test_authorize_must_equal_the_organisation_before_any_request(runner, intent_file, no_network):
    result = runner.invoke(
        app, ["access", "--intent", str(intent_file), "--authorize", "someone-else"]
    )
    assert result.exit_code == EXIT_CONFIG and "my-test-org" in result.output
    assert no_network.requests == []


def test_unapproved_intent_is_refused_before_any_request(
    runner, unapproved_intent_file, no_network
):
    result = runner.invoke(app, ARGS(unapproved_intent_file))
    assert result.exit_code == EXIT_CONFIG and "not approved" in result.output
    assert no_network.requests == []


def test_unreadable_intent_is_one_line_exit_two(runner, tmp_path, no_network):
    result = runner.invoke(app, ARGS(tmp_path / "missing.yaml"))
    assert result.exit_code == EXIT_CONFIG and "Traceback" not in result.output
    assert no_network.requests == []


def test_missing_env_var_is_named_not_shown(runner, intent_file, monkeypatch):
    monkeypatch.delenv("OWNER_TOKEN", raising=False)
    result = runner.invoke(app, ARGS(intent_file))
    assert result.exit_code == EXIT_CONFIG and "OWNER_TOKEN" in result.output


def test_app_identity_needs_the_owner_token_flag(runner, intent_file, no_network):
    result = runner.invoke(app, ["access", "--intent", str(intent_file), "--authorize", ORG])
    assert result.exit_code == EXIT_CONFIG and "--owner-token-env" in result.output
    assert no_network.requests == []


def test_classic_identity_needs_the_token_flag(runner, classic_intent_file, no_network):
    result = runner.invoke(
        app, ["access", "--intent", str(classic_intent_file), "--authorize", ORG]
    )
    assert result.exit_code == EXIT_CONFIG and "--token-env" in result.output
    assert no_network.requests == []


@pytest.mark.parametrize(
    "extra",
    [["--app-id", str(APP_ID)], ["--app-key-env", "APP_KEY_PATH"]],
)
def test_app_id_and_app_key_env_come_together(runner, intent_file, no_network, extra):
    result = runner.invoke(app, [*ARGS(intent_file), *extra])
    assert result.exit_code == EXIT_CONFIG
    assert "--app-id" in result.output and "--app-key-env" in result.output
    assert no_network.requests == []


def test_missing_key_file_names_the_variable(
    runner, intent_file, no_network, monkeypatch, tmp_path
):
    missing = tmp_path / "nowhere" / "key.pem"
    monkeypatch.setenv("APP_KEY_PATH", str(missing))
    result = runner.invoke(
        app, [*ARGS(intent_file), "--app-id", str(APP_ID), "--app-key-env", "APP_KEY_PATH"]
    )
    assert result.exit_code == EXIT_CONFIG and "APP_KEY_PATH" in result.output
    assert "Traceback" not in result.output
    assert no_network.requests == []


# -- the run -------------------------------------------------------------------


def test_over_grant_exits_one_and_writes_both_files(
    runner, intent_file, over_granted_github, tmp_path
):
    out = tmp_path / "out"
    result = runner.invoke(app, [*ARGS(intent_file), "--no-drill", "--out", str(out)])
    assert result.exit_code == EXIT_FINDINGS
    assert (out / "report.md").exists() and (out / "report.json").exists()
    assert "REPO_NOT_INTENDED" in result.output
    data = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert data["drill"]["reason"] == "skipped with --no-drill"


def test_matching_grant_exits_zero_and_drill_is_not_tested_without_a_key(
    runner, intent_file, matching_github, tmp_path
):
    result = runner.invoke(app, [*ARGS(intent_file), "--out", str(tmp_path)])
    assert result.exit_code == EXIT_SUCCESS, result.output
    assert "private key" in (tmp_path / "report.md").read_text(encoding="utf-8")
    data = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert data["drill"]["status"] == "not_tested"
    assert data["drill"]["reason"] == (
        "the drill needs the App's private key, which only the App's owner holds"
    )
    assert "not_tested" in result.output


def test_no_token_text_in_output_or_files(
    runner, intent_file, matching_github, tmp_path, monkeypatch
):
    secret = "ghp_" + "q" * 36  # pragma: allowlist secret
    monkeypatch.setenv("OWNER_TOKEN", secret)
    result = runner.invoke(app, [*ARGS(intent_file), "--out", str(tmp_path)])
    assert result.exit_code == EXIT_SUCCESS, result.output
    assert secret not in result.output
    assert all(secret not in p.read_text(encoding="utf-8") for p in tmp_path.iterdir())


def test_refused_token_is_one_line_exit_two(runner, intent_file, github_401):
    result = runner.invoke(app, ARGS(intent_file))
    assert result.exit_code == EXIT_CONFIG and "Traceback" not in result.output
    assert "OWNER_TOKEN" in result.output


def test_revocation_not_expected_skips_the_drill(runner, tmp_path, matching_github, monkeypatch):
    intent = tmp_path / "intent.yaml"
    intent.write_text(APP_INTENT + "controls:\n  revocation: not_expected\n", encoding="utf-8")
    monkeypatch.setenv("APP_KEY_PATH", str(tmp_path / "unused.pem"))
    out = tmp_path / "out"
    result = runner.invoke(
        app,
        [
            *ARGS(intent),
            "--app-id",
            str(APP_ID),
            "--app-key-env",
            "APP_KEY_PATH",
            "--out",
            str(out),
        ],
    )
    assert result.exit_code == EXIT_SUCCESS, result.output
    data = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert data["drill"]["reason"] == "the intent does not expect revocation"


def _classic_routes() -> dict[tuple[str, str], Route]:
    return {
        ("GET", "/user"): httpx.Response(
            200, json={"login": "agent-bot"}, headers={"X-OAuth-Scopes": "repo"}
        ),
        ("GET", "/user/repos"): httpx.Response(
            200,
            json=[
                {
                    "full_name": f"{ORG}/service-a",
                    "private": True,
                    "owner": {"login": ORG},
                    "permissions": {"admin": False, "push": True, "pull": True},
                }
            ],
        ),
        ("GET", f"/orgs/{ORG}"): httpx.Response(200, json={"plan": {"name": "team"}}),
        ("GET", f"/repos/{ORG}/service-a/rulesets"): httpx.Response(200, json=[]),
    }


def test_classic_token_reads_with_the_agent_token_and_does_not_drill(
    runner, classic_intent_file, monkeypatch, tmp_path
):
    agent_token = "ghp_" + "a" * 36
    monkeypatch.setenv("AGENT_TOKEN", agent_token)
    built = _install(monkeypatch, _classic_routes())
    result = runner.invoke(
        app,
        [
            "access",
            "--intent",
            str(classic_intent_file),
            "--authorize",
            ORG,
            "--token-env",
            "AGENT_TOKEN",
            "--out",
            str(tmp_path),
        ],
    )
    assert result.exit_code == EXIT_SUCCESS, result.output
    assert built and all(token == agent_token for token, _jwt in built)
    data = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert data["drill"]["reason"] == (
        "a classic token can only be revoked by hand in GitHub settings"
    )
    assert agent_token not in result.output


def _drill_routes() -> Callable[[httpx.Request], httpx.Response]:
    """A GitHub App backend where revocation applies at once."""
    revoked: set[str] = set()
    minted = iter(["ghs_" + "a" * 36, "ghs_" + "b" * 36])

    def handler(request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("Authorization", "").removeprefix("Bearer ")
        path = request.url.path
        if (
            request.method == "POST"
            and path == f"/app/installations/{INSTALLATION_ID}/access_tokens"
        ):
            return httpx.Response(201, json={"token": next(minted)})
        if request.method == "DELETE" and path == "/installation/token":
            revoked.add(auth)
            return httpx.Response(204)
        if request.method == "GET" and path == "/installation/repositories":
            return httpx.Response(401 if auth in revoked else 200, json={"repositories": []})
        return httpx.Response(404)

    return handler


def _private_key_pem() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


def test_drill_runs_with_the_app_key_and_holds(
    runner, intent_file, matching_github, monkeypatch, tmp_path
):
    pem = _private_key_pem()
    key_path = tmp_path / "key.pem"
    key_path.write_text(pem, encoding="utf-8")
    monkeypatch.setenv("APP_KEY_PATH", str(key_path))
    monkeypatch.setattr(
        access_cmd, "_drill_transport", lambda: httpx.MockTransport(_drill_routes())
    )
    monkeypatch.setattr(access_cmd, "_DRILL_INTERVAL_S", 0.01)
    out = tmp_path / "out"
    result = runner.invoke(
        app,
        [
            *ARGS(intent_file),
            "--app-id",
            str(APP_ID),
            "--app-key-env",
            "APP_KEY_PATH",
            "--out",
            str(out),
        ],
    )
    assert result.exit_code == EXIT_SUCCESS, result.output
    data = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert data["drill"]["status"] == "held"
    assert "held" in result.output
    body = result.output + "".join(p.read_text(encoding="utf-8") for p in out.iterdir())
    assert "PRIVATE KEY" not in body and str(key_path) not in body


# -- --draft-intent ------------------------------------------------------------


def DRAFT_ARGS(target: Path) -> list[str]:
    return [
        "access",
        "--draft-intent",
        str(target),
        "--authorize",
        ORG,
        "--identity-kind",
        "github_app",
        "--app-slug",
        APP_SLUG,
        "--owner-token-env",
        "OWNER_TOKEN",
    ]


def test_draft_writes_an_unapproved_file_and_exits_zero(runner, tmp_path, matching_github):
    from mylonite.access.intent import IntentError, load_intent, require_approved

    target = tmp_path / "draft.yaml"
    result = runner.invoke(app, DRAFT_ARGS(target))
    assert result.exit_code == EXIT_SUCCESS, result.output
    intent = load_intent(target)
    assert [r.name for r in intent.repositories] == [f"{ORG}/service-a"]
    with pytest.raises(IntentError, match="not approved"):
        require_approved(intent)
    assert not (tmp_path / "mylonite-access").exists()
    assert "o" * 36 not in result.output


def test_draft_refuses_to_overwrite(runner, tmp_path, matching_github):
    target = tmp_path / "intent.yaml"
    target.write_text("keep", encoding="utf-8")
    result = runner.invoke(app, DRAFT_ARGS(target))
    assert result.exit_code == EXIT_CONFIG
    assert target.read_text(encoding="utf-8") == "keep"


def test_draft_removes_a_partial_file_when_the_write_fails(
    runner, tmp_path, matching_github, monkeypatch
):
    real_open = Path.open

    class _FailingHandle:
        def __init__(self, handle):
            self._handle = handle

        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            self._handle.close()
            return False

        def write(self, text):
            self._handle.write(text[:10])
            self._handle.flush()
            raise OSError(28, "No space left on device")

    def failing_open(self, mode="r", *args, **kwargs):
        handle = real_open(self, mode, *args, **kwargs)
        return _FailingHandle(handle) if mode == "x" else handle

    monkeypatch.setattr(Path, "open", failing_open)
    target = tmp_path / "draft.yaml"
    result = runner.invoke(app, DRAFT_ARGS(target))
    assert result.exit_code == EXIT_CONFIG
    assert "No space left on device" in result.output
    assert not target.exists()


def test_draft_and_intent_are_exclusive(runner, tmp_path, intent_file, no_network):
    result = runner.invoke(app, [*DRAFT_ARGS(tmp_path / "d.yaml"), "--intent", str(intent_file)])
    assert result.exit_code == EXIT_CONFIG
    assert not (tmp_path / "d.yaml").exists()
    assert no_network.requests == []


def test_draft_needs_identity_flags(runner, tmp_path, no_network):
    target = tmp_path / "d.yaml"
    base = ["access", "--draft-intent", str(target), "--owner-token-env", "OWNER_TOKEN"]
    assert runner.invoke(app, base).exit_code == EXIT_CONFIG
    no_kind = [*base, "--authorize", ORG]
    assert runner.invoke(app, no_kind).exit_code == EXIT_CONFIG
    no_slug = [*no_kind, "--identity-kind", "github_app"]
    assert runner.invoke(app, no_slug).exit_code == EXIT_CONFIG
    assert not target.exists() and no_network.requests == []


# -- the drill does not run on a mismatched or incomplete installation ---------


def _drill_args(intent: Path, out: Path, app_id: int) -> list[str]:
    return [
        *ARGS(intent),
        "--app-id",
        str(app_id),
        "--app-key-env",
        "APP_KEY_PATH",
        "--out",
        str(out),
    ]


@pytest.fixture
def drill_recorder(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> _Recorder:
    key_path = tmp_path / "key.pem"
    key_path.write_text(_private_key_pem(), encoding="utf-8")
    monkeypatch.setenv("APP_KEY_PATH", str(key_path))
    recorder = _Recorder()
    monkeypatch.setattr(
        access_cmd, "_drill_transport", lambda: httpx.MockTransport(recorder.handler)
    )
    return recorder


def test_app_id_differing_from_the_installation_skips_the_drill(
    runner, intent_file, matching_github, drill_recorder, tmp_path
):
    out = tmp_path / "out"
    result = runner.invoke(app, _drill_args(intent_file, out, APP_ID + 1))
    assert result.exit_code == EXIT_SUCCESS, result.output
    data = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert data["drill"]["status"] == "not_tested"
    assert data["drill"]["reason"] == (
        f"--app-id {APP_ID + 1} does not match the installation's app id {APP_ID}"
    )
    assert not any(r.url.path.endswith("/access_tokens") for r in drill_recorder.requests)
    assert drill_recorder.requests == []


def test_installation_without_an_id_skips_the_drill(
    runner, intent_file, matching_github, drill_recorder, tmp_path, monkeypatch
):
    from dataclasses import replace

    real = access_cmd.read_app_grant

    def without_id(owner: GitHubClient, org: str, slug: str):
        return replace(real(owner, org, slug), installation_id=None)

    monkeypatch.setattr(access_cmd, "read_app_grant", without_id)
    out = tmp_path / "out"
    result = runner.invoke(app, _drill_args(intent_file, out, APP_ID))
    assert result.exit_code == EXIT_SUCCESS, result.output
    data = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert data["drill"]["status"] == "not_tested"
    assert data["drill"]["reason"] == "the installation has no id to mint a token for"
    assert drill_recorder.requests == []


# -- the console summary --------------------------------------------------------


def test_summary_line_carries_the_not_tested_count(runner, intent_file, matching_github, tmp_path):
    result = runner.invoke(app, [*ARGS(intent_file), "--out", str(tmp_path)])
    assert result.exit_code == EXIT_SUCCESS, result.output
    count = len(json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))["not_tested"])
    assert f"result: PASS ({count} items not tested; see report.md)" in result.output


def test_summary_line_says_findings_on_an_over_grant(
    runner, intent_file, over_granted_github, tmp_path
):
    result = runner.invoke(app, [*ARGS(intent_file), "--no-drill", "--out", str(tmp_path)])
    assert result.exit_code == EXIT_FINDINGS
    assert "result: FINDINGS (" in result.output
    assert "FAIL" not in result.output
