"""The hidden ``mylonite access`` command: a coding agent's GitHub grant against its intent.

The order is fixed, and the tests pin it:

1. load the intent, require it approved, and refuse unless ``--authorize``
   equals its organisation -- all before any network call;
2. check the flags the identity needs, and that each named variable is set
   (the variable is named, its value never shown);
3. read the grant, compare it with the intent, and check the escalations;
4. run the revocation drill when it can run, or record why it did not;
5. write ``report.md`` and ``report.json`` and exit with the report's code.

Tokens and the App's private-key path come only from environment variables.
Network access goes through :func:`_make_client` and :func:`_drill_transport`
so tests can replace both.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import httpx
import typer

from mylonite._cli_io import echo, echo_err
from mylonite._redaction import mask_registered_values, register_masked_value
from mylonite.access.compare import Finding, compare_grant, escalation_findings
from mylonite.access.drill import DrillResult, not_tested_drill, run_revocation_drill
from mylonite.access.github_client import GitHubClient, GitHubError
from mylonite.access.grants import Grant, GrantError, read_app_grant, read_classic_token_grant
from mylonite.access.intent import Intent, IntentError, load_intent, require_approved
from mylonite.access.report import build_report, exit_code, to_json, to_markdown
from mylonite.exit_codes import EXIT_CONFIG
from mylonite.version import __version__

_DRILL_DEADLINE_S = 60.0
_DRILL_INTERVAL_S = 2.0

_REASON_CLASSIC = "a classic token can only be revoked by hand in GitHub settings"
_REASON_NO_KEY = "the drill needs the App's private key, which only the App's owner holds"
_REASON_NO_DRILL = "skipped with --no-drill"
_REASON_NOT_EXPECTED = "the intent does not expect revocation"


def _make_client(token: str, *, bearer_is_jwt: bool = False) -> GitHubClient:
    """Build a GitHub client. Tests replace this to keep off the network."""
    return GitHubClient(token, bearer_is_jwt=bearer_is_jwt)


def _drill_transport() -> httpx.BaseTransport | None:
    """The drill's transport: ``None`` (the real network) outside tests."""
    return None


def _refuse(message: str) -> typer.Exit:
    echo_err(f"error: {message}")
    return typer.Exit(code=EXIT_CONFIG)


def _env_value(name: str, flag: str) -> str:
    """The value of the variable ``name``; refuse naming it, never its value."""
    value = os.environ.get(name, "")
    if not value.strip():
        raise _refuse(f"the variable {name} named by {flag} is not set")
    value = value.strip()
    register_masked_value(value)
    return value


def _read_key(var: str) -> str:
    """Read the private key from the file whose path is in ``var``."""
    path = _env_value(var, "--app-key-env")
    try:
        pem = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        raise _refuse(
            f"the private key file named by {var} could not be read as UTF-8 text"
        ) from None
    register_masked_value(pem.strip())
    return pem


def _load(intent_path: Path, authorize: str) -> Intent:
    try:
        intent = load_intent(intent_path)
        require_approved(intent)
    except IntentError as exc:
        raise _refuse(str(exc)) from None
    if authorize != intent.organisation:
        raise _refuse(
            f"--authorize must equal the intent's organisation {intent.organisation};"
            " it asserts you own that test organisation (see SECURITY.md)"
        )
    return intent


def _drill_skip_reason(
    intent: Intent, *, no_drill: bool, app_id: int | None, key_var: str | None
) -> str | None:
    if no_drill:
        return _REASON_NO_DRILL
    if intent.controls.revocation == "not_expected":
        return _REASON_NOT_EXPECTED
    if intent.identity.kind == "classic_token":
        return _REASON_CLASSIC
    if app_id is None or key_var is None:
        return _REASON_NO_KEY
    return None


def _run_drill(grant: Grant, app_id: int, pem: str) -> DrillResult:
    if grant.installation_id is None:
        return not_tested_drill("the installation has no id to mint a token for")
    if grant.app_id is not None and grant.app_id != app_id:
        return not_tested_drill(
            f"--app-id {app_id} does not match the installation's app id {grant.app_id}"
        )
    return run_revocation_drill(
        app_id=app_id,
        private_key_pem=pem,
        installation_id=grant.installation_id,
        deadline_s=_DRILL_DEADLINE_S,
        interval_s=_DRILL_INTERVAL_S,
        transport=_drill_transport(),
    )


def _print(findings: list[Finding], drill: DrillResult, out: Path, code: int) -> None:
    counted = [f for f in findings if f.status in ("over_grant", "escalation")]
    echo(f"{len(counted)} finding(s) against the intent; {len(findings) - len(counted)} note(s).")
    for f in findings:
        echo(f"{f.status.upper()} {f.code} {f.subject}: {f.change}")
    echo(f"revocation drill: {drill.status} ({drill.reason})")
    echo(f"report written to {out / 'report.md'} and {out / 'report.json'}")
    echo("result: FAIL" if code else "result: PASS")


def access(
    intent_path: Annotated[
        Path,
        typer.Option("--intent", help="The owner-approved intent file (YAML)."),
    ],
    authorize: Annotated[
        str,
        typer.Option(
            "--authorize",
            help="Must equal the intent's organisation. Asserts you own that test organisation.",
        ),
    ],
    token_env: Annotated[
        str | None,
        typer.Option("--token-env", help="Variable holding the agent's classic token."),
    ] = None,
    owner_token_env: Annotated[
        str | None,
        typer.Option(
            "--owner-token-env",
            help="Variable holding an organisation owner's token, used read-only (GitHub App).",
        ),
    ] = None,
    app_id: Annotated[
        int | None,
        typer.Option("--app-id", help="The GitHub App's ID, for the revocation drill."),
    ] = None,
    app_key_env: Annotated[
        str | None,
        typer.Option(
            "--app-key-env",
            help="Variable holding the path to the App's private key file, for the drill.",
        ),
    ] = None,
    no_drill: Annotated[
        bool,
        typer.Option("--no-drill", help="Skip the revocation drill."),
    ] = False,
    out: Annotated[
        Path,
        typer.Option("--out", help="Directory for report.md and report.json."),
    ] = Path("mylonite-access"),
) -> None:
    """Compare a coding agent's real GitHub grant with an owner-approved intent file.

    Reads grants, scopes, repository names and rule names; never file contents.
    The one write is revoking an installation token the drill minted itself.
    """
    # 1. Intent, approval and authorization: no network yet.
    intent = _load(intent_path, authorize)

    # 2. The flags and variables the identity needs: still no network.
    if (app_id is None) != (app_key_env is None):
        raise _refuse("--app-id and --app-key-env must be given together")
    if intent.identity.kind == "classic_token":
        if token_env is None:
            raise _refuse("a classic_token identity needs --token-env NAME")
        reader_token = _env_value(token_env, "--token-env")
        reader_var = token_env
    else:
        if owner_token_env is None:
            raise _refuse("a github_app identity needs --owner-token-env NAME")
        reader_token = _env_value(owner_token_env, "--owner-token-env")
        reader_var = owner_token_env
    skip = _drill_skip_reason(intent, no_drill=no_drill, app_id=app_id, key_var=app_key_env)
    pem = _read_key(app_key_env) if skip is None and app_key_env is not None else None

    # 3. The grant, the comparison and the escalations.
    reader = _make_client(reader_token)
    try:
        if intent.identity.kind == "classic_token":
            grant = read_classic_token_grant(reader, intent.organisation)
        else:
            grant = read_app_grant(reader, intent.organisation, intent.identity.app_slug or "")
        findings = compare_grant(intent, grant)
        esc_findings, esc_not_tested = escalation_findings(intent, grant, reader)
    except GrantError as exc:
        raise _refuse(f"could not read the grant with the token in {reader_var}: {exc}") from None
    except GitHubError as exc:
        raise _refuse(" ".join(str(exc).split())) from None
    finally:
        reader.close()
    findings += esc_findings

    # 4. The drill, or why it did not run.
    if skip is None and app_id is not None and pem is not None:
        drill = _run_drill(grant, app_id, pem)
    else:
        drill = not_tested_drill(skip or _REASON_NO_KEY)

    # 5. The report.
    report = build_report(
        intent,
        grant,
        findings,
        drill,
        esc_not_tested,
        tool_version=__version__,
        now=datetime.now(UTC),
    )
    try:
        out.mkdir(parents=True, exist_ok=True)
        (out / "report.md").write_text(
            mask_registered_values(to_markdown(report)), encoding="utf-8"
        )
        (out / "report.json").write_text(mask_registered_values(to_json(report)), encoding="utf-8")
    except OSError as exc:
        raise _refuse(f"could not write the report under {out}: {exc.strerror or exc}") from None
    code = exit_code(report)
    _print(list(report.findings), drill, out, code)
    raise typer.Exit(code=code)
