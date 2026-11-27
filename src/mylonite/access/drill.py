"""The revocation drill: does a revoked GitHub App installation token stop working?

The drill mints two installation tokens, A and B, and checks both reach
``GET /installation/repositories``. It then runs two arms:

* **with the control:** revoke A with ``DELETE /installation/token`` and probe
  every ``interval_s`` seconds until a 401 or the deadline;
* **with the control removed:** leave B alone, wait as long as the first arm
  took, and probe once.

Revocation holds only when A ends on 401 and B still answers 200. If B also
fails, the probe cannot tell revocation from a broken probe, and the result
is ``invalid``. Both tokens are revoked again in cleanup, whatever happened.

The only write is ``DELETE /installation/token``, on a token the drill minted.
No token or private-key text appears in a result.
"""

from __future__ import annotations

import contextlib
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

import httpx

from mylonite.access.github_client import GitHubClient, GitHubError

PROBE_PATH = "/installation/repositories"
JWT_BACKDATE_SECONDS = 60
JWT_LIFETIME_SECONDS = 540
_PYJWT_HINT = (
    "the drill needs PyJWT to sign the App's token request; install PyJWT with the crypto extra"
)

DrillStatus = Literal["held", "not_held", "invalid", "not_tested"]


@dataclass(frozen=True)
class ArmResult:
    """One arm of the drill: the probe status before and after, and the wait."""

    revoked: bool
    status_before: int
    status_after: int
    seconds: float


@dataclass(frozen=True)
class DrillResult:
    """The drill's verdict on the revocation control."""

    control: Literal["revocation"]
    status: DrillStatus
    with_control: ArmResult | None
    control_removed: ArmResult | None
    reason: str


def not_tested_drill(reason: str) -> DrillResult:
    """A drill that could not run, with the reason."""
    return DrillResult(
        control="revocation",
        status="not_tested",
        with_control=None,
        control_removed=None,
        reason=reason,
    )


class _MissingPyJWT(ImportError):
    pass


def mint_app_jwt(app_id: int, private_key_pem: str, *, now: int) -> str:
    """Sign a GitHub App JWT with RS256.

    ``iat`` is back-dated 60 seconds for clock drift and ``exp`` is 540
    seconds ahead, inside GitHub's 10-minute maximum. Raises an
    :class:`ImportError` when PyJWT is not installed.
    """
    try:
        import jwt
    except ImportError:
        raise _MissingPyJWT(_PYJWT_HINT) from None
    claims = {
        "iat": now - JWT_BACKDATE_SECONDS,
        "exp": now + JWT_LIFETIME_SECONDS,
        "iss": str(app_id),
    }
    return str(jwt.encode(claims, private_key_pem, algorithm="RS256"))


def _verdict(with_control: ArmResult, control_removed: ArmResult) -> tuple[DrillStatus, str]:
    after_a, after_b = with_control.status_after, control_removed.status_after
    waited = f"{with_control.seconds:g} seconds"
    if after_a == 401 and after_b == 200:
        return (
            "held",
            f"the revoked token was refused after {waited}; the token left unrevoked still worked",
        )
    if after_a == 200 and after_b == 200:
        return (
            "not_held",
            f"the revoked token still worked after {waited}, the deadline",
        )
    if after_a == 401 and after_b == 401:
        return (
            "invalid",
            "the token left unrevoked was refused too, so the probe cannot tell"
            " revocation apart from a broken probe",
        )
    if after_a == 200 and after_b == 401:
        return (
            "invalid",
            "the revoked token still worked while the token left unrevoked was refused,"
            " so the probe cannot tell the two arms apart",
        )
    return (
        "not_tested",
        f"the probe gave an unexpected result: revoked token {after_a}, unrevoked token {after_b}",
    )


def run_revocation_drill(
    *,
    app_id: int,
    private_key_pem: str,
    installation_id: int,
    deadline_s: float = 60.0,
    interval_s: float = 2.0,
    transport: httpx.BaseTransport | None = None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> DrillResult:
    """Run the revocation drill against one App installation.

    Never raises on a GitHub or network failure, or on any other error inside
    the drill; those become ``not_tested`` with the reason (an unexpected
    error is named by type only). Both tokens are revoked in cleanup either
    way. Raises :class:`ValueError` on a non-positive deadline or interval.
    """
    if deadline_s <= 0 or interval_s <= 0:
        raise ValueError("deadline_s and interval_s must be positive")

    try:
        app_jwt = mint_app_jwt(app_id, private_key_pem, now=int(time.time()))
    except (ImportError, NotImplementedError):
        # NotImplementedError: PyJWT is present but RS256 needs its crypto extra.
        return not_tested_drill(_PYJWT_HINT)
    except Exception as exc:  # any key failure; never echo its text
        return not_tested_drill(
            f"the App private key could not sign a token request ({type(exc).__name__})"
        )

    token_clients: list[GitHubClient] = []
    cleanup_problems: list[str] = []
    jwt_client = GitHubClient(app_jwt, transport=transport, bearer_is_jwt=True)
    try:
        result = _drill(
            jwt_client,
            installation_id,
            token_clients,
            deadline_s=deadline_s,
            interval_s=interval_s,
            transport=transport,
            sleep=sleep,
            clock=clock,
        )
    except Exception as exc:  # anything _drill does not handle; never echo its text
        result = not_tested_drill(
            f"the drill stopped on an unexpected error ({type(exc).__name__})"
        )
    finally:
        for label, client in zip("AB", token_clients, strict=False):
            problem = _revoke_in_cleanup(client)
            if problem:
                cleanup_problems.append(f"token {label} could not be revoked in cleanup: {problem}")
        jwt_client.close()

    if cleanup_problems:
        result = DrillResult(
            control=result.control,
            status=result.status,
            with_control=result.with_control,
            control_removed=result.control_removed,
            reason="; ".join([result.reason, *cleanup_problems]),
        )
    return result


def _revoke_in_cleanup(client: GitHubClient) -> str | None:
    """Revoke one token and close its client; return a problem, or ``None``.

    204 is revoked; 401 and 404 mean the token is already gone. Any exception
    is named by type only, since its message could carry secret text.
    """
    try:
        status = client.delete_own_installation_token()
    except Exception as exc:  # cleanup must never raise or skip the next token
        return type(exc).__name__
    finally:
        with contextlib.suppress(Exception):  # closing is best effort
            client.close()
    if status in (204, 401, 404):
        return None
    return f"GitHub returned {status}"


def _drill(
    jwt_client: GitHubClient,
    installation_id: int,
    token_clients: list[GitHubClient],
    *,
    deadline_s: float,
    interval_s: float,
    transport: httpx.BaseTransport | None,
    sleep: Callable[[float], None],
    clock: Callable[[], float],
) -> DrillResult:
    """The drill body. Every client it builds is appended to ``token_clients``
    so the caller can revoke and close it, whatever happens here."""
    try:
        for _ in range(2):
            token = jwt_client.post_mint_installation_token(installation_id)
            token_clients.append(GitHubClient(token, transport=transport))
    except GitHubError as exc:
        return not_tested_drill(f"an installation token could not be minted: {exc}")
    client_a, client_b = token_clients

    try:
        # Both baselines come first, so no write is sent unless both tokens work.
        before_a = client_a.get(PROBE_PATH).status_code
        if before_a != 200:
            return not_tested_drill(
                f"the first probe with the token to revoke returned {before_a}, not 200"
            )
        before_b = client_b.get(PROBE_PATH).status_code
        if before_b != 200:
            return not_tested_drill(
                f"the first probe with the token left unrevoked returned {before_b}, not 200"
            )

        # The arm with the control: revoke A, then poll until 401 or the deadline.
        revoke_status = client_a.delete_own_installation_token()
        if revoke_status != 204:
            return not_tested_drill(
                f"the revocation call returned {revoke_status}, not 204,"
                " so the control was not exercised"
            )
        started = clock()
        while True:
            after_a = client_a.get(PROBE_PATH).status_code
            elapsed = clock() - started
            if after_a != 200 or elapsed >= deadline_s:
                break
            sleep(interval_s)
        with_control = ArmResult(
            revoked=True, status_before=before_a, status_after=after_a, seconds=elapsed
        )

        # The arm with the control removed: wait as long, then probe B once.
        started = clock()
        sleep(elapsed)
        after_b = client_b.get(PROBE_PATH).status_code
        control_removed = ArmResult(
            revoked=False,
            status_before=before_b,
            status_after=after_b,
            seconds=clock() - started,
        )
    except GitHubError as exc:
        return not_tested_drill(f"the drill could not reach GitHub: {exc}")

    status, reason = _verdict(with_control, control_removed)
    return DrillResult(
        control="revocation",
        status=status,
        with_control=with_control,
        control_removed=control_removed,
        reason=reason,
    )
