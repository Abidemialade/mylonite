"""A read-only GitHub REST client.

It reads with GET and sends exactly two writes: minting an installation token
(with an App JWT) and revoking the installation token it was built with. There
is deliberately no generic ``post``, ``put``, ``patch`` or ``delete``.

Every token the client is given or mints is registered with
:mod:`mylonite._redaction`, and every error message is masked before it is
raised, so no token character reaches a log, a traceback or a report.
"""

from __future__ import annotations

from typing import Any, Literal

import httpx

from mylonite._redaction import mask_registered_values, register_masked_value

API_VERSION = "2022-11-28"
DEFAULT_BASE_URL = "https://api.github.com"
PER_PAGE = 100
MAX_PAGES = 50
_TIMEOUT_SECONDS = 30.0

TokenKind = Literal["classic", "installation", "fine_grained", "oauth_user", "unknown"]

_PREFIXES: tuple[tuple[str, TokenKind], ...] = (
    ("github_pat_", "fine_grained"),
    ("ghp_", "classic"),
    ("ghs_", "installation"),
    ("gho_", "oauth_user"),
    ("ghu_", "oauth_user"),
)


def token_kind(token: str) -> TokenKind:
    """Name the kind of GitHub token from its prefix."""
    for prefix, kind in _PREFIXES:
        if token.startswith(prefix):
            return kind
    return "unknown"


class GitHubError(Exception):
    """A GitHub call failed: a non-success status, or no response at all.

    ``status`` is the HTTP status, or ``None`` when the request never got a
    response. ``path`` is the API path that was called. The message is masked.
    """

    def __init__(self, message: str, *, status: int | None, path: str) -> None:
        super().__init__(mask_registered_values(message))
        self.status = status
        self.path = path


def _error_detail(response: httpx.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        return ""
    if isinstance(body, dict) and isinstance(body.get("message"), str):
        return f": {body['message']}"
    return ""


class GitHubClient:
    """One authenticated connection to the GitHub REST API.

    ``bearer_is_jwt`` marks a client built with a GitHub App JWT rather than a
    token; on such a client only :meth:`post_mint_installation_token` is
    meaningful.
    """

    def __init__(
        self,
        token: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        transport: httpx.BaseTransport | None = None,
        bearer_is_jwt: bool = False,
    ) -> None:
        register_masked_value(token)
        self.base_url = base_url.rstrip("/")
        self.bearer_is_jwt = bearer_is_jwt
        self._base = httpx.URL(self.base_url)
        self._http = httpx.Client(
            base_url=self.base_url,
            transport=transport,
            timeout=_TIMEOUT_SECONDS,
            follow_redirects=False,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": API_VERSION,
            },
        )

    def __repr__(self) -> str:
        return f"GitHubClient(base_url={self.base_url!r})"

    def close(self) -> None:
        self._http.close()

    def _send(
        self,
        method: str,
        url: str | httpx.URL,
        *,
        path: str,
        params: dict[str, str] | None = None,
    ) -> httpx.Response:
        try:
            return self._http.request(method, url, params=params)
        except httpx.HTTPError as exc:
            raise GitHubError(
                f"GitHub {method} {path} failed with no response ({type(exc).__name__})",
                status=None,
                path=path,
            ) from None

    def get(self, path: str, *, params: dict[str, str] | None = None) -> httpx.Response:
        """GET ``path``; return the response whatever its status.

        Raises :class:`GitHubError` only when no response arrives.
        """
        return self._send("GET", path, path=path, params=params)

    def get_all(self, path: str, *, key: str | None = None) -> list[dict[str, Any]]:
        """GET every page of a list endpoint, following ``Link: rel="next"``.

        ``key`` names the field holding the list when the endpoint wraps it in
        an object. Stops after 50 pages. Raises :class:`GitHubError` on any
        non-200 page, or on a next link that leaves the API host.
        """
        items: list[dict[str, Any]] = []
        response = self._send("GET", path, path=path, params={"per_page": str(PER_PAGE)})
        for page in range(1, MAX_PAGES + 1):
            if response.status_code != 200:
                raise GitHubError(
                    f"GitHub GET {path} returned {response.status_code}{_error_detail(response)}",
                    status=response.status_code,
                    path=path,
                )
            body = response.json()
            chunk = body.get(key, []) if key is not None and isinstance(body, dict) else body
            if not isinstance(chunk, list):
                raise GitHubError(
                    f"GitHub GET {path} did not return a list",
                    status=response.status_code,
                    path=path,
                )
            items.extend(item for item in chunk if isinstance(item, dict))
            next_url = response.links.get("next", {}).get("url")
            if not next_url or page == MAX_PAGES:
                break
            url = httpx.URL(next_url)
            if (url.scheme, url.host, url.port) != (
                self._base.scheme,
                self._base.host,
                self._base.port,
            ):
                raise GitHubError(
                    f"GitHub GET {path} gave a next page on another host",
                    status=response.status_code,
                    path=path,
                )
            response = self._send("GET", url, path=path)
        return items

    def post_mint_installation_token(self, installation_id: int) -> str:
        """Mint an installation token with this client's App JWT.

        Returns the new token, already registered for masking. Raises
        :class:`GitHubError` on any status other than 201.
        """
        path = f"/app/installations/{int(installation_id)}/access_tokens"
        response = self._send("POST", path, path=path)
        if response.status_code != 201:
            raise GitHubError(
                f"GitHub POST {path} returned {response.status_code}{_error_detail(response)}",
                status=response.status_code,
                path=path,
            )
        try:
            token = response.json().get("token")
        except (ValueError, AttributeError):
            token = None
        if not isinstance(token, str) or not token:
            raise GitHubError(
                f"GitHub POST {path} returned no token",
                status=response.status_code,
                path=path,
            )
        register_masked_value(token)
        return token

    def delete_own_installation_token(self) -> int:
        """Revoke the installation token this client was built with.

        Returns the status code (204 on success). Never raises on a 401 or
        404, so cleanup can call it on a token that is already revoked.
        """
        path = "/installation/token"
        return int(self._send("DELETE", path, path=path).status_code)
