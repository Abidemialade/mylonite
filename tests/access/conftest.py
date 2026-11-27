"""Shared helpers for the access tests: a GitHub client on a mock transport."""

from __future__ import annotations

from collections.abc import Callable, Iterator

import httpx
import pytest

from mylonite._redaction import clear_masked_values
from mylonite.access.github_client import GitHubClient

Route = httpx.Response | Callable[[httpx.Request], httpx.Response]

DEFAULT_TOKEN = "ghp_" + "x" * 36


def mock_client(
    routes: dict[tuple[str, str], Route],
    token: str = DEFAULT_TOKEN,
    *,
    bearer_is_jwt: bool = False,
) -> GitHubClient:
    """A client whose requests are answered from ``routes``.

    Keys are ``(METHOD, path)`` with the query string left out. A value is
    either a fixed response or a callable that takes the request. Any request
    with no route fails the test.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        key = (request.method, request.url.path)
        if key not in routes:
            pytest.fail(f"unrouted request: {request.method} {request.url.path}")
        route = routes[key]
        if isinstance(route, httpx.Response):
            return route
        return route(request)

    return GitHubClient(token, transport=httpx.MockTransport(handler), bearer_is_jwt=bearer_is_jwt)


@pytest.fixture(autouse=True)
def _reset_masked_values() -> Iterator[None]:
    """Each client registers its token; forget them so tests stay isolated."""
    clear_masked_values()
    yield
    clear_masked_values()
