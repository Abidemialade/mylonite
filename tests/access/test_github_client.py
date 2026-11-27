"""The read-only GitHub client: auth, pagination, the two writes, redaction."""

from __future__ import annotations

import httpx
import pytest
from tests.access.conftest import mock_client

from mylonite._redaction import mask_registered_values
from mylonite.access.github_client import (
    API_VERSION,
    GitHubClient,
    GitHubError,
    token_kind,
)

BASE = "https://api.github.com"


def test_token_kind_by_prefix():
    assert token_kind("ghp_abc") == "classic"
    assert token_kind("ghs_abc") == "installation"
    assert token_kind("github_pat_abc") == "fine_grained"
    assert token_kind("gho_abc") == "oauth_user"
    assert token_kind("ghu_abc") == "oauth_user"
    assert token_kind("nonsense") == "unknown"
    assert token_kind("") == "unknown"


def test_client_has_no_generic_write_method():
    assert not any(hasattr(GitHubClient, m) for m in ("post", "put", "patch", "delete"))


def test_get_sends_auth_and_version_headers():
    seen: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"login": "octo"})

    token = "ghp_" + "h" * 36
    client = mock_client({("GET", "/user"): handle}, token=token)
    response = client.get("/user", params={"a": "b"})
    assert response.status_code == 200
    request = seen[0]
    assert request.headers["Authorization"] == f"Bearer {token}"
    assert request.headers["Accept"] == "application/vnd.github+json"
    assert request.headers["X-GitHub-Api-Version"] == API_VERSION == "2022-11-28"
    assert request.url.params["a"] == "b"
    assert str(request.url).startswith(BASE + "/user")


def test_get_returns_error_statuses_without_raising():
    client = mock_client({("GET", "/orgs/acme"): httpx.Response(404, json={})})
    assert client.get("/orgs/acme").status_code == 404


def test_get_all_follows_next_links():
    def handle(request: httpx.Request) -> httpx.Response:
        assert request.url.params["per_page"] == "100"
        if request.url.params.get("page") == "2":
            return httpx.Response(200, json=[{"id": 3}])
        return httpx.Response(
            200,
            json=[{"id": 1}, {"id": 2}],
            headers={"Link": f'<{BASE}/user/repos?per_page=100&page=2>; rel="next"'},
        )

    client = mock_client({("GET", "/user/repos"): handle})
    assert [r["id"] for r in client.get_all("/user/repos")] == [1, 2, 3]


def test_get_all_reads_items_under_a_key():
    body = {"total_count": 2, "installations": [{"id": 7}, {"id": 8}]}
    client = mock_client({("GET", "/orgs/acme/installations"): httpx.Response(200, json=body)})
    items = client.get_all("/orgs/acme/installations", key="installations")
    assert [i["id"] for i in items] == [7, 8]


@pytest.mark.parametrize(
    "body",
    [{"total_count": 0}, {"installations": None}, {"installations": {"id": 7}}],
)
def test_get_all_refuses_an_object_without_the_key_list(body):
    client = mock_client({("GET", "/orgs/acme/installations"): httpx.Response(200, json=body)})
    with pytest.raises(GitHubError) as info:
        client.get_all("/orgs/acme/installations", key="installations")
    assert info.value.status == 200
    assert info.value.path == "/orgs/acme/installations"
    assert "installations" in str(info.value)
    assert "/orgs/acme/installations" in str(info.value)


def test_get_all_raises_past_fifty_pages_instead_of_truncating():
    calls = 0

    def handle(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        page = int(request.url.params.get("page", "1"))
        return httpx.Response(
            200,
            json=[{"id": page}],
            headers={"Link": f'<{BASE}/user/repos?per_page=100&page={page + 1}>; rel="next"'},
        )

    client = mock_client({("GET", "/user/repos"): handle})
    with pytest.raises(GitHubError) as info:
        client.get_all("/user/repos")
    assert calls == 50
    assert info.value.status is None
    assert info.value.path == "/user/repos"
    assert "not read in full" in str(info.value)


def test_get_all_reads_exactly_fifty_pages_without_error():
    def handle(request: httpx.Request) -> httpx.Response:
        page = int(request.url.params.get("page", "1"))
        headers = {}
        if page < 50:
            headers["Link"] = f'<{BASE}/user/repos?per_page=100&page={page + 1}>; rel="next"'
        return httpx.Response(200, json=[{"id": page}], headers=headers)

    client = mock_client({("GET", "/user/repos"): handle})
    assert len(client.get_all("/user/repos")) == 50


def test_get_all_raises_github_error_on_invalid_json():
    client = mock_client({("GET", "/user/repos"): httpx.Response(200, content=b"<html>")})
    with pytest.raises(GitHubError) as info:
        client.get_all("/user/repos")
    assert info.value.status == 200
    assert info.value.path == "/user/repos"


@pytest.mark.parametrize(
    "bad_path",
    ["https://evil.example/x", "//evil.example/x", "user", "", "/x?u=http://evil.example"],
)
def test_get_and_get_all_refuse_a_non_api_path_before_any_request(bad_path):
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=[])

    client = GitHubClient("ghp_" + "p" * 36, transport=httpx.MockTransport(handler))
    with pytest.raises(GitHubError) as info:
        client.get(bad_path)
    assert info.value.status is None
    with pytest.raises(GitHubError):
        client.get_all(bad_path)
    assert seen == []


def test_delete_own_installation_token_raises_on_network_failure():
    def handle(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down", request=request)

    client = mock_client({("DELETE", "/installation/token"): handle}, token="ghs_" + "d" * 36)
    with pytest.raises(GitHubError) as info:
        client.delete_own_installation_token()
    assert info.value.status is None
    assert info.value.path == "/installation/token"


def test_get_all_refuses_a_next_link_to_another_host():
    sent_elsewhere: list[str] = []

    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.host != "api.github.com":
            sent_elsewhere.append(str(request.url))
        return httpx.Response(
            200,
            json=[{"id": 1}],
            headers={"Link": '<https://evil.example/user/repos?page=2>; rel="next"'},
        )

    client = mock_client({("GET", "/user/repos"): handle})
    with pytest.raises(GitHubError):
        client.get_all("/user/repos")
    assert sent_elsewhere == []


@pytest.mark.parametrize(
    "next_link",
    [
        "http://api.github.com/user/repos?page=2",
        "https://api.github.com:8443/user/repos?page=2",
    ],
)
def test_get_all_refuses_a_next_link_with_another_scheme_or_port(next_link):
    calls = 0

    def handle(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json=[{"id": 1}], headers={"Link": f'<{next_link}>; rel="next"'})

    client = mock_client({("GET", "/user/repos"): handle})
    with pytest.raises(GitHubError) as info:
        client.get_all("/user/repos")
    assert "another host" in str(info.value)
    assert calls == 1


def test_get_all_raises_on_non_200():
    client = mock_client(
        {("GET", "/user/repos"): httpx.Response(403, json={"message": "Forbidden"})}
    )
    with pytest.raises(GitHubError) as info:
        client.get_all("/user/repos")
    assert info.value.status == 403
    assert info.value.path == "/user/repos"


def test_token_never_appears_in_an_error():
    token = "ghp_" + "s" * 36
    client = mock_client(
        {("GET", "/user"): httpx.Response(401, json={"message": "Bad credentials"})},
        token=token,
    )
    with pytest.raises(GitHubError) as info:
        client.get_all("/user")
    assert token not in str(info.value) and token not in repr(info.value)
    assert info.value.status == 401


def test_token_echoed_in_an_error_body_is_masked():
    token = "ghp_" + "e" * 36
    client = mock_client(
        {("GET", "/user"): httpx.Response(401, json={"message": f"bad {token}"})},
        token=token,
    )
    with pytest.raises(GitHubError) as info:
        client.get_all("/user")
    assert token not in str(info.value)


def test_network_failure_becomes_github_error():
    token = "ghp_" + "n" * 36

    def handle(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"boom {token}", request=request)

    client = mock_client({("GET", "/user"): handle}, token=token)
    with pytest.raises(GitHubError) as info:
        client.get("/user")
    assert info.value.status is None
    assert info.value.path == "/user"
    assert token not in str(info.value) and token not in repr(info.value)


def test_token_is_registered_for_masking():
    token = "ghp_" + "m" * 36
    mock_client({}, token=token)
    assert token not in mask_registered_values(f"leak {token}")


def test_repr_shows_base_url_only():
    token = "ghp_" + "r" * 36
    client = mock_client({}, token=token)
    assert token not in repr(client)
    assert BASE in repr(client)


def test_mint_installation_token_returns_and_masks_the_token():
    minted = "ghs_" + "i" * 36
    seen: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(201, json={"token": minted, "expires_at": "x"})

    client = mock_client(
        {("POST", "/app/installations/42/access_tokens"): handle},
        token="eyJ" + "j" * 40,
        bearer_is_jwt=True,
    )
    assert client.post_mint_installation_token(42) == minted
    assert seen[0].method == "POST"
    assert minted not in mask_registered_values(minted)


def test_mint_installation_token_raises_on_non_201():
    client = mock_client(
        {
            ("POST", "/app/installations/42/access_tokens"): httpx.Response(
                404, json={"message": "Not Found"}
            )
        },
        token="eyJ" + "j" * 40,
        bearer_is_jwt=True,
    )
    with pytest.raises(GitHubError) as info:
        client.post_mint_installation_token(42)
    assert info.value.status == 404
    assert info.value.path == "/app/installations/42/access_tokens"


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(201, content=b"<html>not json</html>"),
        httpx.Response(201, json={"expires_at": "x"}),
        httpx.Response(201, json={"token": ""}),
        httpx.Response(201, json={"token": 123}),
        httpx.Response(201, json=["ghs_" + "l" * 36]),
    ],
)
def test_mint_installation_token_raises_on_a_201_without_a_usable_token(response):
    client = mock_client(
        {("POST", "/app/installations/42/access_tokens"): response},
        token="eyJ" + "j" * 40,
        bearer_is_jwt=True,
    )
    with pytest.raises(GitHubError) as info:
        client.post_mint_installation_token(42)
    assert info.value.status == 201
    assert info.value.path == "/app/installations/42/access_tokens"


def test_delete_own_installation_token_returns_status():
    for status in (204, 401, 404):
        client = mock_client(
            {("DELETE", "/installation/token"): httpx.Response(status)},
            token="ghs_" + "d" * 36,
        )
        assert client.delete_own_installation_token() == status
