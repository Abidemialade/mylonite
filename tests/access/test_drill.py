"""Tests for the revocation drill.

A fake GitHub answers on a mock transport and keeps the set of revoked
tokens. ``sleep`` and ``clock`` are fakes, so no test waits or touches the
network. The RSA key pair is generated here; no key file is committed.
"""

from __future__ import annotations

import sys
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from mylonite.access.drill import (
    DrillResult,
    mint_app_jwt,
    not_tested_drill,
    run_revocation_drill,
)

_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
TEST_KEY_PEM = _KEY.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
).decode()
TEST_PUBLIC_PEM = (
    _KEY.public_key()
    .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    .decode()
)

INSTALLATION_ID = 7
PROBE = "/installation/repositories"


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


class FakeGitHub:
    """GitHub for one installation; tokens are labelled A, B, ... by mint order."""

    def __init__(
        self,
        *,
        revocation_delay_probes: int = 0,
        revocation_never_applies: bool = False,
        all_tokens_die_after_probes: int | None = None,
        mint_status: int | None = None,
        mint_fails_after: int | None = None,
        first_probe_status: dict[str, int] | None = None,
        delete_status: int | None = None,
        cleanup_network_error: bool = False,
    ) -> None:
        self.revocation_delay_probes = revocation_delay_probes
        self.revocation_never_applies = revocation_never_applies
        self.all_tokens_die_after_probes = all_tokens_die_after_probes
        self.mint_status = mint_status
        self.mint_fails_after = mint_fails_after
        self.first_probe_status = first_probe_status or {}
        self.delete_status = delete_status
        self.cleanup_network_error = cleanup_network_error
        self.minted: list[str] = []
        self.labels: dict[str, str] = {}
        self.requests: list[tuple[str, str]] = []
        self.delete_calls_by_token: dict[str, int] = {}
        self.revoked: set[str] = set()
        self.probes_since_revoke: dict[str, int] = {}
        self.probes_by_token: dict[str, int] = {}
        self.probe_count = 0

    def _token(self, request: httpx.Request) -> str:
        return request.headers["Authorization"].removeprefix("Bearer ")

    def handler(self, request: httpx.Request) -> httpx.Response:
        method, path = request.method, request.url.path
        self.requests.append((method, path))
        if method == "POST" and path == f"/app/installations/{INSTALLATION_ID}/access_tokens":
            return self._mint()
        if method == "GET" and path == PROBE:
            return self._probe(self._token(request))
        if method == "DELETE" and path == "/installation/token":
            return self._delete(self._token(request), request)
        pytest.fail(f"unexpected request: {method} {path}")

    def _mint(self) -> httpx.Response:
        if self.mint_status is not None:
            return httpx.Response(self.mint_status, json={"message": "Forbidden"})
        if self.mint_fails_after is not None and len(self.minted) >= self.mint_fails_after:
            return httpx.Response(500, json={"message": "boom"})
        label = chr(ord("A") + len(self.minted))
        token = "ghs_" + label * 36
        self.minted.append(token)
        self.labels[token] = label
        return httpx.Response(201, json={"token": token, "expires_at": "2026-11-27T01:00:00Z"})

    def _probe(self, token: str) -> httpx.Response:
        self.probe_count += 1
        label = self.labels.get(token, "?")
        self.probes_by_token[label] = self.probes_by_token.get(label, 0) + 1
        if self.probes_by_token[label] == 1 and label in self.first_probe_status:
            return httpx.Response(self.first_probe_status[label], json={"message": "x"})
        if (
            self.all_tokens_die_after_probes is not None
            and self.probe_count > self.all_tokens_die_after_probes
        ):
            return httpx.Response(401, json={"message": "Bad credentials"})
        if self._revocation_applied(token, count=True):
            return httpx.Response(401, json={"message": "Bad credentials"})
        return httpx.Response(200, json={"total_count": 0, "repositories": []})

    def _revocation_applied(self, token: str, *, count: bool) -> bool:
        if token not in self.revoked or self.revocation_never_applies:
            return False
        seen = self.probes_since_revoke.get(token, 0)
        if seen >= self.revocation_delay_probes:
            return True
        if count:
            self.probes_since_revoke[token] = seen + 1
        return False

    def _delete(self, token: str, request: httpx.Request) -> httpx.Response:
        label = self.labels.get(token, "?")
        calls = self.delete_calls_by_token.get(label, 0) + 1
        self.delete_calls_by_token[label] = calls
        if self.cleanup_network_error and (label == "B" or calls > 1):
            raise httpx.ConnectError("network down", request=request)
        if self.delete_status is not None and label == "A" and calls == 1:
            return httpx.Response(self.delete_status, json={"message": "x"})
        if self._revocation_applied(token, count=False):
            return httpx.Response(401, json={"message": "Bad credentials"})
        self.revoked.add(token)
        return httpx.Response(204)


def args(fake: FakeGitHub, clock: FakeClock | None = None) -> dict[str, Any]:
    clock = clock or FakeClock()
    return {
        "app_id": 42,
        "private_key_pem": TEST_KEY_PEM,
        "installation_id": INSTALLATION_ID,
        "transport": httpx.MockTransport(fake.handler),
        "sleep": clock.sleep,
        "clock": clock,
    }


def test_jwt_claims():
    claims = jwt.decode(
        mint_app_jwt(42, TEST_KEY_PEM, now=1_000),
        TEST_PUBLIC_PEM,
        algorithms=["RS256"],
        options={"verify_exp": False},
    )
    assert claims == {"iat": 940, "exp": 1_540, "iss": "42"}


def test_jwt_is_rs256():
    header = jwt.get_unverified_header(mint_app_jwt(42, TEST_KEY_PEM, now=1_000))
    assert header["alg"] == "RS256"


def test_held_when_revocation_bites_and_the_unrevoked_token_still_works():
    result = run_revocation_drill(**args(FakeGitHub(revocation_delay_probes=1)))
    assert result.status == "held"
    assert result.control == "revocation"
    assert result.with_control is not None and result.control_removed is not None
    assert result.with_control.revoked is True
    assert result.with_control.status_before == 200
    assert result.with_control.status_after == 401
    assert result.control_removed.status_before == 200
    assert result.control_removed.status_after == 200
    assert result.control_removed.revoked is False


def test_control_removed_arm_waits_as_long_as_the_control_arm():
    clock = FakeClock()
    result = run_revocation_drill(
        **args(FakeGitHub(revocation_delay_probes=2), clock), interval_s=3
    )
    assert result.with_control is not None and result.control_removed is not None
    assert result.with_control.seconds == 6
    assert result.control_removed.seconds == 6


def test_not_held_when_the_token_survives_the_deadline():
    fake = FakeGitHub(revocation_never_applies=True)
    result = run_revocation_drill(**args(fake), deadline_s=10, interval_s=2)
    assert result.status == "not_held"
    assert result.with_control is not None
    assert result.with_control.status_after == 200
    assert result.with_control.seconds >= 10
    assert "10" in result.reason


def test_invalid_when_the_unrevoked_token_also_fails():
    result = run_revocation_drill(**args(FakeGitHub(all_tokens_die_after_probes=2)))
    assert result.status == "invalid"


def test_not_tested_when_a_token_cannot_be_minted():
    result = run_revocation_drill(**args(FakeGitHub(mint_status=403)))
    assert result.status == "not_tested" and "403" in result.reason
    assert result.with_control is None and result.control_removed is None


def test_second_mint_failure_still_revokes_the_first_token():
    fake = FakeGitHub(mint_fails_after=1)
    result = run_revocation_drill(**args(fake))
    assert result.status == "not_tested" and "500" in result.reason
    assert fake.delete_calls_by_token == {"A": 1}


@pytest.mark.parametrize("label", ["A", "B"])
def test_not_tested_when_a_first_probe_is_not_200(label):
    fake = FakeGitHub(first_probe_status={label: 403})
    result = run_revocation_drill(**args(fake))
    assert result.status == "not_tested" and "403" in result.reason
    assert fake.delete_calls_by_token == {"A": 1, "B": 1}


def test_not_tested_when_the_revocation_call_fails():
    fake = FakeGitHub(delete_status=404)
    result = run_revocation_drill(**args(fake))
    assert result.status == "not_tested" and "404" in result.reason


def test_both_tokens_are_revoked_in_cleanup_even_on_failure():
    fake = FakeGitHub(revocation_never_applies=True)
    run_revocation_drill(**args(fake), deadline_s=4)
    assert fake.delete_calls_by_token == {"A": 2, "B": 1}  # A: the drill, then cleanup


def test_cleanup_network_failure_is_reported_not_raised():
    fake = FakeGitHub(cleanup_network_error=True)
    result = run_revocation_drill(**args(fake))
    assert result.status == "held"
    assert "cleanup" in result.reason
    assert fake.delete_calls_by_token == {"A": 2, "B": 1}


def test_the_only_write_is_delete_installation_token():
    fake = FakeGitHub()
    run_revocation_drill(**args(fake))
    writes = {(m, p) for m, p in fake.requests if m != "GET"}
    assert writes == {
        ("POST", f"/app/installations/{INSTALLATION_ID}/access_tokens"),
        ("DELETE", "/installation/token"),
    }
    assert {p for m, p in fake.requests if m == "GET"} == {PROBE}


def test_no_token_or_key_text_in_the_result():
    fake = FakeGitHub()
    text = repr(run_revocation_drill(**args(fake)))
    assert all(t not in text for t in fake.minted) and "PRIVATE KEY" not in text


def test_a_bad_private_key_is_not_tested_and_not_echoed():
    # Built from parts so no committed line looks like a PEM header.
    marker = "PRIVATE " + "KEY"
    bad_key = f"-----BEGIN {marker}-----\nnot-a-key-at-all\n-----END {marker}-----\n"
    fake = FakeGitHub()
    result = run_revocation_drill(**{**args(fake), "private_key_pem": bad_key})
    assert result.status == "not_tested"
    assert "not-a-key-at-all" not in repr(result) and "PRIVATE KEY" not in repr(result)
    assert fake.requests == []


def test_missing_pyjwt_is_not_tested_with_an_install_hint(monkeypatch):
    monkeypatch.setitem(sys.modules, "jwt", None)
    fake = FakeGitHub()
    result = run_revocation_drill(**args(fake))
    assert result.status == "not_tested"
    assert "PyJWT" in result.reason and "crypto" in result.reason
    assert fake.requests == []


def test_bad_timing_arguments_are_refused():
    with pytest.raises(ValueError):
        run_revocation_drill(**args(FakeGitHub()), interval_s=0)
    with pytest.raises(ValueError):
        run_revocation_drill(**args(FakeGitHub()), deadline_s=-1)


def test_not_tested_drill():
    result = not_tested_drill("a classic token can only be revoked by hand in GitHub settings")
    assert result == DrillResult(
        control="revocation",
        status="not_tested",
        with_control=None,
        control_removed=None,
        reason="a classic token can only be revoked by hand in GitHub settings",
    )
