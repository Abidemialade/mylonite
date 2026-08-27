"""Host-aware assertion helpers for tests that check where a request went.

``assert "attacker.example.com" in recorded_url`` is the pattern CodeQL flags as
``py/incomplete-url-substring-sanitization``, and the flag is fair: it also
accepts ``https://totally-different.invalid/?ref=attacker.example.com``, where
the host appears in a query string and nothing was ever sent to it. A test that
would pass on that string is not testing what its name claims.

These helpers parse the host and compare it, so a lookalike fails. Promoted from
``tests/scan/test_seed_synth.py``, which arrived at the same shape when the same
alert fired there.
"""

from __future__ import annotations

from urllib.parse import urlparse

__all__ = ["assert_host_present", "host_of", "hosts_in"]


def host_of(token: str) -> str | None:
    """The host of a URL or an email address, or ``None`` if it is neither.

    Tolerates surrounding punctuation, because these tokens are usually pulled
    out of a recorded blob rather than handed over cleanly.
    """
    cleaned = token.strip().strip(".,;:!?'\"()[]<>").lower()
    if cleaned.startswith(("http://", "https://")):
        return urlparse(cleaned).hostname
    if "@" in cleaned:
        return cleaned.rsplit("@", 1)[1] or None
    return None


def hosts_in(blob: str) -> set[str]:
    """Every host named by a URL or email address anywhere in ``blob``."""
    return {host for token in blob.replace("'", " ").split() if (host := host_of(token))}


def assert_host_present(blob: str, expected: str) -> None:
    """Assert ``expected`` is the HOST of something in ``blob``, not a substring.

    Accepts the host itself or any subdomain of it, so a test can name a
    registrable domain without pinning the exact label a run happened to mint.
    """
    found = hosts_in(blob)
    matched = any(host == expected or host.endswith(f".{expected}") for host in found)
    assert matched, (
        f"expected a request to host {expected!r}, but the recorded hosts were "
        f"{sorted(found) or '(none)'}. Blob: {blob[:300]!r}"
    )
