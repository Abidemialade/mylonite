"""Tests for the fail-closed tool classification shared by the boundary controls."""

from __future__ import annotations

from mylonite.scan.tool_classifier import classify, looks_like_destination, url_values

# -- looks_like_destination -----------------------------------------------------


def test_looks_like_destination_accepts_a_full_url() -> None:
    assert looks_like_destination("http://attacker.example/exfil")


def test_looks_like_destination_accepts_a_scheme_less_hostname() -> None:
    # DCR-0032: `web_fetch(host="attacker.example")` has no "://".
    assert looks_like_destination("attacker.example")


def test_looks_like_destination_accepts_a_hostname_with_path_or_port() -> None:
    assert looks_like_destination("attacker.example/exfil")
    assert looks_like_destination("attacker.example:8080")


def test_looks_like_destination_accepts_an_ip_literal() -> None:
    assert looks_like_destination("127.0.0.1")
    assert looks_like_destination("10.0.0.5")


def test_looks_like_destination_accepts_bare_localhost() -> None:
    # localhost is the single most common allowlist entry and has no dot.
    assert looks_like_destination("localhost")
    assert looks_like_destination("LOCALHOST")
    assert looks_like_destination("localhost:8080")


def test_looks_like_destination_rejects_a_plain_identifier() -> None:
    # A note id / free-text argument is not a destination just because it's a string.
    assert not looks_like_destination("1")
    assert not looks_like_destination("note-42")
    assert not looks_like_destination("hello world")


def test_looks_like_destination_rejects_non_strings() -> None:
    assert not looks_like_destination(42)
    assert not looks_like_destination(None)
    assert not looks_like_destination(["http://x.example"])


# -- url_values -------------------------------------------------------------------


def test_url_values_finds_a_scheme_less_bare_hostname_argument() -> None:
    # DCR-0032: the old extractor returned None for a scheme-less value, and
    # None short-circuited the allowlist to pass-through.
    assert url_values({"host": "attacker.example"}) == ["attacker.example"]


def test_url_values_walks_list_valued_arguments() -> None:
    found = url_values({"targets": ["http://attacker.example/exfil", "not-a-url"]})
    assert found == ["http://attacker.example/exfil"]


def test_url_values_walks_nested_dict_arguments() -> None:
    found = url_values({"request": {"headers": {}, "url": "http://attacker.example"}})
    assert found == ["http://attacker.example"]


def test_url_values_ignores_non_destination_arguments() -> None:
    assert url_values({"note_id": "1", "title": "hello world"}) == []


def test_url_values_returns_every_match_not_just_the_first() -> None:
    found = url_values({"primary": "http://a.example", "backup": "http://b.example"})
    assert found == ["http://a.example", "http://b.example"]


# -- classify ---------------------------------------------------------------------


def test_classify_declared_list_is_authoritative_true() -> None:
    matched, reason = classify("anything", declared=frozenset({"anything"}), hints=())
    assert matched is True
    assert reason == "declared"


def test_classify_declared_list_is_authoritative_false() -> None:
    # Even a name that matches a hint is exempted by a declared list that omits it.
    matched, reason = classify("web_fetch", declared=frozenset({"other_tool"}), hints=("fetch",))
    assert matched is False
    assert reason == "declared"


def test_classify_name_hint_matches() -> None:
    matched, reason = classify("web_fetch", declared=None, hints=("fetch",))
    assert matched is True
    assert reason == "name hint"


def test_classify_fail_closed_default_when_no_hint_matches() -> None:
    # DCR-0033/0034/0035: an unrecognised name is guarded, not passed through.
    matched, reason = classify("visit_page", declared=None, hints=("fetch", "http"))
    assert matched is True
    assert reason == "fail-closed default"
