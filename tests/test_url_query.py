"""Tests for ``redact_url_query`` — URL query-parameter value scrubber."""

from __future__ import annotations

from urllib.parse import parse_qsl, urlparse

from redactkit import MASK, redact_url_query


def test_no_query_string_returns_url_unchanged() -> None:
    assert redact_url_query("/protected") == "/protected"
    assert redact_url_query("https://example.com/api/foo") == "https://example.com/api/foo"


def test_empty_query_returns_url_unchanged() -> None:
    # Trailing ``?`` with nothing after it is a no-op.
    assert redact_url_query("/api/foo?") == "/api/foo?"


def test_safe_params_pass_through() -> None:
    out = redact_url_query("/protected?page=1&limit=20&lang=en")
    parsed = dict(parse_qsl(urlparse(out).query))
    assert parsed == {"page": "1", "limit": "20", "lang": "en"}


def test_token_value_is_redacted() -> None:
    out = redact_url_query("/protected?token=abcd1234supersecret")
    assert "abcd1234supersecret" not in out
    parsed = dict(parse_qsl(urlparse(out).query))
    assert parsed == {"token": MASK}


def test_password_value_is_redacted() -> None:
    out = redact_url_query("/protected?password=hunter2")
    assert "hunter2" not in out
    parsed = dict(parse_qsl(urlparse(out).query))
    assert parsed == {"password": MASK}


def test_api_key_and_authorization_are_redacted() -> None:
    out = redact_url_query("/protected?api_key=xyz789&authorization=Bearer-zzz")
    assert "xyz789" not in out
    assert "Bearer-zzz" not in out
    parsed = dict(parse_qsl(urlparse(out).query))
    assert parsed == {"api_key": MASK, "authorization": MASK}


def test_mixed_sensitive_and_safe_params() -> None:
    out = redact_url_query("/protected?api_key=xyz789&page=2")
    assert "xyz789" not in out
    parsed = dict(parse_qsl(urlparse(out).query))
    assert parsed == {"api_key": MASK, "page": "2"}


def test_repeated_sensitive_key_redacts_every_occurrence() -> None:
    out = redact_url_query("/protected?token=ZZZZAAA&token=QQQQBBB")
    assert "ZZZZAAA" not in out
    assert "QQQQBBB" not in out
    pairs = parse_qsl(urlparse(out).query)
    assert pairs == [("token", MASK), ("token", MASK)]


def test_path_and_scheme_are_preserved() -> None:
    out = redact_url_query("https://example.com:8443/api/v1/foo?token=secret&page=1")
    assert out.startswith("https://example.com:8443/api/v1/foo?")
    parsed = dict(parse_qsl(urlparse(out).query))
    assert parsed == {"token": MASK, "page": "1"}
