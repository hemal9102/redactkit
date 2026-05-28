"""Tests for ``redact_text`` — free-form string scrubber."""

from __future__ import annotations

from redactkit import MASK, redact_text


def test_redact_text_masks_password_kv_pair() -> None:
    out = redact_text("user reported password=hunter2 in the form")
    assert "hunter2" not in out
    assert "password=" in out and MASK in out


def test_redact_text_masks_token_with_colon_separator() -> None:
    # Single-token kv form: the value is one non-whitespace token,
    # fully captured and masked.
    out = redact_text("debug log: token:abc.def.ghi from header")
    assert "abc.def.ghi" not in out
    assert MASK in out


def test_redact_text_masks_multiple_occurrences() -> None:
    out = redact_text("api_key=live-key-1 and another secret=topsecret value")
    assert "live-key-1" not in out
    assert "topsecret" not in out
    assert out.count(MASK) == 2


def test_redact_text_strips_presigned_url_signature() -> None:
    url = "https://s3/x?X-Amz-Signature=abcdef123&foo=1"
    out = redact_text(url)
    assert "abcdef123" not in out
    assert "X-Amz-Signature=***" in out


def test_redact_text_does_not_overmatch_lookalikes() -> None:
    # `refresh_rate` and `auth_type` are lookalikes that the denylist
    # explicitly excludes; redact_text must inherit that discipline.
    out = redact_text("refresh_rate=5 and auth_type=oidc are config flags")
    assert out == "refresh_rate=5 and auth_type=oidc are config flags"


def test_redact_text_passes_clean_strings_through() -> None:
    text = "operation completed in 1.2s with 3 tool calls"
    assert redact_text(text) == text


def test_redact_text_is_non_mutating() -> None:
    text = "password=secret"
    snapshot = text
    _ = redact_text(text)
    assert text == snapshot
