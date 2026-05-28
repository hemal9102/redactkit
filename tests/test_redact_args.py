"""Tests for ``redact_args`` — deep dict/list/string redaction."""

from __future__ import annotations

from redactkit import MASK, redact_args


def test_top_level_sensitive_keys_are_masked() -> None:
    payload = {
        "password": "hunter2",
        "tool": "extract_text",
        "api_key": "sk-live-abc",
    }
    out = redact_args(payload)
    assert out == {"password": MASK, "tool": "extract_text", "api_key": MASK}


def test_nested_sensitive_keys_are_masked() -> None:
    # Outer key "account" is NOT on the denylist → sub-dict traversed.
    payload = {
        "account": {"bearer_token": "xyz", "user": "alice"},
        "items": [{"secret": "s"}, {"name": "plain"}],
    }
    out = redact_args(payload)
    assert out["account"]["bearer_token"] == MASK
    assert out["account"]["user"] == "alice"
    assert out["items"][0]["secret"] == MASK
    assert out["items"][1]["name"] == "plain"


def test_case_insensitive_key_matching() -> None:
    payload = {"Authorization": "Bearer foo", "API-KEY": "bar", "Cookie": "c=1"}
    out = redact_args(payload)
    assert out == {"Authorization": MASK, "API-KEY": MASK, "Cookie": MASK}


def test_extended_denylist_covers_common_secret_names() -> None:
    payload = {
        "access_key": "ak",
        "private_key": "pk",
        "pwd": "p",
        "passwd": "p2",
        "jwt": "header.payload.sig",
        "oauth_code": "c",
        "sas_token": "s",
        "refresh_token": "rt",
    }
    out = redact_args(payload)
    assert all(value == MASK for value in out.values()), out


def test_denylist_does_not_overmatch_lookalike_fields() -> None:
    # `refresh_rate`, `auth_type`, `credence` are lookalikes that the denylist
    # explicitly excludes. Prevents over-redaction of benign config.
    payload = {
        "refresh_rate": 5,
        "auth_type": "oidc",
        "credence": "none",
    }
    out = redact_args(payload)
    assert out == payload


def test_non_sensitive_data_passes_through() -> None:
    payload = {"file_id": "f_123", "count": 42, "ratio": 0.5, "flag": True, "null": None}
    assert redact_args(payload) == payload


def test_presigned_query_is_scrubbed_in_strings() -> None:
    url = "https://s3.example.com/x?X-Amz-Signature=abcdef123&foo=1"
    out = redact_args({"url": url})
    assert "abcdef123" not in out["url"]
    assert "X-Amz-Signature=***" in out["url"]


def test_list_traversal_preserves_shape() -> None:
    payload = [{"password": "a"}, {"x": 1}]
    out = redact_args(payload)
    assert out[0]["password"] == MASK
    assert out[1]["x"] == 1
    assert isinstance(out, list)


def test_tuple_traversal_preserves_type() -> None:
    payload = ({"password": "a"}, {"x": 1})
    out = redact_args(payload)
    assert isinstance(out, tuple)
    assert out[0]["password"] == MASK
    assert out[1]["x"] == 1


def test_redact_args_is_non_mutating() -> None:
    payload = {"password": "p", "x": {"token": "t"}}
    snapshot = {"password": "p", "x": {"token": "t"}}
    _ = redact_args(payload)
    assert payload == snapshot
