"""Tests for ``summarize_payload`` — wire-safe truncation + overflow handoff."""

from __future__ import annotations

import json

from redactkit import MASK, MAX_SUMMARY_BYTES, summarize_payload


def test_summarize_payload_under_limit() -> None:
    payload = {"tool": "ok", "count": 1}
    summary, overflow = summarize_payload(payload)
    assert overflow is None
    assert json.loads(summary) == {"tool": "ok", "count": 1}


def test_summarize_payload_overflow_truncates_and_returns_full_body() -> None:
    big_value = "x" * 5000
    summary, overflow = summarize_payload({"payload": big_value})
    assert overflow is not None
    assert len(summary.encode("utf-8")) <= MAX_SUMMARY_BYTES
    assert "truncated" in summary
    assert big_value in overflow


def test_summarize_payload_redacts_before_serialising() -> None:
    summary, overflow = summarize_payload({"api_key": "live-secret-value"})
    assert overflow is None
    assert "live-secret-value" not in summary
    assert MASK in summary


def test_summarize_payload_respects_already_redacted_flag() -> None:
    # Pre-redacted dict passed with `already_redacted=True` MUST NOT be
    # modified by summarize_payload (avoids double-work).
    pre = {"password": MASK}
    summary, _ = summarize_payload(pre, already_redacted=True)
    assert MASK in summary


def test_summarize_payload_handles_strings() -> None:
    summary, overflow = summarize_payload("hello world")
    assert overflow is None
    assert summary == "hello world"


def test_summarize_payload_overflow_lands_on_utf8_boundary() -> None:
    # A multi-byte UTF-8 character (each "界" is 3 bytes) at the truncation
    # boundary must not produce mojibake.
    payload = "界" * 1000  # 3000 bytes
    summary, overflow = summarize_payload(payload, max_bytes=100)
    assert overflow == payload
    # If we cut mid-character, decoding without errors='ignore' would raise.
    summary.encode("utf-8").decode("utf-8")
