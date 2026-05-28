"""Tests for ``extend_key_pattern`` — Open/Closed denylist extension."""

from __future__ import annotations

from redactkit import (
    MASK,
    SENSITIVE_KEY_RE,
    extend_key_pattern,
    redact_args,
    redact_text,
)


def test_empty_extras_returns_the_default_pattern() -> None:
    # Identity short-circuit lets callers pass an empty list without paying
    # recompilation cost.
    assert extend_key_pattern(()) is SENSITIVE_KEY_RE


def test_extended_pattern_masks_project_specific_field() -> None:
    pattern = extend_key_pattern([r"vendor_passcode", r"my_internal_token"])
    payload = {
        "vendor_passcode": "supersecret",
        "my_internal_token": "abc",
        "user": "alice",
    }
    out = redact_args(payload, key_pattern=pattern)
    assert out == {
        "vendor_passcode": MASK,
        "my_internal_token": MASK,
        "user": "alice",
    }


def test_extended_pattern_still_masks_defaults() -> None:
    # Open for extension, closed for modification: defaults survive the union.
    pattern = extend_key_pattern([r"vendor_passcode"])
    payload = {"password": "p", "vendor_passcode": "v", "tool": "extract"}
    out = redact_args(payload, key_pattern=pattern)
    assert out == {"password": MASK, "vendor_passcode": MASK, "tool": "extract"}


def test_redact_text_honours_extended_pattern() -> None:
    pattern = extend_key_pattern([r"vendor_passcode"])
    out = redact_text("logs show vendor_passcode=topsecret in trace", key_pattern=pattern)
    assert "topsecret" not in out
    assert MASK in out


def test_module_level_default_is_not_mutated() -> None:
    snapshot = SENSITIVE_KEY_RE.pattern
    _ = extend_key_pattern([r"vendor_passcode", r"my_token"])
    assert SENSITIVE_KEY_RE.pattern == snapshot
