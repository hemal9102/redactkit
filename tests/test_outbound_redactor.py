"""Tests for ``OutboundErrorRedactor`` — caller-supplied term masking."""

from __future__ import annotations

import re

import pytest

from redactkit import MASK, OutboundErrorRedactor


@pytest.fixture
def redactor() -> OutboundErrorRedactor:
    """Redactor compiled against a small fixture vocabulary."""
    return OutboundErrorRedactor.from_terms(
        [
            r"\binternal_widget\b",
            r"\bbeta_pipeline\b",
            r"\bSecretEnvelope\b",
        ]
    )


def test_plain_string_token_is_masked(redactor: OutboundErrorRedactor) -> None:
    # A single banned word inside an error message is masked.
    leaked = "internal_widget dispatch failed for tool"
    assert redactor.apply(leaked) == f"{MASK} dispatch failed for tool"


def test_nested_response_body_is_scrubbed(redactor: OutboundErrorRedactor) -> None:
    # Recursive walk masks tokens at any depth — dicts, lists, tuples.
    content = {
        "code": "VALIDATION_ERROR",
        "message": "validation failed",
        "details": {
            "errors": [
                {"field": "spec.beta_pipeline.0.tools", "message": "missing"},
                {"field": "spec.routing", "message": "internal_widget node missing"},
            ],
            "meta": ("internal_widget", "ok", 42),
        },
    }
    scrubbed = redactor.apply_to_response(content)

    serialised = repr(scrubbed)
    assert "internal_widget" not in serialised
    assert "beta_pipeline" not in serialised
    # MASK itself must appear — proof of substitution, not silent drop.
    assert MASK in serialised


def test_validation_field_path_is_masked(redactor: OutboundErrorRedactor) -> None:
    # Joined validation paths like ``SecretEnvelope.payload.0.beta_pipeline.tools``
    # are a leak vector — every blacklisted segment delimited by non-word chars
    # (``.``, ``[``, ``]``) gets masked.
    field_path = "SecretEnvelope.payload.0.beta_pipeline.tools"
    scrubbed = redactor.apply(field_path)
    assert "SecretEnvelope" not in scrubbed
    assert "beta_pipeline" not in scrubbed
    # Two distinct masks — one per blacklisted segment.
    assert scrubbed.count(MASK) == 2


def test_constructor_accepts_compiled_pattern_directly() -> None:
    # DIP check: caller may inject any compiled pattern.
    custom = re.compile(r"\bfoo\b", re.IGNORECASE)
    redactor = OutboundErrorRedactor(custom)
    assert redactor.apply("foo bar Foo") == f"{MASK} bar {MASK}"
    # An unrelated term passes through unchanged.
    assert redactor.apply("internal_widget") == "internal_widget"


def test_from_terms_with_empty_sequence_is_a_no_op() -> None:
    # Defensive: an empty term list must compile a never-match pattern,
    # not raise and not match everything.
    redactor = OutboundErrorRedactor.from_terms([])
    assert redactor.apply("any text passes through unchanged") == (
        "any text passes through unchanged"
    )


def test_non_string_scalars_pass_through(redactor: OutboundErrorRedactor) -> None:
    # ints, floats, bools, None traverse ``apply_to_response`` unchanged.
    # Tuples preserve their type. Existing MASK values are not double-masked.
    content = {
        "status_code": 500,
        "retry_after": None,
        "flags": {"is_internal": True, "ratio": 1.5},
        "tuple_pass": (1, 2, "internal_widget"),
        "already_masked": MASK,
    }
    scrubbed = redactor.apply_to_response(content)

    assert scrubbed["status_code"] == 500
    assert scrubbed["retry_after"] is None
    assert scrubbed["flags"] == {"is_internal": True, "ratio": 1.5}
    assert isinstance(scrubbed["tuple_pass"], tuple)
    assert scrubbed["tuple_pass"] == (1, 2, MASK)
    # MASK strings are not masked again into double-stars.
    assert scrubbed["already_masked"] == MASK
