"""Tests for ``output_digest`` — deterministic short content reference."""

from __future__ import annotations

from redactkit import output_digest


def test_output_digest_is_deterministic_and_16_hex() -> None:
    body = "hello"
    digest = output_digest(body)
    assert digest == output_digest(body)
    assert len(digest) == 16
    assert all(c in "0123456789abcdef" for c in digest)


def test_output_digest_differs_for_different_bodies() -> None:
    assert output_digest("a") != output_digest("b")
