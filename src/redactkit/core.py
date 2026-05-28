"""Structured-data redaction utilities.

Two concerns, one module:

1. **Key-based redaction.** Dict keys matching the sensitive-name denylist
   are replaced with ``"***"``. Handles nested dicts and lists of dicts.
2. **Value-based redaction.** Strings are scanned for presigned-URL
   signature material (AWS Signature V4 params, ``X-Amz-Signature``, etc.)
   and scrubbed in place.

Overflow handling is deferred to the caller: :func:`summarize_payload`
returns a ``(summary, overflow_body)`` pair. The caller decides whether
to persist the overflow body to a side channel (e.g. object storage).
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any, cast

# Maximum length of a redacted summary carried over the wire.
MAX_SUMMARY_BYTES = 2_048

# Denylist scope: passwords, tokens, generic secrets, HTTP auth headers,
# API keys / access keys / private keys, credentials, cookies, sessions,
# bearer tokens, JWTs, OAuth refresh material. Keep this list a SUPERSET
# of every secret-looking field name that might flow through tool args
# — easier to over-redact than to under-redact.
#
# Terms are raw regex fragments (not literals), so callers can ship negative
# lookaheads like ``auth(?![_-]?type\b)`` to suppress benign lookalikes.
DEFAULT_KEY_TERMS: tuple[str, ...] = (
    r"password",
    r"passwd",
    r"pwd",
    r"token",
    r"jwt",
    r"secret",
    r"authorization",
    r"auth(?![_-]?type\b)",  # http auth, but NOT auth_type flags
    r"api[_-]?key",
    r"access[_-]?key",
    r"private[_-]?key",
    r"credential",
    r"cred(?!ence\b)",  # credentials, but NOT "credence"
    r"cookie",
    r"session",
    r"bearer",
    r"refresh(?![_-]?rate\b)",  # oauth refresh tokens, but NOT refresh_rate
    r"oauth",
    r"sas",
)


def _compile_key_pattern(terms: Sequence[str]) -> re.Pattern[str]:
    """Compile a denylist regex from raw term fragments.

    Wraps the alternation in a single capture group so the result can be
    composed with the ``key=value`` separator pattern by :func:`redact_text`
    without losing group ordering.
    """
    return re.compile(f"({'|'.join(terms)})", re.IGNORECASE)


# Dictionary keys whose leaf values should be replaced with ``"***"``. Regex is
# case-insensitive; matches substring (so ``user_password`` and ``api_key_header``
# both hit).
SENSITIVE_KEY_RE = _compile_key_pattern(DEFAULT_KEY_TERMS)

# AWS Signature V4 / presigned-URL query fragments stripped out of strings.
PRESIGNED_QUERY_RE = re.compile(
    r"(X-Amz-Signature|Signature|X-Amz-Credential|X-Amz-Security-Token)=[^&\s]+",
    re.IGNORECASE,
)

# ``<sensitive_key>=<value>`` and ``<sensitive_key>:<value>`` patterns in
# free-form text. Reuses :data:`SENSITIVE_KEY_RE`'s denylist so the text
# scrubber and the dict scrubber stay in sync — a key added there is
# automatically picked up here. The capture groups split key / separator /
# value so the substitution can mask only the value, preserving the key
# name for audit-grouping (e.g. dashboards counting "password=*** seen N times").
SENSITIVE_KV_TEXT_RE = re.compile(
    SENSITIVE_KEY_RE.pattern + r"(\s*[=:]\s*)(\S+)",
    re.IGNORECASE,
)

MASK = "***"


def extend_key_pattern(extra_terms: Sequence[str]) -> re.Pattern[str]:
    """Compile a denylist regex that unions :data:`DEFAULT_KEY_TERMS` with extras.

    Use this to layer project-specific secret field names on top of the
    library defaults without mutating any module-level state — supports
    the Open/Closed principle: redaction policy is open for extension by
    the caller, closed against in-place modification of the shared regex.

    Example::

        from redactkit import extend_key_pattern, redact_args

        my_pattern = extend_key_pattern([r"my_internal_token", r"vendor_passcode"])
        out = redact_args(payload, key_pattern=my_pattern)

    Each entry is treated as a raw regex fragment (so ``\\b…\\b`` and negative
    lookaheads are supported). Returns a new compiled pattern; the original
    :data:`SENSITIVE_KEY_RE` is unchanged.
    """
    if not extra_terms:
        return SENSITIVE_KEY_RE
    return _compile_key_pattern((*DEFAULT_KEY_TERMS, *extra_terms))


def redact_args(
    payload: Any,
    *,
    key_pattern: re.Pattern[str] = SENSITIVE_KEY_RE,
) -> Any:
    """Deep-redact arbitrary tool / function input args before emission.

    - Dict keys matching ``key_pattern`` → value replaced with ``"***"``.
    - String leaves → presigned-URL signature material scrubbed.
    - Lists / tuples / dicts are traversed; other types pass through.

    ``key_pattern`` defaults to :data:`SENSITIVE_KEY_RE`. Pass a wider
    pattern (see :func:`extend_key_pattern`) when you need to redact
    project-specific field names without mutating the shared default.

    Pure function — returns a new object, never mutates the input.
    """
    if isinstance(payload, dict):
        return {
            key: (
                MASK
                if key_pattern.search(str(key))
                else redact_args(value, key_pattern=key_pattern)
            )
            for key, value in cast(dict[Any, Any], payload).items()
        }
    if isinstance(payload, list):
        return [redact_args(item, key_pattern=key_pattern) for item in cast(list[Any], payload)]
    if isinstance(payload, tuple):
        return tuple(
            redact_args(item, key_pattern=key_pattern)
            for item in cast(tuple[Any, ...], payload)
        )
    if isinstance(payload, str):
        return _scrub_string(payload)
    return payload


def _scrub_string(value: str) -> str:
    return PRESIGNED_QUERY_RE.sub(lambda m: f"{m.group(0).split('=')[0]}=***", value)


def redact_text(
    value: str,
    *,
    key_pattern: re.Pattern[str] = SENSITIVE_KEY_RE,
) -> str:
    """Scrub sensitive material from free-form text.

    Stronger than the internal presigned-URL scrubber: also masks
    ``<sensitive_key>=<value>`` and ``<sensitive_key>:<value>`` patterns
    where the key name matches ``key_pattern`` (default
    :data:`SENSITIVE_KEY_RE`). Use this on text that originated outside
    a typed schema — e.g. exception messages headed for structured logs,
    or LLM-generated free text destined for an audit ledger.

    The dict-scrubber :func:`redact_args` is the right tool when the
    payload IS a dict; this helper handles the case where the payload
    is one big string and ``key=value`` pairs are embedded as substrings.

    Pass a wider ``key_pattern`` (built via :func:`extend_key_pattern`)
    when project-specific field names should also be masked.

    Coverage limit: the value pattern is ``\\S+`` (a single non-whitespace
    token), so ``Authorization: Bearer abc.def.ghi`` masks ``Bearer`` but
    leaves the token. Two-token scheme patterns are uncommon in free-form
    LLM output (the model typically emits ``token=abc.def.ghi`` directly).
    Callers worried about HTTP-header-like patterns should redact the
    structured form via :func:`redact_args` before serialising to text.

    Pure function — returns a new string, never mutates the input.
    """
    kv_pattern = (
        SENSITIVE_KV_TEXT_RE
        if key_pattern is SENSITIVE_KEY_RE
        else re.compile(key_pattern.pattern + r"(\s*[=:]\s*)(\S+)", re.IGNORECASE)
    )
    scrubbed = PRESIGNED_QUERY_RE.sub(lambda m: f"{m.group(0).split('=')[0]}=***", value)
    return kv_pattern.sub(lambda m: f"{m.group(1)}{m.group(2)}{MASK}", scrubbed)


def summarize_payload(
    payload: Any,
    *,
    max_bytes: int = MAX_SUMMARY_BYTES,
    already_redacted: bool = False,
) -> tuple[str, str | None]:
    """Produce a wire-safe summary string plus an optional overflow body.

    Returns ``(summary, overflow_body)``:

    - ``summary`` is a UTF-8 string ≤ ``max_bytes``. Safe to attach to a log
      record, span attribute, or event field.
    - ``overflow_body`` is the full redacted serialisation if it exceeded
      ``max_bytes``, else ``None``. Caller decides whether to persist this
      (e.g. to S3) and reference it by hash via :func:`output_digest`.

    Payload-type handling:

    - ``dict`` / ``list`` / ``tuple`` → JSON dumped with ``ensure_ascii=False``.
    - ``str`` → passed through (scrubbed if ``already_redacted`` is False).
    - Anything else → ``repr()``.

    **Security caveat — ``already_redacted``**: passing ``already_redacted=True``
    skips the :func:`redact_args` pass entirely. Only set this when the caller has
    ALREADY walked the payload through :func:`redact_args` (or an equivalent pass)
    on the same process tick. Passing raw user input with this flag set
    leaks secrets to the wire — there is no second-line defence inside this
    function. When in doubt, leave the flag at its default (False).
    """
    redacted = payload if already_redacted else redact_args(payload)
    if isinstance(redacted, str):
        body = redacted
    else:
        try:
            body = json.dumps(
                redacted,
                ensure_ascii=False,
                separators=(",", ":"),
                default=str,
            )
        except (TypeError, ValueError):
            body = repr(redacted)

    body_bytes = body.encode("utf-8")
    if len(body_bytes) <= max_bytes:
        return body, None

    # ASCII-only truncation marker so bytes == chars in the marker.
    truncation_note = "...[truncated]"
    note_bytes = len(truncation_note)
    budget = max_bytes - note_bytes
    if budget <= 0:
        return body[:max_bytes], body
    cutoff = budget
    # Back off until we land on a UTF-8 char boundary.
    while cutoff > 0 and (body_bytes[cutoff] & 0xC0) == 0x80:
        cutoff -= 1
    head = body_bytes[:cutoff].decode("utf-8", errors="ignore")
    summary = head + truncation_note
    return summary, body


def output_digest(body: str) -> str:
    """First 16 hex chars of sha256(body) — a short, stable content reference."""
    return hashlib.sha256(body.encode("utf-8")).hexdigest()[:16]


class OutboundErrorRedactor:
    """Mask caller-supplied internal terms in outbound payloads.

    Useful when error responses or log records might quote internal
    module names, ticket codes, or vocabulary you don't want to expose
    to external callers. The denylist is **always caller-supplied** —
    there are no implicit defaults, so you stay in control of what
    counts as "internal".

    Construct directly with a compiled pattern, or use
    :meth:`from_terms` to compile a list of literal terms / raw regex
    fragments (each is wrapped in a non-capturing group and joined with
    ``|``).

    Example::

        redactor = OutboundErrorRedactor.from_terms([r"\\binternal_widget\\b", r"\\bbeta_\\w+\\b"])
        safe_text = redactor.apply("Failed in internal_widget pipeline")
        # → "Failed in *** pipeline"
    """

    def __init__(self, pattern: re.Pattern[str]) -> None:
        self._pattern = pattern

    @classmethod
    def from_terms(cls, terms: Sequence[str]) -> OutboundErrorRedactor:
        """Compile ``terms`` into an alternation pattern and return a redactor.

        Each entry in ``terms`` is treated as a raw regex fragment (you can
        write ``\\bsupervisor\\b`` for word-boundary matching). Entries are
        wrapped in non-capturing groups and joined with ``|``. An empty
        ``terms`` sequence yields a never-match pattern (no-op redactor).
        """
        if not terms:
            return cls(re.compile(r"(?!.*)"))
        return cls(re.compile("|".join(f"(?:{t})" for t in terms)))

    def apply(self, text: str) -> str:
        """Return ``text`` with every pattern hit replaced by :data:`MASK`."""
        return self._pattern.sub(MASK, text)

    def apply_to_response(self, content: Mapping[str, Any]) -> dict[str, Any]:
        """Recursively scrub string leaves in a JSON-shaped response body.

        Pure function — never mutates the input mapping. Dict / list / tuple
        nodes are descended into; non-string scalars pass through. Intended
        to wrap a JSON response body produced by an exception handler so
        any internal token that leaked into ``message`` / ``detail`` gets
        masked before the body hits the wire.
        """
        return {key: self._scrub(value) for key, value in content.items()}

    def _scrub(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.apply(value)
        if isinstance(value, Mapping):
            return {k: self._scrub(v) for k, v in cast(Mapping[Any, Any], value).items()}
        if isinstance(value, list):
            return [self._scrub(item) for item in cast(list[Any], value)]
        if isinstance(value, tuple):
            return tuple(self._scrub(item) for item in cast(tuple[Any, ...], value))
        return value


__all__ = [
    "DEFAULT_KEY_TERMS",
    "MASK",
    "MAX_SUMMARY_BYTES",
    "OutboundErrorRedactor",
    "PRESIGNED_QUERY_RE",
    "SENSITIVE_KEY_RE",
    "SENSITIVE_KV_TEXT_RE",
    "extend_key_pattern",
    "output_digest",
    "redact_args",
    "redact_text",
    "summarize_payload",
]
