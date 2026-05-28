"""URL query-string redaction.

Companion to :func:`redactkit.redact_args` for the case where a sensitive
value rides in a URL query parameter rather than in a structured payload.
Keys are matched against the same :data:`SENSITIVE_KEY_RE` denylist used
by the dict scrubber, so policy stays in one place.
"""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode

from .core import MASK, SENSITIVE_KEY_RE


def redact_url_query(url: str) -> str:
    """Redact sensitive query-parameter values from a URL.

    Keys matching :data:`SENSITIVE_KEY_RE` (``token``, ``password``,
    ``api_key``, ``authorization``, …) have their values replaced with
    ``"***"``; all other params, the path, and the scheme pass through.
    The URL is returned unchanged if it has no ``?`` separator or an
    empty query component.

    Pure function — returns a new string, never mutates the input.
    """
    qmark = url.find("?")
    if qmark == -1:
        return url
    path, query = url[:qmark], url[qmark + 1 :]
    if not query:
        return url
    pairs = parse_qsl(query, keep_blank_values=True)
    redacted = [(k, MASK if SENSITIVE_KEY_RE.search(k) else v) for k, v in pairs]
    return f"{path}?{urlencode(redacted)}"


__all__ = ["redact_url_query"]
