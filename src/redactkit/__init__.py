"""redactkit — production-hardened Python redaction for structured logs,
LLM agent payloads, and AWS-signed URLs.

Zero runtime dependencies. Pure stdlib.
"""

from __future__ import annotations

from .core import (
    DEFAULT_KEY_TERMS,
    MASK,
    MAX_SUMMARY_BYTES,
    PRESIGNED_QUERY_RE,
    SENSITIVE_KEY_RE,
    SENSITIVE_KV_TEXT_RE,
    OutboundErrorRedactor,
    extend_key_pattern,
    output_digest,
    redact_args,
    redact_text,
    summarize_payload,
)
from .url_query import redact_url_query

__version__ = "0.1.1"

__all__ = [
    "DEFAULT_KEY_TERMS",
    "MASK",
    "MAX_SUMMARY_BYTES",
    "OutboundErrorRedactor",
    "PRESIGNED_QUERY_RE",
    "SENSITIVE_KEY_RE",
    "SENSITIVE_KV_TEXT_RE",
    "__version__",
    "extend_key_pattern",
    "output_digest",
    "redact_args",
    "redact_text",
    "redact_url_query",
    "summarize_payload",
]
