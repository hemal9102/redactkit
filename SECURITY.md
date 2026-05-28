# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | ✅ |

Pre-1.0: only the latest minor receives security fixes.

## Reporting a vulnerability

**Please do not open a public GitHub issue.** Instead:

- Open a private advisory at
  https://github.com/CoreNovus/redactkit/security/advisories/new, **or**
- Email **support@corenovus.com** with the subject `[redactkit security]`.

Include: redactkit version, Python version, a minimal reproducer, and the
impact you observed.

## Response timeline

| Stage | Target |
|---|---|
| Acknowledgement | 3 business days |
| Initial assessment | 7 business days |
| Fix released | 30 days for high severity, 90 days otherwise |

We follow a **90-day coordinated disclosure window** by default; we'll
negotiate earlier disclosure if a fix ships sooner, or longer if a complex
fix requires it.

## Scope

In scope:

- Redaction bypass (a secret value or sensitive key escapes redaction)
- ReDoS / catastrophic-backtracking on any module regex
- Code execution via crafted payloads to any public function

Out of scope:

- Free-form text PII not caught — by design, redactkit does not do NLP-based
  PII detection. Use Presidio / scrubadub for that.
