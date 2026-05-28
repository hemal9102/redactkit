# redactkit

[![PyPI](https://img.shields.io/pypi/v/redactkit.svg?style=flat-square&logo=pypi&logoColor=white)](https://pypi.org/project/redactkit/)
[![Python](https://img.shields.io/pypi/pyversions/redactkit.svg?style=flat-square&logo=python&logoColor=white)](https://pypi.org/project/redactkit/)
[![CI](https://img.shields.io/github/actions/workflow/status/CoreNovus/redactkit/ci.yml?branch=main&style=flat-square&logo=github)](https://github.com/CoreNovus/redactkit/actions/workflows/ci.yml)
[![Downloads](https://img.shields.io/pypi/dm/redactkit.svg?style=flat-square)](https://pypi.org/project/redactkit/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE)

**Production-hardened Python redaction for structured logs, LLM agent payloads, and
AWS-signed URLs.** Zero dependencies — pure stdlib. Built for `dict[str, Any]`, not
for free-form prose.

> **Status: Beta (0.1.x)** · Pre-1.0 — the API may evolve based on
> early-user feedback before v1.0. Pin to `redactkit~=0.1.0` if you want
> patch-level updates only.

```python
from redactkit import redact_args

redact_args({"password": "hunter2", "user": "alice"})
# → {"password": "***", "user": "alice"}
```

## Install

```bash
pip install redactkit
```

Requires Python ≥ 3.10. No runtime dependencies.

## Why redactkit?

1. **Structured-data first.** Recursive `dict` / `list` / `tuple` traversal out of
   the box. Drop into any code that already speaks `Mapping[str, Any]`.
2. **AWS SigV4 redaction.** Scrubs `X-Amz-Signature`, `X-Amz-Credential`,
   `X-Amz-Security-Token` from presigned URLs — a real production gap most redaction
   libraries ignore.
3. **Overflow splitting.** `summarize_payload` returns a short wire-safe summary
   plus an optional full body, so a 5 MB tool result doesn't blow your log budget.
4. **Comprehensive + extensible denylist.** Passwords, tokens, JWT, OAuth, bearer,
   credentials, cookies, sessions covered out of the box. Add your own via
   `extend_key_pattern` — no module-state mutation, no monkey-patching.
5. **Zero deps, production provenance.** Pure stdlib (Python ≥ 3.10). Extracted
   from the [Convilyn](https://convilyn.com) agent platform — used in LLM agent
   middleware, supervisor handoffs, event emission, and HTTP response redaction.

## When to pick redactkit vs. alternatives

| Tool | Approach | Best at | Deps | Pick when… |
|---|---|---|---|---|
| **[Microsoft Presidio](https://github.com/microsoft/presidio)** | ML-based NER (spaCy / transformers) | Free-form text PII (names, addresses) | Heavy (~1 GB models) | Document / chat PII detection in regulated industries |
| **[scrubadub](https://github.com/LeapBeyond/scrubadub)** | NLP rules + named recognizers | Free-form text (emails, phones, names) | nltk, textblob | Scrubbing user-generated prose |
| **Hand-rolled `logging.Filter`** | Custom filter per team | Logging-specific | None | Reinventing the wheel; AWS SigV4 never covered |
| **redactkit** | Key denylist + AWS SigV4 + overflow splitting | **Structured data**: dicts, JSON, kwargs, OTel attrs, request bodies | **None** | LLM agent logs, API request/response logs, anywhere `dict[str, Any]` is the unit |

**Non-goals.** redactkit does not do free-form NLP PII detection, cryptographic
anonymization, or database-column encryption. Reach for Presidio or scrubadub for
those.

## Three killer examples

### 1. Structured dict redaction

```python
from redactkit import redact_args

payload = {
    "account": {"bearer_token": "xyz", "user": "alice"},
    "items": [{"secret": "s"}, {"name": "plain"}],
}
redact_args(payload)
# → {
#     "account": {"bearer_token": "***", "user": "alice"},
#     "items": [{"secret": "***"}, {"name": "plain"}],
# }
```

Case-insensitive, recursive, and non-mutating. Covers nested dicts, list-of-dicts,
and tuples (preserving type).

### 2. AWS presigned URL scrubbing

```python
from redactkit import redact_args

redact_args({
    "url": "https://s3.example.com/x?X-Amz-Signature=abcdef123&foo=1",
})
# → {"url": "https://s3.example.com/x?X-Amz-Signature=***&foo=1"}
```

Strings inside payloads get scanned for AWS Signature V4 query fragments and
scrubbed in place. Most logging filters miss this — redactkit doesn't.

### 3. Overflow splitting for big payloads

```python
from redactkit import summarize_payload, output_digest

big_tool_result = {"items": [...]}  # 5 MB
summary, overflow = summarize_payload(big_tool_result, max_bytes=2048)

# Attach the short summary to your span / log event:
span.set_attribute("tool.output_summary", summary)

# Persist the full body to S3 if it overflowed:
if overflow is not None:
    digest = output_digest(overflow)
    s3.put_object(Bucket="logs", Key=f"overflow/{digest}", Body=overflow)
    span.set_attribute("tool.output_ref", f"s3://logs/overflow/{digest}")
```

UTF-8 boundary safe — no mojibake even if the cut lands mid-character.

## Public API

| Symbol | Kind | Purpose |
|---|---|---|
| `redact_args(payload, *, key_pattern=SENSITIVE_KEY_RE)` | function | Deep-redact dicts/lists/strings |
| `redact_text(value, *, key_pattern=SENSITIVE_KEY_RE)` | function | Scrub `key=value` patterns + presigned URLs from free-form text |
| `redact_url_query(url)` | function | Redact sensitive values in URL query strings |
| `summarize_payload(payload, *, max_bytes=2048, already_redacted=False)` | function | Wire-safe truncation; returns `(summary, overflow_body)` |
| `output_digest(body)` | function | 16-hex SHA-256 prefix — content-addressable overflow reference |
| `extend_key_pattern(extra_terms)` | function | Open/Closed denylist extension without module-state mutation |
| `OutboundErrorRedactor(pattern)` | class | Mask caller-supplied internal terms in error/log payloads |
| `OutboundErrorRedactor.from_terms(terms)` | classmethod | Compile a term list into a redactor |
| `SENSITIVE_KEY_RE`, `SENSITIVE_KV_TEXT_RE`, `PRESIGNED_QUERY_RE` | regex | Public patterns for direct use |
| `DEFAULT_KEY_TERMS` | tuple[str, ...] | Raw fragments backing `SENSITIVE_KEY_RE` |
| `MASK` | str | The redaction placeholder (`"***"`) |
| `MAX_SUMMARY_BYTES` | int | Default cap for `summarize_payload` (2048) |

## Extending the denylist

The default denylist covers password / token / secret / bearer / cookie / session
families. To add project-specific field names without monkey-patching:

```python
from redactkit import extend_key_pattern, redact_args

my_pattern = extend_key_pattern([r"vendor_passcode", r"internal_id"])
redact_args({"vendor_passcode": "x", "user": "alice"}, key_pattern=my_pattern)
# → {"vendor_passcode": "***", "user": "alice"}
```

`extend_key_pattern` returns a new compiled regex; `SENSITIVE_KEY_RE` is never
mutated (Open/Closed principle).

## FAQ

<details>
<summary><b>Does it handle free-form text PII (names, addresses)?</b></summary>

No. Use [Presidio](https://github.com/microsoft/presidio) or
[scrubadub](https://github.com/LeapBeyond/scrubadub) for that. redactkit's
strength is structured data and known-schema secrets.
</details>

<details>
<summary><b>Does it handle nested dicts and lists?</b></summary>

Yes. `redact_args` walks recursively. Tuples preserve their type.
</details>

<details>
<summary><b>Can I add my own sensitive key names?</b></summary>

Yes — use `extend_key_pattern([r"my_term"])` and pass the result via the
`key_pattern=` argument. No module-level state is mutated.
</details>

<details>
<summary><b>Is it thread-safe?</b></summary>

Yes. All redaction functions are pure (no global mutation, no I/O) and the
module-level regexes are immutable compiled patterns.
</details>

<details>
<summary><b>Is <code>redact_args</code> non-mutating?</b></summary>

Yes. It always returns a new object — the input dict / list / tuple is never
modified in place.
</details>

<details>
<summary><b>Will redaction slow down my hot path?</b></summary>

The dominant cost is the regex `.search` per dict key. For typical agent
payloads (< 100 keys, < 10 KB serialized) the overhead is sub-millisecond.
</details>

## Contributing

Issues and PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the dev
setup, what we do and don't accept, and the PR checklist. Conduct expectations
are in [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Security

Found a redaction bypass or ReDoS pattern? Please don't open a public issue.
See [SECURITY.md](SECURITY.md) for the private-advisory process and our
90-day coordinated disclosure window.

## Production users

Used in production by [Convilyn](https://convilyn.com). Open a PR adding your
project here once you've shipped redactkit to prod.

## License

[MIT](LICENSE). Copyright © 2026 CoreNovus.
