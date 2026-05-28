# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-05-28

### Changed

- Docs only — no functional or API changes.
- README: retargeted Convilyn link from `convilyn.com` (dead) to
  `convilyn.corenovus.com` (the actual platform URL).
- README: polished badges (`flat-square` style + logos), added a pre-1.0
  `Status: Beta` callout, collapsed FAQ into `<details>` blocks, condensed
  the "Why" section, retargeted the Python badge to python.org.
- README: dropped redundant footer copyright (still present in `LICENSE`).
- Wired `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, and `SECURITY.md` into
  the README's bottom sections.

### Why a docs-only release?

PyPI freezes the rendered description at upload time, so the v0.1.0
PyPI page kept the day-1 README. This release syncs the PyPI page with
the polished README on GitHub. No code on disk changes between 0.1.0
and 0.1.1 — pin either one safely.

## [0.1.0] - 2026-05-28

### Added

- `redact_args(payload, *, key_pattern=SENSITIVE_KEY_RE)` — deep-redact dict / list /
  tuple / string payloads. Keys matching the denylist regex have their values replaced
  with `"***"`; string leaves have AWS Signature V4 presigned-URL signatures scrubbed.
- `redact_text(value, *, key_pattern=SENSITIVE_KEY_RE)` — scrub `key=value` and
  `key:value` patterns plus presigned-URL signatures from free-form text.
- `summarize_payload(payload, *, max_bytes=2048, already_redacted=False)` — wire-safe
  truncation with UTF-8 boundary safety; returns `(summary, overflow_body)` so callers
  can persist the overflow to a side channel.
- `output_digest(body)` — deterministic 16-hex SHA-256 prefix for referencing
  overflow bodies by content.
- `redact_url_query(url)` — redact sensitive query-parameter values from a URL while
  preserving keys, path, and scheme.
- `OutboundErrorRedactor` — mask caller-supplied internal terms in outbound payloads.
  Constructor takes a compiled `re.Pattern`; `OutboundErrorRedactor.from_terms(terms)`
  compiles a list of raw regex fragments. No implicit defaults — callers stay in
  control of what counts as "internal".
- `extend_key_pattern(extra_terms)` — Open/Closed extension hook: returns a new
  compiled pattern that unions `DEFAULT_KEY_TERMS` with caller-supplied extras,
  without mutating the shared module-level `SENSITIVE_KEY_RE`.
- Public regex constants `SENSITIVE_KEY_RE`, `SENSITIVE_KV_TEXT_RE`,
  `PRESIGNED_QUERY_RE`, plus `DEFAULT_KEY_TERMS`, `MASK`, `MAX_SUMMARY_BYTES`.
- PEP 561 `py.typed` marker — type information ships with the package.

### Notes

- Zero runtime dependencies. Python 3.10, 3.11, 3.12, 3.13 supported.
- Pre-1.0 release: API may evolve based on early user feedback before v1.0.0.

[Unreleased]: https://github.com/CoreNovus/redactkit/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/CoreNovus/redactkit/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/CoreNovus/redactkit/releases/tag/v0.1.0
