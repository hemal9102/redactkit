# Contributing to redactkit

Thanks for considering a contribution. redactkit aims to stay small, focused,
and zero-runtime-dep — please read this before opening a PR.

## Quick start

```bash
git clone https://github.com/CoreNovus/redactkit
cd redactkit
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -q && ruff check . && pyright src
```

All three checks must be green before opening a PR. CI runs the same matrix on
Python 3.10 / 3.11 / 3.12 / 3.13.

## What we accept

- **Bug fixes** with a regression test that fails before / passes after.
- **New denylist terms** for `DEFAULT_KEY_TERMS` — must demonstrate a real
  secret-leak class, not a theoretical one. Open an issue first if unsure.
- **New `redact_*` helpers** that solve a structured-data redaction case
  (URLs, headers, log records) without pulling in a runtime dependency.

## What we don't accept (without prior discussion)

- Free-form text PII / NLP detection — out of scope. Use
  [Presidio](https://github.com/microsoft/presidio) or
  [scrubadub](https://github.com/LeapBeyond/scrubadub).
- New runtime dependencies. "Zero deps" is a load-bearing differentiator.
- Performance optimizations without a benchmark showing the win on a realistic
  payload size (<10 KB JSON).

## Pull request checklist

- [ ] Tests added/updated; `pytest -q` green
- [ ] `ruff check .` clean
- [ ] `pyright src` clean (we run strict)
- [ ] `CHANGELOG.md` entry under `[Unreleased]`
- [ ] Public API changes reflected in `README.md` and `src/redactkit/__init__.py`'s `__all__`

## Issue & PR turnaround

First-response SLA: 5 business days. PRs that have been green for 7 days
without maintainer feedback can be pinged with a comment.

## License

By contributing you agree your work is licensed under the
[MIT License](LICENSE).
