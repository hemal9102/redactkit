# OSS Launch Roadmap — Redaction Library

A self-contained roadmap for extracting `backend-api/app/core/security/redaction.py`
into a public, community-friendly OSS Python library under
`github.com/CoreNovus/<name>`. Take this document to the new repo's workspace; you
shouldn't need to come back to the monorepo to execute it.

---

## 1. Project identity

| Field | Value |
|---|---|
| GitHub org | `CoreNovus` |
| License | **MIT** |
| Python support | `>=3.10` (matches monorepo + reaches widest audience) |
| Dependencies | **Zero runtime deps** (stdlib `re` + `hashlib` only) |
| Initial version | `0.1.0` (semver; pre-1.0 signals API may evolve) |

### Name candidates (verify PyPI availability before committing)

Priorities: function-focused, easy to understand without context, no `convilyn-` prefix.

| Candidate | Why | Watch out for |
|---|---|---|
| `redactkit` (recommended) | "Toolkit for redaction" — implies batteries-included, not a single function | Check `pip index versions redactkit` |
| `pyredact` | "Python redaction" — instantly understood | Generic; may already be taken |
| `redactly` | Catchy, brandable | Less function-literal |
| `safelog` | Logging-focused angle (one of the main use cases) | Narrows positioning to logs only |
| `pii-redact` | SEO friendly (PII is a hot search term) | Slightly over-specific — the lib also handles AWS SigV4, not just PII |

**Action**: run `pip index versions <name>` (or visit `pypi.org/project/<name>`) for the top 3
before opening the repo. Pick the first one that's free **and** has a clean GitHub org name
collision check (`gh repo view CoreNovus/<name>`).

The rest of this roadmap uses `redactkit` as the placeholder.

---

## 2. Positioning

> One-sentence tagline candidate:
> **"Production-hardened Python redaction for structured logs, LLM agent payloads,
> and AWS-signed URLs — zero dependencies, batteries included."**

Target audience:
- LLM / agent developers who emit structured logs and need PII / token scrubbing
- Backend engineers writing FastAPI / Flask middleware to redact request bodies
- SRE / observability teams piping payloads to CloudWatch / Datadog / Splunk
- Anyone shipping AWS presigned URLs through logs or error reports

Non-goals (state explicitly in the README to set expectations):
- Free-form NLP PII detection in arbitrary prose (use **Presidio** or **scrubadub**)
- Cryptographic anonymization / differential privacy
- Database-column-level encryption

---

## 3. Competitive landscape

Include this table in the README so users self-select correctly.

| Tool | Approach | Data shape it shines at | Deps | When to pick it |
|---|---|---|---|---|
| **Microsoft Presidio** | ML-based NER (spaCy / transformers) | Free-form text PII (names, addresses, phone) | spaCy, transformers, heavy (~1 GB models) | Document / chat PII detection, multi-language, regulated industries |
| **scrubadub** | NLP rules + named recognizers | Free-form text (emails, phones, names) | nltk, textblob | Scrubbing user-generated prose / support transcripts |
| **commentjson / various python-redact PyPI** | Regex on strings | Whatever you hand-write | None | Ad-hoc one-offs; no batteries |
| **Hand-rolled `logging.Filter`** | Custom filter per team | Logging-specific | None | Reinventing-the-wheel hell; AWS SigV4 never covered |
| **`redactkit` (this library)** | Key-denylist + AWS SigV4 value scrub + overflow splitting | **Structured data**: dicts, JSON, kwargs, OTel attributes, request bodies | **None** | LLM agent logs, API request/response logs, anywhere `dict[str, Any]` is the unit |

### Differentiators (lead the README with these)

1. **Structured-data first** — built for `Mapping[str, Any]`, not free-form text. Recursive dict / list traversal out of the box.
2. **AWS SigV4 redaction** — scrubs `X-Amz-Signature` / `X-Amz-Credential` from presigned URLs (a real production gap; most libs ignore this).
3. **Overflow splitting** — payload too big? `summarize_payload` returns a short summary + a stable hash, with the full body addressable separately (e.g., to S3) — pattern used in OTel attribute caps.
4. **Comprehensive default denylist** — passwords, tokens, JWT, OAuth, bearer, credentials, cookies, sessions — covered out of the box; user-extensible.
5. **Zero dependencies** — pure stdlib. Drop into any Python ≥3.10 project, no transitive bloat.
6. **Production-hardened** — extracted from the Convilyn agent platform; battle-tested in LLM agent middleware, supervisor handoffs, event emission, and HTTP response redaction.

---

## 4. Source material (in this monorepo)

| Source path | LoC | Status |
|---|---|---|
| `backend-api/app/core/security/redaction.py` | 266 | Core module — copy verbatim |
| `backend-api/app/core/security/_outbound_blacklist.py` | 58 | Companion — copy verbatim |
| `backend-api/tests/unit/core/security/test_outbound_error_redaction.py` | — | Migrate (low coupling) |
| `backend-api/tests/unit/orchestrator/agents/events/test_redaction.py` | — | Migrate (rename imports) |
| `backend-api/tests/unit/orchestrator/agents/events/test_redaction_shim_parity.py` | — | **Skip** — tests the shim, not core |
| `backend-api/tests/unit/core/test_middleware_url_redaction.py` | — | Adapt — FastAPI middleware, becomes "FastAPI integration" example |
| `backend-api/tests/unit/orchestrator/agents/test_call_tool_redaction.py` | — | **Skip** — Convilyn-specific (call_tool node) |
| `backend-api/tests/unit/orchestrator/agents/supervisor/test_handoff_redaction.py` | — | **Skip** — supervisor-specific |
| `backend-api/tests/eval/builder_agent/test_p5b_pii_redaction.py` | — | **Skip** — builder eval |

**Imports inside the two source files**: only stdlib + sibling. Verified with:

```bash
grep -E "^(from|import)" backend-api/app/core/security/redaction.py backend-api/app/core/security/_outbound_blacklist.py
# Result: stdlib only (re, json, hashlib, collections.abc, typing, functools, pathlib)
```

No further coupling. Extraction is genuinely a copy job.

---

## 5. Target repo skeleton

```
redactkit/
├── LICENSE                              # MIT (Anthropic-standard text)
├── README.md                            # Tagline → install → 30-sec example → comparison table → API ref pointer
├── CHANGELOG.md                         # Keep-a-Changelog; start v0.1.0
├── CONTRIBUTING.md                      # Dev setup, test cmd, PR checklist, issue triage
├── CODE_OF_CONDUCT.md                   # Contributor Covenant 2.1 (verbatim)
├── SECURITY.md                          # Vuln disclosure: security@<domain> or GitHub private advisory
├── pyproject.toml                       # Hatchling backend, no deps, py>=3.10
├── .gitignore                           # Python standard
├── .python-version                      # 3.11 for local dev
├── .pre-commit-config.yaml              # ruff + pyright + detect-secrets
├── src/
│   └── redactkit/
│       ├── __init__.py                  # Re-exports: redact_args, summarize_payload, SENSITIVE_KEY_RE
│       ├── core.py                      # ← redaction.py content, renamed
│       ├── outbound_blacklist.py        # ← _outbound_blacklist.py (drop leading _)
│       └── py.typed                     # PEP 561 marker
├── tests/
│   ├── conftest.py
│   ├── test_redact_args.py
│   ├── test_summarize_payload.py
│   ├── test_outbound_blacklist.py
│   └── integration/
│       └── test_fastapi_middleware.py   # Adapted from monorepo middleware_url_redaction test
├── docs/                                # Optional Phase 2: MkDocs Material
│   ├── index.md
│   ├── quickstart.md
│   ├── api.md
│   ├── recipes/
│   │   ├── fastapi-middleware.md
│   │   ├── logging-filter.md
│   │   ├── otel-span-attrs.md
│   │   └── aws-presigned-urls.md
│   └── comparison.md
└── .github/
    ├── ISSUE_TEMPLATE/
    │   ├── bug_report.yml               # YAML form: version, repro, expected vs actual
    │   ├── feature_request.yml          # Use case, alternatives considered
    │   └── config.yml                   # Disable blank issues, link to Discussions
    ├── PULL_REQUEST_TEMPLATE.md         # Checklist: tests added, changelog entry, docs updated
    ├── workflows/
    │   ├── ci.yml                       # pytest matrix (3.10/3.11/3.12/3.13) + ruff + pyright
    │   ├── publish.yml                  # On tag v*: build sdist + wheel → PyPI Trusted Publisher
    │   └── codeql.yml                   # Static analysis (free for public)
    ├── dependabot.yml                   # Weekly dep upgrades on dev tooling
    ├── CODEOWNERS                       # @<your-handle> on src/, tests/, .github/
    └── FUNDING.yml                      # Optional: GitHub Sponsors link
```

---

## 6. Launch phases

### Phase 0 — Extract & polish (estimate: 0.5 day)

- [ ] Pick the final name; confirm PyPI + GitHub availability.
- [ ] `gh repo create CoreNovus/<name> --public --license MIT --description "..."`.
- [ ] Copy `redaction.py` → `src/<name>/core.py`; copy `_outbound_blacklist.py` → `src/<name>/outbound_blacklist.py`.
- [ ] Update internal import: `from ._outbound_blacklist import ...` → `from .outbound_blacklist import ...`.
- [ ] Write `src/<name>/__init__.py` with explicit public-API re-exports + `__version__`.
- [ ] Drop in `py.typed` marker.
- [ ] Create `pyproject.toml` (template in §8 below).
- [ ] Migrate the 3 portable test files; verify `pytest` green on a clean venv.

### Phase 1 — v0.1.0 public release (estimate: 1 day)

- [ ] Write `README.md` — structure in §7 below.
- [ ] Write `LICENSE` (MIT, with `Copyright (c) 2026 CoreNovus`).
- [ ] Write `CHANGELOG.md` with v0.1.0 entry.
- [ ] Set up `.github/workflows/ci.yml` — pytest matrix on Python 3.10/3.11/3.12/3.13, ruff, pyright.
- [ ] Set up `.github/workflows/publish.yml` — uses [PyPI Trusted Publishers](https://docs.pypi.org/trusted-publishers/) (no API token in secrets).
- [ ] Tag `v0.1.0`; let publish workflow push to PyPI.
- [ ] Smoke-test from a clean venv: `pip install <name>` → minimal example works.

### Phase 2 — Community-ready (estimate: 0.5 day)

- [ ] `CONTRIBUTING.md` — dev setup, `make test`, PR checklist, label scheme.
- [ ] `CODE_OF_CONDUCT.md` — Contributor Covenant 2.1 (copy verbatim, fill contact email).
- [ ] `SECURITY.md` — disclosure email + GitHub private advisory link; 90-day disclosure window standard.
- [ ] `.github/ISSUE_TEMPLATE/` — bug + feature YAML forms; disable blank issues in `config.yml`.
- [ ] `.github/PULL_REQUEST_TEMPLATE.md` — tests / changelog / docs checklist.
- [ ] Enable **GitHub Discussions** (Q&A, Show & Tell) — issues stay for bugs / requests.
- [ ] Add `good-first-issue` and `help-wanted` labels with 2-3 starter issues seeded.

### Phase 3 — Docs site (optional, estimate: 1 day)

- [ ] MkDocs Material in `docs/`; GitHub Actions deploy to GitHub Pages on `main`.
- [ ] Recipes: FastAPI middleware, stdlib logging filter, OTel span attribute redaction, AWS presigned URL handler.
- [ ] API reference auto-generated via mkdocstrings.

### Phase 4 — Monorepo migration (defer; not blocking launch)

- [ ] Once v0.1.0 is on PyPI, add `<name>>=0.1.0,<0.2` to `backend-api/pyproject.toml`.
- [ ] Replace `from app.core.security.redaction import ...` with `from <name> import ...` across `backend-api/`.
- [ ] Delete `backend-api/app/core/security/redaction.py` and `_outbound_blacklist.py`.
- [ ] Keep `app/core/security/__init__.py` re-exporting from the new package as a one-version compat shim, then remove.
- [ ] Run full unit + contract test suite; PR to develop with Tier T1 verification per `.claude/rules/git-workflow.md`.

---

## 7. README structure (skeleton)

Open with a one-paragraph "what / why / when not". Then:

1. **Badges** — PyPI version, Python versions, CI status, license, downloads.
2. **30-second example** — show `redact_args({"password": "hunter2", "user": "alice"})` → `{"password": "***", "user": "alice"}`.
3. **Install** — `pip install <name>`. One line. No "optional extras" until v0.2.
4. **Why this library?** — 3-bullet differentiator block from §3.
5. **Comparison table** — copy from §3 verbatim.
6. **Three killer examples**:
   - Structured dict redaction (the bread-and-butter case)
   - AWS presigned URL scrubbing (the unique-selling-point)
   - Overflow splitting → S3 (the production-scale case)
7. **API reference** — short table of public symbols + one-line description each; link to full docs if Phase 3 done.
8. **FAQ** — "Does it handle text PII?" (No, use Presidio.) "Does it handle nested dicts?" (Yes.) "Custom denylist?" (Yes, extend `SENSITIVE_KEY_RE`.) "Is it thread-safe?" (Yes — pure functions, no global state.)
9. **Contributing** — link to CONTRIBUTING.md; explicitly welcome PRs.
10. **Production users** — initially just "Used in production by [Convilyn](https://convilyn.com)". Grow this list.
11. **License** — MIT, link to LICENSE.

Tone: friendly, concrete, code-heavy. No marketing fluff. Every claim backed by a runnable example.

---

## 8. `pyproject.toml` template

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "redactkit"                                      # ← replace
version = "0.1.0"
description = "Production-hardened Python redaction for structured logs, LLM agent payloads, and AWS-signed URLs."
readme = "README.md"
license = { text = "MIT" }
requires-python = ">=3.10"
authors = [{ name = "CoreNovus" }]                      # add your name + email if you want commit credit on PyPI
keywords = ["redaction", "pii", "logging", "observability", "security", "aws", "sigv4", "llm", "agent"]
classifiers = [
    "Development Status :: 4 - Beta",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: MIT License",
    "Operating System :: OS Independent",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Programming Language :: Python :: 3.13",
    "Topic :: Security",
    "Topic :: System :: Logging",
    "Typing :: Typed",
]
dependencies = []                                       # ← zero runtime deps is a differentiator; keep it that way

[project.urls]
Homepage = "https://github.com/CoreNovus/redactkit"
Documentation = "https://corenovus.github.io/redactkit/"
Repository = "https://github.com/CoreNovus/redactkit"
Issues = "https://github.com/CoreNovus/redactkit/issues"
Changelog = "https://github.com/CoreNovus/redactkit/blob/main/CHANGELOG.md"

[project.optional-dependencies]
dev = ["pytest>=8", "ruff>=0.6", "pyright>=1.1.380", "pre-commit>=3"]

[tool.hatch.build.targets.wheel]
packages = ["src/redactkit"]                            # ← replace

[tool.ruff]
line-length = 100
target-version = "py310"

[tool.pyright]
strict = ["src/redactkit"]                              # ← replace
pythonVersion = "3.10"
```

---

## 9. CI workflow — `.github/workflows/ci.yml`

```yaml
name: CI
on:
  push: { branches: [main] }
  pull_request:
jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.10", "3.11", "3.12", "3.13"]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
          cache: pip
      - run: pip install -e ".[dev]"
      - run: ruff check .
      - run: pyright src
      - run: pytest -v --cov=src --cov-report=xml
      - uses: codecov/codecov-action@v5
        if: matrix.python-version == '3.12'
        with: { fail_ci_if_error: false }
```

## 10. Publish workflow — `.github/workflows/publish.yml`

Use **PyPI Trusted Publishers** so you never store an API token.
First-time: register the repo + workflow at <https://pypi.org/manage/account/publishing/>.

```yaml
name: Publish
on:
  push:
    tags: ["v*"]
jobs:
  build-and-publish:
    runs-on: ubuntu-latest
    permissions:
      id-token: write       # required for trusted publishing
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install build
      - run: python -m build
      - uses: pypa/gh-action-pypi-publish@release/v1
```

---

## 11. Contribution policy (drives CONTRIBUTING.md)

| Topic | Policy |
|---|---|
| **License grant** | All contributions licensed under MIT. No CLA — DCO sign-off encouraged but not enforced. |
| **Issue triage SLA** | First response within 5 business days; aim to label within 7. |
| **PR review SLA** | First review within 5 business days. |
| **Breaking changes** | Discuss in an issue first. Bumps minor version pre-1.0, major version post-1.0. |
| **Test coverage** | Every PR adds tests for the change. CI must be green. |
| **Code style** | `ruff format` + `ruff check` clean. `pyright` strict on `src/`. |
| **Changelog** | Every PR adds a `CHANGELOG.md` entry under `[Unreleased]`. |
| **Good-first-issues** | Maintain at least 3 open `good-first-issue` labels at any time. |
| **Security issues** | Use GitHub private advisory; do **not** open a public issue. 90-day disclosure window. |

---

## 12. Naming / behavior decisions to lock before v0.1.0

These are public API. Changing them post-v1.0 = breaking change.

- [ ] **Function names**: `redact_args` and `summarize_payload` are the internal names. They're fine, but consider whether `redact` (alias) reads better as the headline API. (Recommendation: keep both; `redact_args` for backwards-compat, `redact` as the documented entry.)
- [ ] **Constant name**: `SENSITIVE_KEY_RE` — readable, but is it public-extensible or read-only? Decide and document. (Recommendation: expose a `with_extra_keys(*patterns)` factory rather than mutating a module-level global.)
- [ ] **Redaction placeholder**: currently `***`. Make it configurable (`placeholder="***"`) for users who want `[REDACTED]` or `<redacted>`.
- [ ] **Hash algorithm**: currently `hashlib.sha256` for overflow summaries. Pin in API or allow override? (Recommendation: pin to sha256 in v0.1; revisit if requested.)
- [ ] **Mapping return type**: `redact_args` currently returns a new dict — confirm immutability guarantee in docstring + add a test.

---

## 13. Day-one announcement plan (optional but recommended)

| Channel | Format | When |
|---|---|---|
| GitHub repo description | "Production-hardened Python redaction…" tagline | At repo creation |
| Hacker News "Show HN" | Title: "Show HN: redactkit — zero-dep Python redaction for LLM agent logs (incl. AWS SigV4)" | After v0.1.0 on PyPI |
| `r/Python` weekly thread | Same pitch | Same week |
| Convilyn engineering blog | Long-form: "Why we open-sourced our redaction layer" — covers the SigV4 gap | T+7 days |
| Reply-when-relevant on existing Presidio / scrubadub issues asking about structured data | Direct, non-spammy: "We just open-sourced a complementary library focused on structured data — might help your use case" | Within first 30 days |

---

## 14. Open decisions for you (resolve before Phase 0)

1. **Final package name** — pick one from §1, verify availability on PyPI + GitHub.
2. **Maintainer identity** — which GitHub handle is the human face? (Affects CODEOWNERS, FUNDING.yml, blog byline.)
3. **Disclosure email** — what address goes in SECURITY.md? Personal vs `security@convilyn.com`?
4. **Trusted Publisher binding** — confirm you have admin on `CoreNovus` org to register PyPI trusted publisher.
5. **Docs site Y/N** — ship Phase 3 (MkDocs site) at launch or defer to v0.2?

---

## 15. Anti-patterns to avoid

- ❌ Copying the entire monorepo `tests/` tree blindly — most tests are coupled to `app.*` and won't run standalone. Only migrate the 3 portable ones; rewrite the rest as fresh integration examples.
- ❌ Publishing v1.0.0 on day one — pre-1.0 lets you evolve the API based on early-user feedback without breaking semver.
- ❌ Accepting a runtime dependency in v0.1.0 — "zero deps" is a load-bearing differentiator vs Presidio. Don't let an "it would be nicer with `attrs`" PR through.
- ❌ Hand-maintained API token in publish workflow — use Trusted Publishers; rotation becomes free.
- ❌ Leaving `convilyn` references in code/docs — search the staging dir for `convilyn`, `corenovus`, customer names, AWS account IDs **before** the first push (mirror the audit step in `docs/operations/oss-extraction.md`).
- ❌ Treating CONTRIBUTING.md as boilerplate — write it like a real human; the SLA + label scheme is what actually attracts contributors.

---

## 16. Estimated total effort

| Phase | Effort | Blocking for launch? |
|---|---|---|
| Phase 0 (extract + polish) | 0.5 day | Yes |
| Phase 1 (v0.1.0 release) | 1 day | Yes |
| Phase 2 (community-ready) | 0.5 day | Yes (need before announcing) |
| Phase 3 (docs site) | 1 day | No — can ship later |
| Phase 4 (monorepo migration) | 0.5-1 day | No — pure cleanup |

**Critical path to public launch**: ~2 days of focused work.
