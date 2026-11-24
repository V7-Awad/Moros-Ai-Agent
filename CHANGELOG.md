# Changelog — Moros AI

All notable changes to the Moros AI Agent project are documented in this file.

## [2.1.0] - 2026-11-24
### Added
- **Learning Engine Integration**: Full SQLite WAL-backed memory system with 5 hooks (`record_finding`, `record_triage`, `recall`, `distill`, `score`) and session lifecycle intelligence.
- **Cross-Session Memory**: FTS5 full-text search across prior findings, false-positive signatures, and verified attack lessons.
- **9 New Security Skills**:
  - `idor-audit`: Insecure Direct Object Reference (BOLA) scanner.
  - `ssti-detect`: Server-Side Template Injection expression evaluator.
  - `path-traversal`: Directory traversal & Local File Inclusion auditor.
  - `crlf-injection`: HTTP response splitting and header injection detector.
  - `subdomain-takeover`: Dangling DNS CNAME takeover detector.
  - `rate-limit-test`: Authentication brute-force & anti-automation analyzer.
  - `host-header-injection`: Host & X-Forwarded-Host cache/reset poisoning auditor.
  - `xxe-detect`: XML External Entity injection detector.
  - `business-logic`: Agentic multi-step workflow flaw analyzer.
- **Expanded Test Suite**: Reached 53/53 automated tests with 100% pass rate.
- **Modern Build Metadata**: Added `pyproject.toml` and cleaned runtime dependencies.
- **Dashboard APIs**: Added `/api/learning/stats`, `/api/learning/recall`, `/api/learning/graph`, `/api/learning/finding`, and `/api/learning/triage`.

### Fixed
- Added `.get()` and `.head()` convenience methods to `ScopedHttpClient`.
- Expanded `allowed_headers` whitelist in `ScopedHttpClient` for CORS, auth, and redirect headers.
- Fixed `ScopeValidator` to respect `MOROS_IN_SCOPE` and `MOROS_OUT_OF_SCOPE` environment variables.
- Removed duplicate `ollama` entry in CLI provider argument parser.
- Auto-generated `scope.json` and `scope-of-work.md` templates during `setup.py init-target`.
- Added retry backoff logic for 429/503 errors in OpenAI-compatible LLM endpoints.
