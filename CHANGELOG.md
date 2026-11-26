# Changelog — Moros AI

All notable changes to the Moros AI Agent project are documented in this file.

## [2.3.0] - 2026-11-26
### Added
- **Smart Model Router (`tools/model_router.py`)**: Complexity-aware routing across configured providers (`--smart-route`) with pre-execution scan cost range estimation and automatic low-budget downgrade.
- **Cost Transparency Engine (`tools/cost_tracker.py`)**: Thread-safe token and cost accounting per LLM call and skill, USD budget cap enforcement (`--budget`), JSONL step logging, and scan cost receipts in `output/costs/receipt.json`.
- **MCP Client Support (`tools/mcp_client.py`)**: JSON-RPC 2.0 Model Context Protocol client with stdio and HTTP transports, tool discovery, argument schema validation, allowlist filtering, and `--mcp-server` CLI integration.
- **Tiered Persistent Memory (`tools/memory_manager.py`)**: Per-target SQLite WAL memory database (`memory.db`) storing episodic events, semantic infrastructure facts, procedural technique outcomes, and resume checkpoints.
- **Execution Sandbox Abstraction (`tools/sandbox_manager.py`)**: Scrubbed `LocalSandbox`, `DockerSandbox`, and explicit-fail `E2BSandbox`/`ModalSandbox` adapters.
- **OWASP Agentic Security Controls (`tools/agent_security.py`, `docs/OWASP_AGENTIC_SECURITY.md`)**: Observation spotlighting, prompt injection detection and stripping, per-skill tool permission scoping, `ActionBudget` gates, and output sanitization.
- **Structured Observability (`tools/trace_logger.py`)**: Hierarchical OpenTelemetry-compatible span tracing exported to `output/traces/` (`--no-trace` to disable).
- **Parallel Deep Recon & Subagent Fan-Out**: Added `skills/deep-recon/SKILL.md` (`--deep-recon`), `SkillRunner.run_deep_recon()`, and `spawn_subagents_parallel` in `tools/agent_runtime.py`.
- **AAIF Skill Frontmatter & Eval Harness**: Added YAML frontmatter parsing + `export_aaif_manifest()` in `tools/skill_registry.py`, plus deterministic safety/routing evaluations in `tools/eval_harness.py` and `evals/`.
- **Dashboard Endpoints**: Added `/api/security/posture`, `/api/targets/<target>/costs`, `/api/targets/<target>/traces`, and `/api/targets/<target>/memory` in `dashboard/server.py`.

## [2.2.0] - 2026-11-24
### Added
- **Official FIRST CVSS v3.1 Calculator**: Automatic Base Score, qualitative severity, and Vector String calculation for all findings and SARIF 2.1.0 exports.
- **WAF Detection & Adaptive Evasion Engine**: Automated fingerprinting of Cloudflare, AWS WAF, Akamai, Imperva, ModSecurity, Sucuri, and F5 BIG-IP with automatic dynamic rate-limiting and evasion pacing.
- **Technology Stack Profiler**: Heuristic profiling of backend languages, web frameworks, CMS, and API architectures (Spring Boot, Django, Laravel, Express, Next.js, WordPress, GraphQL) with dynamic attack skill re-prioritization.
- **Directed Attack Graph Visualizer**: Mapping of target assets, subdomains, endpoints, and vulnerability sinks into an interconnected graph with Mermaid visualization.
- **Cryptographic False Positive Filter**: Signature-hash verification against `memory/FALSE_POSITIVE_DB.md` to prevent alert noise and repeated scanning loops.
- **Test Suite Expansion**: Reached 62/62 automated tests passing with 100% coverage.

## [2.1.0] - 2026-11-24
### Added
- **Learning Engine Integration**: Full SQLite WAL-backed memory system with 5 hooks (`record_finding`, `record_triage`, `recall`, `distill`, `score`) and session lifecycle intelligence.
- **Cross-Session Memory**: FTS5 full-text search across prior findings, false-positive signatures, and verified attack lessons.
- **10 New Security Skills**:
  - `http-smuggling`: HTTP Request Smuggling (CWE-444) via CL.TE and TE.CL desync timing probes.
  - `idor-audit`: Insecure Direct Object Reference (BOLA) scanner.
  - `ssti-detect`: Server-Side Template Injection expression evaluator.
  - `path-traversal`: Directory traversal & Local File Inclusion auditor.
  - `crlf-injection`: HTTP response splitting and header injection detector.
  - `subdomain-takeover`: Dangling DNS CNAME takeover detector.
  - `rate-limit-test`: Authentication brute-force & anti-automation analyzer.
  - `host-header-injection`: Host & X-Forwarded-Host cache/reset poisoning auditor.
  - `xxe-detect`: XML External Entity injection detector.
  - `business-logic`: Agentic multi-step workflow flaw analyzer.
- **Parallel Skill Execution**: Added `--parallel` CLI flag supporting concurrent independent vulnerability skill execution via `concurrent.futures.ThreadPoolExecutor`.
- **Real-Time Progress Streaming (SSE)**: Added `/api/scan/stream` endpoint for live event updates without polling.
- **Dynamic Dependency Parsing**: Added markdown `## Dependencies` header parser in `SkillRegistry` for automated prerequisite chaining.
- **Robust Skill Import Architecture**: Migrated all custom skill runner scripts to dynamic project root discovery.
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
