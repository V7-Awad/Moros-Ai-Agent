# Changelog — Moros AI

All notable changes to the Moros AI Agent project are documented in this file.

## [2.4.0] - 2026-11-26
### Added
- **Phase 1 — Exploit Validation Engine (`tools/exploit_validator.py`)**: Added `ValidationResult`, `ProofRecorder` (sanitized request/response proof bundles under `output/evidence/validation/` + SHA-256 entries in `output/evidence/ledger.jsonl`), `ValidationStrategyRegistry` (9 core deterministic strategies + `generic-replay`), `ReproductionRunner`, and `ExploitValidator`, strictly enforced by `ScopeValidator`, `ScopedHttpClient`, `CheckpointManager`, `OOBServer`, and `AuthDiffChecker`.
- **Phase 1 Lifecycle & Reporting Upgrades (`tools/finding_dedupe.py`, `tools/finding_review.py`, `tools/poc_generator.py`, `tools/sarif_exporter.py`, `tools/report_i18n.py`)**: Added additive lifecycle states (`candidate`, `validating`, `confirmed`, `validated`, `inconclusive`, `false_positive`, `fixed`, `accepted_risk`), multi-method/redacted PoC generation for `confirmed` and `validated` findings, and lifecycle metadata in SARIF 2.1.0 and bilingual reports.
- **Phase 2 — Correlated Attack Chain Engine (`tools/attack_chain.py`, `tools/attack_graph.py`)**: Added `FindingRelationshipGraph`, `AttackPathAnalyzer`, `AttackPathScorer`, and `AttackChainEngine` to correlate findings via explicit technical signals, distinguish `verified` vs `inferred` transitions, report missing prerequisites, and emit `output/report/attack-chains.json` + enriched `output/report/attack-graph.json`.
- **Phase 3 — Remediation Assistant (`tools/remediation_assistant.py`)**: Added `CodeContextAnalyzer`, `RootCauseAnalyzer`, `PatchGenerator`, `PatchSafetyReviewer`, `PatchTestRunner`, `RemediationReport`, and `RemediationAssistant` operating strictly on confirmed findings (by default) inside isolated `LocalSandbox` / detached `git worktree` environments with human-approval branch gating and zero auto-commit/push.
- **Phase 4 — Retesting Engine (`tools/retest_engine.py`)**: Added `RetestPlanner`, `BeforeAfterComparator`, `RegressionAnalyzer`, `RetestRunner`, `RetestEngine`, and `update_finding_lifecycle()` persisting `RetestResult` records (`output/evidence/retests/`) with SHA-256 ledger provenance, mandatory limitation notes on `fixed` outcomes, and full preservation of historical evidence.
- **Phase 5 — GitHub & CI/CD Integration (`tools/ci_gate.py`, `.github/actions/moros-scan/action.yml`, `.github/workflows/moros-dast-example.yml`, `.github/workflows/moros-retest-example.yml`)**: Added configurable `GateConfig` policy gate evaluator, SARIF 2.1.0 validator, secret-redacted PR summary generator, composite GitHub Action with distinct exit codes (`0`, `2`, `3`, `4`), and SHA-pinned workflows with fork-PR scope guards.
- **Phase 6 — Continuous Learning & Skill Governance (`learning_engine/`, `tools/skill_learner.py`)**: Added additive outcome/telemetry/tech/attack-path ingestion and advisory-only recommendation helpers (`recommend_skills_for_tech`, `recommend_validation_strategies`, `estimate_scan_value_and_cost`, `recommend_regression_tests`, `get_advisory_patterns`), plus `SkillLearner` versioning, provenance tracking, `rollback_proposal()`, `disable_proposal()`, `enable_proposal()`, and `validate_proposal_policy_invariants()`.
- **Orchestrator & CLI Wiring (`tools/hackbot_orchestrator.py`, `run.py`)**: Added `validate_candidates` and `apply_advisory_prioritization()` in `HackbotOrchestrator`, plus CLI flags `--validate`, `--remediate <finding_id>`, `--repo-dir <path>`, `--retest <finding_id>`, `--ci-gate`, `--min-severity`, `--fail-on-confirmed`, and `--pr-summary-out`.
- **Dashboard Lifecycle APIs & UI (`dashboard/server.py`, `dashboard/static/index.html`)**: Added `GET /api/targets/{target}/attack-graph`, `POST /api/targets/{target}/validate`, `POST /api/targets/{target}/remediate`, `POST /api/targets/{target}/retest`, and `POST /api/targets/{target}/skill-proposals/rollback`, plus finding lifecycle badges, Attack Chain visualization, and proposal rollback/disable UI controls.
- **Documentation**: Added [`docs/ROADMAP_AUDIT.md`](docs/ROADMAP_AUDIT.md), [`docs/ROADMAP_IMPLEMENTATION_DESIGN.md`](docs/ROADMAP_IMPLEMENTATION_DESIGN.md), and [`docs/EXAMPLE_LIFECYCLE_REPORT.md`](docs/EXAMPLE_LIFECYCLE_REPORT.md); updated [`docs/API_REFERENCE.md`](docs/API_REFERENCE.md), [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md), and [`README.md`](README.md).

### Fixed
- Fixed `run.py` `--oob-listen` callback summary wiring (`oob_server.base_url`, `poll_callbacks()`, `summarize_findings()`) and added `log_dir` / `list_callbacks()` compatibility aliases in `tools/oob_server.py`.
- Fixed `skills/idor-audit/run.py` calling `diff_checker.check_endpoints()` instead of nonexistent `check_batch()`.
- Added `RunManager.get_event_stream(run_id)` in `tools/run_manager.py` for dashboard SSE streaming.
- Fixed `tools/attack_graph.py` artifact loading to ingest `SkillRunner` outputs (`recon/subdomains-all.txt`, `js/endpoints.json`, `js/parameters.json`, `api/endpoints.json`) alongside legacy paths.
- Fixed `tools/skill_runner.py` `run_report_conglomeration()` to preserve machine-confirmed findings via `resolve_finding_lifecycle()` and `PoCGenerator.is_poc_eligible()`.

### Compatibility & Migration Notes
- **Additive Lifecycle Statuses:** Unverified findings lacking deterministic `validation_result` (`proof_artifact` + `evidence_ids`) or human `validation_record` continue to resolve to `status="candidate"` / `validation_status="unverified"`, keeping `--fail-on-candidate` and existing audit invariants intact.
- **Database Evolution:** `learning_engine` applies additive schema migrations (`outcome_events`, `tech_fingerprints`, `skill_telemetry`, `attack_paths`) automatically while preserving existing `triage` verdicts (`confirmed`, `false_positive`, `unverified`).
- **CI Exit Codes:** `tools/ci_gate.py` and `.github/actions/moros-scan/action.yml` separate exit codes into `0` (pass), `2` (policy gate triggered), `3` (scope/authorization violation), and `4` (invalid configuration or missing/malformed artifacts), while `run.py --fail-on-candidate` continues exiting `2`.

## [2.3.1] - 2026-11-26
### Added
- **Containerization & CI/CD (`Dockerfile`, `docker-compose.yml`, `.github/workflows/ci.yml`)**: Non-root container image, CLI/dashboard Compose profiles, and Python 3.10 / 3.12 GitHub Actions workflow.
- **HTTP Resilience (`tools/scoped_http.py`)**: Scoped HTTP/HTTPS/SOCKS5 proxy support (`--proxy` / `MOROS_PROXY`), safe `GET`/`HEAD` exponential backoff retries, and optional `CookieJar` persistence.
- **Cross-Provider LLM Failover (`tools/llm_client.py`)**: Automatic fallback across configured LLM providers (`--no-failover` to disable) and transient 429/503 retries for Anthropic.
- **Scan Resumability & Business Logic Skill (`tools/run_manager.py`, `tools/hackbot_orchestrator.py`, `skills/business-logic/run.py`)**: `--resume` flag to continue interrupted scans from saved run state and executable workflow risk analyzer for checkout/payment/role endpoints.
- **Dashboard Security Hardening (`dashboard/server.py`)**: Optional TLS/HTTPS (`--ssl-cert` / `--ssl-key`), CSRF `Origin`/`Referer` checks on mutations, API rate limiting, and `docs/API_REFERENCE.md` + `docs/DEPLOYMENT.md`.

### Fixed
- Separated blocked off-host redirects (`stopped_by_policy`) from real out-of-scope deviations in `hackbot_orchestrator.py` and `finding_review.py`, with persisted `blocked_scope` terminal state recovery in `dashboard/server.py`.

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
- **OOB Callback Server & Dual-Auth IDOR Diffing (`tools/oob_server.py`, `tools/auth_diff.py`)**: Built-in HTTP/DNS canary token correlation server for blind XSS/SSRF/XXE (`--oob-url`) and multi-session User A vs User B vs Unauthenticated response diffing (`--cookie-b`, `--auth-header-b`).
- **Sandboxed Execution & Per-Step Routing (`tools/skill_runner.py`, `tools/agent_runtime.py`, `tools/agent_security.py`)**: Custom skill scripts execute inside `LocalSandbox` with scrubbed secrets, optional `per_step_routing` dynamically selects per-step models, and `SKILL_TOOL_PERMISSIONS` maps standard agent tools cleanly across tiers.
- **Dashboard Observability UI, MCP SSE & Arabic Reporting (`dashboard/static/index.html`, `tools/mcp_client.py`, `tools/report_i18n.py`)**: Interactive tabs for Costs, Traces, Memory, and OWASP Posture; SSE `text/event-stream` response parsing + `mcp-servers.json` loader; and `--lang ar --dialect msa|egyptian` bilingual reporting.
- **Scheduler, A2A Protocol, Skill Learner & Juice Shop Benchmark (`tools/scheduler.py`, `tools/a2a_server.py`, `tools/skill_learner.py`, `evals/juice_shop_benchmark.py`)**: Scheduled/webhook scan manager, `/.well-known/agent.json` & `/api/a2a` endpoints, Trace2Skill candidate skill proposal generator (requiring explicit approval), and vulnerable-app TP/FP regression benchmark.

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
