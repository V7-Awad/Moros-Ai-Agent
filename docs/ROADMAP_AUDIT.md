# MOROS AI — Phase 0 Repository Audit & Baseline Report

**Audit Date:** 2026-11-26  
**Repository HEAD:** `8d9b184` (`main`)  
**Scope:** Phase 0 repository audit and baseline verification prior to implementing Phases 1–6 of `MOROS_Development_Roadmap.md`.

---

## 1. Executive Summary of Current Architecture

Moros AI is a Python 3.10+ modular web penetration testing framework organized around five main layers:

1. **CLI & Entry Points (`run.py`, `setup.py`, `dashboard.py`)**:
   - `run.py` parses assessment flags, enforces a live LLM preflight check (`LLMClient(provider="auto").is_available()` + `"READY"` probe, exiting `2` on failure unless `--dry-run`), invokes `HackbotOrchestrator`, optionally starts `OOBServer`, handles `--resume`, `--schedule`, `--proposals`, `--fail-on-candidate`, and exits with status codes (`0`, `1`, `2`, `3`, `130`).
   - `setup.py` initializes `targets/<domain>/` with `scope.json`, `scope-of-work.md`, and `output/` directories.
2. **Orchestration & Skill Execution (`tools/hackbot_orchestrator.py`, `tools/skill_registry.py`, `tools/skill_runner.py`, `tools/run_manager.py`)**:
   - `SkillRegistry` discovers 16 core skills and custom `skills/<id>/` directories (33 total skills currently installed), parses `SKILL.md` YAML frontmatter / `## Dependencies`, and orders execution via DAG topological sorting.
   - `HackbotOrchestrator` verifies `scope-of-work.*`, profiles WAFs (`WafDetector`) and tech stacks (`TechProfiler`), tracks durable run state (`RunManager` -> `output/runs/<run_id>/`), executes prerequisite skills serially, runs independent vuln skills serially or via `ThreadPoolExecutor` (`--parallel`), invokes `review-skill`, runs `report-conglomeration`, builds `output/report/attack-graph.json`, and invokes `LearningEngine`.
3. **Bounded Agent Runtime & Security Guardrails (`tools/agent_runtime.py`, `tools/agent_security.py`, `tools/scope_validator.py`, `tools/scoped_http.py`, `tools/sandbox_manager.py`, `tools/checkpoint_manager.py`)**:
   - `AgentRunner` executes a bounded ReAct (`Thought` / `Action` / `Final Answer`) loop (default `max_steps=25`, `timeout_seconds=600`, `ActionBudget` of `50` actions / `10` writes), fails closed if no LLM is connected, scrubs observations with spotlighting (`detect_injection()` / `sanitize_for_prompt()`), and checks `SKILL_TOOL_PERMISSIONS` when `enforce_permissions=True`.
   - `ScopedHttpClient` enforces `ScopeValidator` allow/deny rules, `GET`/`HEAD`-only defaults, ports `80`/`443` only, cross-host redirect blocking (`_SafeRedirectHandler`), proxy redaction, safe retry backoff, and HITL `CheckpointManager` approval gates (`MOROS_ALLOW_GATED_POST`, `MOROS_HITL_BLOCKING`).
   - `LocalSandbox` / `DockerSandbox` isolate custom skill execution and scrub sensitive environment credentials (`build_scrubbed_env()`).
4. **Findings, Review & Reporting (`tools/finding_review.py`, `tools/finding_dedupe.py`, `tools/poc_generator.py`, `tools/cvss_calculator.py`, `tools/sarif_exporter.py`, `tools/report_i18n.py`, `tools/attack_graph.py`)**:
   - Candidate findings are deduplicated (`deduplicate_findings`), checked against artifact SHA-256 hashes (`review_candidates`), exported to Markdown/JSON (`--lang en|ar`) and OASIS SARIF 2.1.0, and linked to static `GET` PoC scripts (only when human-validated).
5. **Observability, Learning & Dashboard (`tools/memory_manager.py`, `learning_engine/`, `tools/skill_learner.py`, `tools/scheduler.py`, `dashboard/server.py`, `dashboard/static/index.html`)**:
   - Per-target `memory.db` (SQLite WAL), cross-target `learning_engine` (SQLite + FTS5), `SkillLearner` unapproved `SKILL.md` proposals, `ScanScheduler`, and a 13-tab web operations console with bearer token auth, CSRF checks, TLS, SSE streaming, and A2A JSON-RPC.

---

## 2. Feature-by-Feature Status Table

| Area | Status | Evidence in Repository | Specific Gaps Found | Recommended Action |
| :--- | :--- | :--- | :--- | :--- |
| **Exploit validation** | **Partial / Missing Engine** | `tools/finding_review.py` (`review_candidates`), `tools/finding_dedupe.py`, `tools/poc_generator.py`, `tools/oob_server.py`, `tools/auth_diff.py`, `skills/review-skill/`, `tests/test_scope_audit.py`, `tests/test_oob_and_auth_diff.py` | No `ExploitValidator`, `ValidationStrategyRegistry`, `ReproductionRunner`, `ProofRecorder`, or `ValidationResult`. `review_candidates()` is non-invasive (`network_requests: 0`) and forces all items to `candidate`/`unverified`. Report/dashboard only recognize manual `validation_record` with `verified_by="human:..."`. `PoCGenerator` only emits static `GET` templates. Missing lifecycle states (`validating`, `confirmed`, `inconclusive`, `false_positive`, `fixed`, `accepted_risk`). | **Phase 1:** Build `tools/exploit_validator.py` (with `ExploitValidator`, `ValidationStrategyRegistry`, `ReproductionRunner`, `ProofRecorder`, `ValidationResult`), unify finding status/proof schema backward-compatibly, wire `OOBServer`/`AuthDiffChecker`/`FalsePositiveFilter`, and upgrade `PoCGenerator` + `finding_review.py` + `sarif_exporter.py`. |
| **Attack-chain correlation** | **Partial (Surface Only)** | `tools/attack_graph.py` (`AttackGraphBuilder`), `tools/hackbot_orchestrator.py` (L630–636), `learning_engine/graph/builder.py`, `tests/test_advanced_features.py` | `AttackGraphBuilder` only creates a flat root -> subdomain -> endpoint -> finding tree (`{source, target, relation}`). It reads stale paths (`recon/subdomains.txt` instead of `recon/subdomains-all.txt`, misses `js/endpoints.json`). No `AttackChainEngine`, `FindingRelationshipGraph`, `AttackPathAnalyzer`, or `AttackPathScorer`. Edges lack `evidence_ids`, `confidence`, and `verified` vs `inferred` flags. Dashboard (`dashboard/server.py`, `index.html`) does not serve or render `attack-graph.json`. | **Phase 2:** Extend `tools/attack_graph.py` (plus new `tools/attack_chain.py`) to fix artifact paths, correlate findings via shared assets/identities/trust boundaries/prerequisites, score paths separately from finding severity, distinguish demonstrated vs inferred edges, and expose `/api/targets/{t}/attack-graph` in Dashboard. |
| **Remediation** | **Missing** | Generic text templates only in `tools/report_i18n.py` (L93, L436) and `tools/sarif_exporter.py` (L167–168) | No `CodeContextAnalyzer`, `RootCauseAnalyzer`, `PatchGenerator`, `PatchSafetyReviewer`, `PatchTestRunner`, or `RemediationReport`. No source-code context mapping, isolated test execution, diff safety validation, or human-approved branch/PR workflow. | **Phase 3:** Build `tools/remediation_assistant.py` operating strictly on confirmed findings inside an isolated worktree/sandbox, generating minimal diffs + test results with explicit human approval gates before any branch/PR creation. |
| **Retesting** | **Missing** | Scheduling/resume foundations only in `tools/scheduler.py`, `tools/run_manager.py`, `tools/finding_review.py` | No `RetestPlanner`, `RetestRunner`, `BeforeAfterComparator`, or `RegressionAnalyzer`. Cannot link a remediation/commit to an original finding proof, replay its exact safe validation strategy, compare before/after responses, or update lifecycle to `fixed` / `still_vulnerable` / `regression_detected` / `inconclusive` while preserving historical evidence. | **Phase 4:** Build `tools/retest_engine.py` reusing Phase 1 `ReproductionRunner` & `ProofRecorder` and Phase 3 remediation metadata, persisting immutable retest records and regression checks. |
| **GitHub / CI integration** | **Partial** | `.github/workflows/ci.yml`, `run.py` (`--fail-on-candidate`), `tools/sarif_exporter.py`, `docs/DEPLOYMENT.md`, `tests/test_sarif_exporter.py`, `tests/test_scan_resume_and_cli.py` | No reusable GitHub Action (`action.yml`) with documented inputs/outputs. `.github/workflows/ci.yml` uses unpinned `@v4`/`@v5` tags rather than immutable SHAs. No PR summary/comment generator, no severity/confidence gate thresholds (only binary `--fail-on-candidate`), exit code `2` overloaded between CLI model preflight failure (`run.py:454,460`) and `--fail-on-candidate` (`run.py:544`), and no retest-on-PR workflow. | **Phase 5:** Add reusable composite GitHub Action + example workflow with pinned SHAs, configurable severity/confidence/validation gates, distinct exit codes, PR markdown summary generator, SARIF upload, and optional retest workflow. |
| **Learning and memory** | **Existing / Partial** | `tools/memory_manager.py`, `learning_engine/` (`engine.py`, `analytics/`, `retrieval/`, `scoring/`, `graph/`), `tools/skill_learner.py`, `tools/fp_filter.py`, `tests/test_learning_engine.py`, `tests/test_skill_learner.py` | `FalsePositiveFilter` (`tools/fp_filter.py`) is not wired into `SkillRunner`/`finding_review.py`. `LearningEngine` verdicts are restricted to `("confirmed", "false_positive", "unverified")` and do not ingest validation confidence, `inconclusive`, remediation/retest outcomes (`fixed`/`regression_detected`), skill duration/cost, or attack paths. `SkillLearner` lacks proposal versioning, provenance links to validation/retest runs, and disable/rollback controls. | **Phase 6:** Wire `fp_filter.py`, expand `LearningEngine` / `MemoryManager` inputs from Phases 1–4 as advisory signals, add provenance + versioning + rollback/disable controls to `SkillLearner`, and keep all security policies/scopes immutable to learning. |

---

## 3. Existing Wiring Bugs & Discrepancies Discovered During Audit

1. **`run.py` vs `tools/oob_server.py` (`--oob-listen`)**:
   - `run.py` L507 calls `OOBServer(host="127.0.0.1", port=0, log_dir=...)`, whereas `OOBServer.__init__` (`tools/oob_server.py` L64–71) accepts `persistence_path`, not `log_dir` (causing `TypeError`, silently caught at L512).
   - `run.py` L519 calls `oob_server.list_callbacks()`, whereas `OOBServer` exposes `poll_callbacks()` / `summarize_findings()`.
2. **`skills/idor-audit/run.py` vs `tools/auth_diff.py`**:
   - `skills/idor-audit/run.py` L361 calls `diff_checker.check_batch(diff_targets)`, whereas `AuthDiffChecker` defines `check_endpoints()`, not `check_batch()` (exception swallowed at L380).
3. **`dashboard/server.py` vs `tools/run_manager.py`**:
   - `dashboard/server.py` L2869 calls `rm.get_event_stream(run_id)`, which does not exist on `RunManager` (`run_manager.py` only writes `events.jsonl` via `log_event`).
4. **`tools/attack_graph.py` artifact path mismatch**:
   - Reads `recon/subdomains.txt`, `recon/endpoints.txt`, `content/discovered-endpoints.txt`, `api/openapi-endpoints.json` instead of `SkillRunner`'s actual outputs (`recon/subdomains-all.txt`, `js/endpoints.json`, `js/parameters.json`, `api/endpoints.json`), and is not wired into `dashboard/server.py` or `dashboard/static/index.html`.
5. **Report stale-snapshot coupling (`dashboard/server.py` L2246–2287)**:
   - `get_target_findings()` checks `source_artifact_mtimes` recorded inside `hackbot-report-*.json`. Any validation, attack-chain, or retest artifacts created after report generation must either run prior to `report-conglomeration` or be tracked cleanly without invalidating historical evidence.

---

## 4. Baseline Test & Verification Results (2026-11-26)

| Check / Command | Scope | Result | Notes |
| :--- | :--- | :--- | :--- |
| `python -m pytest tests/ evals/ -q --tb=short` | Full unit, integration, security, dashboard, and eval test suites | **361 passed** (`68.97s`, exit `0`) | Zero skipped, zero failing tests on baseline `8d9b184`. |
| `python tools/eval_harness.py` | Scope enforcement (6), injection resistance (7), secret redaction (3), model routing (3) | **19 / 19 passed** (`100.0%`, exit `0`) | Verified offline deterministic guardrails. |
| `python evals/juice_shop_benchmark.py --json` | Simulated vulnerable vs safe target benchmark (XSS, SQLi, IDOR, LFI, JWT `alg:none`, Open Redirect, CORS) | **14 / 14 accurate** (`7 TP, 7 TN, 0 FP, 0 FN`; `F1 = 1.0`) | Controlled simulation fixture. |
| `python -m compileall -q tools tests dashboard skills evals run.py setup.py dashboard.py` | Syntax & bytecode compilation across all project packages | **Passed** (exit `0`) | Note: running `compileall` on `.` also hits untracked `_ref/` external sample data (`_ref/.../f4-PG260106_src_app.py:306`), not part of Moros source. |
| `python run.py --check` | Python version, Playwright, JSBeautifier, PyYAML prerequisites | **Passed** (`All prerequisites met!`, exit `0`) | Verified in local Windows Python environment. |
| `ruff` / `flake8` / `mypy` | Static linters / type checkers | **Not installed / not configured** | Not present in `requirements.txt`, `pyproject.toml`, or `.github/workflows/ci.yml`. |

---

## 5. Current Data Models & Persistence Formats

### 5.1 Finding Schemas (Current Fragmentation)
- **`SkillRunner.run_vuln_skill()` (`output/findings/<skill>/candidates-<skill>.json`)**:
  `{"target": str, "status": str, "findings": [{title, type, url, parameter?, sink?, status: "candidate", validation_status: "unverified", confidence, evidence_ids: [...], evidence: [dict], severity: "Triage Severity: UNASSESSED...", notes}]}`.
- **Custom skills (`skills/*/run.py`) & `AgentRunner.record_finding()`**:
  Produces `{"findings": [...], "count": N}` or `{"target": ..., "skill": ..., "findings": [...]}` where `evidence` is frequently a **plain `str`**, `evidence_ids` is often omitted, and `severity` uses `"LOW"`/`"MEDIUM"`/`"HIGH"`.
- **`AuthDiffChecker` (`tools/auth_diff.py`)**:
  Uses `status` in `{"blocked_scope", "budget_exhausted", "candidate", "passed", "inconclusive"}` and `validation_status` in `{"blocked_scope", "inconclusive", "unverified", "verified_negative"}`.
- **Dashboard (`dashboard/server.py:2353-2384`) & `report_i18n.py` & `sarif_exporter.py`**:
  Only promotes to `status="validated"` / `validation_status="validated"` when `validation_record` has `verified_by.startswith("human:")`, non-empty `method`, non-empty `evidence_ids`, and `outcome == "reproduced"`.
- **`learning_engine` (`schemas/findings.json`, `schemas/triage.json`)**:
  Validates triage `verdict` strictly against `("confirmed", "false_positive", "unverified")`.

### 5.2 Other Persistent Stores
- **Evidence Ledger (`targets/<t>/output/evidence/ledger.jsonl`)**: Append-only JSONL keyed by `ev-<sha256[:16]>`, currently hardcoding `evidence_type: "endpoint_metadata"` and `verification_status: "unverified"`.
- **Run Lifecycle (`targets/<t>/output/runs/<run_id>/`)**: `run.json`, `events.jsonl`, `agents.jsonl` (`RunManager`).
- **HITL Checkpoints (`targets/<t>/output/logs/checkpoints.json`)**: Atomic JSON keyed by `cp-<sha256[:12]>` (`WAITING_APPROVAL`, `APPROVED`, `REJECTED`).
- **Target Memory (`targets/<t>/memory.db`)**: SQLite WAL tables `episodic`, `semantic`, `procedural`, `checkpoints`.
- **Global Learning (`learning_engine/memory/learning.db`)**: SQLite + FTS5 tables (`findings`, `triage`, `lessons`, `lessons_fts`, `findings_fts`).
- **Schedules & Learned Proposals**: `targets/<t>/schedules.json`, `targets/<t>/output/skill-proposals/<id>/proposal.json`.

---

## 6. Compatibility Constraints & Security-Sensitive Code Paths

1. **Scope & Non-Destructive Defaults (`tools/scope_validator.py`, `tools/scoped_http.py`, `tools/checkpoint_manager.py`)**:
   - All validation, attack-chain verification, and retesting network traffic **must** pass through `ScopedHttpClient` + `ScopeValidator` + `CheckpointManager` (`MOROS_ALLOW_GATED_POST` / `MOROS_HITL_BLOCKING`). Never bypass via raw `urllib`/`requests`/`curl` subprocesses.
   - Redirects (`_SafeRedirectHandler`) and LLM suggestions must never expand scope.
2. **Untrusted Content & Secret Scrubbing (`tools/agent_security.py`, `tools/llm_client.py`, `tools/sandbox_manager.py`)**:
   - Target responses, code files, and repo READMEs ingested during validation or remediation must pass through `detect_injection()` / `sanitize_for_prompt()` (`spotlight()`), and artifacts/diffs/logs must redact credentials via `redact_headers()`, `redact_secrets()`, and `sanitize_output()`.
3. **Backward Compatibility with Existing Tests & CLI Gates**:
   - Keep `"status": "candidate"` / `"validation_status": "unverified"` semantics intact for unvalidated findings so `tests/test_scope_audit.py`, `tests/test_vuln_skills.py`, `tests/test_e2e_local_target.py`, and `--fail-on-candidate` remain valid.
   - Normalize Windows vs POSIX paths (`/` separators) in artifact references and ledger checks.
   - Maintain compatibility with `learning_engine`'s verdict validation (`confirmed`, `false_positive`, `unverified`) when bridging Phase 1/4 states.

---

## 7. Proposed Implementation Sequence, Modules & Complexity

| Phase | Proposed Modules (New / Modified) | Estimated Complexity | Notes |
| :--- | :--- | :--- | :--- |
| **Phase 1: Exploit Validation Engine** | **New:** `tools/exploit_validator.py`, `tests/test_exploit_validator.py`<br>**Update:** `tools/finding_review.py`, `tools/finding_dedupe.py`, `tools/poc_generator.py`, `tools/cvss_calculator.py`, `tools/skill_runner.py`, `tools/hackbot_orchestrator.py`, `tools/sarif_exporter.py`, `tools/report_i18n.py`, `tools/oob_server.py`, `skills/idor-audit/run.py`, `run.py`, `dashboard/server.py` | **High** (1–2 weeks equiv.) | Highest priority. Also fixes `--oob-listen` and `idor-audit` `check_batch` wiring bugs while preserving existing candidate/unverified tests. |
| **Phase 2: Attack Chain Engine** | **New:** `tools/attack_chain.py`, `tests/test_attack_chain.py`<br>**Update:** `tools/attack_graph.py`, `tools/hackbot_orchestrator.py`, `tools/report_i18n.py`, `dashboard/server.py`, `dashboard/static/index.html` | **Medium** (~1 week equiv.) | Consumes Phase 1 validated/candidate findings + fixed recon/JS paths; surfaces interactive chain view in Dashboard. |
| **Phase 3: Remediation Assistant** | **New:** `tools/remediation_assistant.py`, `tests/test_remediation_assistant.py`<br>**Update:** `tools/sandbox_manager.py`, `tools/checkpoint_manager.py`, `dashboard/server.py`, `run.py` | **High** (1–2 weeks equiv.) | Isolated git worktree / sandbox execution only; prompt-injection defense on scanned repo files; strict human approval gate before branch/PR creation. |
| **Phase 4: Retesting Engine** | **New:** `tools/retest_engine.py`, `tests/test_retest_engine.py`<br>**Update:** `tools/exploit_validator.py`, `tools/run_manager.py`, `tools/scheduler.py`, `run.py`, `dashboard/server.py` | **Medium** (~1 week equiv.) | Reuses Phase 1 `ReproductionRunner` & `ProofRecorder` and Phase 3 metadata; keeps immutable proof history. |
| **Phase 5: GitHub & CI/CD Integration** | **New:** `.github/actions/moros-scan/action.yml`, `.github/workflows/moros-dast-example.yml`, `.github/workflows/moros-retest-example.yml`, `tools/ci_gate.py`, `tests/test_ci_gate.py`<br>**Update:** `.github/workflows/ci.yml` (pin SHAs), `run.py`, `docs/DEPLOYMENT.md` | **Medium** (~1 week equiv.) | Separates CLI config error exit code from gate failure exit codes; adds configurable severity/validation/confidence thresholds and PR summary markdown. |
| **Phase 6: Continuous Learning Improvements** | **Update:** `learning_engine/core/config.py`, `learning_engine/engine.py`, `learning_engine/analytics/patterns.py`, `tools/skill_learner.py`, `tools/fp_filter.py`, `tools/hackbot_orchestrator.py`, `dashboard/server.py`, `tests/test_learning_engine.py`, `tests/test_skill_learner.py` | **Medium** (Incremental) | Advisory only; adds versioning, rollback/disable switches, trace provenance, and validation/retest outcome feedback without altering security policy. |

---

## 8. Risks & Design Decisions Requiring Operator Approval Before Phase 1

1. **Automated Confirmation vs. Human Validation Policy (`confirmed` vs `validated`)**:
   - Currently, `dashboard/server.py` and `skill_runner.py` require `validation_record.verified_by.startswith("human:")` before leaving `candidate`/`unverified` status.
   - **Proposed Decision:** Introduce an additive machine-verified lifecycle (`candidate` -> `validating` -> `confirmed` | `inconclusive` | `false_positive` -> `fixed` | `accepted_risk`) backed by deterministic `ProofRecorder` criteria (e.g., exact unescaped canary reflection, OOB canary token callback match, differential `AuthDiffChecker` access leak, reproducible before/after probe), while keeping `accepted_risk` strictly human-only and keeping `human_reviewed` / `validation_record` distinct from automated `confirmed`.
2. **Active Validation Execution Budget & State-Changing Probes**:
   - **Proposed Decision:** `ExploitValidator` will run strictly within `ScopedHttpClient` (`GET`/`HEAD` by default) and `HackbotOrchestrator`'s remaining request/cost budget, and any state-changing validation (`POST`/`PUT`/`DELETE`) will remain blocked behind `MOROS_ALLOW_GATED_POST` + `CheckpointManager` HITL approval.
3. **Exit Code Separation for CI vs. Model Preflight**:
   - Currently, `run.py` returns exit code `2` for *both* missing/failing LLM preflight (`run.py:454,460`) and `--fail-on-candidate` (`run.py:544`).
   - **Proposed Decision:** Keep `2` for policy/finding gates (`--fail-on-candidate` and Phase 5 severity/confidence gates) and map configuration/model-unavailable preflight failures cleanly (e.g., exit code `4`, documented in Phase 5), unless existing callers rely on `2` for preflight.
4. **LLM-Backed vs. Deterministic Validation & Remediation in Offline Tests**:
   - Note that recent commits (`ea90f1b`, `8d9b184`) enforce a connected LLM in `run.py` / `AgentRunner` runtime actions. Deterministic validation strategies in Phase 1 (`ValidationStrategyRegistry` / `ReproductionRunner`) and `BeforeAfterComparator` in Phase 4 should operate deterministically without requiring live LLM calls so they remain fast, reproducible, and testable offline.
