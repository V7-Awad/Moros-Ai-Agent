# Moros Agentic Security Architecture (OWASP Agentic AI Top 10 Mapping)

Moros executes automated security assessments across untrusted HTTP responses, JavaScript bundles, and third-party API specifications. Because agent runtimes process external content directly inside LLM context windows, Moros implements explicit runtime controls mapped to the OWASP Agentic AI Top 10 (2026).

---

## Control Matrix

| ID | Risk Category | Moros Control | Implementation |
|:---|:---|:---|:---|
| **ASI01** | Prompt Injection | Spotlighting (`«DATA_BEGIN»`/`«DATA_END»` delimiters), regex injection detection, observation stripping | [`tools/agent_security.py`](../tools/agent_security.py), [`tools/agent_runtime.py`](../tools/agent_runtime.py) |
| **ASI02** | Broken Authorization / Privilege Escalation | Role-based per-skill tool scoping (`recon`, `analysis`, `active`, `reporting`) | [`tools/agent_security.py`](../tools/agent_security.py) |
| **ASI03** | Excessive Agency | Hard per-session action and HTTP-write caps (`ActionBudget`), plus HITL blocking gates | [`tools/agent_security.py`](../tools/agent_security.py), [`tools/checkpoint_manager.py`](../tools/checkpoint_manager.py) |
| **ASI04** | Insufficient Logging & Monitoring | Structured OpenTelemetry-compatible span tracing exported to `output/traces/` | [`tools/trace_logger.py`](../tools/trace_logger.py) |
| **ASI05** | Unsafe Output Handling | Final-response marker and secret sanitization before terminal/dashboard display | [`tools/agent_security.py`](../tools/agent_security.py) |
| **ASI06** | Insecure Plugins & External Tools | Schema validation and explicit `tool_allowlist` filtering on all MCP tool servers | [`tools/mcp_client.py`](../tools/mcp_client.py) |
| **ASI07** | Resource & Cost Overconsumption | Pre-scan cost estimation, per-step token metering, and hard USD budget caps | [`tools/cost_tracker.py`](../tools/cost_tracker.py), [`tools/model_router.py`](../tools/model_router.py) |
| **ASI08** | Excessive Sensitive Data Exposure | API key / Bearer token scrubbing on LLM completions and subprocess sandbox environments | [`tools/llm_client.py`](../tools/llm_client.py), [`tools/sandbox_manager.py`](../tools/sandbox_manager.py) |
| **ASI09** | Target Denial of Service | Same-host request counters, minimum inter-request delays, and adaptive WAF backoff | [`tools/scoped_http.py`](../tools/scoped_http.py), [`tools/waf_detector.py`](../tools/waf_detector.py) |
| **ASI10** | Trust Boundary Violation | Domain/IP/port allowlists blocking private networks, loopback, and cloud metadata IPs | [`tools/scope_validator.py`](../tools/scope_validator.py) |

---

## Key Mechanisms

### 1. Observation Spotlighting & Injection Filtering (ASI01)
Before appending tool output to the ReAct conversation history, `AgentRunner` scans observations with `detect_injection()`. If known prompt-injection patterns appear (e.g., instruction overrides, ChatML/XML role spoofing), the event is logged in `MemoryManager` (`prompt_injection_blocked`), matched directives are replaced with `[REDACTED_INJECTION]`, and the payload is wrapped inside `«DATA_BEGIN» ... «DATA_END»` delimiters.

### 2. Least-Privilege Tool Scoping & Action Caps (ASI02 / ASI03)
- **Skill Scoping**: Passive reconnaissance skills (`recon-subdomain`, `api-spec-discovery`, `js-discover`) are limited to read-only operations. State-changing probes require active skill categorization and explicit scope authorization.
- **Action Budgets**: `ActionBudget` enforces `max_actions` (default `50`) and `max_http_writes` (default `10`) per session, halting autonomous execution into a `blocked` state for operator review when reached.

### 3. Secret Scrubbing in Subprocesses & Outputs (ASI08)
- `redact_secrets()` masks Google, OpenAI, Anthropic, query-string keys, and Bearer tokens before responses leave `LLMClient`.
- `LocalSandbox.build_scrubbed_env()` strips cloud (`AWS_*`, `AZURE_*`, `GCP_*`, `E2B_*`, `MODAL_*`) and LLM API credentials before launching skill or tool subprocesses.

### 4. Continuous Regression Verification
Security controls are verified in automated regression tests and the built-in evaluation suite:
```bash
python tools/eval_harness.py
python -m pytest evals/ tests/test_agent_security.py -v
```
