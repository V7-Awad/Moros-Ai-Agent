# Moros AI Dashboard — REST API Reference

This document describes the HTTP REST, Server-Sent Events (SSE), and A2A JSON-RPC endpoints implemented in [`dashboard/server.py`](../dashboard/server.py).

> **Note on MCP (Model Context Protocol):** `dashboard/server.py` does **not** expose `/api/mcp/*` HTTP endpoints. Moros integrates with external MCP servers client-side via [`tools/mcp_client.py`](../tools/mcp_client.py) (`StdioTransport` / `HttpTransport` / `MCPClient.load_from_config`) and the `--mcp-server` CLI flag in [`run.py`](../run.py).

---

## Base URL & Transport

- **Default Local URL:** `http://127.0.0.1:8080`
- **TLS / HTTPS:** Enabled when both `--ssl-cert` / `MOROS_DASHBOARD_SSL_CERT` and `--ssl-key` / `MOROS_DASHBOARD_SSL_KEY` are supplied (`https://<host>:<port>`).
- **Content Type:** JSON endpoints accept and return `application/json; charset=utf-8` (with `X-Content-Type-Options: nosniff` and `Cache-Control: no-store`).
- **Payload Size Limit:** `POST` request bodies are capped at `1,000,000` bytes (`413` on overflow) and must decode to a JSON object (`400` otherwise).

---

## Authentication, CSRF Protection & Rate Limiting

### 1. Token Authentication (`/api/*`)

- **Loopback bind (`127.0.0.1`, `localhost`, `::1`):** Authentication is optional unless `MOROS_DASHBOARD_TOKEN` is set in the environment.
- **Non-loopback bind (e.g., `0.0.0.0`):** Authentication is **always required** on `/api/*` routes. If `MOROS_DASHBOARD_TOKEN` is unset, `run_dashboard()` auto-generates a 32-byte URL-safe runtime token and prints it to stdout at startup.
- **Accepted Headers:**
  - `Authorization: Bearer <token>`
  - `X-Moros-Token: <token>`
- **Failure Response (`401 Unauthorized`):**
  ```json
  {
    "error": "Unauthorized: valid dashboard token required",
    "status": "error"
  }
  ```

Static UI assets (`/`, `/index.html`, etc.) remain readable without a token so the browser can prompt for credentials.

### 2. Host & Cross-Origin / CSRF Protection

- **Host Restriction:** When bound locally (`allow_remote=False`), requests with a non-loopback `Host` header are rejected with `403`.
- **Origin / Referer Check (`POST`, `PUT`, `DELETE`, plus `Origin` on `GET`):**
  - If `Origin` is present (or `Referer` when `Origin` is absent on `POST`/`PUT`/`DELETE`), its hostname and port must match the request's `Host` header (or loopback equivalents `127.0.0.1`, `localhost`, `::1` on the same port).
  - Mismatched cross-site origins (including `Origin: null`) are rejected with `403 Forbidden`:
    ```json
    {
      "error": "Cross-origin request blocked",
      "status": "error"
    }
    ```
  - Headerless API clients (such as `curl`, automation scripts, or unit tests omitting `Origin` and `Referer`) pass through directly to standard token authentication.
- **`OPTIONS` / `PUT` / `DELETE`:** `OPTIONS` returns `405` (`"Cross-origin requests are not supported"`). `PUT` and `DELETE` pass through CSRF, host, rate-limit, and auth checks and currently return `405` (`"Method not allowed"`).

### 3. Rate Limiting (`/api/*`)

- Per-client IP sliding-window limiter (`60`-second window).
- **Default Limit:** `600` requests/minute (`DEFAULT_RATE_LIMIT_RPM = 600`).
- **Configuration:** Set via `MOROS_DASHBOARD_RATE_LIMIT`, CLI `--rate-limit`, or `httpd.rate_limit_rpm` (`<= 0` disables rate limiting).
- **Exceeded Response (`429 Too Many Requests`):** Includes `Retry-After: <seconds>` response header and JSON body:
  ```json
  {
    "error": "Rate limit exceeded: too many requests",
    "status": "error"
  }
  ```

---

## Endpoints Summary

| Method | Path | Category | Description |
|:---|:---|:---|:---|
| `GET` | `/` / `/{asset}` | Static UI | Serves `dashboard/static/` assets with path containment and SPA fallback to `index.html` |
| `GET` | `/.well-known/agent.json` | A2A | Returns A2A AgentCard metadata |
| `POST` | `/api/a2a` | A2A | JSON-RPC 2.0 task dispatcher (`tasks/send`, `tasks/get`, `tasks/cancel`) |
| `GET` | `/api/system` | System | Runtime health, Python version, Playwright availability, active scan/target/skill counts |
| `GET` | `/api/skills` | Skills | Lists all discovered core and custom skills |
| `POST` | `/api/skills/create` | Skills | Registers a new custom skill under `skills/` |
| `POST` | `/api/skills/delete` | Skills | Deletes a custom skill (core skills protected) |
| `GET` | `/api/security/posture` | Security | OWASP Agentic AI Top 10 control coverage matrix |
| `GET` | `/api/targets` | Targets | Lists all target workspaces under `targets/` with finding severity summaries |
| `POST` | `/api/targets/create` | Targets | Initializes a new target workspace |
| `GET` | `/api/targets/{target}` | Targets | Target summary (alias for `/summary`) |
| `GET` | `/api/targets/{target}/summary` | Targets | Target summary metrics, tech fingerprint, and scan state |
| `GET` | `/api/targets/{target}/skills` | Targets | Per-skill execution state, review status, and log file counts for latest run |
| `GET` | `/api/targets/{target}/findings` | Targets | Deduplicated findings, JS secrets, and DOM XSS sink candidates |
| `GET` | `/api/targets/{target}/endpoints` | Targets | Discovered JS and OpenAPI endpoints inventory |
| `GET` | `/api/targets/{target}/tech` | Targets | Technology fingerprint JSON (`tech-fingerprint.json`) |
| `GET` | `/api/targets/{target}/logs` | Targets | Lists `.log` files or reads `?file=<relpath>` securely |
| `GET` | `/api/targets/{target}/checkpoints` | Checkpoints | Lists HITL checkpoints for target |
| `POST` | `/api/checkpoints/action` | Checkpoints | Approves or rejects a HITL checkpoint |
| `GET` | `/api/targets/{target}/runs` | Runs | Lists durable runs for target |
| `GET` | `/api/targets/{target}/runs/{run_id}` | Runs | Retrieves metadata for a specific run |
| `GET` | `/api/targets/{target}/runs/{run_id}/agents` | Runs | Lists child agent sessions recorded for a run |
| `GET` | `/api/runs/active` | Runs | Lists all runs with `status == "running"` across all targets |
| `GET` | `/api/targets/{target}/conversations` | Chat | Reads target/agent conversation transcript and subagent roster |
| `POST` | `/api/conversations/chat` | Chat | Sends interactive prompt/directive to coordinator or specialist agent |
| `GET` | `/api/targets/{target}/report` | Reports | Latest markdown & JSON report with stale-snapshot detection |
| `GET` | `/api/targets/{target}/sarif` | Reports | OASIS SARIF 2.1.0 export |
| `GET` | `/api/targets/{target}/costs` | Observability | LLM spend receipt and per-call cost log |
| `GET` | `/api/targets/{target}/traces` | Observability | Up to 10 most recent OpenTelemetry trace span files |
| `GET` | `/api/targets/{target}/memory` | Observability | Target `MemoryManager` stats, facts, techniques, and recent events |
| `GET` | `/api/targets/{target}/schedules` | Automation | Lists configured scan schedules for target |
| `GET` | `/api/targets/{target}/skill-proposals` | Learning | Lists drafted self-improving skill proposals for target |
| `POST` | `/api/scan/start` | Scans | Launches background `run.py` scan job |
| `POST` | `/api/scan/stop` | Scans | Terminates active scan subprocess for target |
| `GET` | `/api/scan/status` | Scans | Polls in-memory scan status and buffered console logs |
| `GET` | `/api/scan/stream` | Scans (SSE) | `text/event-stream` live scan progress & run event stream |
| `GET` | `/api/config/llm` | Config | Current LLM provider/model and connection state (secrets redacted) |
| `POST` | `/api/config/llm` | Config | Saves LLM settings to `.env` and `os.environ` |
| `POST` | `/api/config/llm/test` | Config | Tests LLM connectivity with a `PONG` probe |
| `GET` | `/api/config/notifications` | Config | Returns boolean status for Discord, Telegram, and Slack alerts |
| `POST` | `/api/config/notifications` | Config | Saves or clears alert webhook/bot credentials in `.env` and `os.environ` |
| `GET` | `/api/learning/stats` | Learning | Distills and returns cross-run learning statistics and FP patterns |
| `GET` | `/api/learning/recall` | Learning | Searches recalled lessons and findings (`?q=...&limit=...`) |
| `GET` | `/api/learning/graph` | Learning | Exports learning engine knowledge graph |
| `POST` | `/api/learning/finding` | Learning | Records a finding in `LearningEngine` |
| `POST` | `/api/learning/triage` | Learning | Records a human triage verdict in `LearningEngine` |
| `POST` | `/api/learning/score` | Learning | Scores signal dictionaries via `learning_engine.scoring.engine.score()` |

---

## Detailed Endpoint Reference

### System, Skills & Security Posture

#### `GET /api/system`
Returns dashboard environment status.
- **Response (`200`):**
  ```json
  {
    "name": "Moros AI Agent Dashboard",
    "version": "1.0.0",
    "python_version": "3.11.x ...",
    "playwright_installed": true,
    "active_scans_count": 0,
    "targets_count": 2,
    "all_skills_count": 33
  }
  ```

#### `GET /api/skills`
Returns metadata array for all skills discovered under `skills/`.

#### `POST /api/skills/create`
Creates a custom skill directory, `SKILL.md`, and `manifest.json`.
- **Request Body:**
  ```json
  {
    "id": "custom-header-audit",
    "title": "Custom Header Audit",
    "description": "Checks reverse-proxy header handling.",
    "category": "Custom Security",
    "checklist": ["Probe X-Forwarded-Host"],
    "methodology": "Send benign header probes within scope."
  }
  ```
- **Errors:** `400` if `id`/`title` missing or skill already exists.

#### `POST /api/skills/delete`
Deletes a custom skill (`id` required). Core built-in skills cannot be deleted (`400`). Returns `404` if the skill does not exist.

#### `GET /api/security/posture`
Returns the OWASP Agentic AI Top 10 (`ASI01`–`ASI10`) control mapping from `tools/agent_security.py`.

---

### Targets & Workspace Artifacts

All `/api/targets/{target}/...` routes validate `{target}` via `setup.validate_target_name()` (`400` on invalid names) and verify `targets/{target}` exists (`404` if missing).

#### `GET /api/targets`
Lists all targets under `targets/` with scope presence, deduplicated/raw finding counts, severity breakdown (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`, `UNASSESSED`), `is_scanning`, and `created_at`.

#### `POST /api/targets/create`
Initializes a target workspace via `setup.init_target(domain)`.
- **Request Body:** `{ "domain": "example.com" }`
- **Response (`200`):** `{ "status": "success", "message": "Target example.com created", "target": "example.com" }`

#### `GET /api/targets/{target}` / `GET /api/targets/{target}/summary`
Returns target metrics (`has_scope`, `scope_file`, `total_findings`, `raw_findings_count`, `severities`, `total_endpoints`, `total_js_files`, `total_subdomains`, `tech_fingerprint`, `is_scanning`).

#### `GET /api/targets/{target}/skills`
Returns per-skill execution state for the latest run (`state`, `review_status`, `logs_count`, `log_files`, `latest_run_id`, `requested_in_latest_run`).

#### `GET /api/targets/{target}/findings`
Aggregates and deduplicates findings from `output/findings/**`, `output/js/secrets-findings.json`, and `output/js/gadgets.json`, or returns the canonical `hackbot-report-*.json` snapshot when its `source_artifact_mtimes` manifest matches current disk artifacts.

#### `GET /api/targets/{target}/endpoints`
Combines JavaScript AST endpoints (`output/js/endpoints.json`) and OpenAPI endpoints (`output/api/endpoints.json` or `openapi-endpoints.json`) with sanitized `source_file` references.

#### `GET /api/targets/{target}/tech`
Returns `output/js/tech-fingerprint.json` (or `{}` if absent).

#### `GET /api/targets/{target}/logs`
- **Query Params:** `file` (optional relative path inside `output/logs/`)
- **Response (`200`):** `{ "logs": [{"path": "...", "size": 123, "modified": "..."}], "content": "..." }` (traversal paths safely return empty `content`).

#### `GET /api/targets/{target}/runs`
Returns `{ "target": "...", "runs": [...] }` from `RunManager.list_runs()`.

#### `GET /api/targets/{target}/runs/{run_id}`
Returns the `run.json` record for `run_id` (`404` if not found).

#### `GET /api/targets/{target}/runs/{run_id}/agents`
Returns `{ "run_id": "...", "agents": [...] }` from `RunManager.list_agent_sessions(run_id)`.

#### `GET /api/runs/active`
Returns `{ "active_runs": [...] }` across all target directories where `status == "running"`.

#### `GET /api/targets/{target}/report`
Returns `{ "markdown": "...", "json": {...}, "files": [...] }`. Prepends a stale-snapshot warning banner to `markdown` if the saved report count differs from current live findings.

#### `GET /api/targets/{target}/sarif`
Returns OASIS SARIF 2.1.0 JSON from `output/report/findings.sarif` (or builds it on the fly via `tools.sarif_exporter.build_sarif_report()`).

#### `GET /api/targets/{target}/costs`
Returns `output/costs/receipt.json` if present, otherwise aggregates `output/costs/cost-log.jsonl` into `summary` (`total_cost_usd`, `total_input_tokens`, `total_output_tokens`, `total_llm_calls`) and `entries`.

#### `GET /api/targets/{target}/traces`
Returns `{ "target": "...", "traces": [{"file": "...", "spans": ...}] }` for up to the 10 newest `trace*.json` files under `output/traces/`.

#### `GET /api/targets/{target}/memory`
Returns `{ "target": "...", "stats": ..., "facts": [...], "techniques": [...], "recent_events": [...] }` via `MemoryManager`.

#### `GET /api/targets/{target}/schedules`
Returns `{ "target": "...", "schedules": [...] }` via `ScanScheduler.list_schedules()`.

#### `GET /api/targets/{target}/skill-proposals`
Returns `{ "target": "...", "proposals": [...] }` via `SkillLearner.list_proposals()`.

---

### Scans & Live SSE Stream

#### `POST /api/scan/start`
Starts a background `run.py` scan (`--https-only --max-http-requests 40 --request-delay 0.4`). Automatically initializes `targets/{target}` if missing.
- **Request Body:**
  ```json
  {
    "target": "example.com",
    "skills": "all",
    "models": "default",
    "dry_run": false,
    "scan_mode": "quick",
    "max_subagents": 10
  }
  ```
- **Response (`200`):** `{ "status": "success", "message": "...", "target": "example.com", "initialized_target": false }` (returns `{"status": "error", ...}` if already running).

#### `POST /api/scan/stop`
Terminates an active scan process for `target`.
- **Request Body:** `{ "target": "example.com" }`

#### `GET /api/scan/status`
- **Query Params:** `target`
- **Response (`200`):** `{ "status": "idle|starting|running|completed|stopped|failed|blocked_scope|error", "target": "...", "start_time": "...", "logs": "..." }`

#### `GET /api/scan/stream`
Server-Sent Events (`Content-Type: text/event-stream`) stream emitting JSON `data:` frames every `1.0` second (up to 60 iterations or until completion).
- **Query Params:** `target` (required; `400` if missing/invalid, `404` if target directory does not exist)
- **Event Payload:**
  ```json
  {
    "scan_status": { "status": "running", "target": "example.com", "logs": "..." },
    "latest_run": { "run_id": "...", "status": "running" },
    "new_events": [],
    "timestamp": "2026-11-26T12:00:00+00:00"
  }
  ```

---

### HITL Checkpoints

#### `GET /api/targets/{target}/checkpoints`
Returns array of checkpoint records from `targets/{target}/output/logs/checkpoints.json`.

#### `POST /api/checkpoints/action`
Records an approval or rejection decision and wakes any blocked worker thread via `CheckpointManager.decide(..., decider="dashboard_operator")`.
- **Request Body:**
  ```json
  {
    "target": "example.com",
    "checkpoint_id": "cp-a1b2c3d4e5f6",
    "action": "approve",
    "notes": "Verified safe test payload"
  }
  ```

---

### Interactive Agent & LLM Chat

#### `GET /api/targets/{target}/conversations`
- **Query Params:** `agent` (default `coordinator`), `limit` (default `200`, bounded `1`–`1000`)
- **Response (`200`):** `{ "target": "...", "agent": "...", "agents": [...], "roster": [...], "messages": [...] }`

#### `POST /api/conversations/chat`
Executes an interactive ReAct turn via `AgentRunner` if an LLM is configured and reachable, or falls back to deterministic workspace tools (`source: "deterministic_fallback"`).
- **Request Body:**
  ```json
  {
    "target": "example.com",
    "agent": "coordinator",
    "message": "Summarize discovered endpoints"
  }
  ```
- **Limits:** `message` must be non-empty and `<= 60000` characters.

---

### LLM & Notification Configuration

#### `GET /api/config/llm`
Returns `{ "provider", "model", "base_url", "is_available", "has_api_key", "connection_state", "model_responding", "last_error", "last_tested" }`. API keys are never returned; `last_error` is passed through `redact_secrets()`.

#### `POST /api/config/llm`
Saves LLM configuration (`provider`, `model`, `api_key`, `base_url`) to `os.environ` and `.env`. Rejects newline characters and non-`http://`/`https://` `base_url` values with `400`.

#### `POST /api/config/llm/test`
Tests LLM connectivity (`"Ping. Respond with 'PONG' only."`) and updates `llm_runtime_state`. Returns `200` on success or `400` on error/missing credentials.

#### `GET /api/config/notifications`
Returns `{ "has_discord_webhook": bool, "has_telegram": bool, "has_slack_webhook": bool }`.

#### `POST /api/config/notifications`
Saves or clears `DISCORD_WEBHOOK_URL` (`https://discord.com/api/webhooks/...`), `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID`, and `SLACK_WEBHOOK_URL` (`https://hooks.slack.com/(services|workflows|triggers)/...`) in `.env` and `os.environ`.

---

### Learning Engine

#### `GET /api/learning/stats`
Runs `LearningEngine().distill()` and returns distilled per-class counts, FP rates, lessons, and summary.

#### `GET /api/learning/recall`
- **Query Params:** `q` (search query), `limit` (integer, default `10`)
- **Response (`200`):** `{ "results": [...] }`

#### `GET /api/learning/graph`
Returns the knowledge graph (`nodes`, `edges`) from `LearningEngine().export_graph()`.

#### `POST /api/learning/finding`
Ingests a finding into `LearningEngine.record_finding(...)`.
- **Request Body:** `{ "target": "...", "vuln_class": "...", "title": "...", "severity": "medium", "confidence": 0.5, "evidence": "...", "signals": {}, "source": "dashboard" }`

#### `POST /api/learning/triage`
Ingests a triage verdict into `LearningEngine.record_triage(...)`.
- **Request Body:** `{ "finding_id": "...", "verdict": "confirmed|false_positive|unverified", "reason": "...", "reviewer": "dashboard" }`

#### `POST /api/learning/score`
Evaluates bounded signal score via `learning_engine.scoring.engine.score(body.get("signals", {}))`.

---

### Agent-to-Agent (A2A) Protocol

#### `GET /.well-known/agent.json`
Returns the A2A Agent Card (`protocolVersion`, `capabilities`, `authentication.schemes`, and registered `skills`) built with the request's `Host` and `http`/`https` scheme.

#### `POST /api/a2a`
Dispatches JSON-RPC 2.0 A2A requests (`tasks/send`, `tasks/get`, `tasks/cancel`) to `tools.a2a_server.A2ATaskHandler`. Task state is persisted to `targets/.a2a_tasks.json`, and `tasks/send` enforces `ScopeValidator` against any target referenced in `params.metadata.target` or message data parts.
