# Moros

<div align="center">

<img src="dashboard/static/logo.png" alt="Moros Logo" width="160" style="border-radius: 12px; border: 1px solid rgba(2, 119, 255, 0.4);">

### Modular Offensive Security & Web Penetration Testing Framework

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)](tests/)
[![SARIF 2.1.0](https://img.shields.io/badge/SARIF-2.1.0-orange.svg)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
[![CVSS v3.1](https://img.shields.io/badge/CVSS-v3.1-red.svg)](https://www.first.org/cvss/v3.1/)

</div>

---

## Overview

**Moros** is a modular offensive security framework engineered for authorized black-box web penetration testing, attack surface mapping, and vulnerability assessment. 

Traditional DAST scanners frequently spray indiscriminate payload lists at web targets, resulting in IP bans from Web Application Firewalls (WAFs), excessive log noise, and high false-positive rates. Moros replaces generic scanning with an evidence-driven, methodology-oriented architecture:

- **Target Profiling & WAF Evasion**: Automatically fingerprints upstream WAFs (Cloudflare, AWS WAF, Akamai, Imperva, ModSecurity, F5 BIG-IP) and backend stacks (Spring Boot, Django, Laravel, Express, Next.js, WordPress, GraphQL), dynamically throttling concurrency and selecting tailored attack vectors.
- **Modular Micro-Skills Suite (33 Skills)**: Decoupled security modules covering surface discovery, client-side vulnerabilities, server-side injection, authentication bypasses, race conditions, and business logic flaws.
- **Enforceable Human-in-the-Loop (HITL) Checkpoints**: Deterministic thread-blocking approval gates pause execution before any state-changing HTTP request (`POST`, `PUT`, `DELETE`, password resets, race audits) until explicitly confirmed by the operator.
- **Resilient HTTP & LLM Failover**: Supports scoped HTTP/HTTPS/SOCKS5 proxy routing (`--proxy`), idempotent `GET`/`HEAD` retry backoff, optional session cookie jars, complexity-based model routing (`--smart-route`), and automatic cross-provider LLM failover.
- **Scan Resumability & Sandboxed Execution**: Resumes interrupted runs cleanly from durable state (`--resume`) and isolates custom skill scripts inside scrubbed local or Docker sandboxes (`--sandbox`).
- **Cryptographic False-Positive Suppression**: Automatically hashes attack responses (`status:length:body_snippet`) against a local false-positive database (`memory/FALSE_POSITIVE_DB.md`) to eliminate repetitive alerts.
- **Deterministic Exploit Validation (`tools/exploit_validator.py`)**: Reproduces candidate findings safely within `ScopedHttpClient` and `CheckpointManager` HITL gates, writing sanitized request/response proof bundles (`output/evidence/validation/`) with SHA-256 provenance entries in `output/evidence/ledger.jsonl`.
- **Correlated Attack Chain Engine (`tools/attack_chain.py`, `tools/attack_graph.py`)**: Links assets, endpoints, identities, trust boundaries, and findings via explicit technical signals, distinguishing `verified` vs `inferred` transitions and scoring paths independently of finding severity.
- **Controlled Remediation & Retesting (`tools/remediation_assistant.py`, `tools/retest_engine.py`)**: Generates minimal single-file unified diffs tested inside isolated sandboxes/worktrees (`approval_status: "pending_approval"`), then verifies fixes with before/after comparison, regression checks, and preserved historical evidence.
- **Standardized Outputs, CI Gate & Standalone PoCs**: Confirmed and validated findings are scored with FIRST CVSS v3.1 metrics, exported to OASIS SARIF 2.1.0, evaluated by [`tools/ci_gate.py`](tools/ci_gate.py) / [`.github/actions/moros-scan/action.yml`](.github/actions/moros-scan/action.yml), and accompanied by reproducible Bash/cURL and Python scripts.
- **Interactive Operations Dashboard**: Local web interface with optional TLS/HTTPS, Bearer token auth, live SSE event streams, visual attack graphs, cost/trace/memory panels, scheduling, and checkpoint management.

---

## Architecture

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                       MOROS ORCHESTRATOR & RUNTIME                          │
│   • Scope Boundary Guard                  • Run Lifecycle Manager           │
│   • Target & WAF Fingerprinting           • Blocking HITL Approval Gate     │
└───────────────────────┬──────────────────────────────┬──────────────────────┘
                        │                              │
         ┌──────────────▼──────────────┐ ┌─────────────▼─────────────┐
         │     SKILL REGISTRY (33)     │ │     REACT TOOL ENGINE     │
         │  • Recon & AST Parsers      │ │  • Scoped HTTP Client     │
         │  • Client-Side Audits       │ │  • Headless Browser (JS)  │
         │  • Injections (SQL/SSRF/XXE)│ │  • Execution Timeouts     │
         │  • Auth & Logic Flaws       │ │  • Multi-Provider LLM     │
         └──────────────┬──────────────┘ └─────────────┬─────────────┘
                        │                              │
                        └──────────────┬───────────────┘
                                       ▼
                       targets/<target>/output/
                       ├── runs/<run_id>/ (run.json, events.jsonl, agents.jsonl)
                       ├── logs/checkpoints.json (durable HITL gate records)
                       ├── pocs/ (standalone poc_<sanitized_title>_<hash>.sh and .py scripts)
                       └── report/
                           ├── findings.sarif (OASIS SARIF 2.1.0)
                           ├── attack-graph.json (includes embedded Mermaid graph)
                           └── hackbot-report-<target>-<date>.md
```

---

## Security Skills Suite

Moros includes 33 built-in security micro-skills under `skills/` organized by operational category:

| Category | Skill Identifier | Description |
|:---|:---|:---|
| **Reconnaissance & Surface Mapping** | `recon-subdomain` | Multi-source passive DNS and Certificate Transparency enumeration |
| | `deep-recon` | Parallel fan-out reconnaissance across CT logs, Wayback, WAF, and tech profiling |
| | `subdomain-takeover` | Dangling DNS CNAME checks against unclaimed cloud service fingerprints |
| | `api-spec-discovery` | OpenAPI/Swagger, GraphQL, and Postman endpoint collection |
| | `js-discover` | Headless browser discovery of scripts and dynamic script imports |
| | `js-analyze` | AST parameter extraction, endpoint mining, and gadget mapping |
| | `content-discovery` | Bounded, safe directory and route enumeration |
| **Server-Side Injection** | `sqli-heuristic` | Non-destructive error-based and boolean SQL injection testing |
| | `ssti-detect` | Server-Side Template Injection mathematical probe evaluator |
| | `xxe-detect` | XML External Entity parsing and out-of-band resolution testing |
| | `ssrf-identify` | Server-Side Request Forgery entry-point identification |
| | `ssrf-post-exploit` | Cloud metadata and internal service pivot verification |
| | `crlf-injection` | HTTP response splitting and header injection testing |
| | `http-smuggling` | CL.TE and TE.CL HTTP request desynchronization probes |
| | `path-traversal` | Local File Inclusion and directory traversal verification |
| **Client-Side & DOM Vulnerabilities** | `xss-reflected` | Reflected Cross-Site Scripting canary injection and context analysis |
| | `xss-dom` | Headless browser taint analysis from source to dangerous sinks |
| | `xss-stored` | Stored XSS candidate submission and retrieval tracking |
| | `xss-blind` | Out-of-band blind XSS canary callback monitoring |
| | `cors-audit` | Origin reflection, null origin, and wildcard credential analysis |
| | `open-redirect` | Unvalidated redirect parameter tampering and filter bypasses |
| | `prototype-pollution` | Object prototype tampering via URL query and JSON body injection |
| | `websocket-audit` | CSWSH and unauthenticated WebSocket handshake testing |
| **Authentication & Access Control** | `idor-audit` | Insecure Direct Object Reference (BOLA) and parameter tampering |
| | `jwt-analysis` | Token structure analysis, `alg: none`, and weak signing key checks |
| | `auth-password-reset-bruteforce` | Password reset rate-limiting and token entropy testing |
| | `idp-race-condition` | Concurrent HTTP request desynchronization and token reuse testing |
| | `rate-limit-test` | Anti-automation and credential stuffing defense verification |
| | `host-header-injection` | Host & X-Forwarded-Host header cache poisoning checks |
| | `graphql-audit` | Introspection query discovery, batching, and query depth checks |
| | `business-logic` | Multi-step state machine flaw and workflow sequence analysis |
| **Verification & Reporting** | `review-skill` | Automated checklist verification, artifact checks, and retry management |
| | `report-conglomeration` | Unified markdown report generation, CVSS scoring, and SARIF export |

> **Note:** Source map extraction (`tools/sourcemap-hunter.py`) and JavaScript secret scanning (`tools/secret-scanner.py`) are standalone utility scripts in `tools/` invoked during JS discovery/analysis rather than `skills/*/run.py` skill directories.

---

## Installation

### Prerequisites
- Python 3.10 or higher
- Git

### Setup

```bash
# 1. Clone the repository
git clone https://github.com/V7-Awad/Moros-Ai-Agent.git
cd Moros-Ai-Agent

# 2. Create and activate a virtual environment
python -m venv venv

# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Install Playwright browser binaries (for headless JS crawling)
playwright install chromium
```

### Model Configuration

An available LLM provider is required for active scans and agent actions. The CLI and orchestrator verify that the configured model responds before making requests to a target. Dashboard scans also require a successful connection test in Settings. If the model is unavailable during an agent action, the action stops; deterministic offline fallback execution is disabled.

Copy `.env.example` to `.env` and configure a provider:

```bash
cp .env.example .env
```

Supported backends:
- **Cloud Providers**: DeepSeek (`DEEPSEEK_API_KEY`), OpenAI (`OPENAI_API_KEY`), Anthropic (`ANTHROPIC_API_KEY`), Groq (`GROQ_API_KEY`), Google Gemini (`GEMINI_API_KEY`), OpenRouter (`OPENROUTER_API_KEY`), Mistral (`MISTRAL_API_KEY`), xAI (`XAI_API_KEY`), Together, Cerebras, SambaNova, Fireworks, Perplexity, and Cohere.
- **Local Self-Hosted**: Ollama (`http://localhost:11434`), LM Studio, or vLLM (`http://localhost:1234/v1`).

### Docker & Compose (Optional)

Run the dashboard or CLI scanner inside non-root containers using [Dockerfile](Dockerfile) and [docker-compose.yml](docker-compose.yml):

```bash
# Start web operations dashboard (bound to 127.0.0.1:8080)
docker compose up -d dashboard

# Run a dry-run CLI scan with local target mount
docker compose --profile cli run --rm scanner --target app.example.com --dry-run
```

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for TLS/HTTPS setup, HITL blocking configuration, and container build options.

---

## Quick Start

### 1. Initialize Target Workspace
Every target assessment maintains its own isolated workspace under `targets/<domain>/`:

```bash
python setup.py init-target --domain app.example.com
```

This initializes the directory structure along with default `scope.json` and `scope-of-work.md` policy templates.

### 2. Verify Prerequisites
Run the pre-flight verification check:

```bash
python run.py --check
```

### 3. Launch Assessment

```bash
# Quick mode: Surface recon, JS discovery, and initial vulnerability checks
python run.py --target app.example.com --scan-mode quick

# Full / Deep mode (default): Full 33-skill audit suite with concurrent execution
python run.py --target app.example.com --scan-mode full --parallel

# Passive mode: Zero active HTTP probes (OSINT, cert logs, and Wayback only)
python run.py --target app.example.com --scan-mode passive

# Specific skills only:
python run.py --target app.example.com --skills recon-subdomain,js-discover,js-analyze

# Dry-run execution plan:
python run.py --target app.example.com --dry-run
```

---

## Command-Line Reference

| Flag | Argument | Description |
|:---|:---|:---|
| `--target` | `<domain>` | Target domain to assess (required for scan execution) |
| `--target-dir` | `<path>` | Custom target directory (default: `targets/<domain>`) |
| `--scan-mode` | `quick \| deep \| full \| passive` | Assessment depth profile (default: `full`) |
| `--skills` | `all \| <s1,s2,...>` | Comma-separated list of skills to run (default: `all`) |
| `--deep-recon` | | Include parallel `deep-recon` fan-out skill in scan |
| `--parallel` | | Run independent skills concurrently via `ThreadPoolExecutor` (up to 4 workers) |
| `--max-subagents` | `<int>` | Maximum autonomous child subagents cap (default: `10`; forwarded to orchestrator and enforced at runtime) |
| `--sandbox` | `none \| local \| docker` | Execution sandbox mode for custom skills (default: `local`) |
| `--models` | `<m1,m2,...>` | Comma-separated model names (default: `default`) |
| `--runs-per-skill` | `<int>` | Number of runs per skill per model (default: `1`) |
| `--review-model` | `<model>` | Model to use for `review-skill` (default: same as skill model) |
| `--provider` | `<name>` | LLM provider override (`deepseek`, `openai`, `anthropic`, `groq`, `gemini`, etc.) |
| `--api-key` | `<key>` | API key for the selected provider |
| `--model` | `<name>` | Model name override for the selected provider |
| `--smart-route` | | Enable complexity-based cost-aware model routing |
| `--no-failover` | | Disable cross-provider LLM failover (sets `MOROS_LLM_FAILOVER=0`) |
| `--budget` | `<float>` | Maximum LLM spend budget in USD (default: `10.0`) |
| `--api-spec` | `<path>` | Local OpenAPI/Swagger JSON or YAML file for `api-spec-discovery` |
| `--active-host-limit` | `<int>` | Maximum hosts for recon HEAD checks (default: `100`) |
| `--root-only-active` | | Limit active recon checks to the exact target hostname |
| `--https-only` | | Do not fall back to plaintext HTTP during active recon |
| `--max-http-requests` | `<int>` | Maximum same-host GET/HEAD requests per scan (default: `150`) |
| `--request-delay` | `<float>` | Minimum seconds between target requests (default: `0.3`) |
| `--proxy` | `<url>` | HTTP/HTTPS/SOCKS5 proxy URL for scoped target requests (sets `MOROS_PROXY`) |
| `--resume` | `[run_id]` | Resume the latest (or specified) incomplete scan run ID |
| `--validate` | | Enable deterministic Phase 1 candidate validation before report assembly |
| `--remediate` | `<finding_id>` | Generate and sandbox-test a minimal remediation patch for `FINDING_ID` (no auto-commit) |
| `--repo-dir` | `<path>` | Authorized source repository root for `--remediate` (default: project root) |
| `--retest` | `<finding_id>` | Run deterministic Phase 4 retest verification for `FINDING_ID` |
| `--ci-gate` | | Evaluate CI/CD policy gate against target artifacts (`tools/ci_gate.py`) |
| `--min-severity` | `info \| low \| medium \| high \| critical` | Minimum severity threshold for `--ci-gate` (default: `high`) |
| `--fail-on-confirmed` | `[true \| false]` | Fail `--ci-gate` (exit `2`) when confirmed/validated findings meet thresholds |
| `--pr-summary-out` | `<path>` | Write secret-redacted Markdown PR summary from `--ci-gate` to `PATH` |
| `--fail-on-candidate` | | Exit with code `2` when unverified candidate findings are present (CI gate) |
| `--mcp-server` | `<cmd_or_url>` | External MCP tool server URL (HTTP/SSE) or stdio command (repeatable) |
| `--no-trace` | | Disable OpenTelemetry trace export under `output/traces/` |
| `--lang` | `en \| ar` | Report output language (`ar` generates an Arabic bilingual sidecar) |
| `--dialect` | `msa \| egyptian` | Arabic report tone when `--lang ar` is enabled |
| `--cookie-b` | `<string>` | Secondary session cookie for dual-auth IDOR/BOLA comparison |
| `--auth-header-b` | `<string>` | Secondary Authorization header for dual-auth IDOR/BOLA comparison |
| `--oob-url` | `<url>` | External OOB/Interactsh callback URL for blind vulnerability checks |
| `--oob-listen` | | Start local loopback OOB HTTP callback listener during scan |
| `--schedule` | `<spec>` | Register recurring scan (`interval:3600` or `cron:0 2 * * *`) and exit |
| `--list-schedules` | | List saved scan schedules for `--target` and exit |
| `--proposals` | `list \| generate` | List or generate Trace2Skill proposals for `--target` and exit |
| `--approve-proposal` | `<id>` | Approve and activate a pending skill proposal ID |
| `--cookie` | `<string>` | Session cookie string for authenticated testing |
| `--auth-header` | `<string>` | Custom Authorization header (e.g. `Authorization: Bearer <token>`) |
| `--auth-file` | `<path>` | Path to JSON file containing cookies and headers |
| `--in-scope` | `<patterns>` | Comma-separated allowed host patterns (e.g. `*.example.com`) |
| `--out-of-scope` | `<patterns>` | Comma-separated forbidden host patterns |
| `--bug-bounty-id` | `<id>` | Identifier sent in `X-Bug-Bounty` HTTP request header |
| `--dashboard`, `view` | | Launch the local web operations dashboard |
| `--port` | `<int>` | Web dashboard port (default: `8080`) |
| `--no-open` | | Do not open a browser when launching the dashboard |
| `--verbose`, `-v` | | Enable verbose debug logging |
| `--quiet`, `-q` | | Suppress informational logs, output errors and results only |
| `--log-level` | `DEBUG \| INFO \| WARNING \| ERROR` | Set logging verbosity (default: `INFO`) |
| `--check` | | Check system prerequisites and exit |
| `--list-skills` | | List all installed and custom skills and exit |
| `--dry-run` | | Print execution plan without sending network requests |

---

## Authenticated Testing

Moros supports authenticated scanning across all HTTP modules and headless browser sessions:

```bash
# 1. Via session cookie
python run.py --target app.example.com --cookie "session_id=s%3A98765; role=admin"

# 2. Via Bearer token / custom header
python run.py --target api.example.com --auth-header "Authorization: Bearer eyJhbGciOi..."

# 3. Via auth profile JSON
python run.py --target app.example.com --auth-file "targets/app.example.com/auth.json"
```

Example `auth.json`:
```json
{
  "headers": {
    "Authorization": "Bearer eyJhbGciOi...",
    "X-Tenant-ID": "corp-tenant-01"
  },
  "cookies": {
    "session_id": "993a4b12cf",
    "jwt_token": "eyJ..."
  }
}
```

---

## Scope & Compliance Enforcement

Boundary validation is enforced at runtime by `ScopeValidator`:

1. **CLI Scope Bounds**: Define explicit scope boundaries via `--in-scope` and `--out-of-scope`.
2. **Target Scope Manifest**: Configured per-target in `targets/<target>/scope.json`.
3. **Signed Scope-of-Work Verification**: `verify_scope()` requires a readable `scope-of-work.*` file (`.md`, `.txt`, `.yaml`, `.yml`, or `.json`; `.pdf` is not parsed) in the target directory naming the target domain and authorization wording before active attack skills can execute. If missing, the framework automatically downgrades execution to passive discovery mode.

```bash
python run.py --target example.com \
  --in-scope "*.example.com,example.com" \
  --out-of-scope "checkout.example.com,payment.example.com" \
  --bug-bounty-id "security-audit-team"
```

---

## Web Operations Dashboard

Moros includes a local web-based operations console for monitoring scans, reviewing checkpoints, and visualizing attack paths:

```bash
# Start dashboard on http://127.0.0.1:8080
python run.py --dashboard

# Or via the standalone launcher with TLS/HTTPS enabled:
python dashboard.py --port 8443 --ssl-cert server.crt --ssl-key server.key
```

### Dashboard Features
- **Operations Console**: Real-time target selection, scope verification status, and one-click assessment launcher.
- **HITL Checkpoints Manager**: Live queue of pending state-changing requests with one-click Approve and Reject actions.
- **Attack Graph & Chain Visualizer**: Interactive graph and attack-chain view (`/api/targets/{t}/attack-graph`) distinguishing verified vs inferred paths across assets, endpoints, identities, and findings.
- **Live Event Stream**: Server-Sent Events (SSE) streaming real-time tool logs and scan progress.
- **Vulnerability Inspector & Lifecycle Actions**: Structured finding cards with lifecycle badges (`candidate`, `confirmed`, `validated`, `inconclusive`, `false_positive`, `fixed`, `accepted_risk`), CVSS v3.1 breakdowns, and `/validate`, `/remediate`, and `/retest` actions.
- **Observability & Automation**: Interactive panels for LLM spend/tokens, trace spans, tiered memory, recurring schedules, and learned skill proposal approval/disable/rollback controls.
- **Hardened API Controls**: Bearer token auth (`MOROS_DASHBOARD_TOKEN`), same-origin CSRF checks on mutations, and configurable `/api/` rate limiting.

### Further Documentation
- [Architecture & Operations Guide](docs/architecture.md)
- [Phases 1–6 Implementation Design](docs/ROADMAP_IMPLEMENTATION_DESIGN.md)
- [Controlled-Lab Lifecycle Example Report](docs/EXAMPLE_LIFECYCLE_REPORT.md)
- [Dashboard & A2A API Reference](docs/API_REFERENCE.md)
- [Deployment & Hardening Guide](docs/DEPLOYMENT.md)
- [OWASP Agentic Security Control Matrix](docs/OWASP_AGENTIC_SECURITY.md)
- [Phase 0 Audit & Baseline Report](docs/ROADMAP_AUDIT.md)
- [PDF Operator Guide](docs/MOROS_AI_OPERATOR_GUIDE.pdf)

---

## Automated Proof-of-Concept (PoC) Scripts

For discovered findings, `PoCGenerator` creates standalone, dependency-free reproduction scripts under `targets/<target>/output/pocs/`:

1. **Bash / cURL Script (`poc_<sanitized_title>_<hash>.sh`)**: Ready-to-execute cURL command with exact headers, parameters, and target URL.
2. **Python Script (`poc_<sanitized_title>_<hash>.py`)**: Self-contained Python script using standard libraries to replay the request and inspect the response.

```bash
# Execute standalone PoC
bash targets/app.example.com/output/pocs/poc_reflected_xss_a1b2c3d4.sh
python targets/app.example.com/output/pocs/poc_idor_profile_read_9f8e7d6c.py
```

---

## SARIF 2.1.0 & CI/CD Pipeline Integration

Findings are automatically formatted into OASIS SARIF 2.1.0 (`findings.sarif`) with complete CVSS scores, CWE taxons, lifecycle verification metadata, and code/endpoint locations. Use [`tools/ci_gate.py`](tools/ci_gate.py) and the composite GitHub Action [`.github/actions/moros-scan/action.yml`](.github/actions/moros-scan/action.yml) to enforce scope-guarded security gates and upload SARIF to GitHub Code Scanning.

### GitHub Actions Example (Composite Action)

See [`.github/workflows/moros-dast-example.yml`](.github/workflows/moros-dast-example.yml) and [`.github/workflows/moros-retest-example.yml`](.github/workflows/moros-retest-example.yml) for full SHA-pinned workflows with fork-PR guards and PR summary comments:

```yaml
- name: Run Moros AI Scan & CI Gate
  uses: ./.github/actions/moros-scan
  with:
    target: app.example.com
    scan-mode: quick
    budget: "3.0"
    min-severity: high
    fail-on-candidate: "false"
    fail-on-confirmed: "true"
    upload-sarif: "true"
```

---

## Custom Skill Development

Moros is designed for modular extensibility. New security skills can be added without modifying the core orchestrator:

1. Create a directory: `skills/<skill-id>/`
2. Add a `SKILL.md` specification file:
   ```markdown
   # Custom Header Injection Hunter (`custom-header-hunter`)

   **Category:** Server-Side Injection

   ## Description
   Audits custom reverse-proxy headers for IP spoofing and ACL bypasses.

   ## Verification Checklist
   - [ ] Step 1: Probe endpoints with X-Forwarded-For and X-Real-IP headers
     - Expected artifact: `targets/<target>/output/custom-headers.json`
     - Log file: `targets/<target>/output/logs/custom-headers.log`
   ```
3. (Optional) Provide a `run.py` executable accepting `--target`, `--target-dir`, and `--output-dir`.
4. Verify auto-discovery:
   ```bash
   python run.py --list-skills
   ```

---

## Automated Testing

The repository includes automated offline test suites across `tests/`, `evals/`, and GitHub Actions CI ([.github/workflows/ci.yml](.github/workflows/ci.yml)). Phase 0 baseline verification recorded **361 passing tests** across `tests/` and `evals/`, **19/19** passing checks in `tools/eval_harness.py`, and **14/14** accurate cases in `evals/juice_shop_benchmark.py --json`, expanded with dedicated unit and end-to-end test suites for Phases 1–6 (`test_exploit_validator.py`, `test_attack_chain.py`, `test_remediation_assistant.py`, `test_retest_engine.py`, `test_ci_gate.py`, `test_dashboard_roadmap_apis.py`, and `test_roadmap_e2e.py`):

```bash
# Run the full unit, integration, security, and local E2E test suite
python -m pytest tests/ -q

# Run the offline Juice Shop benchmark evaluation
python evals/juice_shop_benchmark.py --json
```

Coverage includes:
- Scope boundary validation, HITL checkpoint gating, prompt injection scrubbing, and secret redaction
- Deterministic exploit validation, SHA-256 evidence ledger provenance, correlated attack chains, isolated sandbox remediation, and post-fix retesting
- HTTP proxy routing, safe `GET`/`HEAD` backoff retries, cookie jar persistence, and cross-provider LLM failover
- Scan resumability, sandbox isolation (`LocalSandbox` / `DockerSandbox`), `business-logic` runner, and end-to-end local mock target lifecycle testing
- Dashboard TLS/HTTPS, CSRF origin enforcement, rate limiting, REST/SSE/A2A endpoints, CI gate evaluation, and DevOps config checks

---

## Legal & Compliance Notice

> **IMPORTANT**: Moros is designed strictly for authorized penetration testing, vulnerability assessments under formal contracts or signed rules of engagement, and approved bug bounty programs.
>
> Executing offensive security scans against target infrastructure without prior explicit written authorization from the system owner is illegal under computer misuse legislation (including the US CFAA, UK Computer Misuse Act, and equivalent international laws). Operators are solely responsible for ensuring all testing activities remain within permitted scope and legal boundaries.

---

## License

This project is licensed under the [MIT License](LICENSE).
