# Moros

<div align="center">

<img src="dashboard/static/logo.png" alt="Moros Logo" width="160" style="border-radius: 12px; border: 1px solid rgba(2, 119, 255, 0.4);">

### Modular Offensive Security & Web Penetration Testing Framework

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-62%20passing-brightgreen.svg)](tests/)
[![SARIF 2.1.0](https://img.shields.io/badge/SARIF-2.1.0-orange.svg)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
[![CVSS v3.1](https://img.shields.io/badge/CVSS-v3.1-red.svg)](https://www.first.org/cvss/v3.1/)

</div>

---

## Overview

**Moros** is a modular offensive security framework engineered for authorized black-box web penetration testing, attack surface mapping, and vulnerability assessment. 

Traditional DAST scanners frequently spray indiscriminate payload lists at web targets, resulting in IP bans from Web Application Firewalls (WAFs), excessive log noise, and high false-positive rates. Moros replaces generic scanning with an evidence-driven, methodology-oriented architecture:

- **Target Profiling & WAF Evasion**: Automatically fingerprints upstream WAFs (Cloudflare, AWS WAF, Akamai, Imperva, ModSecurity, F5 BIG-IP) and backend stacks (Spring Boot, Django, Laravel, Express, Next.js, WordPress, GraphQL), dynamically throttling concurrency and selecting tailored attack vectors.
- **Modular Micro-Skills Suite (32 Skills)**: A comprehensive library of decoupled security modules covering surface discovery, client-side vulnerabilities, server-side injection, authentication bypasses, race conditions, and business logic flaws.
- **Enforceable Human-in-the-Loop (HITL) Checkpoints**: Deterministic thread-blocking approval gates pause execution before any state-changing HTTP request (`POST`, `PUT`, `DELETE`, password resets, race audits) until explicitly confirmed by the operator.
- **Cryptographic False-Positive Suppression**: Automatically hashes attack responses (`status:length:body_snippet`) against a local false-positive database (`memory/FALSE_POSITIVE_DB.md`) to eliminate repetitive alerts.
- **Standardized Outputs & Standalone PoCs**: Every verified finding is mathematically scored using official FIRST CVSS v3.1 metrics, exported to OASIS SARIF 2.1.0 for CI/CD integration, and accompanied by reproducible Bash/cURL and Python reproduction scripts.
- **Interactive Operations Dashboard**: Local web interface providing live multi-agent event streams, real-time tool terminals, visual attack graphs, and one-click checkpoint management.

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
         │     SKILL REGISTRY (32)     │ │     REACT TOOL ENGINE     │
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
                       ├── pocs/ (standalone poc-*.sh and poc-*.py scripts)
                       └── report/
                           ├── findings.sarif (OASIS SARIF 2.1.0)
                           ├── attack-graph.json & attack-graph.mmd
                           └── hackbot-report-<target>-<date>.md
```

---

## Security Skills Suite

Moros includes 32 built-in security micro-skills organized by operational category:

| Category | Skill Identifier | Description |
|:---|:---|:---|
| **Reconnaissance & Surface Mapping** | `recon-subdomain` | Multi-source passive DNS and Certificate Transparency enumeration |
| | `api-spec-discovery` | OpenAPI/Swagger, GraphQL, and Postman endpoint collection |
| | `js-discover` | Headless browser discovery of scripts and dynamic script imports |
| | `js-analyze` | AST parameter extraction, endpoint mining, and gadget mapping |
| | `sourcemap-hunter` | Automated source map (.map) extraction and source reconstruction |
| | `secret-scanner` | Heuristic and entropy-based API key/token scanning in JS assets |
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

### Configuration (Optional)

Moros is fully functional out of the box with deterministic offline fallbacks. To enable optional LLM-assisted ReAct reasoning, copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

Supported backends:
- **Cloud Providers**: DeepSeek (`DEEPSEEK_API_KEY`), OpenAI (`OPENAI_API_KEY`), Anthropic (`ANTHROPIC_API_KEY`), Groq (`GROQ_API_KEY`), Google Gemini (`GEMINI_API_KEY`), OpenRouter (`OPENROUTER_API_KEY`), Mistral (`MISTRAL_API_KEY`), xAI (`XAI_API_KEY`).
- **Local Self-Hosted**: Ollama (`http://localhost:11434`), LM Studio, or vLLM (`http://localhost:1234/v1`).

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

# Deep mode: Full 32-skill audit suite with concurrent execution
python run.py --target app.example.com --scan-mode deep --parallel

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
| `--scan-mode` | `quick \| deep \| passive` | Assessment depth profile (default: `deep`) |
| `--skills` | `all \| <s1,s2,...>` | Comma-separated list of skills to run (default: `all`) |
| `--parallel` | | Run independent skills concurrently using thread pools |
| `--max-subagents` | `<int>` | Maximum concurrent workers during parallel execution (default: 10) |
| `--cookie` | `<string>` | Session cookie string for authenticated testing |
| `--auth-header` | `<string>` | Custom Authorization header (e.g. `Bearer <token>`) |
| `--auth-file` | `<path>` | Path to JSON file containing cookies and headers |
| `--in-scope` | `<patterns>` | Comma-separated allowed host patterns (e.g. `*.example.com`) |
| `--out-of-scope` | `<patterns>` | Comma-separated forbidden host patterns |
| `--bug-bounty-id` | `<id>` | Identifier sent in `X-Bug-Bounty` HTTP request header |
| `--dashboard` | | Launch the local web operations dashboard |
| `--port` | `<int>` | Web dashboard port (default: 8080) |
| `--verbose`, `-v` | | Enable verbose debug logging |
| `--quiet`, `-q` | | Suppress informational logs, output errors and results only |
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
3. **Signed Scope-of-Work Verification**: Requires a `scope-of-work.md` or `.pdf` file in the target directory before active attack skills can execute. If missing, the framework automatically downgrades execution to passive discovery mode.

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

# Or via the standalone launcher:
python dashboard.py --port 8080
```

### Dashboard Features
- **Operations Console**: Real-time target selection, scope verification status, and one-click assessment launcher.
- **HITL Checkpoints Manager**: Live queue of pending state-changing requests with one-click Approve and Reject actions.
- **Attack Graph Visualizer**: Interactive network graph showing discovered assets, endpoints, parameters, and vulnerability sinks.
- **Live Event Stream**: Server-Sent Events (SSE) streaming real-time tool logs and scan progress.
- **Vulnerability Inspector**: Structured finding cards with CVSS v3.1 vector breakdowns, CWE mappings, and linked reproduction scripts.
- **Dynamic Skills Registry**: Browse, inspect, and register custom micro-skills directly through the interface.

---

## Automated Proof-of-Concept (PoC) Scripts

For every verified vulnerability, Moros generates standalone, dependency-free reproduction scripts under `targets/<target>/output/pocs/`:

1. **Bash / cURL Script (`poc-<vuln-id>.sh`)**: Ready-to-execute cURL command with exact headers, parameters, and payloads.
2. **Python Script (`poc-<vuln-id>.py`)**: Self-contained Python script using standard libraries with automated response assertions.

```bash
# Execute standalone PoC
bash targets/app.example.com/output/pocs/poc-sqli-01.sh
python targets/app.example.com/output/pocs/poc-idor-02.py
```

---

## SARIF 2.1.0 & CI/CD Pipeline Integration

Findings are automatically formatted into OASIS SARIF 2.1.0 (`findings.sarif`) with complete CVSS scores, CWE taxons, and code locations. This enables direct integration with GitHub Code Scanning alerts, GitLab Security, and DefectDojo.

### GitHub Actions Example

```yaml
name: Moros Security Audit
on:
  push:
    branches: [main]
  schedule:
    - cron: '0 2 * * 1'

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install Dependencies
        run: |
          pip install -r requirements.txt
          playwright install chromium

      - name: Run Moros Assessment
        run: |
          python setup.py init-target --domain app.example.com
          python run.py --target app.example.com --scan-mode quick

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: targets/app.example.com/output/report/findings.sarif
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

   ## Methodology Checklist
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

The framework includes a comprehensive unit and integration test suite:

```bash
python -m pytest tests/ -v
```

```text
============================= test session starts =============================
collected 62 items (100% passing)

tests/test_advanced_features.py .........                                [ 14%]
tests/test_agent_runtime.py ....                                         [ 20%]
tests/test_checkpoint_manager.py ....                                    [ 27%]
tests/test_dependency_validation.py ...                                  [ 32%]
tests/test_dynamic_skills_and_subagents.py ....                          [ 38%]
tests/test_integration.py ....                                           [ 45%]
tests/test_learning_engine.py .                                          [ 46%]
tests/test_run_manager.py ....                                           [ 53%]
tests/test_sarif_exporter.py ...                                         [ 58%]
tests/test_scan_modes.py ....                                            [ 64%]
tests/test_skill_registry.py .....                                       [ 72%]
tests/test_subagent_chat.py ...                                          [ 77%]
tests/test_universal_llm.py .....                                        [ 85%]
tests/test_vuln_skills.py .......                                        [100%]

============================= 62 passed in 10.42s =============================
```

---

## Legal & Compliance Notice

> **IMPORTANT**: Moros is designed strictly for authorized penetration testing, vulnerability assessments under formal contracts or signed rules of engagement, and approved bug bounty programs.
>
> Executing offensive security scans against target infrastructure without prior explicit written authorization from the system owner is illegal under computer misuse legislation (including the US CFAA, UK Computer Misuse Act, and equivalent international laws). Operators are solely responsible for ensuring all testing activities remain within permitted scope and legal boundaries.

---

## License

This project is licensed under the [MIT License](LICENSE).
