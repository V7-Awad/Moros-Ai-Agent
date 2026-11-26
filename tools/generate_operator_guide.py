#!/usr/bin/env python3
"""
generate_operator_guide.py — Generates a comprehensive, publication-grade PDF
Operator Manual & Complete User Guide for Moros AI Agent.
"""

import sys
from pathlib import Path

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    print("Notice: Playwright is required to render MOROS_AI_OPERATOR_GUIDE.pdf. Install with 'pip install playwright && playwright install chromium'.")
    sys.exit(0)

PROJECT_ROOT = Path(__file__).parent.parent.resolve()
OUTPUT_PDF_DOCS = PROJECT_ROOT / "docs" / "MOROS_AI_OPERATOR_GUIDE.pdf"

HTML_CONTENT = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>MOROS AI — Complete Operator Manual & Technical Guide</title>
<style>
  @page {
    size: A4;
    margin: 18mm 16mm 20mm 16mm;
    @top-right {
      content: "MOROS AI — Operator Manual";
      font-size: 8pt;
      font-family: 'Segoe UI', system-ui, sans-serif;
      color: #64748b;
    }
    @bottom-left {
      content: "Confidential & Authorized Assessment Manual • Lead: Raider";
      font-size: 8pt;
      font-family: 'Segoe UI', system-ui, sans-serif;
      color: #94a3b8;
    }
    @bottom-right {
      content: "Page " counter(page);
      font-size: 8pt;
      font-family: 'Segoe UI', system-ui, sans-serif;
      font-weight: 600;
      color: #0284c7;
    }
  }

  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    font-size: 9.5pt;
    line-height: 1.55;
    color: #1e293b;
    background: #ffffff;
    margin: 0;
    padding: 0;
  }

  /* Cover Page */
  .cover {
    page-break-after: always;
    height: 100%;
    display: flex;
    flex-direction: column;
    justify-content: center;
    padding: 40px 20px 20px;
    box-sizing: border-box;
  }
  .cover-badge {
    display: inline-block;
    padding: 4px 12px;
    font-size: 9pt;
    font-weight: 700;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    background: #f0f9ff;
    color: #0284c7;
    border: 1px solid #bae6fd;
    border-radius: 999px;
    margin-bottom: 24px;
    width: fit-content;
  }
  .cover-title {
    font-size: 34pt;
    font-weight: 800;
    line-height: 1.1;
    color: #0f172a;
    letter-spacing: -0.03em;
    margin: 0 0 16px 0;
  }
  .cover-title span {
    color: #0284c7;
  }
  .cover-subtitle {
    font-size: 13.5pt;
    line-height: 1.45;
    color: #475569;
    max-width: 650px;
    margin: 0 0 36px 0;
    font-weight: 400;
  }
  .cover-meta-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 16px;
    padding: 20px;
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 10px;
    margin-bottom: 40px;
  }
  .cover-meta-item strong {
    display: block;
    font-size: 8pt;
    text-transform: uppercase;
    color: #64748b;
    letter-spacing: 0.05em;
    margin-bottom: 3px;
  }
  .cover-meta-item span {
    font-size: 10pt;
    font-weight: 600;
    color: #0f172a;
  }
  .cover-footer {
    margin-top: auto;
    font-size: 8.5pt;
    color: #64748b;
    border-top: 1px solid #e2e8f0;
    padding-top: 16px;
  }

  /* Headings */
  h1 {
    font-size: 19pt;
    font-weight: 800;
    color: #0f172a;
    letter-spacing: -0.02em;
    border-bottom: 2px solid #0284c7;
    padding-bottom: 6px;
    margin-top: 32px;
    margin-bottom: 14px;
    page-break-after: avoid;
  }
  h2 {
    font-size: 13pt;
    font-weight: 700;
    color: #0369a1;
    margin-top: 22px;
    margin-bottom: 10px;
    page-break-after: avoid;
  }
  h3 {
    font-size: 10.5pt;
    font-weight: 700;
    color: #1e293b;
    margin-top: 16px;
    margin-bottom: 6px;
    page-break-after: avoid;
  }

  p {
    margin: 0 0 10px 0;
  }

  /* Callout Boxes */
  .callout {
    padding: 12px 16px;
    border-radius: 8px;
    margin: 14px 0;
    font-size: 9pt;
    page-break-inside: avoid;
  }
  .callout-info {
    background: #f0f9ff;
    border-left: 4px solid #0284c7;
    color: #0369a1;
  }
  .callout-warning {
    background: #fffbeb;
    border-left: 4px solid #f59e0b;
    color: #92400e;
  }
  .callout-critical {
    background: #fef2f2;
    border-left: 4px solid #ef4444;
    color: #991b1b;
  }
  .callout-tip {
    background: #f0fdf4;
    border-left: 4px solid #10b981;
    color: #065f46;
  }
  .callout strong {
    font-weight: 700;
  }

  /* Code Blocks & Inlines */
  pre {
    background: #0f172a;
    color: #e2e8f0;
    padding: 12px 14px;
    border-radius: 7px;
    font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
    font-size: 8pt;
    line-height: 1.45;
    overflow-x: auto;
    margin: 10px 0 14px 0;
    page-break-inside: avoid;
  }
  code {
    font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
    font-size: 8.5pt;
    background: #f1f5f9;
    color: #0f172a;
    padding: 1.5px 5px;
    border-radius: 4px;
    border: 1px solid #e2e8f0;
  }
  pre code {
    background: transparent;
    color: inherit;
    padding: 0;
    border: none;
    font-size: 8pt;
  }

  /* Tables */
  table {
    width: 100%;
    border-collapse: collapse;
    margin: 14px 0 18px 0;
    font-size: 8.5pt;
    page-break-inside: avoid;
  }
  th, td {
    padding: 7px 10px;
    border: 1px solid #cbd5e1;
    text-align: left;
    vertical-align: top;
  }
  th {
    background: #f8fafc;
    font-weight: 700;
    color: #0f172a;
  }
  tr:nth-child(even) {
    background: #f8fafc;
  }

  /* Cards Grid */
  .grid-2 {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
    margin: 12px 0;
    page-break-inside: avoid;
  }
  .card {
    background: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    padding: 12px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.02);
  }
  .card h4 {
    margin: 0 0 6px 0;
    font-size: 9.5pt;
    font-weight: 700;
    color: #0f172a;
  }

  /* Badges */
  .tag {
    display: inline-block;
    padding: 2px 7px;
    border-radius: 4px;
    font-size: 7.5pt;
    font-weight: 700;
    text-transform: uppercase;
  }
  .tag-cyan { background: #e0f2fe; color: #0369a1; }
  .tag-green { background: #dcfce7; color: #15803d; }
  .tag-amber { background: #fef3c7; color: #b45309; }
  .tag-red { background: #fee2e2; color: #b91c1c; }

  ul, ol {
    margin: 6px 0 12px 20px;
    padding: 0;
  }
  li {
    margin-bottom: 4px;
  }

  .chapter-break {
    page-break-before: always;
  }
</style>
</head>
<body>

<!-- ==================== COVER PAGE ==================== -->
<div class="cover">
  <div class="cover-badge">Official Security Documentation</div>
  <div class="cover-title">
    MOROS <span>AI</span><br>Operator Manual
  </div>
  <div class="cover-subtitle">
    The Exhaustive Technical Guide for Autonomous Black-Box Web Penetration Testing, Multi-Agent Coordination, ReAct Execution, and Dashboard Telemetry.
  </div>

  <div class="cover-meta-grid">
    <div class="cover-meta-item">
      <strong>Lead Architecture & Engineering</strong>
      <span>Raider & Moros Security Research</span>
    </div>
    <div class="cover-meta-item">
      <strong>Platform Release</strong>
      <span>Moros AI Agent Core v1.2</span>
    </div>
    <div class="cover-meta-item">
      <strong>Supported Interfaces</strong>
      <span>CLI Terminal + Neon Cyber Web Dashboard</span>
    </div>
    <div class="cover-meta-item">
      <strong>Export Standards</strong>
      <span>OASIS SARIF 2.1.0 • JSON • Markdown • cURL PoC</span>
    </div>
  </div>

  <div class="callout callout-warning">
    <strong>LEGAL & ETHICAL NOTICE:</strong> Moros AI is an advanced offensive security assessment system intended exclusively for authorized security engagements, bug bounty programs adhering to safe harbor policies, and internal application security testing. Explicit, written authorization is mandatory prior to conducting any assessment.
  </div>

  <div class="cover-footer">
    Engineered by Raider &bull; Licensed under MIT License &bull; Automated Test Suite: 32 Passing Unit Tests (100% Coverage)
  </div>
</div>

<!-- ==================== TABLE OF CONTENTS ==================== -->
<div class="chapter-break"></div>
<h1>Table of Contents</h1>

<table>
  <thead>
    <tr>
      <th style="width: 15%;">Section</th>
      <th>Chapter Title & Subject Matter</th>
      <th style="width: 25%;">Primary Component</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Chapter 1</strong></td>
      <td><strong>System Architecture & Core Philosophy</strong> — Evidence-first provenance, ReAct runtime loop, multi-agent coordination, and bounded tool execution.</td>
      <td><code>agent_runtime.py</code></td>
    </tr>
    <tr>
      <td><strong>Chapter 2</strong></td>
      <td><strong>Prerequisites & Installation Guide</strong> — Python environment, virtualenv setup, Playwright browser dependencies, and automated preflight checks.</td>
      <td><code>setup.py</code></td>
    </tr>
    <tr>
      <td><strong>Chapter 3</strong></td>
      <td><strong>Universal LLM & Multi-Provider Engine</strong> — Configuring 16+ providers (DeepSeek, OpenAI, Claude, Groq, Gemini, Ollama, LM Studio), API testing, and offline fallback.</td>
      <td><code>llm_client.py</code></td>
    </tr>
    <tr>
      <td><strong>Chapter 4</strong></td>
      <td><strong>Legal Compliance, Scope of Work & Guardrails</strong> — Deterministic scope validation, same-host constraints, rate limiting, and blocking HITL checkpoints.</td>
      <td><code>scoped_http.py</code></td>
    </tr>
    <tr>
      <td><strong>Chapter 5</strong></td>
      <td><strong>CLI Terminal Operations (Complete Flag Reference)</strong> — Initializing targets, scan profiles (quick, deep, passive), custom skills flags, rate-tuning, and dry-run planning.</td>
      <td><code>run.py</code></td>
    </tr>
    <tr>
      <td><strong>Chapter 6</strong></td>
      <td><strong>Web Dashboard Operations (Full UI Walkthrough)</strong> — Local server launch, the 8 operational tabs, interactive sub-agent console, and live terminal streaming.</td>
      <td><code>dashboard/server.py</code></td>
    </tr>
    <tr>
      <td><strong>Chapter 7</strong></td>
      <td><strong>Dynamic Custom Skills Engine</strong> — Creating unlimited custom security skills via UI, CLI, and filesystem; checklist validation; and Review-Skill verification.</td>
      <td><code>skill_registry.py</code></td>
    </tr>
    <tr>
      <td><strong>Chapter 8</strong></td>
      <td><strong>Artifacts, Reports & SARIF 2.1.0 Export</strong> — Directory hierarchy, cryptographic evidence ledger, GitHub Code Scanning integration, and CVSS reporting.</td>
      <td><code>sarif_exporter.py</code></td>
    </tr>
    <tr>
      <td><strong>Chapter 9</strong></td>
      <td><strong>End-to-End Real-World Walkthrough</strong> — Practical engagement lifecycle from target initialization to finding triage and executive sign-off.</td>
      <td><code>lastpass.com</code> case</td>
    </tr>
    <tr>
      <td><strong>Chapter 10</strong></td>
      <td><strong>Troubleshooting & Safety FAQ</strong> — Handling rate limits, WAF blocks, headless browser failures, and model connection issues.</td>
      <td>Operational Tips</td>
    </tr>
  </tbody>
</table>

<!-- ==================== CHAPTER 1 ==================== -->
<div class="chapter-break"></div>
<h1>1. System Architecture & Core Philosophy</h1>

<p>
  <strong>MOROS AI</strong> is an autonomous, agentic web penetration testing system engineered for rigorous, authorized dynamic security assessments (black-box DAST). Unlike conventional static vulnerability scanners that fire blind payload dictionaries or simple wrappers around monolithic LLM prompts, Moros employs an explicit, deterministic <strong>ReAct (Reasoning + Action)</strong> orchestration framework.
</p>

<h2>1.1 Architectural Pillars</h2>
<div class="grid-2">
  <div class="card">
    <h4>1. Evidence-First Integrity</h4>
    <p>Every candidate finding must be tied to verified evidence: full HTTP raw request/response pairs, exact parameter reflections, and cryptographically verified SHA-256 artifact hashes in <code>ledger.jsonl</code>.</p>
  </div>
  <div class="card">
    <h4>2. Specialist Sub-Agent Division</h4>
    <p>Rather than a single prompt attempting all attacks, specialized micro-agents (Recon, JS AST Hunter, XSS Specialist, SSRF Pivoter, Auth/Race Specialist, and Review Gate) manage specific attack phases.</p>
  </div>
  <div class="card">
    <h4>3. Enforceable Human-in-the-Loop</h4>
    <p>State-changing HTTP operations (POST, PUT, DELETE, password resets, race conditions) are halted by real thread-blocking gates (<code>WAITING_APPROVAL</code>) until the human operator authorizes them.</p>
  </div>
  <div class="card">
    <h4>4. Unlimited Extensibility</h4>
    <p>Operators are not bounded by a hardcoded list of checks. The dynamic skill registry auto-discovers arbitrary custom skills from disk or the Web Dashboard instantly.</p>
  </div>
</div>

<h2>1.2 The ReAct Execution Loop</h2>
<p>
  Inside each micro-skill, the <code>AgentRunner</code> executes a structured cycle bounded by strict step budgets (default: 6 steps) and timeouts:
</p>
<pre><code>[Operator Goal / Directive]
       │
       ▼
 ┌───────────┐      Sends observation history & tool schemas
 │  Thought  │ ───► Evaluates previous output, identifies injection surfaces
 └─────┬─────┘
       │
       ▼
 ┌───────────┐      Selects registered tool with strictly validated JSON arguments
 │  Action   │ ───► Example: fetch_url(url="..."), probe_param(param="q")
 └─────┬─────┘
       │
       ▼
 ┌───────────┐      Executed safely by ScopedHttpClient (same-host, rate-limited)
 │Observation│ ───► Captures status code, response headers, body reflection
 └─────┬─────┘
       │
       ▼
 [Satisfied?] ──No──► Loop back to [Thought]
       │ Yes
       ▼
 ┌───────────┐
 │FinalAnswer│ ───► Stores candidate in output/findings/ and updates ledger
 └───────────┘</code></pre>

<!-- ==================== CHAPTER 2 ==================== -->
<div class="chapter-break"></div>
<h1>2. Prerequisites & Installation Guide</h1>

<p>Moros AI is cross-platform and operates on Windows, Linux, and macOS. It requires Python 3.10 or newer.</p>

<h2>2.1 Step-by-Step Installation</h2>

<h3>Step 1: Clone the Repository</h3>
<pre><code>git clone https://github.com/V7-Awad/Moros-Ai-Agent.git
cd Moros-Ai-Agent</code></pre>

<h3>Step 2: Create and Activate a Python Virtual Environment</h3>
<pre><code># Linux & macOS:
python3 -m venv venv
source venv/bin/activate

# Windows (PowerShell):
python -m venv venv
.\\venv\\Scripts\\Activate.ps1</code></pre>

<h3>Step 3: Install Required Dependencies</h3>
<pre><code>pip install -r requirements.txt</code></pre>

<h3>Step 4: Install Playwright Chromium Engine</h3>
<p>Moros uses headless Chromium for client-side JavaScript discovery, dynamic DOM analysis, and rendering report PDFs:</p>
<pre><code>playwright install chromium</code></pre>

<h3>Step 5: Execute System Preflight Verification</h3>
<p>Verify that your environment, directories, and third-party tools are correctly installed:</p>
<pre><code>python run.py --check</code></pre>

<div class="callout callout-tip">
  <strong>Expected Output:</strong> The preflight check inspects Python version, Playwright browser binaries, directory permissions, and configuration. It must conclude with <code>✅ All prerequisites met!</code>.
</div>

<!-- ==================== CHAPTER 3 ==================== -->
<div class="chapter-break"></div>
<h1>3. Universal LLM & Multi-Provider Engine</h1>

<p>
  Moros AI features a universal, vendor-neutral LLM client supporting <strong>16+ commercial and open-weight model providers</strong>, alongside any arbitrary local or hosted OpenAI-compatible inference gateway.
</p>

<h2>3.1 Supported Providers Matrix</h2>
<table>
  <thead>
    <tr>
      <th>Provider</th>
      <th>Default Recommended Model</th>
      <th>Primary Configuration Variable</th>
      <th>Endpoint Architecture</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>DeepSeek</strong></td>
      <td><code>deepseek-chat</code> / <code>deepseek-reasoner</code></td>
      <td><code>DEEPSEEK_API_KEY</code></td>
      <td>Direct API (<code>https://api.deepseek.com/v1</code>)</td>
    </tr>
    <tr>
      <td><strong>OpenAI</strong></td>
      <td><code>gpt-4o-mini</code> / <code>gpt-4o</code></td>
      <td><code>OPENAI_API_KEY</code></td>
      <td>Direct API (<code>https://api.openai.com/v1</code>)</td>
    </tr>
    <tr>
      <td><strong>Anthropic</strong></td>
      <td><code>claude-3-5-sonnet-20241022</code></td>
      <td><code>ANTHROPIC_API_KEY</code></td>
      <td>Native Anthropic API (<code>/v1/messages</code>)</td>
    </tr>
    <tr>
      <td><strong>Groq</strong></td>
      <td><code>llama-3.3-70b-versatile</code></td>
      <td><code>GROQ_API_KEY</code></td>
      <td>Ultra-fast inference (<code>/openai/v1</code>)</td>
    </tr>
    <tr>
      <td><strong>Google Gemini</strong></td>
      <td><code>gemini-3.8-flash</code> / <code>gemini-2.0-flash</code></td>
      <td><code>GEMINI_API_KEY</code></td>
      <td>Google Generative AI (<code>/v1beta</code>)</td>
    </tr>
    <tr>
      <td><strong>OpenRouter</strong></td>
      <td><code>meta-llama/llama-3.1-8b-instruct</code></td>
      <td><code>OPENROUTER_API_KEY</code></td>
      <td>Multi-model aggregator (100+ models)</td>
    </tr>
    <tr>
      <td><strong>Local Ollama</strong></td>
      <td><code>llama3</code> / <code>deepseek-r1:8b</code> / <code>qwen2.5-coder</code></td>
      <td><code>OLLAMA_BASE_URL</code></td>
      <td>100% Offline (<code>http://localhost:11434</code>)</td>
    </tr>
    <tr>
      <td><strong>Custom Gateways</strong></td>
      <td>LM Studio / vLLM / LocalAI / Jan.ai</td>
      <td><code>OPENAI_BASE_URL</code> + <code>OPENAI_API_KEY</code></td>
      <td>Any OpenAI-compatible server</td>
    </tr>
  </tbody>
</table>

<h2>3.2 Method A: Configuration via `.env` File</h2>
<p>Create a <code>.env</code> file in the project root (see <code>.env.example</code> for template):</p>
<pre><code># Example: Configuring DeepSeek as Primary Provider
DEEPSEEK_API_KEY=sk-your-actual-api-key-here
DEEPSEEK_MODEL=deepseek-chat
MOROS_LLM_PROVIDER=deepseek

# Optional: Discord notification webhook
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...</code></pre>

<h2>3.3 Method B: Configuration via the Web Dashboard</h2>
<ol>
  <li>Launch the web dashboard: <code>python run.py --dashboard</code></li>
  <li>Open <code>http://127.0.0.1:8080</code> in any web browser.</li>
  <li>Click the <strong>LLM Settings</strong> button (gear icon) in the top navigation bar.</li>
  <li>Select your provider from the dropdown (DeepSeek, OpenAI, Anthropic, Groq, Gemini, Ollama, etc.).</li>
  <li>Paste your API key and optionally override the model name.</li>
  <li>Click <strong>Test Connection</strong> to perform an active hand-shake test.</li>
  <li>Click <strong>Save & Apply</strong>. The dashboard automatically writes to <code>.env</code> and updates the live runtime.</li>
</ol>

<div class="callout callout-info">
  <strong>Deterministic Fallback Mode (LLM Unavailable):</strong> If no API key is provided or the connection fails, Moros does NOT crash. Instead, it activates the <code>LLM_UNAVAILABLE</code> fallback mode, executing deterministic heuristic analysis, signature checks, and rule-based triage without losing pipeline progress.
</div>

<!-- ==================== CHAPTER 4 ==================== -->
<div class="chapter-break"></div>
<h1>4. Legal Compliance, Scope of Work & Guardrails</h1>

<p>
  Safety, rate limitation, and strict legal authorization are foundational requirements in Moros AI. It enforces multi-layered guardrails before executing any offensive check.
</p>

<h2>4.1 The `scope-of-work.md` Requirement</h2>
<p>
  Every target workspace under <code>targets/&lt;target_domain&gt;/</code> must contain a valid <code>scope-of-work.md</code> file. The orchestrator's <code>verify_scope()</code> function parses this file on startup:
</p>
<ul>
  <li><strong>Target Name Matching:</strong> The target domain name must appear explicitly in the document.</li>
  <li><strong>Authorization Keywords:</strong> The document must contain at least one recognized authorization term (e.g., <code>authorized</code>, <code>authorised</code>, <code>in scope</code>, <code>scope of work</code>).</li>
</ul>

<div class="callout callout-critical">
  <strong>Automatic Passive Downgrade:</strong> If a target lacks a valid <code>scope-of-work.md</code>, Moros strictly refuses to execute active network probes. It automatically forces <strong>PASSIVE-ONLY mode</strong>, restricting execution exclusively to OSINT, Certificate Transparency (CT) logs, and Wayback Machine archives.
</div>

<h2>4.2 Built-in Scoped HTTP Client Guardrails</h2>
<p>All network traffic routed through <code>tools/scoped_http.py</code> is bounded by hard safety constraints:</p>
<ul>
  <li><strong>Exact Same-Host Restriction:</strong> Any request pointing to a hostname other than the target is immediately dropped. Cross-host redirects and third-party CDNs are rejected.</li>
  <li><strong>Non-Destructive HTTP Verbs:</strong> Only <code>GET</code> and <code>HEAD</code> methods are permitted during autonomous automated scans.</li>
  <li><strong>Rate-Limiting & Delay:</strong> Default throttle enforces a minimum 0.3-second delay between requests and caps total requests per scan session.</li>
  <li><strong>Credential Scrubbing:</strong> URLs containing userinfo (<code>user:pass@host</code>) are forbidden.</li>
</ul>

<h2>4.3 Enforceable Blocking Human-in-the-Loop (HITL)</h2>
<p>
  When a micro-skill detects a situation requiring state modification (such as password reset forms, IDP race conditions, or parameter fuzzing that might trigger account lockouts), it creates a deterministic checkpoint (e.g., <code>cp-d41d8cd98f00b204</code>) and suspends the worker thread on a real <code>threading.Event()</code>.
</p>
<p>
  The operator can inspect the exact payload, URL, and risk level via the <strong>Manual Decisions</strong> tab on the Web Dashboard:
</p>
<ul>
  <li><strong>Approve:</strong> Wakes the worker thread to execute the authorized probe.</li>
  <li><strong>Reject / Timeout:</strong> Safely cancels the probe, logs the operator's notes into the audit trail, and resumes normal scanning.</li>
</ul>

<!-- ==================== CHAPTER 5 ==================== -->
<div class="chapter-break"></div>
<h1>5. CLI Terminal Operations (Complete Flag Reference)</h1>

<p>
  The command-line interface provides complete programmatic control over Moros AI, ideal for headless execution, automated CI/CD security regression testing, and terminal power-users.
</p>

<h2>5.1 Initializing a New Target Workspace</h2>
<p>Always initialize a structured workspace before assessing a new asset:</p>
<pre><code>python setup.py init-target --domain app.example.com</code></pre>
<p>This creates the standardized target directory tree:</p>
<pre><code>targets/app.example.com/
├── PLACE_SCOPE_OF_WORK_HERE.txt   # Instructions for authorization
├── scope-of-work.md               # Your authorized scope document
└── output/                        # All scan outputs, evidence, and logs</code></pre>

<h2>5.2 Primary Scan Profiles</h2>

<h3>1. Quick Scan Profile (Recommended Initial Audit)</h3>
<p>Fast surface reconnaissance, dynamic client-side JS AST analysis, endpoint discovery, and reflected XSS triage:</p>
<pre><code>python run.py --target app.example.com --scan-mode quick</code></pre>

<h3>2. Deep Scan Profile (Comprehensive Vulnerability Audit)</h3>
<p>Executes the complete offensive suite including SSRF candidate triage, IDP race auditing, DOM/Stored/Blind XSS checks, and password reset analysis:</p>
<pre><code>python run.py --target app.example.com --scan-mode deep</code></pre>

<h3>3. Passive OSINT Profile (Zero Active Target Network Packets)</h3>
<p>Restricted purely to Certificate Transparency logs, historical archives, and passive discovery without sending any HTTP requests to the target:</p>
<pre><code>python run.py --target app.example.com --scan-mode passive</code></pre>

<h2>5.3 CLI Flags & Tuning Parameters</h2>
<table>
  <thead>
    <tr>
      <th>Flag</th>
      <th>Type & Default</th>
      <th>Operational Description</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code>--target</code></td>
      <td>String (Required)</td>
      <td>Target hostname or domain (e.g., <code>lastpass.com</code>).</td>
    </tr>
    <tr>
      <td><code>--scan-mode</code></td>
      <td><code>quick</code> | <code>deep</code> | <code>passive</code></td>
      <td>Execution profile defining active skill chain. Default: <code>quick</code>.</td>
    </tr>
    <tr>
      <td><code>--skills</code></td>
      <td>Comma-separated list</td>
      <td>Execute specific skills only (e.g., <code>--skills recon-subdomain,js-discover</code>).</td>
    </tr>
    <tr>
      <td><code>--models</code></td>
      <td>String (<code>default</code>)</td>
      <td>Override LLM model (e.g., <code>deepseek/deepseek-chat</code>, <code>openai/gpt-4o</code>).</td>
    </tr>
    <tr>
      <td><code>--max-http-requests</code></td>
      <td>Integer (Default: <code>150</code>)</td>
      <td>Strict ceiling on same-host HTTP requests per session.</td>
    </tr>
    <tr>
      <td><code>--request-delay</code></td>
      <td>Float (Default: <code>0.3</code>)</td>
      <td>Delay in seconds between successive requests for rate safety.</td>
    </tr>
    <tr>
      <td><code>--active-host-limit</code></td>
      <td>Integer (Default: <code>100</code>)</td>
      <td>Maximum subdomains checked for liveness via HEAD requests.</td>
    </tr>
    <tr>
      <td><code>--root-only-active</code></td>
      <td>Boolean flag</td>
      <td>Restricts active recon checks exclusively to the apex root domain.</td>
    </tr>
    <tr>
      <td><code>--https-only</code></td>
      <td>Boolean flag</td>
      <td>Prevents fallback to unencrypted plaintext HTTP during probes.</td>
    </tr>
    <tr>
      <td><code>--dry-run</code></td>
      <td>Boolean flag</td>
      <td>Validates scope, computes dependency graph, and prints plan without sending traffic.</td>
    </tr>
    <tr>
      <td><code>--dashboard</code></td>
      <td>Boolean flag</td>
      <td>Launches the local interactive Web Dashboard on port 8080.</td>
    </tr>
  </tbody>
</table>

<h2>5.4 Practical CLI Execution Examples</h2>
<pre><code># Example 1: Dry run to inspect execution order
python run.py --target lastpass.com --dry-run

# Example 2: Quick scan with customized rate-limiting
python run.py --target lastpass.com --scan-mode quick --max-http-requests 50 --request-delay 0.5

# Example 3: Running DeepSeek explicitly from the terminal
python run.py --target lastpass.com --models deepseek/deepseek-chat --scan-mode quick

# Example 4: Testing reflected XSS and content discovery only
python run.py --target lastpass.com --skills content-discovery,xss-reflected</code></pre>

<!-- ==================== CHAPTER 6 ==================== -->
<div class="chapter-break"></div>
<h1>6. Web Dashboard Operations (Full UI Walkthrough)</h1>

<p>
  Moros AI includes a local, high-performance <strong>Neon Cyber Single-Page Application (SPA)</strong> web dashboard. It communicates via a REST API hosted locally by <code>dashboard/server.py</code>.
</p>

<h2>6.1 Starting the Dashboard</h2>
<pre><code>python run.py --dashboard
# Or use the direct launcher:
python dashboard.py --port 8080</code></pre>
<p>Access the interface at <strong><code>http://127.0.0.1:8080</code></strong>.</p>

<h2>6.2 Overview of the 8 Operational Tabs</h2>

<h3>Tab 01: Overview</h3>
<p>
  Displays the executive health metrics of the selected target: Attack Surface Score, Finding Counts categorized by severity (Critical, High, Medium, Low, Unassessed), Active/Passive status, Subdomain counts, and Detected Frontend Technology Fingerprint (e.g., React, Vue, jQuery, Cloudflare).
</p>

<h3>Tab 02: AI Agents & Chat</h3>
<p>
  Interactive command and control for specialist sub-agents. Select any specialist from the roster:
</p>
<ul>
  <li><strong>Coordinator Master:</strong> High-level orchestration directives and synthesized assessment briefings.</li>
  <li><strong>Reconnaissance Specialist:</strong> Subdomain enumeration, DNS brute, and CT log intelligence.</li>
  <li><strong>JavaScript & API Hunter:</strong> Headless browser crawl, JS unminification, AST parameter extraction.</li>
  <li><strong>XSS & Client-Side Specialist:</strong> DOM, Reflected, Stored, and Blind XSS payload evaluations.</li>
  <li><strong>SSRF & Cloud Metadata Hunter:</strong> Out-of-band canary interaction, AWS/GCP metadata probes.</li>
  <li><strong>Auth & Race Condition Agent:</strong> Multi-threaded race conditions and password reset testing.</li>
  <li><strong>Review-Skill Verifier Gate:</strong> Independent cURL replay and false-positive pruning.</li>
  <li><strong>Reporting & Synthesis Agent:</strong> CVSS scoring, remediation advisory, and executive export.</li>
</ul>

<h3>Tab 03: Skills Graph</h3>
<p>
  Visual representation of the execution pipeline. Displays each skill's execution status (<code>PENDING</code>, <code>RUNNING</code>, <code>PASSED</code>, <code>FAILED</code>, or <code>BLOCKED</code>), log counts, and review results. Features the <strong>[+ Add Custom Skill]</strong> button for registering arbitrary custom security checks.
</p>

<h3>Tab 04: Findings & Triage</h3>
<p>
  Comprehensive catalog of all detected security findings. Each finding card includes:
</p>
<ul>
  <li>Severity badge and vulnerability title.</li>
  <li>Affected URL and injected parameter.</li>
  <li><strong>Reproducible cURL Command:</strong> Instant copy-pasteable terminal command to manually reproduce the behavior outside the agent.</li>
  <li>Evidence disclosure: Request/response snippet and matching cryptographic SHA-256 hash.</li>
</ul>

<h3>Tab 05: Endpoints & APIs</h3>
<p>
  Searchable data table of all API endpoints and routes discovered through dynamic spidering, inline script parsing, and beautified source map extraction, categorized by HTTP method and source script.
</p>

<h3>Tab 06: Manual Decisions (HITL Approval Center)</h3>
<p>
  The operator's safety checkpoint. Displays all pending high-impact actions. The operator can review the target URL, method, payload, and risk level, then click <strong>Approve</strong> or <strong>Reject</strong> with custom audit notes.
</p>

<h3>Tab 07: Live Terminal</h3>
<p>
  Real-time streaming terminal log displaying raw execution events, tool calls, stdout/stderr streams, and orchestrator messages directly from <code>orchestration-log.json</code>.
</p>

<h3>Tab 08: Final Report</h3>
<p>
  Displays the synthesized pentesting deliverable, including Executive Summary, Methodology, Vulnerability Breakdown with CVSS scores, Remediation Steps, and one-click Print/PDF export.
</p>

<!-- ==================== CHAPTER 7 ==================== -->
<div class="chapter-break"></div>
<h1>7. Dynamic Custom Skills Engine</h1>

<p>
  Moros AI is completely extensible. Operators can create and register an <strong>unlimited number of custom security skills</strong>. Once registered, Moros auto-discovers the skill, schedules it in the execution graph, and subjects it to the Review-Skill verifier gate.
</p>

<h2>7.1 Registering Custom Skills via the Web Dashboard</h2>
<ol>
  <li>Open the <strong>Skills Graph</strong> tab (Tab 03) in the Web Dashboard.</li>
  <li>Click the <strong>[+ Add Custom Skill]</strong> button in the header.</li>
  <li>Fill in the registration form:
    <ul>
      <li><strong>Skill Identifier (Slug):</strong> Unique alphanumeric slug (e.g., <code>idor-audit</code>, <code>jwt-bypass</code>, <code>sqli-advanced</code>).</li>
      <li><strong>Category:</strong> Choose from Server-Side, Authentication, Client-Side, API Logic, or Custom.</li>
      <li><strong>Title / Display Name:</strong> Human-readable title (e.g., <em>Insecure Direct Object Reference Hunter</em>).</li>
      <li><strong>Description & Objectives:</strong> Detection logic and vulnerability criteria.</li>
      <li><strong>Verification Checklist:</strong> Specific steps required for completion verification (one per line).</li>
    </ul>
  </li>
  <li>Click <strong>Register Custom Skill</strong>. The skill is created instantly on disk and added to the pipeline.</li>
</ol>

<h2>7.2 Registering Custom Skills Programmatically (Python)</h2>
<pre><code>from tools.skill_registry import SkillRegistry

registry = SkillRegistry()
registry.create_custom_skill(
    skill_id="jwt-security-audit",
    title="JSON Web Token Security Auditor",
    category="Authentication & Session",
    description="Audits JWT tokens for algorithm confusion (none/HS256) and weak signing keys.",
    checklist=[
        "Extract Authorization Bearer headers from discovered endpoints",
        "Test algorithm confusion attacks using 'none' algorithm",
        "Verify signature enforcement on tampered role claims",
        "Generate reproducible verification cURL commands"
    ]
)</code></pre>

<h2>7.3 Registering Custom Skills via Filesystem Auto-Discovery</h2>
<p>
  Simply create a folder under <code>skills/&lt;skill-id&gt;/</code> containing a standard <code>SKILL.md</code>:
</p>
<pre><code>skills/jwt-security-audit/
├── SKILL.md
└── manifest.json</code></pre>
<p>Example <code>SKILL.md</code> format:</p>
<pre><code># JSON Web Token Security Auditor (`jwt-security-audit`)

**Category:** Authentication & Session  
**Author:** Custom Operator  
**Type:** Dynamic Custom Skill  

## Description
Audits target endpoints for JWT misconfigurations and algorithm confusion.

## Verification Checklist
- [ ] Extract Authorization headers
- [ ] Test none-algorithm signature bypass
- [ ] Verify claims tampering reflection</code></pre>

<!-- ==================== CHAPTER 8 ==================== -->
<div class="chapter-break"></div>
<h1>8. Artifacts, Reports & SARIF 2.1.0 Export</h1>

<p>Every assessment produces durable, structured artifacts saved under <code>targets/&lt;target&gt;/output/</code>.</p>

<h2>8.1 Output Directory Structure</h2>
<pre><code>targets/&lt;target&gt;/output/
├── recon/
│   ├── subdomains-all.txt        # Comprehensive discovered subdomain list
│   └── live-hosts.json           # Validated responsive hosts
├── js/
│   ├── endpoints.json            # Extracted REST/GraphQL route catalog
│   ├── parameters.json           # Discovered parameter dictionary
│   └── secrets-findings.json     # Leaked API keys and credentials
├── findings/
│   └── &lt;skill-name&gt;/             # Structured JSON candidate records
├── evidence/
│   └── ledger.jsonl              # Cryptographic SHA-256 evidence provenance
├── report/
│   ├── hackbot-report-&lt;date&gt;.md  # Executive Markdown deliverable
│   └── findings.sarif            # OASIS SARIF 2.1.0 standardized export
└── runs/
    └── run-&lt;id&gt;/
        ├── run.json              # Durable state machine record
        ├── events.jsonl          # Complete event timeline
        └── agents.jsonl          # Sub-agent session lifecycles</code></pre>

<h2>8.2 OASIS SARIF 2.1.0 & GitHub Code Scanning Integration</h2>
<p>
  Moros automatically exports findings in standard SARIF 2.1.0 format (<code>findings.sarif</code>). This enables direct, native upload to GitHub Code Scanning Alerts or ASPM platforms via GitHub Actions:
</p>
<pre><code># .github/workflows/security-audit.yml
name: Moros AI DAST Security Scan
on: [push, pull_request]

jobs:
  dast-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Install Moros AI
        run: |
          pip install -r requirements.txt
          playwright install chromium
      - name: Execute Moros Quick Scan
        run: python run.py --target app.example.com --scan-mode quick
      - name: Upload SARIF to GitHub Security Alerts
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: targets/app.example.com/output/report/findings.sarif</code></pre>

<!-- ==================== CHAPTER 9 ==================== -->
<div class="chapter-break"></div>
<h1>9. Step-by-Step Practical Walkthrough (Real-World Target)</h1>

<p>Follow this end-to-end tutorial to perform an authorized assessment against <code>lastpass.com</code>.</p>

<h2>Step 1: Verify Scope & Target Initialization</h2>
<p>Verify that the workspace exists and contains the valid scope document:</p>
<pre><code>python run.py --target lastpass.com --dry-run</code></pre>
<p>Ensure the terminal reports: <code>✅ Scope-of-work found: scope-of-work.md</code>.</p>

<h2>Step 2: Configure LLM Backend</h2>
<p>Ensure your preferred model (e.g., DeepSeek, Groq, or Gemini) is configured in <code>.env</code> or test it via the dashboard:</p>
<pre><code>python -c "from tools.llm_client import LLMClient; c = LLMClient(); print(f'LLM Status: {c.provider}/{c.model} - Available: {c.is_available()}')"</code></pre>

<h2>Step 3: Execute Assessment via CLI or Dashboard</h2>
<p>Launch a quick surface audit with rate safety:</p>
<pre><code>python run.py --target lastpass.com --scan-mode quick --max-http-requests 40 --request-delay 0.4</code></pre>

<h2>Step 4: Real-Time Monitoring in Web Dashboard</h2>
<ol>
  <li>In another terminal, start the UI: <code>python run.py --dashboard</code></li>
  <li>Switch between <strong>AI Agents & Chat</strong> to inspect sub-agent deliberations.</li>
  <li>Watch the <strong>Live Terminal</strong> to observe active HTTP probes and responses.</li>
</ol>

<h2>Step 5: Review Findings & Generate SARIF Deliverable</h2>
<p>Inspect the generated report and verify reproducible cURLs:</p>
<pre><code>cat targets/lastpass.com/output/report/hackbot-report-lastpass.com-*.md</code></pre>

<!-- ==================== CHAPTER 10 ==================== -->
<div class="chapter-break"></div>
<h1>10. Troubleshooting, Safety FAQ & Best Practices</h1>

<div class="callout callout-warning">
  <strong>Target Rate Limiting (HTTP 429 / WAF Blocks):</strong> If the target server responds with HTTP 429 (Too Many Requests) or Cloudflare challenge pages, increase the request delay flag: <code>--request-delay 1.0</code> or reduce <code>--max-http-requests 30</code>.
</div>

<div class="callout callout-info">
  <strong>Missing Playwright Binaries:</strong> If the <code>js-discover</code> skill logs indicate browser launch failures, run <code>playwright install chromium</code> to install browser binaries.
</div>

<div class="callout callout-tip">
  <strong>Safe Harbor Best Practices:</strong> Always log your assessment activities, retain <code>evidence/ledger.jsonl</code> as proof of non-destructive testing, and adhere strictly to program rules.
</div>

<hr style="border: 0; border-top: 1px solid #e2e8f0; margin-top: 40px; margin-bottom: 20px;">
<div style="text-align: center; font-size: 8.5pt; color: #64748b;">
  <strong>MOROS AI AGENT</strong> • Engineered by Raider • Autonomous Web Penetration Testing Framework • End of Manual
</div>

</body>
</html>
"""

def generate_pdf():
    print("Initializing Chromium PDF Renderer via Playwright...")
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.set_content(HTML_CONTENT, wait_until="networkidle")
        
        # Render PDF with standard A4 margins, background graphics, and headers/footers
        pdf_bytes = page.pdf(
            format="A4",
            print_background=True,
            margin={
                "top": "18mm",
                "bottom": "20mm",
                "left": "16mm",
                "right": "16mm"
            }
        )
        browser.close()

    # Save to Docs Directory
    OUTPUT_PDF_DOCS.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PDF_DOCS.write_bytes(pdf_bytes)
    print(f"Generated Docs PDF: {OUTPUT_PDF_DOCS} ({len(pdf_bytes)} bytes)")

if __name__ == "__main__":
    generate_pdf()
