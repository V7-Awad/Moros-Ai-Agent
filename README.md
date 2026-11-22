# Moros AI Agent — Hackbot

<div align="center">

**🛡️ Agentic Web Penetration Testing Automation System**

*A modular, skill-based AI agent that automates authorized black-box web application security testing.*

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Authorized Testing Only](https://img.shields.io/badge/⚠️-Authorized%20Testing%20Only-red.svg)](#%EF%B8%8F-legal--ethical-notice)

</div>

---

## ⚠️ Legal & Ethical Notice

> **This tool is designed exclusively for AUTHORIZED security testing.** You MUST have written authorization (scope-of-work, bug bounty program rules, or signed penetration testing agreement) before testing any target. Unauthorized testing is illegal and unethical.

The system enforces this by **requiring a `scope-of-work` file** in every target directory before offensive skills will execute.

---

## 🏗️ Architecture

Moros AI is NOT one giant agent that "hacks everything." It is a collection of **15 small, single-purpose skills** orchestrated by a harness, with built-in self-review and human checkpoints.

Moros uses an evidence-first result model: endpoint heuristics create unverified triage candidates, source artifacts receive SHA-256-linked evidence IDs, and reports distinguish candidates from independently validated findings. Missing inputs are reported as missing; the pipeline does not invent sample endpoints or evidence to make a run look complete. See [the agent differentiation note](docs/agent-differentiation.md).

```
┌─────────────────────────────────────────────────┐
│              ORCHESTRATOR / HARNESS              │
│  • Scope verification    • Model routing         │
│  • Human checkpoints     • Multi-model runs      │
└───────┬──────────────┬──────────────┬────────────┘
        │              │              │
   ┌────▼────┐    ┌────▼────┐   ┌────▼─────┐
   │ SKILLS  │    │  TOOLS  │   │  REVIEW  │
   │ (15x)   │    │  (7x)   │   │  SKILL   │
   └────┬────┘    └────┬────┘   └────┬─────┘
        └──────────────┼──────────────┘
                       ▼
            targets/<domain>/output/
```

### Skills Pipeline

```
recon-subdomain → js-discover → js-analyze → content-discovery
                                     ↓
                    ┌────────────────┬┴───────────────┐
                    ▼                ▼                 ▼
              xss-reflected    ssrf-identify    idp-race-condition
              xss-stored       ssrf-post-exploit
              xss-dom          auth-password-reset-bruteforce
              xss-blind
                    │                │                 │
                    └────────────────┴─────────────────┘
                                     ▼
                          report-conglomeration
```

Each skill runs → **review-skill** verifies completion → retry if needed → next skill.

---

## 🚀 Quick Start

### 1. Clone & Install

```bash
git clone https://github.com/V7-Awad/Moros-Ai-Agent.git
cd Moros-Ai-Agent

# Create virtual environment
python -m venv venv

# Activate it
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install Playwright browsers
playwright install chromium
```

### 2. Set Up a Target

```bash
# Create a target directory
python setup.py init-target --domain example.com

# Place your authorization document
# Copy your scope-of-work PDF into targets/example.com/
cp /path/to/scope-of-work.pdf targets/example.com/
```

### 3. Launch Web Dashboard (Interactive Viewer)

Inspired by Strix (`usestrix/strix`), Moros AI features a local web viewer dashboard:

```bash
# Launch dashboard directly (opens in your default browser at http://127.0.0.1:8080)
python dashboard.py

# Or via run.py (similar to 'strix view')
python run.py view
python run.py --dashboard
```

**Dashboard Features:**
- 📊 **Executive Overview**: High-level severity metrics, vulnerability breakdown charts, and target tech stack.
- 🕸️ **Agent Multi-Skill Graph**: Visual orchestration tree of all 14 micro-skills and their review status.
- 🚨 **Vulnerabilities & Exploits**: Full finding cards with AI-proposed severities, context, and 1-click copy cURL PoCs.
- 🛡️ **Human-in-the-Loop (HITL) Center**: Actionable checkpoints to approve/reject state-changing or destructive actions.
- 💻 **Live Terminal & Tool Logs**: Real-time streaming console for inspecting skill logs.
- 📄 **Report Viewer**: Formatted markdown penetration testing report with print/PDF export.

### Import an API specification

Import a local OpenAPI/Swagger JSON or YAML file into a structured endpoint inventory. The importer makes no network requests:

```bash
python tools/openapi_import.py --spec ./openapi.yaml --output targets/example.com/output/api/openapi-endpoints.json --target example.com
```

YAML input uses PyYAML, installed with `pip install -r requirements.txt`. The result includes methods, paths, parameters, body content types, and declared security requirements. Treat the inventory as an assessment input; declared security is not proof of enforcement.

---

### 4. Run a Scan (CLI)

```bash
# Run the full pipeline against a target
python run.py --target example.com

# Run specific skills only
python run.py --target example.com --skills recon-subdomain,js-discover,js-analyze

# Run with multiple models
python run.py --target example.com --models claude-sonnet,gpt-4o-mini --runs-per-skill 2

# Dry run (shows what would execute without running)
python run.py --target example.com --dry-run
```

### 4. Run Individual Tools

```bash
# Browser-driven crawl
python tools/browser-crawl.py --target "https://example.com" \
    --output-dir "targets/example.com/output/js/raw/"

# Wayback Machine historical JS fetch
python tools/wayback-fetch.py --domain "example.com" \
    --output-dir "targets/example.com/output/js/raw/historical/"

# Source map hunting
python tools/sourcemap-hunter.py \
    --js-dir "targets/example.com/output/js/raw/" \
    --output-dir "targets/example.com/output/js/source-maps/"

# Secret scanning
python tools/secret-scanner.py \
    --input-dir "targets/example.com/output/js/beautified/" \
    --output "targets/example.com/output/js/secrets-findings.json"

# Endpoint extraction
python tools/endpoint-extractor.py \
    --input-dir "targets/example.com/output/js/beautified/" \
    --output-endpoints "targets/example.com/output/js/endpoints.json" \
    --output-params "targets/example.com/output/js/parameters.json" \
    --output-curl "targets/example.com/output/js/curl-commands.sh" \
    --target-domain "example.com"
```

---

## 📁 Project Structure

```
Moros-Ai-Agent/
├── skills/                              # 15 micro-skills
│   ├── recon-subdomain/SKILL.md         # Subdomain enumeration
│   ├── api-spec-discovery/SKILL.md      # Local OpenAPI/Swagger import
│   ├── js-discover/SKILL.md             # JS collection (browser-driven)
│   ├── js-analyze/SKILL.md              # JS deep analysis
│   ├── content-discovery/SKILL.md       # Directory brute-forcing
│   ├── xss-reflected/SKILL.md           # Reflected XSS
│   ├── xss-stored/SKILL.md              # Stored XSS
│   ├── xss-dom/SKILL.md                 # DOM-based XSS
│   ├── xss-blind/SKILL.md              # Blind XSS
│   ├── ssrf-identify/SKILL.md           # SSRF identification
│   ├── ssrf-post-exploit/SKILL.md       # SSRF post-exploitation
│   ├── idp-race-condition/SKILL.md      # IdP redirect race
│   ├── auth-password-reset-bruteforce/  # Hidden admin reset
│   ├── review-skill/SKILL.md            # Completion verification
│   └── report-conglomeration/SKILL.md   # Final report assembly
├── tools/                               # Python tool wrappers
│   ├── browser-crawl.py                 # Playwright browser crawler
│   ├── wayback-fetch.py                 # Wayback Machine fetcher
│   ├── sourcemap-hunter.py              # Source map discovery
│   ├── js-beautifier.py                 # JS beautification
│   ├── secret-scanner.py                # Secret/key scanner
│   ├── endpoint-extractor.py            # API endpoint extractor
│   ├── openapi_import.py                # OpenAPI/Swagger inventory importer
│   └── hackbot-orchestrator.py          # Pipeline orchestrator
├── targets/                             # Engagement folders (gitignored output)
├── docs/
│   ├── architecture.md                  # System design & human checkpoints
│   └── completion-checklist-format.md   # Checklist standard
├── run.py                               # Main entry point
├── setup.py                             # Setup & target initialization
├── requirements.txt                     # Python dependencies
└── README.md                            # This file
```

---

## 🔒 Human-in-the-Loop Checkpoints

The system **NEVER** runs in fully unattended mode. These are mandatory pause points:

| Checkpoint | Skills | What Gets Reviewed |
|---|---|---|
| **Pre-Run Authorization** | All | Scope-of-work must exist |
| **Destructive Actions** | xss-stored, auth-* | Before any state-changing request |
| **Exploit Chains** | report-conglomeration | Before labeling chains as critical |
| **Credential Testing** | auth-password-reset-bruteforce | Before any brute-forcing |
| **Final Report** | report-conglomeration | All AI severities are provisional |

---

## 🤖 Multi-Model Strategy

The system is designed to run each skill with **multiple AI models** for coverage:

| Tier | Purpose | Examples |
|---|---|---|
| Frontier | Novel reasoning, "bitter pill" exploration | Claude Opus, GPT-4o |
| Mid-tier | Methodology-driven skill execution | Claude Sonnet, GPT-4o-mini |
| Local | High-volume, budget-friendly runs | Llama, Mistral, Qwen |

```bash
# Example: 2 runs per skill across 3 models
python run.py --target example.com \
    --models claude-sonnet,gpt-4o-mini,llama \
    --runs-per-skill 2
```

---

## 📊 Completion Verification (Anti-Bias)

LLMs exhibit **completion bias** — they tend to claim tasks are done when steps were skipped. Moros AI fights this with:

1. **Markdown checklists** in every skill (not done until every box is checked with evidence)
2. **Review-skill** runs after every primary skill (preferably on a different model)
3. **Artifact + log verification** — non-zero-byte files required for every step
4. **Bounded retry loops** — nudge and re-run failed steps (max 3 retries)
5. **Critical failure escalation** — humans are alerted, never silent failure

---

## 🛠️ Development

### Adding a New Skill

1. Create `skills/<skill-name>/SKILL.md` with frontmatter (`name`, `description`)
2. Add methodology checklist following `docs/completion-checklist-format.md`
3. Add the skill to `SKILL_ORDER` and `SKILL_DEPENDENCIES` in `tools/hackbot-orchestrator.py`
4. Create a `reference.md` with 5-10 example outputs
5. Test with review-skill verification

### Retuning After Model Updates

When underlying models are upgraded, follow the retuning process:
1. Run each skill in "bare model" mode (strip instructions)
2. If the model handles something natively, remove that instruction
3. Keep skills as lean as possible

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🙏 Credits

- Architecture inspired by Jason's DEF CON / Bug Bounty Village talk (Arcanum Information Security / "Armada")
- Built with Claude Code–style agent skill patterns
- Uses [Playwright](https://playwright.dev/) for browser automation
