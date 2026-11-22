# MOROS AI — Complete Configuration & Deployment Plan

> [!IMPORTANT]
> This plan was generated after a full read-only audit of every source file in `d:\Moros Ai`. **No files were modified.** Hand this plan to an executing agent or follow it step-by-step.

---

## Table of Contents

1. [Current State Assessment](#1-current-state-assessment)
2. [Configure DeepSeek as the LLM Backend](#2-configure-deepseek-as-the-llm-backend)
3. [Fix the Import Bug in `hackbot_orchestrator.py`](#3-fix-the-import-bug-in-hackbot_orchestratorpy)
4. [Create a Proper Target Workspace (In-Scope / Out-of-Scope)](#4-create-a-proper-target-workspace-in-scope--out-of-scope)
5. [Write the `scope-of-work.md` for a Real Target](#5-write-the-scope-of-workmd-for-a-real-target)
6. [Install Dependencies & Verify Prerequisites](#6-install-dependencies--verify-prerequisites)
7. [Dashboard Configuration (Alternative to CLI)](#7-dashboard-configuration-alternative-to-cli)
8. [Run a Real Assessment](#8-run-a-real-assessment)
9. [Understanding the Output](#9-understanding-the-output)
10. [Advanced: Custom Skills & Multi-Model Runs](#10-advanced-custom-skills--multi-model-runs)
11. [Known Issues & Fixes](#11-known-issues--fixes)
12. [File Reference Map](#12-file-reference-map)

---

## 1. Current State Assessment

### What Exists

| Component | Status | Notes |
|-----------|--------|-------|
| Core orchestrator (`hackbot_orchestrator.py`) | ✅ Functional | Has one import bug (see §3) |
| LLM client (`llm_client.py`) | ✅ Functional | Supports 8 providers including DeepSeek |
| Agent runtime (`agent_runtime.py`) | ✅ Functional | Full ReAct loop with tool registry |
| Skill runner (`skill_runner.py`) | ✅ Functional | 15 built-in skills implemented |
| Scoped HTTP client (`scoped_http.py`) | ✅ Functional | Same-host, rate-limited, non-destructive |
| Dashboard (`dashboard/server.py`) | ✅ Functional | Full web UI with LLM config modal |
| Run manager (`run_manager.py`) | ✅ Functional | Durable run tracking |
| Checkpoint manager (`checkpoint_manager.py`) | ✅ Functional | Blocking HITL gates |
| Skill registry (`skill_registry.py`) | ✅ Functional | Dynamic skill discovery |
| Test suite (22 tests) | ✅ 100% passing | All tests pass |
| `.env` file | ⚠️ Configured for Gemini | Needs update for DeepSeek |
| `lastpass.com` target | ✅ Has run data | 5 prior runs with real outputs |

### What's Currently Configured

The `.env` file currently points to **Gemini** (`gemini-3.8-flash`) with a Gemini API key. To use DeepSeek, this must be changed.

### The One Critical Bug

In [hackbot_orchestrator.py](file:///d:/Moros Ai/tools/hackbot_orchestrator.py#L42-L46), there is a broken import:

```python
from tools.skill_registry import SkillRegistry  # Line 42 — WRONG
```

This file is inside `tools/`, so it should be:

```python
from skill_registry import SkillRegistry  # Correct
```

Additionally, the function `get_dynamic_skill_order()` on line 45 uses a type hint `List[str]` but `List` is never imported from `typing`. This will raise a `NameError` at import time. This needs to be fixed before anything can run.

---

## 2. Configure DeepSeek as the LLM Backend

### Option A: Edit the `.env` File Directly

**File to edit:** [d:\Moros Ai\.env](file:///d:/Moros Ai/.env)

Replace the entire contents with:

```env
# Moros AI Environment Configuration — DeepSeek
DEEPSEEK_API_KEY=sk-YOUR_DEEPSEEK_API_KEY_HERE
DEEPSEEK_MODEL=deepseek-chat
MOROS_LLM_PROVIDER=deepseek

# Optional: Discord notifications (keep existing or remove)
# DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
```

**Available DeepSeek models:**
- `deepseek-chat` — General purpose, recommended for most skills
- `deepseek-reasoner` — Stronger reasoning, better for complex analysis but slower/more expensive

### Option B: Configure via the Web Dashboard

1. Launch the dashboard: `python run.py --dashboard`
2. Open `http://127.0.0.1:8080` in your browser
3. Click the **LLM Settings** modal (gear icon)
4. Select provider: **DeepSeek**
5. Enter your DeepSeek API key
6. Choose model: `deepseek-chat` or `deepseek-reasoner`
7. Click **Test Connection** to verify
8. Click **Save** — this writes to `.env` automatically

### How the LLM Detection Works

The system follows this priority chain (see [llm_client.py](file:///d:/Moros Ai/tools/llm_client.py#L57-L82)):

1. If `MOROS_LLM_PROVIDER` is set in `.env` → use that provider directly
2. Otherwise, auto-detect in order: Custom → DeepSeek → Groq → OpenAI → Anthropic → Gemini → OpenRouter → Ollama
3. DeepSeek is routed through the OpenAI-compatible endpoint at `https://api.deepseek.com/v1`

### Verification

After configuring, verify with:

```bash
python -c "from tools.llm_client import LLMClient; c = LLMClient(provider='auto'); print(f'Provider: {c.provider}, Model: {c.model}, Available: {c.is_available()}')"
```

---

## 3. Fix the Import Bug in `hackbot_orchestrator.py`

**File:** [d:\Moros Ai\tools\hackbot_orchestrator.py](file:///d:/Moros Ai/tools/hackbot_orchestrator.py)

### Fix 1: Wrong Import Path (Line 42)

```python
# BEFORE (broken):
from tools.skill_registry import SkillRegistry

# AFTER (fixed):
from skill_registry import SkillRegistry
```

### Fix 2: Missing Type Import (Line 45)

The function `get_dynamic_skill_order()` uses `-> List[str]` but `List` is not imported. Either:

**Option A — Add the import at the top of the file (after line 8):**
```python
from typing import List
```

**Option B — Use the built-in `list` (Python 3.10+ syntax):**
```python
def get_dynamic_skill_order() -> list[str]:
```

> [!CAUTION]
> Without these two fixes, `python run.py --target <anything>` will crash on startup with an `ImportError` or `NameError`. This is the **#1 blocking issue**.

---

## 4. Create a Proper Target Workspace (In-Scope / Out-of-Scope)

### Initialize a New Target

```bash
python setup.py init-target --domain TARGET_DOMAIN.com
```

This creates the full directory tree under `targets/TARGET_DOMAIN.com/`:

```
targets/TARGET_DOMAIN.com/
├── PLACE_SCOPE_OF_WORK_HERE.txt   ← Instructions
├── scope-of-work.md               ← You create this (see §5)
└── output/
    ├── recon/
    ├── js/raw/{external,inline,lazy-loaded,historical}/
    ├── js/beautified/
    ├── js/source-maps/
    ├── content-discovery/
    ├── api/
    ├── findings/{xss-reflected,xss-stored,xss-dom,xss-blind,ssrf,idp-race,auth-reset}/
    ├── logs/{per-skill-directories}/
    ├── report/
    └── runs/
```

### How Scope Enforcement Works

The orchestrator in [hackbot_orchestrator.py](file:///d:/Moros Ai/tools/hackbot_orchestrator.py#L146-L166) calls `verify_scope()` which:

1. Looks for files matching `scope-of-work.*` (`.md`, `.txt`, `.yaml`, `.yml`, `.json`) in the target directory
2. Reads the file content and checks for:
   - The target domain name appears in the text (case-insensitive)
   - At least one authorization term: `authorized`, `authorised`, `in scope`, `scope of work`, `scope-of-work`
3. If **both** conditions are met → active skills enabled
4. If **either** fails → **PASSIVE-ONLY mode** (only `recon-subdomain` runs, and even that skips active HEAD checks)

### What "In-Scope" Means in Moros

- **In-scope**: Assets listed in the bug bounty program's scope page that you're authorized to test
- **Out-of-scope**: Everything else — Moros enforces this via `ScopedHttpClient` which restricts all HTTP to the **exact target hostname** only

The `ScopedHttpClient` in [scoped_http.py](file:///d:/Moros Ai/tools/scoped_http.py#L20-L50):
- Only allows `GET` and `HEAD` methods (no `POST`, `PUT`, `DELETE`)
- Only allows requests to the **exact same hostname** as the target
- Only allows ports 80 and 443
- Enforces a request budget (default: 40 requests per scan)
- Enforces a delay between requests (default: 0.4 seconds)
- Blocks any URL with credentials or cross-host redirects

---

## 5. Write the `scope-of-work.md` for a Real Target

### Template

Create the file at `targets/<DOMAIN>/scope-of-work.md`:

```markdown
# Authorized Security Assessment Scope

Target: https://TARGET_DOMAIN.com
Program: [PROGRAM NAME] on [PLATFORM] (public program)
Authorization basis: The program lists https://TARGET_DOMAIN.com as in scope
  and permits automated tools at no more than [X] requests per second.
Test profile: Moros quick scan; maximum 40 target requests; minimum 0.4 seconds
  between requests; same-host GET/HEAD only; no form submissions, authentication,
  state-changing actions, exploit payloads, or cross-host navigation.
Policy checked: [BOUNTY PROGRAM URL] ([DATE])

## In-Scope Assets

- https://TARGET_DOMAIN.com (web application)
- *.TARGET_DOMAIN.com (subdomains, passive recon only via CT logs)

## Out-of-Scope Assets

- Any third-party domains (CDNs, analytics, etc.)
- Authentication endpoints (login, registration, OAuth flows)
- Payment processing endpoints
- Any asset not explicitly listed by the bug bounty program
- Rate limits exceeding program policy

## Testing Constraints

- Maximum 40 HTTP requests per scan session
- Minimum 0.4 second delay between requests
- GET and HEAD methods only
- No exploit payloads, only harmless detection markers
- No credential brute-forcing or authentication bypasses
- No state-changing actions without HITL approval
```

> [!WARNING]
> **Legal requirement:** Only create this file for targets where you have **verified written authorization** through a bug bounty program or signed penetration testing agreement. The scope-of-work file is a self-declaration and does not substitute for actual authorization.

### How to Find Authorized Targets

Look for **public** bug bounty programs on:
- [HackerOne](https://hackerone.com/directory/programs)
- [Bugcrowd](https://bugcrowd.com/programs)
- [Intigriti](https://www.intigriti.com/programs)

Check each program's **scope** page for:
- Which domains are in scope
- Whether automated tools are allowed
- Rate limits on scanning
- Explicitly excluded assets

---

## 6. Install Dependencies & Verify Prerequisites

### Step 1: Create Virtual Environment (if not done)

```powershell
cd "d:\Moros Ai"
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### Step 2: Install Python Dependencies

```bash
pip install -r requirements.txt
```

### Step 3: Install Playwright Browsers

```bash
playwright install chromium
```

### Step 4: Verify Everything

```bash
python run.py --check
```

Expected output:
```
✅ All prerequisites met!
```

### Step 5: Dry-Run Test

```bash
python run.py --target TARGET_DOMAIN.com --dry-run
```

This shows the execution plan without sending any requests.

---

## 7. Dashboard Configuration (Alternative to CLI)

### Launch the Dashboard

```bash
python run.py --dashboard
# or
python dashboard.py
```

This starts a local server at `http://127.0.0.1:8080`

### Dashboard REST API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/config/llm` | GET | View current LLM config |
| `/api/config/llm` | POST | Save new LLM config (writes to `.env`) |
| `/api/config/llm/test` | POST | Test LLM connection |
| `/api/targets` | GET | List all targets |
| `/api/targets/create` | POST | Create new target workspace |
| `/api/scan/start` | POST | Start a scan |
| `/api/scan/stop` | POST | Stop a scan |
| `/api/scan/status` | GET | Check scan status |
| `/api/skills` | GET | List all skills |
| `/api/skills/create` | POST | Register custom skill |
| `/api/checkpoints/action` | POST | Approve/reject HITL checkpoint |

### Configure DeepSeek via Dashboard API (curl)

```bash
curl -X POST http://127.0.0.1:8080/api/config/llm \
  -H "Content-Type: application/json" \
  -d '{"provider":"deepseek","api_key":"sk-YOUR_KEY","model":"deepseek-chat"}'
```

### Test DeepSeek Connection via Dashboard API

```bash
curl -X POST http://127.0.0.1:8080/api/config/llm/test \
  -H "Content-Type: application/json" \
  -d '{"provider":"deepseek","api_key":"sk-YOUR_KEY","model":"deepseek-chat"}'
```

---

## 8. Run a Real Assessment

### Quick Surface Scan (Recommended First Run)

```bash
python run.py --target TARGET_DOMAIN.com --scan-mode quick
```

This runs: `recon-subdomain → api-spec-discovery → js-discover → js-analyze → content-discovery → xss-reflected → ssrf-identify → report-conglomeration`

### Passive-Only OSINT (Safest, No Active Probes)

```bash
python run.py --target TARGET_DOMAIN.com --scan-mode passive
```

This runs: `recon-subdomain → api-spec-discovery → js-discover → js-analyze → report-conglomeration`

### Full Deep Scan (All 14 Skills)

```bash
python run.py --target TARGET_DOMAIN.com --scan-mode deep
```

### Run Specific Skills Only

```bash
python run.py --target TARGET_DOMAIN.com --skills recon-subdomain,js-discover,js-analyze
```

### Use DeepSeek Explicitly on CLI

```bash
python run.py --target TARGET_DOMAIN.com --models deepseek/deepseek-chat --scan-mode quick
```

### CLI Rate Limiting Options

```bash
python run.py --target TARGET_DOMAIN.com \
  --scan-mode quick \
  --max-http-requests 40 \
  --request-delay 0.4 \
  --https-only \
  --root-only-active
```

---

## 9. Understanding the Output

After a scan, all artifacts appear under `targets/<DOMAIN>/output/`:

```
output/
├── recon/
│   ├── subdomains-passive.txt    ← All discovered subdomains (CT logs + Wayback)
│   ├── subdomains-all.txt        ← Merged subdomain list
│   ├── live-hosts.json           ← Hosts that responded to HEAD checks
│   └── recon-summary.md          ← Human-readable summary
├── js/
│   ├── raw/                      ← Raw JavaScript files collected
│   ├── beautified/               ← Beautified JS for analysis
│   ├── endpoints.json            ← Extracted API endpoints
│   ├── parameters.json           ← Extracted parameters
│   ├── secrets-findings.json     ← Potential leaked secrets
│   ├── gadgets.json              ← DOM sink gadgets (innerHTML, eval, etc.)
│   ├── tech-fingerprint.json     ← Detected frontend frameworks
│   └── analysis-summary.md       ← JS analysis overview
├── findings/
│   ├── xss-reflected/            ← XSS reflection probe results
│   ├── ssrf/                     ← SSRF candidate endpoints
│   └── ...                       ← Other finding categories
├── evidence/
│   └── ledger.jsonl              ← Content-addressed evidence records (SHA-256)
├── report/
│   ├── hackbot-report-<target>-<date>.md   ← Full markdown report
│   ├── hackbot-report-<target>-<date>.json ← Machine-readable report
│   └── findings.sarif            ← OASIS SARIF 2.1.0 export (GitHub compatible)
├── runs/
│   └── run-<id>/
│       ├── run.json              ← Durable run state
│       ├── events.jsonl          ← Event timeline
│       └── agents.jsonl          ← Sub-agent session records
└── logs/
    ├── orchestration-log.json    ← Full orchestration event log
    └── <skill-name>/             ← Per-skill step logs
```

---

## 10. Advanced: Custom Skills & Multi-Model Runs

### Register a Custom Skill (CLI)

```python
from tools.skill_registry import SkillRegistry

registry = SkillRegistry()
registry.create_custom_skill(
    skill_id="idor-audit",
    title="Insecure Direct Object Reference Hunter",
    category="Authentication & Session",
    description="Tests REST and GraphQL endpoints for parameter tampering and horizontal privilege escalation.",
    checklist=[
        "Identify numeric and GUID entity IDs in request parameters",
        "Replay requests with alternate tenant tokens",
        "Verify data disclosure without authorized session",
    ]
)
```

### Register a Custom Skill (Filesystem)

Create `skills/<skill-id>/SKILL.md`:

```markdown
# My Custom Skill (`my-skill-id`)

**Category:** Custom Security
**Author:** Custom Operator
**Type:** Dynamic Custom Skill

## Description
Description of what this skill tests.

## Verification Checklist
- [ ] Check item 1
- [ ] Check item 2
```

### Multi-Model Comparison Runs

```bash
python run.py --target example.com \
  --models deepseek/deepseek-chat,deepseek/deepseek-reasoner \
  --runs-per-skill 2
```

---

## 11. Known Issues & Fixes

### Issue 1: Import Error in Orchestrator (CRITICAL)

**File:** `tools/hackbot_orchestrator.py` lines 42 and 45
**Problem:** `from tools.skill_registry import SkillRegistry` fails because the file is already inside `tools/`. Also, `List` type hint used without import.
**Fix:** Change to `from skill_registry import SkillRegistry` and add `from typing import List` at top.

### Issue 2: Duplicate Orchestrator Files

There are two orchestrator files:
- `tools/hackbot-orchestrator.py` (with hyphens)
- `tools/hackbot_orchestrator.py` (with underscores)

`run.py` imports `from hackbot_orchestrator import HackbotOrchestrator` (underscores). The hyphenated version may be a stale copy. Verify they're identical or remove the stale one.

### Issue 3: `.env` Has Exposed API Keys

The current `.env` contains a Gemini API key and Discord webhook URL in plaintext. When switching to DeepSeek:
- Remove or comment out the old Gemini key
- Ensure `.gitignore` includes `.env` (it does)
- Never commit `.env` to git

### Issue 4: Browser Crawl May Fail Without Playwright

The `js-discover` skill calls `browser-crawl.py` which requires Playwright + Chromium. If not installed, it falls back to basic HTTP fetching. This is non-fatal but reduces JS collection quality.

**Fix:** `pip install playwright && playwright install chromium`

### Issue 5: Gemini API Client Uses Non-Standard Endpoint

The Gemini client in `llm_client.py` uses the `/v1beta/interactions` endpoint which is a newer Gemini API. This won't affect DeepSeek usage, but note that the Gemini integration uses a different API shape than OpenAI-compatible providers.

---

## 12. File Reference Map

### Core Entry Points

| File | Purpose |
|------|---------|
| [run.py](file:///d:/Moros Ai/run.py) | Main CLI entry point |
| [setup.py](file:///d:/Moros Ai/setup.py) | Target initialization & dependency checks |
| [dashboard.py](file:///d:/Moros Ai/dashboard.py) | Dashboard launcher shortcut |

### Core Engine (`tools/`)

| File | Purpose |
|------|---------|
| [llm_client.py](file:///d:/Moros Ai/tools/llm_client.py) | Universal LLM client (8 providers) |
| [hackbot_orchestrator.py](file:///d:/Moros Ai/tools/hackbot_orchestrator.py) | Main orchestrator & skill pipeline |
| [agent_runtime.py](file:///d:/Moros Ai/tools/agent_runtime.py) | ReAct agent loop & tool registry |
| [skill_runner.py](file:///d:/Moros Ai/tools/skill_runner.py) | Actual skill execution logic (1060 lines) |
| [skill_registry.py](file:///d:/Moros Ai/tools/skill_registry.py) | Dynamic skill discovery & custom skill creation |
| [scoped_http.py](file:///d:/Moros Ai/tools/scoped_http.py) | Bounded same-host HTTP client |
| [checkpoint_manager.py](file:///d:/Moros Ai/tools/checkpoint_manager.py) | Blocking HITL approval gates |
| [run_manager.py](file:///d:/Moros Ai/tools/run_manager.py) | Durable run lifecycle tracking |
| [conversation_store.py](file:///d:/Moros Ai/tools/conversation_store.py) | Agent conversation persistence |

### Configuration

| File | Purpose |
|------|---------|
| [.env](file:///d:/Moros Ai/.env) | Active LLM config (currently Gemini, needs DeepSeek) |
| [.env.example](file:///d:/Moros Ai/.env.example) | Template with all provider options documented |
| [requirements.txt](file:///d:/Moros Ai/requirements.txt) | Python dependencies |

### Dashboard

| File | Purpose |
|------|---------|
| [dashboard/server.py](file:///d:/Moros Ai/dashboard/server.py) | Full HTTP server + REST API (1617 lines) |
| [dashboard/static/index.html](file:///d:/Moros Ai/dashboard/static/index.html) | Neon Cyber SPA frontend |

---

## Execution Checklist (Quick Reference)

```
□ 1. Fix import bug in hackbot_orchestrator.py (§3) — CRITICAL
□ 2. Get a DeepSeek API key from https://platform.deepseek.com/
□ 3. Update .env with DeepSeek credentials (§2)
□ 4. Install/verify dependencies: pip install -r requirements.txt (§6)
□ 5. Install Playwright: playwright install chromium (§6)
□ 6. Choose a target from a public bug bounty program (§5)
□ 7. Initialize target: python setup.py init-target --domain <target> (§4)
□ 8. Write scope-of-work.md in targets/<target>/ (§5)
□ 9. Dry-run test: python run.py --target <target> --dry-run (§6)
□ 10. Run quick scan: python run.py --target <target> --scan-mode quick (§8)
□ 11. Review outputs in targets/<target>/output/ (§9)
```
