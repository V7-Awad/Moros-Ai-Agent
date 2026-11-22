# MOROS AI — Agentic Web Penetration Testing Automation System

<div align="center">

<img src="dashboard/static/logo.png" alt="MOROS AI" width="180" style="border-radius: 16px; box-shadow: 0 0 35px rgba(0, 119, 255, 0.45); border: 2px solid #00e5ff;">

### **MOROS AI AGENT**
**Autonomous Offensive Security & Web Penetration Testing Framework**

*Engineered by Raider & Moros Security Research Team*

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-00e5ff.svg?style=flat-square&logo=python&logoColor=white)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-0077ff.svg?style=flat-square)](LICENSE)
[![Tests Passing](https://img.shields.io/badge/tests-15%20passed%20(100%25)-19e6b0.svg?style=flat-square)](tests/)
[![HITL Gating](https://img.shields.io/badge/HITL-Enforceable%20Blocking-f1c26b.svg?style=flat-square)](#-enforceable-human-in-the-loop-hitl-gating)
[![UI: Neon Cyber](https://img.shields.io/badge/Dashboard-Neon%20Cyber%20Fluid-00e5ff.svg?style=flat-square)](#-interactive-web-dashboard)

</div>

---

## ⚡ Executive Summary

**MOROS AI** is an advanced, modular, agentic web penetration testing system designed for authorized dynamic (black-box) security assessments. Rather than relying on a single monolithic prompt, Moros coordinates **15 specialized micro-skills** via an explicit **ReAct (Reasoning + Action)** decision loop, structured tool registries, and sub-agent session lifecycles.

Moros strictly enforces an **evidence-first result model**: candidates are tied to cryptographically verified SHA-256 artifact hashes, state-changing endpoints are held by blocking human gates, and all operations can be driven through an interactive, full-screen **Neon Cyber Web Dashboard**.

---

## 🛡️ Key Features

- 🧠 **Autonomous ReAct Agent Runtime**: Real decision loop (`Thought` ➔ `Action` ➔ `Observation` ➔ `Final Answer`) with timeout-bounded tool calls and explicit `LLM_UNAVAILABLE` fallback.
- 🎛️ **In-Dashboard LLM & API Management**: Switch models, configure endpoints, and validate API connections (DeepSeek, OpenAI, Anthropic Claude, Groq, Gemini, OpenRouter, Ollama, LM Studio, vLLM) directly inside the Web UI.
- 🛑 **Enforceable Blocking Human-in-the-Loop (HITL)**: Deterministic approval gates (`WAITING_APPROVAL`) that genuinely suspend worker threads before executing state-changing actions (`POST`, `PUT`, `DELETE`, password resets, race conditions) until authorized by the operator.
- 🖥️ **Full-Screen Neon Cyber Web Dashboard**: Ultra-responsive fluid monitoring interface featuring live multi-agent chat, tool terminal streams, PoC reproduction cards, and visual pipeline graphs.
- 🧬 **Sub-Agent Session Tracking**: Child agent lifecycle tracking (`agents.jsonl`) recording runtime metrics, model allocations, and finding provenance.
- 📦 **15 Modular Security Skills**: Subdomain intelligence, headless browser JS crawling, AST parameter extraction, secret scanning, content discovery, XSS (reflected/stored/DOM/blind), SSRF exploitation, and IdP race audits.
- 🔒 **Scope & Compliance Gating**: Mandatory scope-of-work validation (`scope-of-work.md` / `.pdf`) before offensive execution; runs strictly in passive mode when unverified.
- 🧪 **Comprehensive Automated Test Suite**: 100% test coverage across agent loops, blocking gates, durable runs, and dependency resolution (`pytest`).

---

## 🏗️ System Architecture

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                       MOROS AI COORDINATOR & HARNESS                        │
│   • Authorization & Scope Guard           • Run Lifecycle Manager           │
│   • Sub-Agent Session Tracking            • Enforceable Blocking HITL Gate  │
└───────────────────────┬──────────────────────────────┬──────────────────────┘
                        │                              │
         ┌──────────────▼──────────────┐ ┌─────────────▼─────────────┐
         │     SPECIALIZED AGENTS      │ │       REACT RUNTIME       │
         │  • Subdomain Hunter         │ │  • Bounded Tool Registry  │
         │  • JS & API Specialist      │ │  • Context & Memory Store │
         │  • Client-Side Auditor      │ │  • Execution Timeouts     │
         │  • SSRF & Cloud Pivoter     │ │  • Observation Streaming  │
         │  • Auth & Race Condition    │ │  • Fallback Engine        │
         └──────────────┬──────────────┘ └─────────────┬─────────────┘
                        │                              │
                        └──────────────┬───────────────┘
                                       ▼
                       targets/<target>/output/
                       ├── runs/<run_id>/ (run.json, events.jsonl, agents.jsonl)
                       ├── logs/checkpoints.json (durable HITL gate records)
                       ├── evidence/ledger.jsonl (content-addressed provenance)
                       └── report/hackbot-report-<target>-<date>.md
```

---

## 🚀 Quick Start Guide

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/V7-Awad/Moros-Ai-Agent.git
cd Moros-Ai-Agent

# Create and activate Python virtual environment
python -m venv venv

# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Install required dependencies
pip install -r requirements.txt

# Install Playwright browser engine for JavaScript discovery
playwright install chromium
```

### 2. Configure LLM Backend (Optional)

Moros AI is **100% functional offline** out-of-the-box. To enable generative ReAct tool loops, copy `.env.example` to `.env` or configure your API key directly from the Web Dashboard:

```powershell
copy .env.example .env
```

Supports any LLM backend:
- **DeepSeek**: `DEEPSEEK_API_KEY=sk-...` (`deepseek-chat` / `deepseek-reasoner`)
- **OpenAI**: `OPENAI_API_KEY=sk-proj-...` (`gpt-4o`, `gpt-4o-mini`, `o3-mini`)
- **Anthropic**: `ANTHROPIC_API_KEY=sk-ant-...` (`claude-3-5-sonnet-20241022`)
- **Groq**: `GROQ_API_KEY=gsk_...` (`llama-3.3-70b-versatile`)
- **Local Ollama (Offline & Free)**: `OLLAMA_BASE_URL=http://localhost:11434` (`llama3`, `deepseek-r1:8b`)
- **Custom Local Gateway (LM Studio / vLLM)**: `OPENAI_BASE_URL=http://localhost:1234/v1`

---

## 🖥️ Interactive Web Dashboard

Launch the local web dashboard for complete visual control over assessments, real-time agent monitoring, and human checkpoint approvals:

```bash
# Launch dashboard directly (opens http://127.0.0.1:8080)
python run.py --dashboard

# Or via the standalone launcher:
python dashboard.py
```

### Dashboard Capabilities:
- **Operations Center**: Instant target switching, scope verification indicators, and assessment launchpad.
- **LLM Settings Modal**: Configure and test API endpoints dynamically without restarting the server.
- **Agent Command Console**: Interact with specialized sub-agents (`coordinator`, `js-analyzer`, `xss-specialist`, `ssrf-specialist`).
- **HITL Checkpoints Manager**: Real-time review and 1-click Approve/Reject for state-changing HTTP requests.
- **PoC & Evidence Inspector**: Formatted vulnerability cards with ready-to-run cURL reproduction commands and SHA-256 artifact hashes.
- **Live Tool Terminal**: Real-time streaming log viewer for all background processes.
- **Executive Deliverables**: Formatted markdown and JSON report viewer with instant export.

---

## ⌨️ Command Line Interface (CLI)

```bash
# Verify system prerequisites
python run.py --check

# Initialize a new target workspace
python setup.py init-target --domain app.example.com

# Run full assessment pipeline
python run.py --target app.example.com

# Execute specific micro-skills
python run.py --target app.example.com --skills recon-subdomain,js-discover,js-analyze

# Dry-run execution plan without sending network requests
python run.py --target app.example.com --dry-run
```

---

## 🛑 Enforceable Human-in-the-Loop (HITL) Gating

Safety and authorization are non-negotiable architectural requirements. Unlike passive logging systems, Moros AI uses **blocking thread synchronization**:

1. When a micro-skill discovers an endpoint with a state-changing method (`POST`, `PUT`, `DELETE`) or high-impact actions (OAuth redirects, brute-forcing), a deterministic checkpoint (`cp-<hash>`) is registered.
2. The worker thread pauses on a thread event (`threading.Event`).
3. The operator reviews the pending action via the Web Dashboard or REST API.
4. **Approve**: Wakes the worker thread immediately to proceed with testing.
5. **Reject / Timeout**: Safely bypasses the action, records the audit notes, and continues the pipeline without disruption.

---

## 🧩 Adding Custom Micro-Skills

Moros AI is designed for rapid modular extension:

### Step 1: Create Skill Metadata
Create `skills/<new-skill-name>/SKILL.md` defining the skill objective and methodology checklist.

### Step 2: Implement Execution & Register Tools
In `tools/skill_runner.py`, define the execution method and expose tools through `ToolRegistry`:
```python
def run_custom_audit(self) -> Dict[str, Any]:
    registry = ToolRegistry()
    registry.register("audit_tool", my_tool_func, "Executes specific security check")
    
    agent = AgentRunner(llm_client=self.llm)
    context = AgentContext(target=self.target, target_dir=self.target_dir, skill="custom-audit", run_id="run-1")
    
    result = agent.run(
        context=context,
        tools=registry,
        system_prompt="You are a specialized security agent.",
        user_goal=f"Assess target {self.target}."
    )
    return {"status": "SUCCESS", "findings_count": len(result.findings)}
```

### Step 3: Register Dependencies in Orchestrator
In `tools/hackbot_orchestrator.py`:
- Add the skill name to `SKILL_ORDER`.
- Define prerequisites in `SKILL_DEPENDENCIES` (e.g., `{"custom-audit": ["js-analyze"]}`).
- Add the dispatch branch in `_execute_skill()`.

---

## 🧪 Automated Testing

Verify system stability with the complete automated test suite:

```bash
python -m pytest -v tests/
```

```text
============================= test session starts =============================
collected 15 items

tests/test_agent_runtime.py::test_tool_registry_registration_and_execution PASSED [  6%]
tests/test_agent_runtime.py::test_agent_context_and_result_dataclasses PASSED [ 13%]
tests/test_agent_runtime.py::test_agent_runner_react_loop PASSED         [ 20%]
tests/test_agent_runtime.py::test_agent_runner_llm_unavailable_fallback PASSED [ 26%]
tests/test_checkpoint_manager.py::test_checkpoint_creation_and_deterministic_id PASSED [ 33%]
tests/test_checkpoint_manager.py::test_checkpoint_approval_and_rejection PASSED [ 40%]
tests/test_checkpoint_manager.py::test_checkpoint_blocking_worker_wakes_on_decision PASSED [ 46%]
tests/test_checkpoint_manager.py::test_checkpoint_timeout_rejects PASSED [ 53%]
tests/test_dependency_validation.py::test_missing_dependency_unscheduled_is_blocked PASSED [ 60%]
tests/test_dependency_validation.py::test_dependency_with_disk_artifact_is_not_blocked PASSED [ 66%]
tests/test_dependency_validation.py::test_scheduled_prerequisites_are_not_blocked PASSED [ 73%]
tests/test_run_manager.py::test_run_creation_and_persistence PASSED      [ 80%]
tests/test_run_manager.py::test_run_event_stream_and_progress PASSED     [ 86%]
tests/test_run_manager.py::test_finish_run PASSED                        [ 93%]
tests/test_run_manager.py::test_agent_session_tracking PASSED            [100%]

============================= 15 passed in 2.85s ==============================
```

---

## ⚖️ Legal & Ethical Compliance

> **IMPORTANT**: This software is intended strictly for authorized penetration testing, vulnerability assessments under signed rules of engagement, and approved bug bounty programs. Performing unauthorized scans or attacks against computer systems without explicit written permission is strictly prohibited by law.

---

## 👤 Author & Credits

- **Lead Architecture & Development:** **Raider** (`By Raider`)
- **Research & Core Framework:** Moros AI Security Team
- **License:** [MIT License](LICENSE)
