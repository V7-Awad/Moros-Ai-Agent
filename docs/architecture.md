# Moros — Architecture & Operations Guide

> **Moros** is a modular, skill-based offensive security automation framework for authorized dynamic (black-box) web application penetration testing.

---

## System Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     ORCHESTRATOR / HARNESS                  │
│  • Reads scope-of-work before any skill runs                │
│  • Routes skills to configured model backends               │
│  • Enforces human-in-the-loop checkpoints                   │
│  • Manages multi-model / multi-run execution                │
└─────────┬───────────────┬───────────────┬───────────────────┘
          │               │               │
    ┌─────▼─────┐   ┌────▼─────┐   ┌─────▼──────┐
    │  SKILLS   │   │  TOOLS   │   │  REVIEW    │
    │ (micro)   │   │ (wrappers│   │  SKILL     │
    │           │   │  + CLI)  │   │            │
    └─────┬─────┘   └────┬─────┘   └─────┬──────┘
          │               │               │
          └───────────────┼───────────────┘
                          │
                ┌─────────▼──────────┐
                │  targets/<domain>/ │
                │    output/         │
                │    scope-of-work   │
                └────────────────────┘
```

---

## Human-in-the-Loop Checkpoints

These are the **mandatory** points where the system MUST pause and wait for human confirmation before continuing:

| Checkpoint | When | What Must Be Reviewed |
|---|---|---|
| **Pre-Run Authorization** | Before any skill runs against a target | `scope-of-work.{md,txt,yaml,yml,json}` containing the target domain and authorization wording must exist in `targets/<domain>/` (`verify_scope()`) |
| **Destructive Actions** | Before any DELETE, state-changing POST/PUT | Exact request to be sent, target endpoint, rationale |
| **Exploit Chain Claims** | Before labeling a chain of low findings as critical | Full chain with evidence at each step |
| **Password Reset / Auth Brute-force** | Before any credential-related testing | Specific parameters and wordlist to be used |
| **Final Report Approval** | Before report delivery | All findings require operator sign-off and validation before delivery |

---

## Execution Flow

```
1. Load target → Check scope-of-work exists
2. Run recon-subdomain (passive recon)
3. Run js-discover → review-skill checks output
4. Run js-analyze → review-skill checks output
5. Run content-discovery → review-skill checks output
6. Run vulnerability skills (xss-*, ssrf-*, idp-*, auth-*) → review-skill after each
7. Run report-conglomeration to merge all findings
8. Human reviews final report, confirms/adjusts severities
```

Each step may be run with **multiple models** and repeated 2–3 times for coverage.

---

## Severity Rating Policy

All candidate severity ratings MUST be labeled:

```
Triage Severity: <CRITICAL|HIGH|MEDIUM|LOW|INFO> — pending human review
```

A finding's severity is NOT finalized until a human pentester confirms it. Automated scanners systematically over-rate criticality.

---

## Logging Policy

- **Every** tool call, skill step, and agent action writes a log file.
- Zero-byte or missing log files trigger an automatic **FAILED** status from the review-skill.
- Logs are stored in `targets/<domain>/output/logs/<skill-name>/`.
- If a tool "didn't run," that must be explicitly logged as "SKIPPED: <reason>".

---

## Folder Conventions

- Skills NEVER write output inside `skills/<name>/`. All output → `targets/<domain>/output/`.
- Each target gets its own folder under `targets/`.
- `scope-of-work.md` (or `.txt`, `.yaml`, `.yml`, `.json`) containing the target domain and authorization wording is **required** in each target folder before active offensive skills run.

---

## Model Tiering Strategy

| Tier | Use Case | Example Models |
|---|---|---|
| Frontier | Complex reasoning, context escape analysis | Claude 3.5 Sonnet, GPT-4o, DeepSeek-R1 |
| Mid-tier | Methodology-driven skill execution | DeepSeek-Chat, GPT-4o-mini |
| Local/Open | High-volume, offline & budget-friendly runs | Llama 3.3, Mistral, Qwen 2.5 via Ollama/vLLM |

The default workhorse should be mid-tier/local models for methodology-heavy tasks; reserve frontier models for complex multi-step reasoning.
