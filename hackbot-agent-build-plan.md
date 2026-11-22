# Build Plan: Agentic Web Pentest Automation System ("Hackbot")

> Source: distilled from a DEF CON / Bug Bounty Village talk by Jason (Arcanum Information Security, creators of "Armada") on building offensive-security agents with Claude Code–style harnesses.
> Purpose: hand this file to an implementing agent (Claude Code, Codex, OpenCode, etc.) as the authoritative spec for building an **authorized** web-application penetration testing automation system.
> Scope note: this plan is for **authorized security testing only** (bug bounty programs, pentests with signed scope, or lab/academic environments like a graduation project). The implementing agent must enforce explicit written authorization/scope-of-work before any skill runs against a real target, and must keep a human in the loop for all critical decisions (see Section 1).

---

## 0. Project Goal

Build a modular, skill-based AI agent system that automates **dynamic (black-box) web application testing**: given a domain/target with a documented, signed scope of authorization, the system should autonomously perform reconnaissance, JavaScript/endpoint discovery, content discovery, and vulnerability-category-specific testing, producing a structured, reviewed, human-auditable report.

This is NOT meant to be "one giant agent that hacks everything." It is a collection of small, single-purpose **skills** orchestrated by a harness, with built-in self-review and human checkpoints.

---

## 1. Non-Negotiable Design Requirements

1. **Human-in-the-loop is mandatory, not optional.** No skill may be allowed to run in a fully unattended "find and auto-exploit production systems" mode without a human reviewing before any state-changing or destructive action (password resets, data deletion, write/update endpoints).
2. **Authorization artifact required before any run.** Every project/target folder must contain a scope-of-work / rules-of-engagement file (PDF or signed doc) that the harness checks for before executing any skill against that target. If it's missing, the harness refuses to run offensive skills and only allows passive recon.
3. **Never call destructive HTTP methods (DELETE, or state-changing POST/PUT) automatically.** Any skill that discovers a potentially destructive endpoint must stop and flag it for human confirmation rather than invoking it.
4. **Severity ratings proposed by the AI are provisional.** Every finding must be labeled `AI-proposed severity: <level> — pending human review` until a human tester confirms it. AI tends to overrate criticality; do not let unreviewed findings reach a final report.
5. **No chaining of "low" findings into a "critical" claim without a human-approved exploit chain.** The system should surface candidate chains (e.g., open redirect + OAuth misconfig) but a human must validate before reporting as critical.
6. **Everything logged, nothing silent.** Every tool call, every skill step, and every agent action must write a non-empty log file to the project's output folder. If a tool "didn't run," that must be visible, not silently skipped.

---

## 2. Choose the Agent Harness

Recommended, in order of preference:

1. **Claude Code** — primary harness. Supports Agent Skills (Markdown-defined), sub-agents, workflows, hooks, and per-skill model/reasoning-effort selection.
2. **Codex** (OpenAI harness) — secondary/parallel harness for cross-model validation (see Section 7, multi-model runs).
3. **OpenCode** — open-source harness, used specifically for routing to **local/open-weight models** (e.g., Kimi, GLM, or a fine-tuned custom model) so that not every run depends on frontier-model API cost.
4. (Optional, advanced) A custom-built harness, only once you understand where the above three fall short for your use case.

The implementing agent should scaffold the project to work primarily against Claude Code's Agent Skills format, since it's the most portable (Codex and OpenCode have converged on compatible Markdown skill definitions).

---

## 3. Repository / Folder Structure

```
project-root/
  skills/                     # all skill definitions (see Section 4)
    recon-subdomain/
      SKILL.md
    js-discover/
      SKILL.md
    js-analyze/
      SKILL.md
    content-discovery/
      SKILL.md
    xss-reflected/
      SKILL.md
    xss-stored/
      SKILL.md
    xss-dom/
      SKILL.md
    xss-blind/
      SKILL.md
    ssrf-identify/
      SKILL.md
    ssrf-post-exploit/
      SKILL.md
    idp-race-condition/
      SKILL.md
    auth-password-reset-bruteforce/
      SKILL.md
    review-skill/
      SKILL.md             # the "reviewer" / completion-checker, see Section 6
    report-conglomeration/
      SKILL.md
  targets/                    # ONE folder per engagement — never write output inside skills/
    <target-domain>/
      scope-of-work.pdf        # REQUIRED before any skill may run against this target
      output/
        recon/
        js/
        content-discovery/
        findings/
        logs/
        report/
  tools/                       # wrapper scripts with FIXED, explicit syntax (see Section 8)
  docs/
    architecture.md
    completion-checklist-format.md
```

**Rule:** skills must never write their working output inside `skills/<skill-name>/`. All output goes into `targets/<target>/output/...` with full, explicit paths referenced in every prompt. A bloated skill folder degrades agent performance.

---

## 4. Skill Format (Markdown Agent Skills)

Each skill is a folder containing:
- `SKILL.md` — required. Frontmatter with `name` and `description` (this is the ONLY part loaded into context by default — keep the description accurate and free of language that could trip safety classifiers unnecessarily, see Section 9).
- Optional supporting files: `reference.md` (output format spec), `examples/` (example good runs), `scripts/` (helper scripts the skill can invoke).
- Optional per-skill config: target model, reasoning effort, whether it inherits the parent conversation's context or runs as an isolated sub-agent/fork.

### 4.1 Core principle: keep skills small ("micro-skills")

Do **not** build one monolithic "find XSS" skill. Build:
- `xss-reflected`
- `xss-stored`
- `xss-dom`
- `xss-blind`

Why: LLMs exhibit **completion bias** — given a long multi-phase methodology (e.g., 20 steps), the model tends to silently do only the first few steps and report success anyway. The mitigation is to make each skill's job as small and discrete as possible, and to verify completion explicitly (Section 6) rather than trust the model's self-report.

### 4.2 Case study skill: `js-analyze` (treat as the reference implementation)

Because JavaScript analysis is the foundation most other recon depends on, build this skill first and in two parts, per the completion-bias mitigation above:

**Part A — `js-discover` (download/collection only):**
- Collect **live** JavaScript: both external `.js` files AND inline `<script>` blocks on every page. Do not skip inline JS — this is a common miss.
- Collect **lazy-loaded** JavaScript (code that only loads after a click, scroll, auth, or route change) — requires actually driving the browser, not just a static fetch.
- Collect **historical** JavaScript: query the Wayback Machine and similar web-archive snapshot APIs for old `.js` bundles and old API versions that may still be live but unlinked from the current UI.
- Attempt to find leaked **source maps** for every JS file (try `<file>.js.map`, common source-map directories, and check associated mobile apps — mobile app bundles sometimes ship the same JS with source maps attached).
- Do NOT use a generic HTTP client's default user agent for spidering — anti-bot protections will silently block generic fetch/cURL-style requests. Use a real browser-driven approach (see Section 8: Interceptor-style browser tool) so traffic looks like a real user session and nothing gets silently dropped.
- Output: raw + beautified JS files, source maps (where found), one directory per site, saved to `targets/<target>/output/js/raw/` and `.../beautified/`.

**Part B — `js-analyze` (analysis only, consumes Part A's output):**
- Deobfuscate/unminify every collected file.
- Parse out: all API endpoints and routes, all parameters and their mapped functions, organized by recognizable section (admin routes, user routes, etc.).
- Identify "gadgets" / dangerous sink functions usable for client-side bug chaining (e.g., DOM XSS sinks).
- Flag: admin-only feature flags, debug/test parameters, and **developer comments** — comments are frequently overlooked but have historically revealed sensitive info.
- Identify outdated third-party JS libraries with known CVEs.
- Fingerprint the frontend framework/tech stack, and cross-reference with known historical misconfigurations for that framework.
- Extract secrets using both known-pattern regexes (API keys, tokens) AND generic **high-entropy string detection** (to catch secret formats with no known regex).
- Output artifacts, one directory per site, with an EXACT required structure (give the model ~5–10 concrete examples of "what a complete run's output directory looks like" in `reference.md`), e.g.:
  ```
  output/<site>/
    raw/{inline,external}/
    beautified/{inline,external}/
    source-maps/{inline,external}/
    endpoints.json
    parameters.json
    secrets-findings.json
    tech-fingerprint.json
    curl-commands.sh        # one executable curl per discovered endpoint
  ```
- Also emit a `curl-commands.sh` file with one ready-to-run curl command per discovered endpoint, so output is directly usable by a human tester or passed to another skill/agent.

### 4.3 Other skills to scaffold (same micro-skill philosophy)

- **`content-discovery`**: generate a brute-force wordlist that is NOT generic — derive it from the target's actual detected framework/tech stack (from `js-analyze`'s `tech-fingerprint.json`) plus a general baseline list. Separate "generic list" vs. "framework-specific list." Target categories: admin panels, config files, backup files, exposed build artifacts.
- **`ssrf-identify`**: find parameters that accept URLs and test standard SSRF probes. Keep this skill only about *identification*; do not fold post-exploitation into it.
- **`ssrf-post-exploit`** (separate skill, runs only after `ssrf-identify` confirms a hit): deprioritize classic cloud-metadata-endpoint SSRF chains (increasingly mitigated behind required headers; also over-represented/outdated in LLM training data) and prioritize scanning internal `localhost`/loopback services and ports for exposed admin panels (e.g., infrastructure/orchestration admin UIs with no auth) as the primary post-exploitation target.
- **`idp-race-condition`**: specifically watches for the brief window where a single-page app's initial content loads before a redirect to an external identity provider (OAuth/SSO redirect). Many backends rely on the IdP alone for auth and don't separately authenticate each API call — capturing and replaying those pre-redirect API calls without auth is the target bug class. Requires a browser-automation tool capable of intercepting and briefly delaying/blocking redirects to capture this window (see Section 8).
- **`auth-password-reset-bruteforce`**: when a password-reset-style form has no username/email field (suggesting a hidden admin-only password-set function), attempt parameter brute-forcing of common identifier names (`id`, `username`, `admin`, etc.) — but only as a documented technique within authorized scope, and always surfacing the result for human confirmation before any session/auto-login is used.
- **`review-skill`**: see Section 6.
- **`report-conglomeration`**: final skill that reads every finding + log file across all skill runs and all model runs (Section 7) and assembles the unified report, with every finding tagged with its "AI-proposed severity — pending human review" status.

---

## 5. Prompting Principles for Every Skill

1. **Avoid "bitter pill" one-line prompting** ("hack this site, get me a crit, make no mistakes") for anything beyond trivial recon. It works with the most frontier models for simple tasks but performs poorly for deep, multi-step application testing. Use explicit, step-by-step methodology instead.
2. **Fully specify tool syntax — never leave it to the model's discretion.** E.g., don't prompt "probe the subdomain with httpx"; instead specify exact flags: which ports to scan (not just defaults), and which fields to capture (title, server header, IP, CDN, etc.). If syntax is left vague, the model will default to the laziest invocation.
3. **Always reference full, absolute paths** for every tool call, every sub-agent invocation, and every output location. Ambiguous relative paths cause agents to falsely conclude "the tool isn't installed" and either silently skip the step or improvise a worse substitute.
4. **Give the model a concrete "yardstick" for what a complete, successful run's output looks like** — not just instructions on what to do, but ~5–10 examples of the exact expected output directory/file structure. Put this in each skill's `reference.md`.
5. **Markdown checklists inside every skill.** Each skill's methodology should be expressed as a literal Markdown checklist (`- [ ] step A`, `- [ ] step B`, ...). The skill is only considered complete when every box is checked, with evidence. This is the core mechanism used to fight completion bias.

---

## 6. Completion Verification: the Review Skill

Because frontier and local models alike will under-report work done (completion bias) and sometimes claim a tool ran when it didn't, build a **separate reviewer skill** that runs after each primary skill:

- Prefer using a **different model** than the one that ran the skill (e.g., have a Gemini-backed reviewer check Claude's work, or vice versa) — this avoids a model marking its own homework.
- The reviewer's job, mechanically:
  1. Open the skill's Markdown checklist output. Confirm every item is checked.
  2. For every checklist item, confirm a corresponding **non-zero-byte log file** exists for every tool call / action that step claims to have performed.
  3. Optionally parse log contents to confirm the claimed action is plausible given the log.
  4. If anything is missing or a log is empty/zero-byte: mark the skill run as **FAILED** for that specific checklist item (not the whole skill, if other items passed).
- On failure, generate a **nudge prompt** and re-invoke the original skill. Keep the nudge prompt generic (since you often won't know exactly why something failed), e.g.:
  > "Your work was just reviewed and it was found that either you missed a step of analysis or did not generate an artifact of sufficient proof. Look at the Markdown checklist and the output for each step, find what you missed, and complete the step."
- Loop (retry) a bounded number of times; if still failing, report a **critical skill failure** to the human rather than silently giving up or silently declaring success.

---

## 7. Execution Strategy: Multiple Models, Multiple Runs

LLMs are non-deterministic and different model families surface different findings even against identical skills/targets. Design the orchestrator to:

1. Run every skill multiple times across multiple model backends per full assessment (example tiering used as inspiration — adjust to your budget):
   - 1–2 frontier-tier runs (e.g., top-tier hosted model) per skill
   - 1–2 mid-tier hosted model runs (a different vendor) per skill
   - 1–2 cheaper/local model runs (open-weight models via OpenCode) per skill
2. Optionally run 2–3 full repeats of the whole skill set to catch run-to-run variance.
3. Additionally run a couple of "bitter pill" (minimal-prompt) passes with skills disabled, purely to see what the raw frontier model finds unprompted — useful both as a sanity check and as a way to discover what a newer model can already do "for free" without needing it hard-coded into a skill (see Section 10, retuning).
4. Aggregate **all** output directories from all runs into the target's `output/` tree, then invoke `report-conglomeration` once at the end to merge everything into one findings report, deduplicating and cross-referencing by endpoint/vulnerability class.
5. Favor the cheaper tiers as your default workhorse for skill-engineered (methodology-heavy) tasks; reserve frontier/expensive models for tasks that benefit from minimal-prompt "bitter pill" exploration or especially novel reasoning.

---

## 8. Supporting Tooling Requirements

- **Browser-driving tool for dynamic spidering** (instead of raw `curl`/generic HTTP fetch, which gets silently blocked by anti-bot/anti-automation protections on many real sites): the harness needs a tool that drives a real browser, captures all network traffic locally, clicks through every interactive element, follows every link, and specifically supports:
  - A "spider" mode that exhaustively traverses the site (every button, every link) and downloads every piece of code encountered, including JS chunked/loaded from third-party domains.
  - A redirect-interception mode that can briefly hold/delay an in-progress redirect (needed for the `idp-race-condition` skill) to give the agent time to capture pre-redirect API traffic.
  - Logging all captured traffic to disk in a structured, parseable format (for `js-discover` and the SSRF/IdP skills to consume).
- **Wayback-Machine-style historical snapshot tool**: queries web archive snapshot APIs (not just the Wayback Machine alone — include other snapshot/history providers if available) to recover old JS bundles and old/unlinked API versions.
- **Wrapper scripts for all CLI tools used by skills** (e.g., subdomain/port scanners, content-discovery fuzzers): wrap them with a fixed, explicit, pre-agreed syntax/flag set per Section 5, rather than letting the agent invoke the raw binary with whatever flags it chooses.

---

## 9. Classifier / Refusal Considerations (Legitimate-Use Context)

Since this system performs **security testing language and actions** that pattern-match to malicious activity, be deliberate about avoiding false-positive refusals for legitimate, authorized work:

- Keep skill `description` fields (the part always loaded into context) professionally worded and focused on *what artifact the skill produces*, rather than loaded "offensive" terminology, where a more neutral phrasing works just as well.
- Maintain the required `scope-of-work` authorization artifact (Section 1, requirement 2) in every target folder, and have skills reference it explicitly when operating, so there is always a clear, legitimate, documented basis for the work in-context.
- If available for your use case/provider, apply through any official **trusted-access / verified-researcher program** for the model vendor(s) you use — these programs are designed exactly for people doing authorized bug bounty / pentest work and reduce unnecessary refusals.
- Be aware that **agent "workflow" / parallel-fan-out features** are often subject to a more aggressive tool-call classifier than a normal single-agent conversation, and can **silently fail** individual tool calls without surfacing an obvious error — always check per-step logs (Section 1, requirement 6) rather than assuming a workflow run that "looks done" actually completed every step.

---

## 10. Maintenance: Retuning Skills When Models Update

Whenever the underlying model(s) are upgraded:
1. Run each skill's underlying task in a **"safe mode" / bare-model pass**: strip the custom skill instructions and identity/context files, and give only a minimal, bare-pill instruction (e.g., "find all the JavaScript on this site") to see what the new model can already do unaided.
2. If the bare model now reliably handles something that used to require explicit step-by-step prompting in a skill, **remove that explicit instruction from the skill** and rely on the model's native capability instead.
3. Repeat this pass after every model generation change, so skills stay as lean as possible over time and you rely on explicit engineering only where models still need it.

---

## 11. Suggested Build Order (for the implementing agent)

1. Scaffold the folder structure (Section 3).
2. Build `js-discover` + `js-analyze` first (reference implementation, Section 4.2) — almost everything else depends on its output.
3. Build `review-skill` next, and wire it to run after `js-analyze` before anything else — get the completion-verification loop working early since every later skill reuses it.
4. Build `content-discovery`, consuming `js-analyze`'s tech-fingerprint output.
5. Build the vulnerability-class skills one at a time, starting with the simplest (`xss-reflected`) before the harder ones (`ssrf-identify` → `ssrf-post-exploit`, `idp-race-condition`, `auth-password-reset-bruteforce`).
6. Build `report-conglomeration` last.
7. Wire up multi-model/multi-run orchestration (Section 7) only once individual skills are each independently verified to work well on at least one real authorized test target.
8. Document the human-review checkpoints (Section 1) clearly in `docs/architecture.md` so anyone operating the system knows exactly where a human must sign off.

---

## 12. Open Decisions for the Team to Make (not prescribed here)

- Which harness to standardize on first (recommend: Claude Code).
- Which models to use at each tier in Section 7 (budget-dependent).
- Exact wordlists / tool choices for content discovery (framework-specific lists should be curated/reviewed by the team, not fully improvised by the agent).
- Reporting format/template for the final conglomerated report (should align with whatever your course/organization requires for a pentest report deliverable).
