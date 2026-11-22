# Moros AI Agent — Current Gaps and Implementation Plan

**Review date:** 2026-11-22  
**Project:** Moros AI Agent  
**Reference:** Strix architecture and viewer concepts  
**Purpose:** This document lists the current implementation gaps that should be reviewed and addressed by the next development agent.

## Executive Summary

Moros AI currently provides a useful local assessment harness with a Dashboard, target/output structure, OpenAPI import, browser and JavaScript tooling, findings, reports, logs, checkpoints, and a local conversation viewer.

However, it is not yet a fully autonomous multi-agent security system. The largest gap is that the LLM client exists but is not connected to the actual skill execution loop. Most skills still behave as deterministic or heuristic tool pipelines rather than independent AI agents that reason, call tools, maintain context, and communicate with one another.

The next milestone should focus on execution correctness, persistent state, real agent runtime behavior, and test coverage before adding many more security skills.

## Verified Current Health

The following checks currently pass:

```text
python run.py --check                 PASS
python -m compileall -q dashboard tools PASS
```

The Dashboard includes the following working or partially working areas:

- Local target selector and target management.
- Overview metrics and findings display.
- Skills graph and execution status display.
- JavaScript and OpenAPI endpoint inventory.
- Findings and PoC cURL presentation.
- Human checkpoint display and approval buttons.
- Live execution logs and tool terminal.
- Markdown report viewer.
- Agent Conversations tab with local JSONL storage.
- MOROS wordmark beside the logo.

## Priority 0 — Build a Real Agent Runtime

### Problem

`tools/llm_client.py` supports several providers, including OpenAI-compatible APIs, Anthropic, Gemini, OpenRouter, and Ollama. However, the execution engine does not use the LLM client for actual skill decisions.

There are currently no meaningful calls to:

```python
llm.complete(...)
```

inside `SkillRunner`. The LLM client is therefore an available adapter, not an active agent brain.

### Current Consequences

- Skills mostly execute fixed code paths and heuristics.
- The system does not dynamically decide which tool to call next.
- The system does not reason over collected evidence during execution.
- The system does not generate real AI analysis for each skill.
- The Dashboard can show conversation records, but most skill conversations are event timelines rather than actual AI exchanges.

### Required Direction

Implement a small, explicit agent runtime rather than attempting to recreate all of Strix immediately.

Recommended interfaces:

```python
class AgentContext:
    target: str
    target_dir: Path
    skill: str
    run_id: str
    scope: dict
    artifacts: list
    conversation: list
    budget: dict

class AgentResult:
    status: str
    summary: str
    findings: list
    artifacts: list
    next_actions: list
    usage: dict
```

The runtime should support:

1. System prompt construction from the skill definition.
2. Context loading from previous artifacts.
3. A bounded tool registry.
4. LLM tool selection or structured action output.
5. Tool execution with timeouts.
6. Observation messages returned to the model.
7. Maximum step and token budgets.
8. Retry handling for transient provider failures.
9. Final structured result validation.
10. Conversation persistence for every system, user, assistant, and tool message.

### Acceptance Criteria

- At least one skill, preferably `js-analyze`, executes end-to-end through the real runtime.
- The skill makes at least one real LLM call when a provider is configured.
- Tool calls and observations are stored in the agent conversation JSONL.
- The final result is structured and validated.
- Missing LLM configuration produces a clear `LLM_UNAVAILABLE` state instead of pretending that AI analysis occurred.

## Priority 1 — Implement Real Sub-Agent Sessions

### Problem

The current pipeline contains multiple skill names, but these are mostly sequential stages inside one orchestrator. They are not independent child agents with their own sessions.

### Missing Concepts

- Root coordinator agent.
- Child agent identity.
- Parent/child relationships.
- Agent status lifecycle.
- Per-agent context.
- Agent mailbox or message queue.
- Explicit handoff messages.
- Parallel execution where safe.
- Waiting for another agent.
- Resume of an individual agent session.

### Required Direction

Represent every execution as a session with fields similar to:

```json
{
  "run_id": "run-...",
  "agent_id": "js-analyze-...",
  "parent_agent_id": "coordinator-...",
  "skill": "js-analyze",
  "status": "running",
  "created_at": "...",
  "updated_at": "...",
  "context_path": "...",
  "conversation_path": "..."
}
```

The coordinator should be able to:

- Create a child agent.
- Assign a bounded task.
- Wait for a child result.
- Read child artifacts.
- Send a follow-up or retry instruction.
- Mark a child as completed, failed, blocked, or cancelled.

### Acceptance Criteria

- At least two skills run as separate sessions.
- Each skill has its own conversation history.
- The Dashboard displays the coordinator and child-agent relationship accurately.
- Child-agent status survives a Dashboard restart.

## Priority 2 — Make HITL Blocking and Enforceable

### Problem

The orchestrator logs messages such as:

```text
HUMAN CHECKPOINT: Awaiting human approval
```

but continues execution immediately. The Dashboard approval button changes a JSON status, but it does not currently wake or block a real worker.

### Risk

The README claims that destructive actions are not unattended, but the current execution flow does not enforce this claim.

### Required State Machine

Use explicit states such as:

```text
CREATED
AUTHORIZED
RUNNING
WAITING_APPROVAL
APPROVED
REJECTED
PAUSED
FAILED
COMPLETED
CANCELLED
```

A worker must stop before a gated action and wait for a decision. It must not send the gated request before approval.

### Required Behavior

- Create a durable checkpoint with a deterministic ID.
- Move the run to `WAITING_APPROVAL`.
- Block the worker using a condition, event, or durable polling mechanism.
- Allow the Dashboard to approve or reject the checkpoint.
- Wake the worker only after approval.
- Cancel or skip the action after rejection.
- Record the decision, user notes, timestamp, and responsible agent.
- Support timeout and cancellation.

### Acceptance Criteria

- A test proves that no gated tool call occurs while a checkpoint is pending.
- Approval resumes the worker.
- Rejection prevents the gated action.
- Restarting the Dashboard does not silently approve or lose a pending checkpoint.

## Priority 3 — Persist Runs and Support Resume

### Problem

The Dashboard currently keeps active scan state in an in-memory dictionary:

```python
active_scans = {}
```

This state disappears after process termination.

### Missing Data

- Durable `run_id`.
- Run start and end timestamps.
- Current state.
- PID or process information.
- Skill progress.
- Checkpoint state.
- Retry count.
- Artifact manifest.
- Error information.
- Resume metadata.

### Recommended Layout

```text
output/runs/<run_id>/run.json
output/runs/<run_id>/events.jsonl
output/runs/<run_id>/agents.jsonl
output/runs/<run_id>/artifacts.json
output/runs/<run_id>/checkpoints.json
```

SQLite is also acceptable if it remains local and easy to inspect.

### Acceptance Criteria

- A completed or running scan has a durable run record.
- The Dashboard lists previous runs.
- A restart does not erase run history.
- A safe interrupted run can be resumed or marked `ABORTED` explicitly.
- Stop operations terminate the complete subprocess tree where possible.

## Priority 4 — Enforce Dependency Validation

### Problem

Skill dependencies currently produce warnings but do not reliably block execution. For example, a vulnerability skill can run without valid artifacts from `js-analyze`.

### Required Behavior

Before execution:

1. Build a dependency graph.
2. Validate that requested dependencies are included or that valid prior artifacts exist.
3. Validate artifact schema and freshness.
4. Mark a skill `BLOCKED` when prerequisites are missing.
5. Allow explicit override only in a documented expert mode.

### Acceptance Criteria

- Missing dependencies produce `BLOCKED`, not a misleading success.
- Previous-session artifacts can be used only after validation.
- The Dashboard clearly distinguishes `PENDING`, `BLOCKED`, `RUNNING`, `FAILED`, and `COMPLETED`.

## Priority 5 — Add a Proper Test Suite

### Current Gap

Syntax checks pass, but the project does not have a clear automated test suite.

### Minimum Test Coverage

Add tests for:

- Scope-of-work enforcement.
- Passive-only behavior without authorization.
- Target-name and target-path validation.
- OpenAPI JSON and YAML parsing.
- Deterministic checkpoint IDs.
- Checkpoint state transitions.
- Dependency ordering and blocking.
- Conversation JSONL append/read behavior.
- Dashboard GET endpoints.
- Dashboard POST validation.
- Scan start, duplicate start, and stop behavior.
- Dry-run behavior.
- LLM unavailable behavior.
- Report generation with missing inputs.
- Evidence hash and ledger deduplication.

### Recommended Tools

Use `pytest` with temporary directories and local fixtures. Do not perform live offensive requests in tests.

### Acceptance Criteria

A single command should run the test suite, for example:

```powershell
python -m pytest -q
```

## Priority 6 — Secure the Dashboard Before Network Exposure

The Dashboard is acceptable as a localhost-only tool, but it should not be exposed to a LAN or public interface yet.

### Current Concerns

- No authentication.
- Open CORS policy:

```text
Access-Control-Allow-Origin: *
```

- HTTP endpoints can start subprocesses.
- Target/path validation needs to be stricter.
- No CSRF protection.
- No request size and rate limits.
- No audit identity for approval decisions.
- No explicit protection against unsafe host binding.

### Required Direction

For local use:

- Default to `127.0.0.1`.
- Reject unsafe host binding unless an explicit insecure flag is provided.
- Validate target names against a strict allowlist pattern.
- Resolve target paths and verify they remain under `TARGETS_DIR`.
- Limit request body sizes.
- Restrict CORS to the local origin.
- Add an optional local bearer token.
- Record all destructive API actions in an audit log.

### Acceptance Criteria

- Traversal-like target names are rejected.
- The server cannot start a scan outside the configured project directory.
- Unsafe network binding requires an explicit opt-in.
- Approval actions record who/what/when information.

## Priority 7 — Improve Process and Tool Isolation

### Problem

Tools currently execute local subprocesses and browser operations, but there is no unified sandbox policy comparable to Strix.

### Missing Controls

- Network allowlist.
- Maximum request count.
- Per-tool timeout.
- CPU and memory limits where available.
- File access boundaries.
- Complete process-tree termination.
- Rate limiting.
- Browser profile isolation.
- Secrets redaction in logs.

### Recommended Direction

Start with a local execution policy object:

```json
{
  "allowed_hosts": [],
  "max_requests": 200,
  "request_timeout_seconds": 10,
  "tool_timeout_seconds": 120,
  "allow_state_changing_requests": false
}
```

Pass this policy to every tool instead of relying only on skill documentation.

## Priority 8 — Improve Conversation and Agent Observability

The Agent Conversations tab now exists and stores JSONL conversations. It should be extended to show real agent execution metadata.

### Add to Each Message

- `run_id`
- `agent_id`
- `parent_agent_id`
- `role`
- `message_type`
- `tool_name`
- `tool_arguments` with secrets redacted
- `tool_result`
- `provider`
- `model`
- `token_usage`
- `latency_ms`
- `checkpoint_id` when applicable
- `artifact_refs`

### Dashboard Improvements

- Filter by run.
- Filter by agent.
- Filter by message type.
- Expand/collapse tool calls.
- Show model and latency.
- Show errors separately from normal messages.
- Link messages to artifacts and findings.
- Export a complete session transcript.

## Priority 9 — Fix Documentation Drift

The documentation should clearly distinguish implemented behavior from planned behavior.

Known documentation issues:

- Some comparison text still describes the orchestrator as a placeholder even though several tool-backed execution paths now exist.
- The README presents HITL as fully enforced, while the current worker flow does not block reliably.
- The Dashboard skill count and naming should be checked for consistency everywhere.
- The Agent Conversations feature should be documented.
- The exact LLM configuration and `LLM_UNAVAILABLE` behavior should be documented.

Every major README claim should be backed by an automated test or a direct runnable example.

## Priority 10 — Expand Security Coverage After Runtime Stabilization

Do not prioritize adding many more skills before the runtime and safety model are reliable.

After the priorities above, the next useful coverage areas are:

1. IDOR and broken access control.
2. Authentication, session, OAuth, and JWT testing.
3. API authorization and BOLA.
4. SQL injection and NoSQL injection through safe adapters.
5. Command injection and SSTI through controlled test flows.
6. CSRF and clickjacking.
7. Business logic and race-condition workflows.
8. Cloud and infrastructure checks.
9. SAST and diff-aware testing for local source code.

Every new skill must provide:

- Scope requirements.
- Input schema.
- Output schema.
- Evidence rules.
- Safe execution policy.
- Human checkpoint requirements.
- Unit and fixture tests.

## Suggested Milestone Plan

### Milestone 1 — Runtime Proof

- Implement the agent context and tool registry.
- Connect one skill to the real LLM client.
- Persist the complete conversation.
- Validate structured output.
- Handle missing provider configuration.

### Milestone 2 — Safety and Correctness

- Implement blocking HITL.
- Implement dependency blocking.
- Add target validation.
- Add process timeout and cancellation.
- Add initial pytest coverage.

### Milestone 3 — Durable Runs

- Add run directories or SQLite.
- Add resume and recovery states.
- Display run history in the Dashboard.
- Link runs, agents, conversations, artifacts, and findings.

### Milestone 4 — Multi-Agent Coordination

- Add coordinator and child-agent sessions.
- Add mailbox or event queue.
- Add bounded parallel execution.
- Add retry and handoff semantics.
- Display the real graph in the Dashboard.

### Milestone 5 — Coverage Expansion

- Add API authorization, IDOR, JWT, business logic, and other high-value skills.
- Add regression fixtures and quality metrics.
- Add CI/CD mode and meaningful exit codes.

## Definition of Done for the Next Major Release

The next major release should not be considered complete until:

- At least one skill uses a real LLM-driven tool loop.
- Conversations contain actual system, user, assistant, and tool messages.
- HITL blocks gated actions and resumes only after an explicit decision.
- Runs survive Dashboard restarts.
- Missing dependencies block execution safely.
- Target paths and Dashboard actions are validated.
- Automated tests cover the core state transitions and APIs.
- Documentation matches actual behavior.
- Findings clearly distinguish candidates from independently verified vulnerabilities.

## Final Recommendation

Do not attempt to copy all of Strix immediately. Keep Moros focused as a local-first, auditable, evidence-oriented web assessment harness, and implement the smallest reliable agent runtime around the existing skills.

The correct order is:

```text
Real LLM tool loop
→ blocking HITL
→ durable run state
→ tests and validation
→ real child-agent sessions
→ sandbox and resource controls
→ broader security coverage
```

The UI is now ahead of the execution engine. The next engineering effort should focus on making the backend behavior match what the Dashboard and README promise.
