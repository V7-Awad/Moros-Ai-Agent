---
name: review-skill
description: >
  Completion verification skill that runs after each primary skill to verify every checklist
  item was actually completed with valid artifacts and non-zero log files. Preferably run on
  a different model than the skill being reviewed. Generates nudge prompts on failure and
  manages bounded retry loops.
---

# Review Skill — Completion Verification

## Purpose

Fight **completion bias** — the tendency of LLMs to report tasks as complete when steps were skipped or only partially executed. This skill mechanically verifies that every claimed action actually produced the expected output.

## When to Run

- **After every primary skill completes.** No exceptions.
- **Preferably on a different model** than the one that ran the skill being reviewed (avoids a model marking its own homework).

## Inputs

- `SKILL_NAME` — name of the skill to review (e.g., `js-discover`)
- `TARGET_DOMAIN` — the target domain
- `SKILL_MD_PATH` — path to the skill's SKILL.md (to read its checklist)
- `OUTPUT_BASE` — `targets/<domain>/output/`

## Outputs

```
targets/<domain>/output/logs/review/
  <skill-name>-review-<run-number>.json    # structured review result
  <skill-name>-review-<run-number>.log     # human-readable review log
```

## Review Process

### Step 1: Parse the Skill's Checklist

Read the target skill's `SKILL.md` and extract every checklist item. For each item, identify:
- The step description
- The expected artifact path
- The expected log file path

### Step 2: Verify Each Checklist Item

For every checklist item, check ALL THREE conditions:

| # | Condition | How to Check |
|---|---|---|
| 1 | Checkbox is marked `[x]` | Parse the skill's output checklist |
| 2 | Expected artifact exists AND is non-zero bytes | File system check: `stat` the file |
| 3 | Corresponding log file exists AND is non-zero bytes | File system check: `stat` the file |

### Step 3: Validate Log Content (Optional Deep Check)

For each log file that exists, perform a plausibility check:
- Does the log contain timestamps?
- Does the log reference the expected action?
- Does the log indicate success (exit code 0, no unhandled errors)?
- Is the claimed output size consistent with the actual file size?

### Step 4: Generate Review Result

Create a structured JSON review result:

```json
{
  "skill_reviewed": "js-discover",
  "target": "example.com",
  "review_run": 1,
  "review_model": "gemini-2.5-pro",
  "timestamp": "2024-01-15T14:45:00Z",
  "overall_status": "PARTIAL_PASS",
  "total_steps": 9,
  "passed_steps": 7,
  "failed_steps": 2,
  "steps": [
    {
      "step_number": 1,
      "description": "Verify authorization",
      "checkbox_marked": true,
      "artifact_exists": true,
      "artifact_size_bytes": 0,
      "log_exists": true,
      "log_size_bytes": 245,
      "status": "PASS"
    },
    {
      "step_number": 4,
      "description": "Capture lazy-loaded JS",
      "checkbox_marked": true,
      "artifact_exists": false,
      "artifact_size_bytes": 0,
      "log_exists": true,
      "log_size_bytes": 12,
      "status": "FAIL",
      "failure_reason": "Artifact directory is empty and log file is suspiciously small (12 bytes) — likely skipped"
    }
  ]
}
```

### Step 5: Handle Failures

**On any FAIL status:**

1. Generate a **nudge prompt** (kept deliberately generic to avoid biasing the retry):

   > "Your work on `<skill-name>` was just reviewed and it was found that either you missed a step of analysis or did not generate an artifact of sufficient proof. Look at the Markdown checklist and the output for each step, find what you missed, and complete the step."

2. Include specific failed step numbers (but NOT the specific fix — let the skill figure it out):

   > "Specifically, steps <N>, <M> did not pass verification. Their artifacts or logs are missing or empty."

3. Re-invoke the original skill with this nudge prompt appended.

4. After the retry, run this review skill again.

### Step 6: Retry Bounds

- **Maximum retries per skill: 3**
- After 3 failed retries, generate a **CRITICAL SKILL FAILURE** report:

```json
{
  "status": "CRITICAL_FAILURE",
  "skill": "js-discover",
  "target": "example.com",
  "failed_steps": [4, 6],
  "retries_attempted": 3,
  "action_required": "HUMAN_INTERVENTION",
  "message": "Skill js-discover has failed verification 3 times for steps 4, 6. Manual investigation required."
}
```

This report is surfaced to the human operator — the system does NOT silently give up or silently declare success.

## Methodology Checklist

- [ ] Step 1: Parse target skill's SKILL.md and extract all checklist items
  - Expected artifact: Parsed checklist (in-memory)
  - Log file: `targets/<domain>/output/logs/review/<skill>-review-<run>.log`

- [ ] Step 2: Verify file existence and sizes for all artifacts and logs
  - Expected artifact: File verification results
  - Log file: (same log file as step 1)

- [ ] Step 3: Validate log content plausibility (optional deep check)
  - Expected artifact: Content validation results
  - Log file: (same log file as step 1)

- [ ] Step 4: Generate structured review result JSON
  - Expected artifact: `targets/<domain>/output/logs/review/<skill>-review-<run>.json`
  - Log file: (same log file as step 1)

- [ ] Step 5: If failures found, generate nudge prompt and trigger retry (bounded)
  - Expected artifact: Nudge prompt (if applicable)
  - Log file: (same log file as step 1)

## Important Notes

- **Different model is strongly preferred.** If the skill ran on Claude, have Gemini or GPT review it, and vice versa. Same-model review is significantly less effective at catching completion bias.
- **Empty logs are the #1 red flag.** A zero-byte log file almost always means the step was silently skipped. Even a step that legitimately found nothing should log "searched X files, found 0 results."
- **Don't trust self-reported completion.** The checkbox being marked `[x]` is necessary but NOT sufficient. The artifact and log must independently confirm the work was done.
- **Suspiciously small logs.** A log file that exists but is under 50 bytes is almost certainly a stub. Flag it for deeper inspection.
