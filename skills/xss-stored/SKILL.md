---
name: xss-stored
description: >
  Tests for stored (persistent) cross-site scripting vulnerabilities where user input is saved
  server-side and rendered to other users without proper sanitization. Targets user profile
  fields, comments, messages, file uploads, and any other persistent input vectors.
  Requires human approval before submitting payloads to state-changing endpoints.
---

# XSS Stored — Stored Cross-Site Scripting Testing

## Purpose

Identify stored XSS vulnerabilities where malicious input is persisted on the server and rendered to other users. These are typically higher severity than reflected XSS due to their persistent nature and potential to affect multiple users.

## Prerequisites

- `targets/<domain>/scope-of-work.pdf` must exist
- `js-analyze` output: `endpoints.json`, `parameters.json`
- Identified write endpoints (POST/PUT) from endpoint analysis

## Inputs

- `TARGET_DOMAIN` — target domain
- `ENDPOINTS` — `targets/<domain>/output/js/endpoints.json`
- `PARAMETERS` — `targets/<domain>/output/js/parameters.json`

## Outputs

```
targets/<domain>/output/findings/xss-stored/
  write-endpoints.json         # identified endpoints that store user input
  injection-results.json       # results of payload injection attempts
  confirmed-xss.json           # confirmed stored XSS findings
  xss-stored-summary.md        # human-readable summary
```

## Methodology Checklist

- [ ] Step 1: Verify authorization
  - Expected artifact: N/A (gate check)
  - Log file: `targets/<domain>/output/logs/xss-stored/step-01-verify.log`

- [ ] Step 2: Identify write endpoints — from endpoint and parameter data, identify all endpoints that accept and store user input (profile updates, comments, messages, file names, metadata fields).
  - Expected artifact: `targets/<domain>/output/findings/xss-stored/write-endpoints.json`
  - Log file: `targets/<domain>/output/logs/xss-stored/step-02-write-endpoints.log`

- [ ] Step 3: **⚠️ HUMAN CHECKPOINT** — present identified write endpoints to human operator for approval before injecting any payloads. List each endpoint and the payloads planned.
  - Expected artifact: Human approval record
  - Log file: `targets/<domain>/output/logs/xss-stored/step-03-human-approval.log`

- [ ] Step 4: Inject canary strings — submit unique, identifiable but benign strings to approved endpoints. Then browse the application to find where these strings are rendered.
  - Expected artifact: Rendering locations documented
  - Log file: `targets/<domain>/output/logs/xss-stored/step-04-canary.log`

- [ ] Step 5: Test context-appropriate payloads — based on rendering context, inject XSS payloads. Use the same context-aware approach as xss-reflected.
  - Expected artifact: `targets/<domain>/output/findings/xss-stored/injection-results.json`
  - Log file: `targets/<domain>/output/logs/xss-stored/step-05-payloads.log`

- [ ] Step 6: Verify persistence and rendering — confirm payloads persist across page loads and render in other user sessions (if multi-user testing is in scope).
  - Expected artifact: `targets/<domain>/output/findings/xss-stored/confirmed-xss.json`
  - Log file: `targets/<domain>/output/logs/xss-stored/step-06-verify.log`

- [ ] Step 7: Document and clean up — document all findings. Attempt to remove/clean injected payloads from the application (restore original values).
  - Expected artifact: `targets/<domain>/output/findings/xss-stored/xss-stored-summary.md`
  - Log file: `targets/<domain>/output/logs/xss-stored/step-07-document.log`

## ⚠️ Constraints

- **HUMAN APPROVAL REQUIRED** before submitting ANY payload to a write endpoint.
- **Clean up after testing.** Remove or revert injected payloads where possible.
- **Avoid destructive endpoints.** Never test DELETE endpoints or endpoints that could corrupt user data.
- All findings tagged `AI-proposed severity: <level> — pending human review`.
