---
name: xss-blind
description: >
  Tests for blind cross-site scripting where injected payloads execute in a context the
  attacker cannot directly observe (admin panels, log viewers, support ticket dashboards,
  error reporting tools). Uses out-of-band callback mechanisms to detect execution.
  Requires human approval before injecting payloads.
---

# XSS Blind — Blind Cross-Site Scripting Testing

## Purpose

Identify blind XSS vulnerabilities where injected JavaScript executes in a backend context (admin dashboard, log viewer, error reporter, support ticket system) that the tester cannot directly access. Detection relies on out-of-band callbacks.

## Prerequisites

- `targets/<domain>/scope-of-work.pdf` must exist
- Out-of-band callback server configured (e.g., XSS Hunter, Burp Collaborator, or custom callback endpoint)
- `js-analyze` output: `endpoints.json`, `parameters.json`

## Inputs

- `TARGET_DOMAIN` — target domain
- `CALLBACK_URL` — out-of-band callback server URL
- `ENDPOINTS` — `targets/<domain>/output/js/endpoints.json`

## Outputs

```
targets/<domain>/output/findings/xss-blind/
  injection-points.json        # all points where blind XSS payloads were injected
  callback-results.json        # any callbacks received (confirms execution)
  confirmed-blind-xss.json     # confirmed blind XSS findings
  xss-blind-summary.md         # human-readable summary
```

## Methodology Checklist

- [ ] Step 1: Verify authorization and callback server availability
  - Expected artifact: N/A (gate check)
  - Log file: `targets/<domain>/output/logs/xss-blind/step-01-verify.log`

- [ ] Step 2: Identify injection points — target fields likely rendered in admin/backend contexts: contact forms, feedback forms, user-agent strings, referer headers, error messages, support tickets, user profile fields, file upload names.
  - Expected artifact: `targets/<domain>/output/findings/xss-blind/injection-points.json`
  - Log file: `targets/<domain>/output/logs/xss-blind/step-02-injection-points.log`

- [ ] Step 3: **⚠️ HUMAN CHECKPOINT** — present injection plan to human for approval
  - Expected artifact: Human approval record
  - Log file: `targets/<domain>/output/logs/xss-blind/step-03-human-approval.log`

- [ ] Step 4: Inject callback payloads — inject unique-per-field payloads containing callback URLs. Each payload includes a unique identifier to trace back which injection point triggered.
  - Expected artifact: Injection tracking data
  - Log file: `targets/<domain>/output/logs/xss-blind/step-04-inject.log`

- [ ] Step 5: Monitor for callbacks — check callback server for incoming requests. Wait a reasonable period (blind XSS may take hours/days to trigger if admin reviews are infrequent).
  - Expected artifact: `targets/<domain>/output/findings/xss-blind/callback-results.json`
  - Log file: `targets/<domain>/output/logs/xss-blind/step-05-monitor.log`

- [ ] Step 6: Document findings
  - Expected artifact: `targets/<domain>/output/findings/xss-blind/xss-blind-summary.md`
  - Log file: `targets/<domain>/output/logs/xss-blind/step-06-document.log`

## ⚠️ Constraints

- **HUMAN APPROVAL REQUIRED** before injecting any payloads.
- **Callback payloads must be benign.** Only phone home with execution context (URL, cookies, DOM info) — never attempt data exfiltration beyond what's needed to prove the vulnerability.
- All findings tagged `AI-proposed severity: <level> — pending human review`.
