---
name: auth-password-reset-bruteforce
description: >
  Tests password-reset-style forms that lack a username/email field (suggesting admin-only
  password-set functionality). Brute-forces common identifier parameter names to discover
  hidden admin password reset capabilities. Requires human approval before any brute-forcing.
---

# Auth Password Reset Bruteforce — Hidden Admin Reset Discovery

## Purpose

When a password-reset or password-set form has no visible username/email field, it may be a hidden admin-only function that accepts user identifiers through hidden or undocumented parameters. This skill brute-forces common parameter names to discover these hidden admin reset endpoints.

## Prerequisites

- `targets/<domain>/scope-of-work.pdf` must exist
- `js-analyze` output: `endpoints.json`, `parameters.json`, `admin-debug-flags.json`
- Identified password-reset-style forms

## Inputs

- `TARGET_DOMAIN` — target domain
- `ENDPOINTS` — `targets/<domain>/output/js/endpoints.json`

## Outputs

```
targets/<domain>/output/findings/auth-reset/
  reset-endpoints.json         # identified password reset endpoints
  parameter-brute-results.json # results of parameter brute-forcing
  confirmed-findings.json      # confirmed hidden admin reset functionality
  auth-reset-summary.md        # human-readable summary
```

## Methodology Checklist

- [ ] Step 1: Verify authorization
  - Expected artifact: N/A
  - Log file: `targets/<domain>/output/logs/auth-password-reset/step-01-verify.log`

- [ ] Step 2: Identify password reset endpoints — from JS analysis, find forms/endpoints related to password reset, password change, or account recovery that lack standard user identifier fields.
  - Expected artifact: `targets/<domain>/output/findings/auth-reset/reset-endpoints.json`
  - Log file: `targets/<domain>/output/logs/auth-password-reset/step-02-identify.log`

- [ ] Step 3: **⚠️ HUMAN CHECKPOINT** — present identified endpoints and brute-force plan for approval
  - Expected artifact: Human approval record
  - Log file: `targets/<domain>/output/logs/auth-password-reset/step-03-human-approval.log`

- [ ] Step 4: Parameter brute-forcing — test common identifier parameter names: `id`, `user_id`, `username`, `email`, `admin`, `account`, `uid`, `login`, `name`, `user`, `member`, `member_id`, `account_id`. For each, test with common values: `admin`, `administrator`, `root`, `1`, `0`.
  - Expected artifact: `targets/<domain>/output/findings/auth-reset/parameter-brute-results.json`
  - Log file: `targets/<domain>/output/logs/auth-password-reset/step-04-brute.log`

- [ ] Step 5: Analyze responses — compare response codes, sizes, and content for each parameter/value combination. Look for differential responses indicating a valid parameter was found.
  - Expected artifact: `targets/<domain>/output/findings/auth-reset/confirmed-findings.json`
  - Log file: `targets/<domain>/output/logs/auth-password-reset/step-05-analyze.log`

- [ ] Step 6: Document findings — **NEVER auto-use any discovered session/token.** Document and hand to human.
  - Expected artifact: `targets/<domain>/output/findings/auth-reset/auth-reset-summary.md`
  - Log file: `targets/<domain>/output/logs/auth-password-reset/step-06-document.log`

## ⚠️ Constraints

- **HUMAN APPROVAL before any brute-forcing.**
- **NEVER use discovered credentials or sessions.** Document only.
- **Rate-limit brute-forcing** to avoid account lockouts.
- All findings tagged `AI-proposed severity: <level> — pending human review`.
