---
name: idp-race-condition
description: >
  Tests for the IdP redirect race condition where a single-page app's initial content loads
  before the redirect to an external identity provider completes. Captures pre-redirect API
  calls that may work without authentication. Requires browser-based redirect interception.
---

# IdP Race Condition — Identity Provider Redirect Race

## Purpose

Many SPAs rely on an external identity provider (OAuth/SSO) for authentication but don't separately authenticate each API call server-side. When the app loads, there's a brief window where initial content and API calls execute before the redirect to the IdP happens. If those API calls work without auth, they can be captured and replayed.

## Prerequisites

- `targets/<domain>/scope-of-work.pdf` must exist
- Browser-driving tool with redirect interception capability
- `js-analyze` output: `endpoints.json`

## Inputs

- `TARGET_DOMAIN` — target domain
- `ENDPOINTS` — `targets/<domain>/output/js/endpoints.json`

## Outputs

```
targets/<domain>/output/findings/idp-race/
  redirect-analysis.json       # analysis of redirect flow
  pre-redirect-requests.json   # API calls captured before redirect
  replay-results.json          # results of replaying captured calls without auth
  idp-race-summary.md          # human-readable summary
```

## Methodology Checklist

- [ ] Step 1: Verify authorization
  - Expected artifact: N/A
  - Log file: `targets/<domain>/output/logs/idp-race-condition/step-01-verify.log`

- [ ] Step 2: Analyze redirect flow — load the target in a browser and identify the authentication redirect chain. Document: initial page load → redirect to IdP → callback URL → authenticated session.
  - Expected artifact: `targets/<domain>/output/findings/idp-race/redirect-analysis.json`
  - Log file: `targets/<domain>/output/logs/idp-race-condition/step-02-redirect-flow.log`

- [ ] Step 3: Intercept and delay redirect — use the browser tool's redirect interception to briefly hold/delay the redirect to the IdP. During this window, capture ALL network requests the SPA makes (API calls, resource loads, WebSocket connections).
  - Expected artifact: `targets/<domain>/output/findings/idp-race/pre-redirect-requests.json`
  - Log file: `targets/<domain>/output/logs/idp-race-condition/step-03-intercept.log`

- [ ] Step 4: **⚠️ HUMAN CHECKPOINT** — present captured pre-redirect API calls and ask for approval to replay them without authentication.
  - Expected artifact: Human approval record
  - Log file: `targets/<domain>/output/logs/idp-race-condition/step-04-human-approval.log`

- [ ] Step 5: Replay without auth — replay captured API calls without any authentication tokens/cookies. Check which ones return valid data (indicating the backend doesn't independently verify auth).
  - Expected artifact: `targets/<domain>/output/findings/idp-race/replay-results.json`
  - Log file: `targets/<domain>/output/logs/idp-race-condition/step-05-replay.log`

- [ ] Step 6: Document findings
  - Expected artifact: `targets/<domain>/output/findings/idp-race/idp-race-summary.md`
  - Log file: `targets/<domain>/output/logs/idp-race-condition/step-06-document.log`

## ⚠️ Constraints

- **HUMAN APPROVAL before replaying any requests.**
- **No session hijacking.** If valid data is returned, document the finding but do not escalate to session manipulation.
- All findings tagged `AI-proposed severity: <level> — pending human review`.

## Important Notes

- **This is a timing-sensitive test.** The race window may be very short (milliseconds). The browser tool must be able to intercept and hold redirects with sub-second precision.
- **SPA frameworks vary.** React, Angular, and Vue apps all handle IdP redirects differently. Identify the pattern before attempting interception.
