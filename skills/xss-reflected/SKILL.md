---
name: xss-reflected
description: >
  Tests for reflected cross-site scripting (XSS) vulnerabilities. Injects payloads into URL
  parameters, form fields, and HTTP headers, checking if input is reflected unsanitized in
  the response. Uses context-aware payloads based on where reflection occurs (HTML body,
  attribute, JavaScript, URL context). Single-purpose skill — does not test stored, DOM, or blind XSS.
---

# XSS Reflected — Reflected Cross-Site Scripting Testing

## Purpose

Identify reflected XSS vulnerabilities where user-supplied input is immediately echoed back in the HTTP response without proper sanitization or encoding. This is the simplest XSS variant and should be tested first.

## Prerequisites

- `targets/<domain>/scope-of-work.pdf` must exist
- `js-analyze` output: `endpoints.json`, `parameters.json`
- `content-discovery` output: `discovered-paths.json` (for additional parameter discovery)

## Inputs

- `TARGET_DOMAIN` — target domain
- `ENDPOINTS` — `targets/<domain>/output/js/endpoints.json`
- `PARAMETERS` — `targets/<domain>/output/js/parameters.json`

## Outputs

```
targets/<domain>/output/findings/xss-reflected/
  reflection-points.json      # all points where input is reflected
  confirmed-xss.json          # confirmed XSS with working payloads
  xss-reflected-summary.md    # human-readable summary
```

## Methodology Checklist

- [ ] Step 1: Verify authorization and load endpoint/parameter data
  - Expected artifact: N/A (gate check)
  - Log file: `targets/<domain>/output/logs/xss-reflected/step-01-verify.log`

- [ ] Step 2: Identify reflection points — inject a unique canary string (e.g., `hackbot7x7q9`) into every parameter of every endpoint. Check if the canary appears in the response body, headers, or redirect URL.
  - Expected artifact: `targets/<domain>/output/findings/xss-reflected/reflection-points.json`
  - Log file: `targets/<domain>/output/logs/xss-reflected/step-02-reflection.log`

- [ ] Step 3: Determine reflection context — for each reflection point, identify WHERE the input is reflected: HTML body, HTML attribute (quoted/unquoted), inside `<script>` tags, inside JS string literals, in URL/href attributes, in CSS context, in HTTP headers.
  - Expected artifact: Updated `reflection-points.json` with context info
  - Log file: `targets/<domain>/output/logs/xss-reflected/step-03-context.log`

- [ ] Step 4: Test context-appropriate payloads — for each reflection context, test payloads designed for that context:
  - HTML body: `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`
  - HTML attribute: `" onmouseover="alert(1)`, `' autofocus onfocus='alert(1)`
  - JS string: `';alert(1)//`, `\";alert(1)//`
  - URL context: `javascript:alert(1)`, `data:text/html,<script>alert(1)</script>`
  - Expected artifact: Test results appended to findings
  - Log file: `targets/<domain>/output/logs/xss-reflected/step-04-payloads.log`

- [ ] Step 5: Verify and confirm — for each payload that appears to work, verify the XSS actually executes in a real browser context (not just reflected in source). Check for CSP headers that might block execution.
  - Expected artifact: `targets/<domain>/output/findings/xss-reflected/confirmed-xss.json`
  - Log file: `targets/<domain>/output/logs/xss-reflected/step-05-verify.log`

- [ ] Step 6: Document findings — for each confirmed XSS, record: vulnerable URL, parameter, payload, context, CSP bypass (if applicable), reproduction steps. All severities tagged `AI-proposed severity: <level> — pending human review`.
  - Expected artifact: `targets/<domain>/output/findings/xss-reflected/xss-reflected-summary.md`
  - Log file: `targets/<domain>/output/logs/xss-reflected/step-06-document.log`

## ⚠️ Constraints

- **NO state-changing actions.** XSS testing must only use GET requests and safe POST requests that don't modify server state.
- **No automatic exploitation.** Finding and confirming the vulnerability is the goal — do NOT attempt to steal sessions, exfiltrate data, or chain with other vulns without human approval.
- **Respect rate limits.** Space requests to avoid triggering WAF blocks that would blind further testing.

## Important Notes

- **HTTP headers matter.** Test `Referer`, `User-Agent`, `X-Forwarded-For`, and custom headers — these are often reflected in error pages and logs without sanitization.
- **Check ALL response locations.** Input might be reflected in HTML body, HTTP headers (especially `Location` for redirect-based XSS), and even in JSON responses consumed by client-side JS.
- **CSP analysis.** A reflected XSS behind a strict CSP might still be exploitable via CSP bypass techniques. Note the CSP policy in findings.
