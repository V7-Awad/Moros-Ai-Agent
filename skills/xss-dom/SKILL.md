---
name: xss-dom
description: >
  Tests for DOM-based cross-site scripting where the vulnerability exists entirely in
  client-side JavaScript. Uses gadget data from js-analyze to target known dangerous sinks
  (innerHTML, document.write, eval, etc.) and traces data flow from sources (URL, postMessage,
  localStorage) to sinks. Requires browser-based verification.
---

# XSS DOM — DOM-Based Cross-Site Scripting Testing

## Purpose

Identify DOM XSS vulnerabilities where user-controllable data flows from a JavaScript source (URL fragment, query parameter, `postMessage`, `localStorage`, `document.referrer`) to a dangerous sink (`innerHTML`, `document.write`, `eval`, etc.) without proper sanitization — entirely in client-side code.

## Prerequisites

- `targets/<domain>/scope-of-work.pdf` must exist
- `js-analyze` output: `gadgets.json` (dangerous sinks identified)
- Browser-driving tool available for runtime verification

## Inputs

- `TARGET_DOMAIN` — target domain
- `GADGETS` — `targets/<domain>/output/js/gadgets.json`
- `JS_DIR` — `targets/<domain>/output/js/beautified/`

## Outputs

```
targets/<domain>/output/findings/xss-dom/
  source-sink-flows.json       # mapped data flows from sources to sinks
  dom-xss-candidates.json      # candidate vulnerabilities
  confirmed-dom-xss.json       # browser-verified DOM XSS
  xss-dom-summary.md           # human-readable summary
```

## Methodology Checklist

- [ ] Step 1: Verify authorization and load gadget data from js-analyze
  - Expected artifact: N/A (gate check)
  - Log file: `targets/<domain>/output/logs/xss-dom/step-01-verify.log`

- [ ] Step 2: Map sources — identify all user-controllable data sources in the JS code: `location.hash`, `location.search`, `document.URL`, `document.referrer`, `window.name`, `postMessage` event data, `localStorage`/`sessionStorage` reads, `document.cookie`.
  - Expected artifact: Source inventory
  - Log file: `targets/<domain>/output/logs/xss-dom/step-02-sources.log`

- [ ] Step 3: Trace source-to-sink flows — for each dangerous sink from `gadgets.json`, trace backwards to determine if any user-controllable source can reach it. Document the full data flow path including any intermediate transformations.
  - Expected artifact: `targets/<domain>/output/findings/xss-dom/source-sink-flows.json`
  - Log file: `targets/<domain>/output/logs/xss-dom/step-03-trace-flows.log`

- [ ] Step 4: Identify candidate vulnerabilities — from traced flows, identify cases where data reaches a sink without adequate sanitization (no encoding, no DOMPurify, no allowlist filtering).
  - Expected artifact: `targets/<domain>/output/findings/xss-dom/dom-xss-candidates.json`
  - Log file: `targets/<domain>/output/logs/xss-dom/step-04-candidates.log`

- [ ] Step 5: Browser-based verification — for each candidate, craft a URL or interaction sequence that triggers the DOM XSS in a real browser. Verify execution (not just source inspection).
  - Expected artifact: `targets/<domain>/output/findings/xss-dom/confirmed-dom-xss.json`
  - Log file: `targets/<domain>/output/logs/xss-dom/step-05-verify.log`

- [ ] Step 6: Document findings with full reproduction steps
  - Expected artifact: `targets/<domain>/output/findings/xss-dom/xss-dom-summary.md`
  - Log file: `targets/<domain>/output/logs/xss-dom/step-06-document.log`

## Important Notes

- **`postMessage` without origin check is a classic win.** Many SPAs use `postMessage` for cross-frame communication but don't verify the sender's origin.
- **jQuery is a goldmine.** `.html()`, `.append()`, `$()` with user input are all sinks.
- **Angular/React bypass.** Framework-specific bypass techniques exist (Angular template injection, React `dangerouslySetInnerHTML`).
- **URL fragment (#) payloads never hit the server.** DOM XSS via `location.hash` is invisible to server-side WAFs.
