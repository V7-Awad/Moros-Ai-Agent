---
name: js-analyze
description: >
  Analyzes JavaScript collected by js-discover: deobfuscates/unminifies code, extracts API
  endpoints and parameters, identifies dangerous sink functions (DOM XSS gadgets), flags
  admin/debug features, detects outdated libraries with CVEs, fingerprints the tech stack,
  and extracts secrets using both regex patterns and high-entropy string detection.
  Produces structured JSON artifacts and ready-to-use curl commands.
---

# JS Analyze — JavaScript Analysis Skill

## Purpose

Deeply analyze all JavaScript collected by `js-discover` to extract actionable intelligence for downstream vulnerability testing skills. This skill consumes `js-discover`'s output and produces structured data used by `content-discovery`, `xss-*`, `ssrf-*`, and other skills.

## Prerequisites

- `js-discover` skill must have completed successfully (review-skill verified)
- Beautified JS files must exist in `targets/<domain>/output/js/beautified/`
- `collection-manifest.json` must exist

## Inputs

- `TARGET_DOMAIN` — the target domain
- `JS_DIR` — `targets/<domain>/output/js/`
- `OUTPUT_DIR` — `targets/<domain>/output/js/` (analysis artifacts go alongside collection)

## Outputs

```
targets/<domain>/output/js/
  endpoints.json              # all discovered API endpoints
  parameters.json             # all parameters mapped to their functions
  secrets-findings.json       # potential secrets/keys/tokens found
  tech-fingerprint.json       # framework/library detection
  gadgets.json                # dangerous sinks / DOM XSS gadgets
  admin-debug-flags.json      # admin features, debug params, feature flags
  developer-comments.json     # extracted developer comments of interest
  outdated-libraries.json     # libraries with known CVEs
  curl-commands.sh            # one curl per discovered endpoint
  analysis-summary.md         # human-readable summary of all findings
```

## Methodology Checklist

- [ ] Step 1: Verify js-discover output — confirm `beautified/` directory exists and is non-empty, `collection-manifest.json` exists.
  - Expected artifact: N/A (gate check)
  - Log file: `targets/<domain>/output/logs/js-analyze/step-01-verify-input.log`

- [ ] Step 2: Deobfuscate/unminify — for any JS files that are still obfuscated after beautification (webpack bundles, name-mangled code), apply deobfuscation techniques. Identify and handle common obfuscation patterns (string array rotation, control flow flattening, dead code injection).
  - Expected artifact: Updated files in `beautified/` or new `deobfuscated/` subdirectory
  - Log file: `targets/<domain>/output/logs/js-analyze/step-02-deobfuscate.log`

- [ ] Step 3: Extract API endpoints — parse all JS for URL patterns, fetch/XHR calls, API route definitions, GraphQL endpoints, WebSocket URLs. Categorize by HTTP method and group by functional area (admin, user, public, internal).
  - Expected artifact: `targets/<domain>/output/js/endpoints.json`
  - Log file: `targets/<domain>/output/logs/js-analyze/step-03-endpoints.log`

- [ ] Step 4: Map parameters — for every endpoint, extract all parameters (query params, body fields, headers) and map them to the functions that process them. Note which parameters control routing, auth, or access decisions.
  - Expected artifact: `targets/<domain>/output/js/parameters.json`
  - Log file: `targets/<domain>/output/logs/js-analyze/step-04-parameters.log`

- [ ] Step 5: Identify DOM XSS gadgets — find dangerous sink functions: `innerHTML`, `outerHTML`, `document.write`, `eval`, `setTimeout/setInterval` with string args, `location.href` assignments, `postMessage` handlers without origin checks, jQuery `.html()`, Angular `bypassSecurityTrust*`, React `dangerouslySetInnerHTML`.
  - Expected artifact: `targets/<domain>/output/js/gadgets.json`
  - Log file: `targets/<domain>/output/logs/js-analyze/step-05-gadgets.log`

- [ ] Step 6: Flag admin/debug features — identify: admin-only routes, feature flags (especially those toggled by URL params or cookies), debug/test parameters, development-mode checks, hidden functionality behind flags.
  - Expected artifact: `targets/<domain>/output/js/admin-debug-flags.json`
  - Log file: `targets/<domain>/output/logs/js-analyze/step-06-admin-debug.log`

- [ ] Step 7: Extract developer comments — parse all JS (including source maps if available) for comments that may reveal: internal URLs, credentials, TODO items mentioning security, architecture notes, team member names/emails, internal tool names.
  - Expected artifact: `targets/<domain>/output/js/developer-comments.json`
  - Log file: `targets/<domain>/output/logs/js-analyze/step-07-comments.log`

- [ ] Step 8: Detect outdated libraries — identify all third-party JS libraries and their versions. Cross-reference against known CVE databases. Flag any library with known security vulnerabilities.
  - Expected artifact: `targets/<domain>/output/js/outdated-libraries.json`
  - Log file: `targets/<domain>/output/logs/js-analyze/step-08-libraries.log`

- [ ] Step 9: Fingerprint tech stack — determine: frontend framework (React, Angular, Vue, Svelte, etc.), build tool (webpack, Vite, Rollup, etc.), backend indicators (API patterns suggesting Django, Rails, Express, etc.), CDN/hosting indicators, authentication framework.
  - Expected artifact: `targets/<domain>/output/js/tech-fingerprint.json`
  - Log file: `targets/<domain>/output/logs/js-analyze/step-09-fingerprint.log`

- [ ] Step 10: Extract secrets — scan using BOTH approaches:
  - **Known-pattern regex**: AWS keys, GCP keys, Stripe keys, JWT tokens, OAuth secrets, database connection strings, private keys, API tokens for common services.
  - **High-entropy string detection**: flag any string with Shannon entropy > 4.5 that is 16+ characters and doesn't match a known benign pattern (UUIDs, hashes used as identifiers).
  - Expected artifact: `targets/<domain>/output/js/secrets-findings.json`
  - Log file: `targets/<domain>/output/logs/js-analyze/step-10-secrets.log`

- [ ] Step 11: Generate curl commands — for every endpoint in `endpoints.json`, generate a ready-to-run curl command with appropriate method, headers, sample parameters, and any discovered auth tokens. Make the file executable.
  - Expected artifact: `targets/<domain>/output/js/curl-commands.sh`
  - Log file: `targets/<domain>/output/logs/js-analyze/step-11-curl-gen.log`

- [ ] Step 12: Generate analysis summary — create a human-readable markdown summary covering: total endpoints found, notable findings, risk areas requiring further investigation, recommended next skills to run.
  - Expected artifact: `targets/<domain>/output/js/analysis-summary.md`
  - Log file: `targets/<domain>/output/logs/js-analyze/step-12-summary.log`

## Output Schemas

### endpoints.json
```json
{
  "target": "example.com",
  "total_endpoints": 142,
  "endpoints": [
    {
      "url": "/api/v1/users",
      "method": "GET",
      "source_file": "beautified/external/app.chunk.js",
      "line_number": 1247,
      "category": "user",
      "parameters": ["page", "limit", "sort"],
      "auth_required": true,
      "notes": "Pagination endpoint, may be vulnerable to IDOR"
    }
  ]
}
```

### secrets-findings.json
```json
{
  "target": "example.com",
  "findings": [
    {
      "type": "api_key",
      "detection_method": "regex",
      "pattern_name": "stripe_publishable_key",
      "value_preview": "pk_live_*****",
      "source_file": "beautified/inline/index-block-3.js",
      "line_number": 42,
      "severity": "AI-proposed severity: MEDIUM — pending human review",
      "context": "Found in payment initialization code"
    },
    {
      "type": "high_entropy_string",
      "detection_method": "entropy",
      "entropy_score": 5.2,
      "value_preview": "a8f3k2...",
      "source_file": "beautified/external/config.js",
      "line_number": 15,
      "severity": "AI-proposed severity: LOW — pending human review",
      "context": "Unknown high-entropy string in config object"
    }
  ]
}
```

### tech-fingerprint.json
```json
{
  "target": "example.com",
  "frontend": {
    "framework": "React",
    "version": "18.2.0",
    "build_tool": "webpack 5",
    "state_management": "Redux",
    "ui_library": "Material UI"
  },
  "backend_indicators": {
    "likely_framework": "Express/Node.js",
    "api_style": "REST",
    "evidence": ["Express-style error responses", "Node.js stack traces in debug mode"]
  },
  "third_party": [
    {"name": "axios", "version": "0.21.1", "purpose": "HTTP client"},
    {"name": "lodash", "version": "4.17.15", "purpose": "Utility library"}
  ],
  "cdn": "Cloudflare",
  "known_misconfigs_for_stack": [
    "React: dangerouslySetInnerHTML usage",
    "webpack: exposed source maps",
    "Express: default error handler leaks stack traces"
  ]
}
```

## Important Notes

- **Developer comments are gold.** Many testers skip comments, but they frequently contain internal URLs, staging server addresses, credentials left in TODOs, and architecture notes that reveal attack surface.
- **High-entropy detection catches what regex misses.** Not every secret format has a known regex pattern. Shannon entropy analysis finds secrets in custom or unusual formats.
- **Historical JS is especially valuable here.** Old API versions may expose endpoints that have been removed from the current UI but are still live on the server.
- **Source maps make everything easier.** If `js-discover` found source maps, use them — they reveal original variable names, function names, and file structure that make all analysis more accurate.
