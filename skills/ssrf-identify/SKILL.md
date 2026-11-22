---
name: ssrf-identify
description: >
  Identifies Server-Side Request Forgery (SSRF) vulnerabilities by finding parameters that
  accept URLs or hostnames and testing with out-of-band callback probes. This skill is
  identification only — post-exploitation is handled by ssrf-post-exploit.
---

# SSRF Identify — Server-Side Request Forgery Identification

## Purpose

Find parameters that accept URLs, hostnames, or IP addresses and test whether the server makes outbound requests to attacker-controlled destinations. This is **identification only** — do not fold post-exploitation into this skill.

## Prerequisites

- `targets/<domain>/scope-of-work.pdf` must exist
- `js-analyze` output: `endpoints.json`, `parameters.json`
- Out-of-band callback server available

## Inputs

- `TARGET_DOMAIN` — target domain
- `CALLBACK_URL` — out-of-band server URL
- `ENDPOINTS` — `targets/<domain>/output/js/endpoints.json`
- `PARAMETERS` — `targets/<domain>/output/js/parameters.json`

## Outputs

```
targets/<domain>/output/findings/ssrf/
  url-accepting-params.json    # parameters that accept URL-like values
  ssrf-probe-results.json      # results of SSRF probing
  confirmed-ssrf.json          # confirmed SSRF with callback evidence
  ssrf-identify-summary.md     # human-readable summary
```

## Methodology Checklist

- [ ] Step 1: Verify authorization
  - Expected artifact: N/A
  - Log file: `targets/<domain>/output/logs/ssrf-identify/step-01-verify.log`

- [ ] Step 2: Identify URL-accepting parameters — scan parameters for names suggesting URL input: `url`, `uri`, `path`, `redirect`, `next`, `callback`, `return`, `dest`, `link`, `src`, `source`, `image`, `file`, `page`, `feed`, `proxy`, `webhook`.
  - Expected artifact: `targets/<domain>/output/findings/ssrf/url-accepting-params.json`
  - Log file: `targets/<domain>/output/logs/ssrf-identify/step-02-url-params.log`

- [ ] Step 3: Test with out-of-band probes — for each URL-accepting parameter, submit the callback URL and check for incoming requests. Test variations: `http://callback`, `https://callback`, `//callback`, URL-encoded variants.
  - Expected artifact: `targets/<domain>/output/findings/ssrf/ssrf-probe-results.json`
  - Log file: `targets/<domain>/output/logs/ssrf-identify/step-03-oob-probes.log`

- [ ] Step 4: Test bypass techniques — if initial probes are blocked, test common SSRF filter bypasses: IP address formats (decimal, hex, octal), DNS rebinding, URL parser inconsistencies, redirect chains, protocol smuggling.
  - Expected artifact: Updated probe results
  - Log file: `targets/<domain>/output/logs/ssrf-identify/step-04-bypasses.log`

- [ ] Step 5: Confirm and document — for each confirmed SSRF, document the vulnerable endpoint, parameter, working payload, and any observed server behavior.
  - Expected artifact: `targets/<domain>/output/findings/ssrf/confirmed-ssrf.json` and `ssrf-identify-summary.md`
  - Log file: `targets/<domain>/output/logs/ssrf-identify/step-05-document.log`

## ⚠️ Constraints

- **Identification ONLY.** Do not attempt to access internal services, cloud metadata, or other post-exploitation activities. That is `ssrf-post-exploit`'s job.
- **No destructive requests.** Only test with safe HTTP methods against the callback server.
- All findings tagged `AI-proposed severity: <level> — pending human review`.
