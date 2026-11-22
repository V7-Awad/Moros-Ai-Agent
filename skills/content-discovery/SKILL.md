---
name: content-discovery
description: >
  Performs content/directory discovery (brute-forcing) using wordlists tailored to the target's
  detected tech stack from js-analyze. Generates both generic and framework-specific wordlists.
  Targets: admin panels, config files, backup files, exposed build artifacts, API documentation.
---

# Content Discovery — Directory & File Brute-Forcing Skill

## Purpose

Discover hidden files, directories, admin panels, configuration files, backup files, and exposed build artifacts on the target. Uses framework-specific wordlists derived from `js-analyze`'s tech fingerprint rather than relying solely on generic wordlists.

## Prerequisites

- `targets/<domain>/scope-of-work.pdf` must exist
- `js-analyze` must have completed (specifically `tech-fingerprint.json`)
- `recon-subdomain` live hosts data (`live-hosts.json`) recommended

## Inputs

- `TARGET_DOMAIN` — target domain
- `TECH_FINGERPRINT` — `targets/<domain>/output/js/tech-fingerprint.json`
- `LIVE_HOSTS` — `targets/<domain>/output/recon/live-hosts.json`

## Outputs

```
targets/<domain>/output/content-discovery/
  wordlist-generic.txt              # baseline generic wordlist
  wordlist-framework-specific.txt   # derived from tech fingerprint
  wordlist-combined.txt             # merged final wordlist
  discovered-paths.json             # all discovered paths with status codes
  interesting-findings.json         # filtered high-value discoveries
  content-discovery-summary.md      # human-readable summary
```

## Methodology Checklist

- [ ] Step 1: Verify authorization and prerequisites
  - Expected artifact: N/A (gate check)
  - Log file: `targets/<domain>/output/logs/content-discovery/step-01-verify.log`

- [ ] Step 2: Load tech fingerprint — read `tech-fingerprint.json` and determine framework-specific paths to test.
  - Expected artifact: In-memory framework data
  - Log file: `targets/<domain>/output/logs/content-discovery/step-02-load-fingerprint.log`

- [ ] Step 3: Generate generic wordlist — baseline list covering common admin panels (`/admin`, `/dashboard`, `/wp-admin`), config files (`.env`, `web.config`, `.htaccess`), backup files (`*.bak`, `*.old`, `*.swp`), build artifacts (`/.git/`, `/node_modules/`, `/.env.local`).
  - Expected artifact: `targets/<domain>/output/content-discovery/wordlist-generic.txt`
  - Log file: `targets/<domain>/output/logs/content-discovery/step-03-generic-wordlist.log`

- [ ] Step 4: Generate framework-specific wordlist — based on detected tech stack. Examples:
  - React/webpack: `asset-manifest.json`, `precache-manifest.*.js`, `static/js/*.chunk.js`, `/.well-known/`
  - Django: `/admin/`, `/api/docs/`, `/static/`, `/__debug__/`, `/media/`
  - Express/Node: `/api-docs/`, `/swagger/`, `/graphql`, `/health`, `/.env`
  - Rails: `/rails/info/`, `/rails/mailers/`, `/sidekiq/`, `/active_storage/`
  - Expected artifact: `targets/<domain>/output/content-discovery/wordlist-framework-specific.txt`
  - Log file: `targets/<domain>/output/logs/content-discovery/step-04-framework-wordlist.log`

- [ ] Step 5: Combine wordlists — merge generic + framework-specific, deduplicate, sort.
  - Expected artifact: `targets/<domain>/output/content-discovery/wordlist-combined.txt`
  - Log file: `targets/<domain>/output/logs/content-discovery/step-05-combine.log`

- [ ] Step 6: Run content discovery scan — brute-force using combined wordlist against each live host. Record status codes, response sizes, redirects. Filter out generic 404s and soft-404s.
  - Expected artifact: `targets/<domain>/output/content-discovery/discovered-paths.json`
  - Log file: `targets/<domain>/output/logs/content-discovery/step-06-scan.log`

- [ ] Step 7: Filter interesting findings — from discovered paths, extract high-value findings: admin panels (200/302), exposed config files, backup files, API documentation endpoints, debug endpoints, source code exposure.
  - Expected artifact: `targets/<domain>/output/content-discovery/interesting-findings.json`
  - Log file: `targets/<domain>/output/logs/content-discovery/step-07-filter.log`

- [ ] Step 8: Generate summary — human-readable report of content discovery results.
  - Expected artifact: `targets/<domain>/output/content-discovery/content-discovery-summary.md`
  - Log file: `targets/<domain>/output/logs/content-discovery/step-08-summary.log`

## Important Notes

- **Framework-specific wordlists are the differentiator.** Generic brute-forcing is table stakes; the value here is using the detected tech stack to generate targeted paths that generic lists miss.
- **Soft-404 detection is critical.** Many apps return 200 for every path with a custom "not found" page. Detect and filter these by comparing response sizes and content.
- **Don't forget backup file extensions.** Check `.bak`, `.old`, `.swp`, `.save`, `.orig`, `~`, `.backup` variants of discovered files.
