---
name: recon-subdomain
description: >
  Performs passive and active subdomain enumeration for a target domain. Discovers subdomains
  via DNS brute-forcing, certificate transparency logs, web archives, and search engine dorking.
  Validates discovered subdomains and identifies live hosts with open web services.
  Runs as the first skill in the pipeline — only passive recon if no scope-of-work is present.
---

# Recon Subdomain — Subdomain Enumeration Skill

## Purpose

Discover all subdomains associated with the target domain to map the full attack surface before deeper testing begins. This is typically the first skill to run.

## Authorization Behavior

- **With `scope-of-work.pdf`**: Full active + passive enumeration
- **Without `scope-of-work.pdf`**: Passive enumeration ONLY (CT logs, search engines, web archives — no DNS brute-forcing or active probing)

## Inputs

- `TARGET_DOMAIN` — the target root domain (e.g., `example.com`)
- `TARGET_DIR` — full path: `targets/<domain>/`

## Outputs

```
targets/<domain>/output/recon/
  subdomains-passive.txt      # subdomains from passive sources
  subdomains-active.txt       # subdomains from active brute-forcing (if authorized)
  subdomains-all.txt          # merged, deduplicated list
  live-hosts.json             # validated live hosts with HTTP status, title, server header, IP, CDN
  recon-summary.md            # human-readable summary
```

## Methodology Checklist

- [ ] Step 1: Verify authorization status — check if `scope-of-work.pdf` exists. Log whether running in full or passive-only mode.
  - Expected artifact: N/A (gate check)
  - Log file: `targets/<domain>/output/logs/recon-subdomain/step-01-auth-check.log`

- [ ] Step 2: Certificate Transparency logs — query crt.sh and other CT log aggregators for all certificates issued to `*.<domain>`.
  - Expected artifact: Partial `targets/<domain>/output/recon/subdomains-passive.txt`
  - Log file: `targets/<domain>/output/logs/recon-subdomain/step-02-ct-logs.log`

- [ ] Step 3: Web archive enumeration — query Wayback Machine CDX API for all URLs under the target domain. Extract unique subdomains from the URL list.
  - Expected artifact: Appended to `subdomains-passive.txt`
  - Log file: `targets/<domain>/output/logs/recon-subdomain/step-03-web-archives.log`

- [ ] Step 4: Search engine dorking — query search engines for `site:<domain>` and common dork patterns to discover indexed subdomains.
  - Expected artifact: Appended to `subdomains-passive.txt`
  - Log file: `targets/<domain>/output/logs/recon-subdomain/step-04-search-dorking.log`

- [ ] Step 5: DNS brute-forcing (AUTHORIZED ONLY) — if scope-of-work is present, run DNS brute-forcing with a targeted wordlist against the domain. Use explicit port list (80, 443, 8080, 8443, 8000, 3000, 5000, 9090).
  - Expected artifact: `targets/<domain>/output/recon/subdomains-active.txt`
  - Log file: `targets/<domain>/output/logs/recon-subdomain/step-05-dns-brute.log`

- [ ] Step 6: Merge and deduplicate — combine all subdomain lists, remove duplicates, sort alphabetically.
  - Expected artifact: `targets/<domain>/output/recon/subdomains-all.txt`
  - Log file: `targets/<domain>/output/logs/recon-subdomain/step-06-merge.log`

- [ ] Step 7: Validate live hosts — for every discovered subdomain, probe for live HTTP/HTTPS services. Capture: HTTP status code, page title, server header, IP address, CDN detection, response size. Use explicit flags, NOT defaults.
  - Expected artifact: `targets/<domain>/output/recon/live-hosts.json`
  - Log file: `targets/<domain>/output/logs/recon-subdomain/step-07-live-validation.log`

- [ ] Step 8: Generate recon summary — create human-readable summary with: total subdomains found (by source), total live hosts, notable findings (unusual services, exposed admin panels, staging environments).
  - Expected artifact: `targets/<domain>/output/recon/recon-summary.md`
  - Log file: `targets/<domain>/output/logs/recon-subdomain/step-08-summary.log`

## Tool Usage

### Certificate Transparency
```bash
# Query crt.sh
curl -s "https://crt.sh/?q=%25.<domain>&output=json" | \
  python3 -c "import sys,json; [print(d['name_value']) for d in json.load(sys.stdin)]" | \
  sort -u > targets/<domain>/output/recon/ct-subdomains.txt
```

### Live Host Validation
```bash
# httpx with explicit fields — do NOT use bare defaults
tools/httpx-wrapper.sh --list targets/<domain>/output/recon/subdomains-all.txt \
  --ports 80,443,8080,8443,8000,3000,5000,9090 \
  --status-code --title --server --ip --cdn \
  --json --output targets/<domain>/output/recon/live-hosts.json
```

## Important Notes

- **Passive-only without authorization.** This is the ONLY skill that may run (in limited mode) without a scope-of-work. All other skills refuse entirely.
- **Port scanning beyond defaults.** Don't just probe 80/443. Many interesting services run on 8080, 8443, 3000, 5000, 9090.
- **CDN detection matters.** Subdomains behind a CDN may need different testing approaches than direct-to-origin hosts.
