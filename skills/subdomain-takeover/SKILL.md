# Subdomain Takeover Auditor (`subdomain-takeover`)

**Category:** DNS & Infrastructure Security  
**Author:** Moros AI Core  
**Type:** Advanced Offensive Skill  

## Description
Scans discovered subdomains for dangling DNS CNAME records pointing to unclaimed third-party cloud services (GitHub Pages, AWS S3, Heroku, Azure, Zendesk, Fastly).

## Methodology & Objectives
1. Inspect discovered subdomains from `output/recon/subdomains.txt`.
2. Check HTTP responses and DNS CNAME pointers against known provider fingerprints (e.g., "There is no app configured at that hostname", "NoSuchBucket").
3. Flag confirmed dangling subdomains vulnerable to complete takeover.

## Verification Checklist
- [ ] Cross-reference subdomains against cloud service takeover signatures
- [ ] Verify CNAME dangling status without destructive claim
- [ ] Record candidate findings with exact DNS and HTTP response evidence
