---
name: deep-recon
description: >
  Parallel fan-out deep reconnaissance skill. Launches concurrent recon workers
  across Certificate Transparency logs, Wayback archives, technology stack profiling,
  WAF detection, and initial HTTP probing, then merges and deduplicates all findings
  with explicit source attribution per discovered artifact.
---

# Deep Recon — Parallel Fan-Out Reconnaissance (`deep-recon`)

**Category:** Reconnaissance & Surface Mapping  
**Type:** Core Parallel Discovery Skill  

## Description

Performs parallel fan-out reconnaissance across multiple independent intelligence sources simultaneously, merging discovered subdomains, technologies, WAF signatures, and archival endpoints into a source-cited attack surface inventory.

## Methodology & Objectives

1. Query passive subdomain sources (crt.sh Certificate Transparency + Wayback Machine CDX API) in parallel.
2. Fingerprint target WAF signatures and backend technology stack simultaneously.
3. Merge and deduplicate discovered assets while tracking explicit provenance (`sources` list per asset).
4. Record known target infrastructure facts into persistent `MemoryManager` semantic memory for downstream skills.

## Verification Checklist

- [ ] Step 1: Parallel passive subdomain fan-out (crt.sh + Wayback CDX) with source attribution
- [ ] Step 2: Concurrent WAF & technology stack fingerprinting against root target
- [ ] Step 3: Deduplicated merge into `output/recon/deep-recon-summary.json` and `output/recon/subdomains-all.txt`
- [ ] Step 4: Persist semantic target facts into `memory.db`
- [ ] Log file: `targets/<domain>/output/logs/deep-recon/step-01-fanout.log`

## Safety & Scope Constraints

- Strict scope adherence via `ScopedHttpClient` and `ScopeValidator`.
- Passive-first operation; respects configured `max_http_requests` and `request_delay`.
