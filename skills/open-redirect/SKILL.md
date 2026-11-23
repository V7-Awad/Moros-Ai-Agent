# Open Redirect Hunter (`open-redirect`)

**Category:** Web Application Security  
**Author:** Moros AI Core  
**Type:** Advanced Offensive Skill  

## Description
Identifies unvalidated URL redirection vulnerabilities in parameters and endpoints (`redirect`, `url`, `next`, `return_to`, `dest`).

## Methodology & Objectives
1. Extract candidate endpoints and parameters associated with navigation and redirection.
2. Probe with benign external test payloads:
   - Protocol-relative: `//example.com`
   - Authority bypass: `https://{target}@example.com`
   - Standard domain: `https://example.com`
3. Inspect HTTP response code (`301`, `302`, `303`, `307`, `308`) and `Location` header.
4. Flag endpoints reflecting the untrusted destination without domain restriction.

## Verification Checklist
- [ ] Parse redirection parameters from observed endpoints and JavaScript
- [ ] Evaluate Location header reflections
- [ ] Record candidate findings with reproducible cURL proofs
