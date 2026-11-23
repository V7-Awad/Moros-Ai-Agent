# CORS Misconfiguration Auditor (`cors-audit`)

**Category:** Network & Server Configuration  
**Author:** Moros AI Core  
**Type:** Advanced Offensive Skill  

## Description
Audits Cross-Origin Resource Sharing (CORS) policies across target endpoints to detect arbitrary origin reflection, null origin trust, and dangerous credential exposure.

## Methodology & Objectives
1. Inspect API and authenticated endpoints discovered during reconnaissance.
2. Probe endpoints with test origins:
   - Untrusted origin: `https://evil-attacker.com`
   - Null origin: `null`
   - Subdomain bypass: `https://attacker.{target}`
3. Analyze response headers:
   - `Access-Control-Allow-Origin`
   - `Access-Control-Allow-Credentials`
4. Flag endpoints that reflect untrusted origins with `Allow-Credentials: true` as high-severity candidates.

## Verification Checklist
- [ ] Identify candidate endpoints with JSON or sensitive data
- [ ] Send origin reflection requests
- [ ] Verify CORS header combinations
- [ ] Generate reproducible cURL verification proofs
