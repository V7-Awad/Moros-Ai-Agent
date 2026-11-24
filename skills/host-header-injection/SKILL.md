# Host Header Injection Auditor (`host-header-injection`)

**Category:** Web Infrastructure & Routing  
**Author:** Moros AI Core  
**Type:** Advanced Offensive Skill  

## Description
Detects Host Header Injection, Password Reset Poisoning, and virtual host routing manipulation by injecting arbitrary `Host`, `X-Forwarded-Host`, and `X-Forwarded-For` headers.

## Methodology & Objectives
1. Inject arbitrary hosts (`evil-target.com`) via `Host` header.
2. Inject routing overrides via `X-Forwarded-Host` and `X-Host` headers.
3. Observe if injected hostname is reflected in password reset links, redirect URLs (`Location` header), or script imports.

## Verification Checklist
- [ ] Inject custom Host header variations
- [ ] Check response headers and body for arbitrary host reflections
- [ ] Record candidate findings with reproducible curl
