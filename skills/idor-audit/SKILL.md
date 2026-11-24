# Insecure Direct Object Reference (BOLA) Auditor (`idor-audit`)

**Category:** API & Authorization Security  
**Author:** Moros AI Core  
**Type:** Advanced Offensive Skill  

## Description
Detects Insecure Direct Object References (IDOR) and Broken Object Level Authorization (BOLA) across discovered API endpoints and resource routes.

## Methodology & Objectives
1. Inspect discovered endpoints for numeric, sequential, or UUID resource parameters (`/api/users/{id}`, `?order_id=`, `?account=`).
2. Identify endpoints requiring authentication or permission boundaries.
3. Test parameter variations, ID increment/decrement, and cross-object manipulation.
4. Record candidates with affected URLs, parameter names, and reproduction curl commands.

## Verification Checklist
- [ ] Scan endpoint inventory for object ID patterns
- [ ] Test authorization enforcement across parameter boundaries
- [ ] Record candidate findings with exact evidence and reproducible curl
