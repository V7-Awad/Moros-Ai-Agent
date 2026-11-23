# JWT Security Analysis (`jwt-analysis`)

**Category:** Authentication & Session  
**Author:** Moros AI Core  
**Type:** Advanced Offensive Skill  

## Description
Performs deep automated security auditing of JSON Web Tokens (JWT) observed in HTTP headers, cookies, API responses, and JavaScript storage.

## Methodology & Objectives
1. Extract JWTs from Authorization headers, set-cookie headers, and client-side storage tokens.
2. Decode Header and Payload segments without trusting signatures.
3. Test for Algorithm None attack (`alg: "none"`, `alg: "None"`, `alg: "NONE"`).
4. Inspect claims for privilege escalation vectors (e.g. `role: "admin"`, `is_admin: true`).
5. Audit expiration and revocation claims (`exp`, `nbf`, `iat`).

## Verification Checklist
- [ ] Inspect observed authorization headers and bearer tokens
- [ ] Test token decoding and signature header integrity
- [ ] Evaluate algorithm confusion and none algorithm acceptance
- [ ] Record candidate findings with exact token snippets and payload claims
