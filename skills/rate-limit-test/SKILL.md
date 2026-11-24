# Rate Limiting & Abuse Prevention Auditor (`rate-limit-test`)

**Category:** Authentication & Abuse Security  
**Author:** Moros AI Core  
**Type:** Advanced Offensive Skill  

## Description
Assesses rate limiting controls and anti-automation protection on authentication, OTP verification, and password reset endpoints.

## Methodology & Objectives
1. Identify authentication endpoints (`/login`, `/api/auth`, `/forgot-password`, `/verify-otp`).
2. Send a bounded burst of non-destructive requests (5-8 requests) within safety limits.
3. Observe whether HTTP 429 Too Many Requests or throttling headers are returned.
4. Flag endpoints lacking rate limits that allow automated brute force attacks.

## Verification Checklist
- [ ] Locate sensitive authentication and OTP verification routes
- [ ] Measure server response codes across consecutive requests
- [ ] Confirm presence or absence of rate limiting controls
