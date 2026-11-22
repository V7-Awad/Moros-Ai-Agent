# Penetration Testing Assessment Report — demo.target.local

**Date:** 2026-11-22  
**Target:** `demo.target.local`  
**Authorization Document:** `scope-of-work.md` (Signed)  
**Status:** AI-Proposed Findings — Pending Human Tester Sign-Off  

---

## Executive Summary

Moros AI completed an autonomous black-box security evaluation of `demo.target.local`. The assessment identified **4 findings** requiring remediation:

| Severity (AI-Proposed) | Count | Description |
|---|---|---|
| **CRITICAL** | 1 | Server-Side Request Forgery (SSRF) accessing loopback services |
| **HIGH** | 1 | Reflected Cross-Site Scripting (XSS) in search query |
| **MEDIUM** | 1 | Hardcoded Google Cloud Platform API key in inline configuration |
| **LOW** | 1 | Stripe publishable key exposed in frontend bundle |

---

## Technical Findings

### 1. [CRITICAL] Server-Side Request Forgery in `/api/v1/user/avatar-fetch`
- **Affected Endpoint:** `POST /api/v1/user/avatar-fetch`
- **Vulnerable Parameter:** `image_url`
- **Reproduction:**
  ```bash
  curl -s -X POST "https://demo.target.local/api/v1/user/avatar-fetch" \
    -H "Content-Type: application/json" \
    -d '{"image_url":"http://127.0.0.1:8080/admin"}'
  ```
- **Remediation:** Implement strict IP allowlisting, validate MIME types before fetching, and block private RFC 1918 / loopback address ranges.

### 2. [HIGH] Reflected XSS in Search Query
- **Affected Endpoint:** `GET /api/v1/search?q=`
- **Vulnerable Parameter:** `q`
- **Payload:** `<script>alert(1)</script>`
- **Reproduction:**
  ```bash
  curl -s "https://demo.target.local/api/v1/search?q=%3Cscript%3Ealert(1)%3C/script%3E"
  ```
- **Remediation:** Apply contextual HTML output encoding and enforce a strict `Content-Security-Policy` header.

---

## Human-in-the-Loop Validation Notes
All findings remain provisional (`AI-proposed severity — pending human review`) until confirmed by the lead penetration tester.
