# Penetration Testing Assessment Report — demo.target.local

**Assessment Date:** 2026-11-22
**Target Organization:** demo.target.local
**Compliance Notice:** All findings are tagged `AI-proposed severity — pending human review`.

## Executive Summary

Moros AI processed artifacts for `demo.target.local` and recorded **3 triage items**: **3 unverified candidates** and **0 validated findings**. An empty result means insufficient observed evidence, not proof of absence.

| Finding Title | Validation | Severity | Affected URL |
|---|---|---|---|
| Server-Side Request Forgery (SSRF) in Avatar Fetch API | unverified | AI-proposed severity: CRITICAL — pending human review | `https://demo.target.local/api/v1/user/avatar-fetch` |
| Potential reflected-input sink on /api/v1/user | unverified | AI-proposed severity: UNASSESSED — pending evidence and human review | `/api/v1/user` |
| Reflected Cross-Site Scripting (XSS) in Search Query | unverified | AI-proposed severity: HIGH — pending human review | `https://demo.target.local/api/v1/search?q=%3Cscript%3Ealert(1)%3C/script%3E` |

## Evidence and Triage Items

### 1. Server-Side Request Forgery (SSRF) in Avatar Fetch API
- **Validation:** `unverified`
- **Confidence:** `not-scored`
- **Severity:** `AI-proposed severity: CRITICAL — pending human review`
- **Target URL:** `https://demo.target.local/api/v1/user/avatar-fetch`
- **Reproduction cURL:**
```bash
curl -s -X POST "https://demo.target.local/api/v1/user/avatar-fetch" -H "Content-Type: application/json" -d '{"image_url":"http://127.0.0.1:8080/admin"}'
```
- **Details:** Backend downloads remote images using axios without restricting loopback/private IPv4 ranges. Internal admin panel accessible via probe.

### 2. Potential reflected-input sink on /api/v1/user
- **Validation:** `unverified`
- **Confidence:** `low`
- **Severity:** `AI-proposed severity: UNASSESSED — pending evidence and human review`
- **Target URL:** `/api/v1/user`
- **Evidence:** `unlinked` from `unknown source` (SHA256: `unavailable`)
- **Details:** Endpoint-shape heuristic only. No request was sent and no reflection or execution was observed.

### 3. Reflected Cross-Site Scripting (XSS) in Search Query
- **Validation:** `unverified`
- **Confidence:** `not-scored`
- **Severity:** `AI-proposed severity: HIGH — pending human review`
- **Target URL:** `https://demo.target.local/api/v1/search?q=%3Cscript%3Ealert(1)%3C/script%3E`
- **Reproduction cURL:**
```bash
curl -s "https://demo.target.local/api/v1/search?q=%3Cscript%3Ealert(1)%3C/script%3E" -H "Accept: text/html"
```
- **Details:** Parameter 'q' is reflected unsanitized into the response HTML body without encoding or Content-Security-Policy restriction.

