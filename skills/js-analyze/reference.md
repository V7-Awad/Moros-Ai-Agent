# JS Analyze — Reference Output Examples

This document provides concrete examples of what a complete, successful `js-analyze` run's output looks like. Use these as your yardstick when running the skill.

---

## Example 1: React + Express SPA (e-commerce site)

### Directory Structure
```
targets/shop.example.com/output/js/
├── raw/
│   ├── external/
│   │   ├── main.chunk.js            (542 KB)
│   │   ├── vendor.chunk.js          (1.2 MB)
│   │   ├── runtime.js               (12 KB)
│   │   └── 3.chunk.js               (89 KB)
│   ├── inline/
│   │   ├── index_block_0.js         (3 KB)   — config/env variables
│   │   └── checkout_block_0.js      (1.2 KB) — payment init
│   ├── lazy-loaded/
│   │   ├── admin-panel.chunk.js     (234 KB)
│   │   └── analytics.chunk.js      (67 KB)
│   └── historical/
│       ├── 20230415_main.chunk.js   (380 KB)
│       └── 20230901_vendor.chunk.js (1.1 MB)
├── beautified/
│   └── (same structure, beautified versions)
├── source-maps/
│   └── external/
│       └── main.chunk.js.map       (1.8 MB)
├── endpoints.json
├── parameters.json
├── secrets-findings.json
├── tech-fingerprint.json
├── gadgets.json
├── admin-debug-flags.json
├── developer-comments.json
├── outdated-libraries.json
├── curl-commands.sh
├── analysis-summary.md
├── collection-manifest.json
└── collection-stats.json
```

### endpoints.json (excerpt)
```json
{
  "target": "shop.example.com",
  "total_endpoints": 87,
  "endpoints": [
    {
      "url": "/api/v2/products",
      "method": "GET",
      "source_file": "beautified/external/main.chunk.js",
      "line_number": 4521,
      "category": "api",
      "parameters": ["page", "limit", "category", "sort", "q"],
      "auth_required": false,
      "notes": "Public product listing with search"
    },
    {
      "url": "/api/v2/users/me",
      "method": "GET",
      "source_file": "beautified/external/main.chunk.js",
      "line_number": 5102,
      "category": "user",
      "parameters": [],
      "auth_required": true,
      "notes": "Current user profile — requires Bearer token"
    },
    {
      "url": "/api/v2/admin/users",
      "method": "GET",
      "source_file": "beautified/lazy-loaded/admin-panel.chunk.js",
      "line_number": 234,
      "category": "admin",
      "parameters": ["page", "role", "status"],
      "auth_required": true,
      "notes": "Admin user listing — found in lazy-loaded admin chunk"
    },
    {
      "url": "/api/v2/orders",
      "method": "POST",
      "source_file": "beautified/external/3.chunk.js",
      "line_number": 891,
      "category": "payment",
      "parameters": ["items", "shipping_address", "payment_method"],
      "auth_required": true,
      "notes": "Order creation — STATE-CHANGING, requires human review"
    },
    {
      "url": "/api/internal/health",
      "method": "GET",
      "source_file": "beautified/external/vendor.chunk.js",
      "line_number": 12,
      "category": "internal",
      "parameters": [],
      "auth_required": false,
      "notes": "Internal health check — may expose service info"
    }
  ]
}
```

### secrets-findings.json (excerpt)
```json
{
  "target": "shop.example.com",
  "findings": [
    {
      "type": "stripe_publishable",
      "detection_method": "regex",
      "pattern_name": "stripe_publishable_key",
      "value_preview": "pk_live_51HZ...",
      "source_file": "beautified/inline/checkout_block_0.js",
      "line_number": 8,
      "severity": "AI-proposed severity: LOW — pending human review",
      "context": "Publishable key (expected to be client-side, verify no secret key nearby)"
    },
    {
      "type": "generic_api_key",
      "detection_method": "regex",
      "pattern_name": "generic_api_key",
      "value_preview": "AIzaSyB7cV...",
      "source_file": "beautified/inline/index_block_0.js",
      "line_number": 15,
      "severity": "AI-proposed severity: MEDIUM — pending human review",
      "context": "Google Maps API key — check if restricted to domain"
    },
    {
      "type": "high_entropy_string",
      "detection_method": "entropy",
      "entropy_score": 5.4,
      "value_preview": "eyJhbGciOiJIUz...",
      "source_file": "beautified/external/main.chunk.js",
      "line_number": 3201,
      "severity": "AI-proposed severity: HIGH — pending human review",
      "context": "Hardcoded JWT token in auth fallback code — may grant access"
    }
  ]
}
```

### gadgets.json (excerpt)
```json
{
  "target": "shop.example.com",
  "total_gadgets": 12,
  "gadgets": [
    {
      "type": "innerHTML",
      "source_file": "beautified/external/main.chunk.js",
      "line_number": 7823,
      "code_snippet": "element.innerHTML = userInput",
      "controllable_source": "URL hash parameter",
      "risk": "HIGH — direct user input to innerHTML without sanitization",
      "notes": "Product review rendering uses innerHTML with review content"
    },
    {
      "type": "postMessage_no_origin_check",
      "source_file": "beautified/external/vendor.chunk.js",
      "line_number": 1456,
      "code_snippet": "window.addEventListener('message', function(e) { handleData(e.data) })",
      "controllable_source": "Any origin postMessage",
      "risk": "MEDIUM — postMessage handler without origin verification",
      "notes": "Payment iframe communication — no origin check"
    }
  ]
}
```

### tech-fingerprint.json (complete example)
```json
{
  "target": "shop.example.com",
  "frontend": {
    "framework": "React",
    "version": "18.2.0",
    "build_tool": "webpack 5.88.2",
    "state_management": "Redux 4.2.1",
    "ui_library": "Material UI 5.14.0",
    "router": "react-router-dom 6.14.0"
  },
  "backend_indicators": {
    "likely_framework": "Express/Node.js",
    "api_style": "REST (JSON)",
    "api_version": "v2",
    "evidence": [
      "Express-style error format: {error: {message, status}}",
      "X-Powered-By: Express visible in some responses",
      "Node.js stack trace format in 500 error",
      "Sequelize ORM error messages in validation failures"
    ]
  },
  "third_party": [
    {"name": "axios", "version": "0.21.1", "purpose": "HTTP client", "cve_check": "CVE-2021-3749 (SSRF)"},
    {"name": "lodash", "version": "4.17.15", "purpose": "Utility library", "cve_check": "CVE-2020-28500 (ReDoS)"},
    {"name": "moment", "version": "2.29.1", "purpose": "Date handling", "cve_check": "CVE-2022-24785 (path traversal)"},
    {"name": "socket.io-client", "version": "4.5.0", "purpose": "WebSocket client", "cve_check": "None known"},
    {"name": "stripe-js", "version": "1.54.0", "purpose": "Payment processing", "cve_check": "None known"}
  ],
  "cdn": "Cloudflare",
  "hosting_indicators": "AWS (us-east-1 based on latency headers)",
  "known_misconfigs_for_stack": [
    "React: Check for dangerouslySetInnerHTML usage → gadgets.json has findings",
    "webpack 5: Verify source maps are not publicly accessible → source-maps/ hunt results",
    "Express: Default error handler may leak stack traces in production",
    "Sequelize: Verbose error messages may reveal DB schema",
    "axios 0.21.1: Vulnerable to SSRF via protocol-relative URL bypass"
  ]
}
```

---

## Example 2: Angular + Django app (incomplete run — shows what failure looks like)

A run that the review-skill should flag as PARTIAL_PASS:

```
targets/app.example.org/output/js/
├── endpoints.json          (87 bytes — SUSPICIOUS: too small for a real app)
├── parameters.json         (12 bytes — EMPTY: just "{}")
├── secrets-findings.json   (2,891 bytes — OK)
├── tech-fingerprint.json   (1,245 bytes — OK)
├── gadgets.json            (0 bytes — FAIL: zero bytes)
├── admin-debug-flags.json  (0 bytes — FAIL: zero bytes)
├── developer-comments.json (MISSING — FAIL: file doesn't exist)
├── outdated-libraries.json (3,201 bytes — OK)
├── curl-commands.sh        (MISSING — FAIL: file doesn't exist)
└── analysis-summary.md     (456 bytes — OK but suspiciously short)
```

**Review-skill verdict:** FAIL on steps 4, 5, 6, 7, 11 (parameters, gadgets, admin-debug, comments, curl).

**Nudge prompt generated:**
> "Your work on `js-analyze` was just reviewed and it was found that either you missed a step of analysis or did not generate an artifact of sufficient proof. Specifically, steps 4, 5, 6, 7, 11 did not pass verification. Their artifacts or logs are missing or empty. Look at the Markdown checklist and the output for each step, find what you missed, and complete the step."
