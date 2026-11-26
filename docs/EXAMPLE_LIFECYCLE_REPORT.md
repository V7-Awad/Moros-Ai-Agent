# Moros AI — Controlled-Lab End-to-End Lifecycle Example Report

> **Disclaimer:** All targets, URLs, commits, hashes, and outputs in this document represent a **controlled, authorized local lab scenario** (`lab-shop.internal.test`) demonstrating the Moros AI v2.4.0 closed-loop security lifecycle across Phases 1–4.

---

## Target & Assessment Context

- **Target:** `lab-shop.internal.test`
- **Authorization:** `targets/lab-shop.internal.test/scope-of-work.md` (signed controlled-lab engagement)
- **Scope Policy:** `same_host_only: true`, `allow_active_vulnerability_checks: true`, `max_requests: 50`
- **Repository:** Local test application checkout (`/opt/lab/lab-shop`)

---

## Stage 1 — Candidate Discovery (`candidate`)

During skill execution (`xss-reflected`), Moros observes unvalidated reflection of query parameter `q` on `/search` and records an unverified candidate under `targets/lab-shop.internal.test/output/findings/xss-reflected/candidates-xss-reflected.json`:

```json
{
  "finding_id": "fnd-9a3f1c2b8e04",
  "title": "Reflected XSS in Search Query Parameter 'q'",
  "type": "xss-reflected",
  "skill": "xss-reflected",
  "cwe": "CWE-79",
  "method": "GET",
  "url": "https://lab-shop.internal.test/search?q=test",
  "parameter": "q",
  "severity": "Triage Severity: HIGH — pending human review",
  "status": "candidate",
  "validation_status": "unverified",
  "confidence": "medium",
  "evidence_ids": []
}
```

At this stage, `resolve_finding_lifecycle()` keeps the finding as `("candidate", "unverified")`, and `PoCGenerator.is_poc_eligible()` returns `False`.

---

## Stage 2 — Deterministic Exploit Validation (`confirmed` + SHA-256 Proof)

`ExploitValidator` runs strategy `xss-reflected` (`v1.0.0`) inside `ReproductionRunner` via `ScopedHttpClient` (2 GET requests: baseline `morosctrl3a91c0de` and non-executable canary `<moros-probe data-id="MOROSXSS3a91c0de">MOROSXSS3a91c0de</moros-probe>`).

### Proof Bundle (`output/evidence/validation/val-4c8e21a09f12.json`)

```json
{
  "schema_version": "1.0",
  "validation_run_id": "val-4c8e21a09f12",
  "finding_id": "fnd-9a3f1c2b8e04",
  "target": "lab-shop.internal.test",
  "endpoint": "https://lab-shop.internal.test/search?q=test",
  "method": "GET",
  "strategy": "xss-reflected",
  "strategy_version": "1.0.0",
  "status": "confirmed",
  "confidence": 0.92,
  "limitations": [
    "Non-executable <moros-probe> HTML tag verified unescaped reflection; script execution not triggered."
  ],
  "requests_used": 2,
  "reproduction_steps": [
    {
      "step": 1,
      "action": "Send GET request with unescaped HTML probe in 'q'",
      "method": "GET",
      "url": "https://lab-shop.internal.test/search?q=%3Cmoros-probe+data-id%3D%22MOROSXSS3a91c0de%22%3EMOROSXSS3a91c0de%3C%2Fmoros-probe%3E",
      "parameter": "q",
      "payload": "<moros-probe data-id=\"MOROSXSS3a91c0de\">MOROSXSS3a91c0de</moros-probe>"
    }
  ],
  "exchanges": [
    {
      "label": "xss_baseline",
      "request": {
        "method": "GET",
        "url": "https://lab-shop.internal.test/search?q=morosctrl3a91c0de",
        "headers": { "Cookie": "[REDACTED]" }
      },
      "response": {
        "status": "response",
        "status_code": 200,
        "headers": { "content-type": "text/html; charset=utf-8" },
        "body_preview": "<h1>Search Results</h1><p>Results for: morosctrl3a91c0de</p>",
        "body_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      }
    },
    {
      "label": "xss_probe",
      "request": {
        "method": "GET",
        "url": "https://lab-shop.internal.test/search?q=%3Cmoros-probe+data-id%3D%22MOROSXSS3a91c0de%22%3EMOROSXSS3a91c0de%3C%2Fmoros-probe%3E",
        "headers": { "Cookie": "[REDACTED]" }
      },
      "response": {
        "status": "response",
        "status_code": 200,
        "headers": { "content-type": "text/html; charset=utf-8" },
        "body_preview": "<h1>Search Results</h1><p>Results for: <moros-probe data-id=\"MOROSXSS3a91c0de\">MOROSXSS3a91c0de</moros-probe></p>",
        "body_sha256": "4f9d7c6b1a028e5d3a7f2b118d4e0c7f91b23a6c5d8e01f24a6b7c8d9e0f1a2b"
      }
    }
  ]
}
```

### Append-Only Provenance Ledger Entry (`output/evidence/ledger.jsonl`)

```json
{
  "target": "lab-shop.internal.test",
  "skill": "xss-reflected",
  "finding_type": "xss-reflected",
  "finding_id": "fnd-9a3f1c2b8e04",
  "validation_run_id": "val-4c8e21a09f12",
  "evidence_id": "ev-7b2d901a4e8c3f51",
  "evidence_type": "validation_proof",
  "source_artifact": "output/evidence/validation/val-4c8e21a09f12.json",
  "source_sha256": "9f2a8c4e1b07d3f56a91c2e48b0d3a5e7c1f9b2d4e6a8c0b1d3f5a7e9c2b4d6f",
  "source_available": true,
  "claim": "Validation run val-4c8e21a09f12 via 'xss-reflected' produced status 'confirmed' (confidence=0.92).",
  "limitations": "Non-executable <moros-probe> HTML tag verified unescaped reflection; script execution not triggered.",
  "verification_status": "confirmed",
  "confidence": 0.92,
  "recorded_at": "2026-11-26T16:10:04+00:00"
}
```

The finding now holds `status: "confirmed"`, `validation_status: "confirmed"`, `proof_artifact: "output/evidence/validation/val-4c8e21a09f12.json"`, and `evidence_ids: ["ev-7b2d901a4e8c3f51"]`.

---

## Stage 3 — Attack-Chain Correlation (`attack-chains.json`)

`AttackChainEngine` correlates the confirmed `xss` finding (`fnd-9a3f1c2b8e04`) with a candidate `session_hijack` / `admin_access` surface (`fnd-c104e8b21a90`: `"Admin Session Cookie Missing HttpOnly Flag"` on `lab-shop.internal.test/admin`, `status: "candidate"`).

```json
{
  "chain_id": "chain-3f81a92c4d10",
  "name": "Reflected XSS in Search Query Parameter 'q' -> Admin Session Cookie Missing HttpOnly Flag",
  "step_count": 2,
  "verified": false,
  "inferred": true,
  "verified_edge_count": 0,
  "inferred_edge_count": 1,
  "path_risk_score": 7.12,
  "path_severity": "HIGH",
  "impact_score": 9.0,
  "chain_completeness": 0.3333,
  "confidence": 0.654,
  "evidence_quality": 0.6,
  "original_finding_severities": {
    "fnd-9a3f1c2b8e04": "Triage Severity: HIGH — pending human review",
    "fnd-c104e8b21a90": "MEDIUM"
  },
  "technical_signals": [
    "shared_host:lab-shop.internal.test"
  ],
  "missing_prerequisites": [
    "Confirm downstream finding 'Admin Session Cookie Missing HttpOnly Flag' (currently candidate)",
    "Attach verifiable evidence_ids to downstream 'Admin Session Cookie Missing HttpOnly Flag'"
  ],
  "uncertainty": [
    "Downstream 'Admin Session Cookie Missing HttpOnly Flag' is unverified (candidate)",
    "Downstream 'Admin Session Cookie Missing HttpOnly Flag' lacks evidence_ids"
  ],
  "trust_boundaries_crossed": [
    "external_internet",
    "admin_boundary"
  ]
}
```

Notice how `AttackPathAnalyzer` keeps the transition edge marked `inferred: true` (rendered dashed `-.->` in Mermaid) and explicitly lists the missing downstream proof while leaving original finding severities untouched.

---

## Stage 4 — Controlled Remediation (`pending_approval`)

`RemediationAssistant` verifies `is_finding_confirmed(finding) == True`, locates `app/routes/search.py` inside `repo_root` via `CodeContextAnalyzer`, generates a minimal HTML-escaping diff via `PatchGenerator`, validates it with `PatchSafetyReviewer`, and runs regression tests inside an isolated `LocalSandbox` copy (`PatchTestRunner`).

### Remediation Report Summary

- **Finding ID:** `fnd-9a3f1c2b8e04`
- **Affected File:** `app/routes/search.py` (`search_view`, L14–L22)
- **Root Cause:** Untrusted input is rendered directly into an HTML response without context-aware HTML escaping (`CWE-79`).
- **Violated Invariant:** All untrusted values rendered into HTML contexts must be HTML-escaped before serialization.
- **Approval Status:** `pending_approval` (`checkpoint_id: "cp-5f2a9c18e3b0"`, `branch_created: false`, `committed: false`, `pushed: false`)

### Proposed Minimal Unified Diff

```diff
--- a/app/routes/search.py
+++ b/app/routes/search.py
@@ -1,4 +1,5 @@
 from flask import request
+import html
 
 def search_view():
     query = request.args.get("q", "")
-    return f"<h1>Search Results</h1><p>Results for: {query}</p>"
+    return f"<h1>Search Results</h1><p>Results for: {html.escape(str(query), quote=True)}</p>"
```

### Isolated Safety Review & Regression Tests

- **PatchSafetyReviewer:** `approved: true`, `touched_files: ["app/routes/search.py"]`, `added_lines: 2`, `removed_lines: 1`, `secret_findings: []`.
- **PatchTestRunner (`isolation_backend: "local"`):**
  - Command: `python -m pytest tests/test_search_route.py -q`
  - Result: `exit_code: 0`, `passed: true`, `"1/1 test command(s) passed in isolated local sandbox."`
- **Operator Action Required:** Main working tree was **not** modified. After human review, `approve_and_create_branch(..., approved=True, approved_by="human:appsec-lead")` creates local branch `remediation/fnd-9a3f1c2b8e04` without auto-committing or pushing.

---

## Stage 5 — Post-Fix Retest Verification (`fixed` with Limitation Notice & Preserved Evidence)

After the operator merges and deploys commit `a1b2c3d` to `lab-shop.internal.test`, `RetestEngine` builds `RetestPlan` (`plan-6e29c1b04a77`), verifies the SHA-256 hash of `val-4c8e21a09f12.json` against `ledger.jsonl`, replays `xss-reflected` (`rval-9d31f0a8e214`), runs `BeforeAfterComparator` and `RegressionAnalyzer`, and persists `output/evidence/retests/ret-8d14f5a27b30.json`.

### Retest Result (`output/evidence/retests/ret-8d14f5a27b30.json`)

```json
{
  "schema_version": "1.0",
  "retest_id": "ret-8d14f5a27b30",
  "plan_id": "plan-6e29c1b04a77",
  "finding_id": "fnd-9a3f1c2b8e04",
  "target": "lab-shop.internal.test",
  "endpoint": "https://lab-shop.internal.test/search?q=test",
  "method": "GET",
  "strategy": "xss-reflected",
  "strategy_version": "1.0.0",
  "outcome": "fixed",
  "confidence": 0.85,
  "remediation_id": "rem-fnd-9a3f1c2b8e04",
  "code_version": "a1b2c3d",
  "original_validation_run_id": "val-4c8e21a09f12",
  "original_evidence_ids": ["ev-7b2d901a4e8c3f51"],
  "original_proof_artifact": "output/evidence/validation/val-4c8e21a09f12.json",
  "original_proof_sha256": "9f2a8c4e1b07d3f56a91c2e48b0d3a5e7c1f9b2d4e6a8c0b1d3f5a7e9c2b4d6f",
  "retest_validation_run_id": "rval-9d31f0a8e214",
  "retest_proof_artifact": "output/evidence/validation/rval-9d31f0a8e214.json",
  "retest_evidence_ids": ["ev-3c1f8a92b04d7e61", "ev-5a9e2d41c87b0f32"],
  "retest_artifact": "output/evidence/retests/ret-8d14f5a27b30.json",
  "retest_evidence_id": "ev-5a9e2d41c87b0f32",
  "before_after": {
    "status_code_before": 200,
    "status_code_after": 200,
    "status_changed": false,
    "before": {
      "reflection_marker": true,
      "body_preview": "<h1>Search Results</h1><p>Results for: <moros-probe data-id=\"MOROSXSS3a91c0de\">MOROSXSS3a91c0de</moros-probe></p>"
    },
    "after": {
      "reflection_marker": false,
      "body_preview": "<h1>Search Results</h1><p>Results for: &lt;moros-probe data-id=&quot;MOROSXSS3a91c0de&quot;&gt;MOROSXSS3a91c0de&lt;/moros-probe&gt;</p>"
    },
    "original_verified": true,
    "suggested_outcome": "fixed"
  },
  "regression_report": {
    "checked_routes": [
      { "route": "https://lab-shop.internal.test/search?q=test", "status": "response", "status_code": 200 }
    ],
    "blocked_routes": [],
    "regressions": [],
    "regression_detected": false,
    "status": "passed",
    "summary": "No regressions detected across 1 checked route(s)."
  },
  "limitations": [
    "Payload was HTML-escaped, stripped, or rendered in non-HTML context.",
    "Does not prove the entire application is secure; only that the specific tested issue was not reproduced under the recorded conditions"
  ],
  "requests_used": 3
}
```

### Preserved Historical Evidence on Finding Record

`update_finding_lifecycle()` updates the finding to `status: "fixed"` while preserving all historical provenance:

- `finding["proof_artifact"]` remains `"output/evidence/validation/val-4c8e21a09f12.json"`
- `finding["validation_result"]` remains the original Phase 1 `ValidationResult`
- `finding["evidence_ids"]` preserves `"ev-7b2d901a4e8c3f51"` and appends `"ev-3c1f8a92b04d7e61"` and `"ev-5a9e2d41c87b0f32"`
- `finding["retest_history"]` contains the immutable `ret-8d14f5a27b30` entry referencing `original_proof_sha256` and `retest_artifact`
- `ci_gate.py` now classifies this finding under `counts.fixed = 1` (not triggering), yielding exit code `0`.
