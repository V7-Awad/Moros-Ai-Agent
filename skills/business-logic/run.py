#!/usr/bin/env python3
"""
run.py — Executable Runner for Business Logic Vulnerability Analyzer in Moros AI.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_skill_dir = Path(__file__).parent.resolve()
_project_root = _skill_dir
while _project_root != _project_root.parent:
    if (_project_root / "tools").is_dir() and (_project_root / "run.py").is_file():
        break
    _project_root = _project_root.parent
sys.path.insert(0, str(_project_root / "tools"))

from checkpoint_manager import CheckpointManager
from llm_client import LLMClient
from scope_validator import ScopeValidator
from scoped_http import ScopedHttpClient, check_checkpoint_approval, is_gated_post_enabled


_WORKFLOW_RULES: List[Dict[str, Any]] = [
    {
        "category": "Payment & Checkout Flow",
        "keywords": ("checkout", "payment", "pay", "billing", "order", "invoice"),
        "risk_indicators": (
            "workflow_step_skipping",
            "payment_state_tampering",
            "concurrent_double_submit",
        ),
        "severity": "MEDIUM",
        "cwe": "CWE-840",
    },
    {
        "category": "Cart, Price & Quantity Manipulation",
        "keywords": ("cart", "price", "quantity", "qty", "amount", "total", "subtotal"),
        "risk_indicators": (
            "negative_or_zero_quantity",
            "client_controlled_price_override",
            "numeric_boundary_tampering",
        ),
        "severity": "MEDIUM",
        "cwe": "CWE-840",
    },
    {
        "category": "Coupon & Discount Abuse",
        "keywords": ("coupon", "discount", "promo", "voucher"),
        "risk_indicators": (
            "coupon_stacking",
            "race_condition_redeem",
            "negative_discount_inversion",
        ),
        "severity": "MEDIUM",
        "cwe": "CWE-840",
    },
    {
        "category": "Financial Transfer, Refund & Wallet",
        "keywords": ("refund", "transfer", "wallet", "withdraw", "deposit", "balance"),
        "risk_indicators": (
            "double_spend_race_condition",
            "negative_transfer_amount",
            "idempotency_bypass",
        ),
        "severity": "HIGH",
        "cwe": "CWE-362",
    },
    {
        "category": "Subscription & Entitlement Control",
        "keywords": ("subscription", "plan", "tier", "trial", "upgrade", "downgrade"),
        "risk_indicators": (
            "entitlement_state_bypass",
            "plan_price_mismatch",
            "trial_extension_abuse",
        ),
        "severity": "MEDIUM",
        "cwe": "CWE-840",
    },
    {
        "category": "Role, Privilege & Invitation Workflow",
        "keywords": ("role", "permission", "privilege", "invite"),
        "risk_indicators": (
            "mass_assignment_role_escalation",
            "invite_token_reuse",
            "authorization_state_mismatch",
        ),
        "severity": "HIGH",
        "cwe": "CWE-269",
    },
]

_TAMPER_PARAM_NAMES = {
    "price", "unit_price", "amount", "total", "subtotal", "quantity", "qty",
    "count", "discount", "coupon", "promo", "role", "plan", "tier",
    "subscription", "status", "balance", "refund_amount",
}
_STATIC_EXTS = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".woff", ".woff2", ".ico", ".map", ".svg")
_REJECTION_HINTS = (
    "invalid", "must be positive", "greater than 0", "greater than zero",
    "cannot be negative", "non-negative", "denied", "unauthorized", "forbidden",
)


def _parse_budget(default: int, cap: int) -> int:
    raw = os.environ.get("MOROS_HTTP_REQUESTS_REMAINING")
    if raw is None or not raw.strip():
        return min(default, cap)
    try:
        return min(max(0, int(raw.strip())), cap)
    except ValueError:
        return min(default, cap)


def _append_log(log_file: Path, message: str) -> None:
    log_file.parent.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).isoformat()
    with log_file.open("a", encoding="utf-8") as fh:
        fh.write(f"[{ts}] {message}\n")


def _extract_param_names(raw_params: Any) -> List[str]:
    names: List[str] = []
    if not isinstance(raw_params, list):
        return names
    for item in raw_params:
        if isinstance(item, dict):
            name = str(item.get("name") or "").strip()
        else:
            name = str(item or "").strip()
        if name and name not in names:
            names.append(name)
    return names


def _load_endpoint_records(out_dir: Path) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    by_key: Dict[Tuple[str, str], Dict[str, Any]] = {}

    def _add(url: str, method: str, params: List[str], source_rel: str) -> None:
        clean_url = (url or "").strip()
        if not clean_url:
            return
        path_only = clean_url.split("?", 1)[0].lower()
        if path_only.endswith(_STATIC_EXTS):
            return
        clean_method = (method or "GET").upper()
        key = (clean_method, clean_url)
        if key in by_key:
            existing_params = by_key[key]["parameters"]
            for p in params:
                if p not in existing_params:
                    existing_params.append(p)
            return
        rec = {
            "url": clean_url,
            "method": clean_method,
            "parameters": list(params),
            "source_artifact": f"output/{source_rel}",
        }
        by_key[key] = rec
        records.append(rec)

    def _from_item(item: Any, source_rel: str) -> None:
        if isinstance(item, str):
            _add(item, "GET", [], source_rel)
        elif isinstance(item, dict):
            url = str(item.get("url") or "").strip()
            if not url:
                path = str(item.get("path") or "").strip()
                base = str(item.get("base_url") or "").strip().rstrip("/")
                url = f"{base}/{path.lstrip('/')}" if base and path else path
            method = str(item.get("method") or "GET").upper()
            params = _extract_param_names(item.get("parameters") or [])
            _add(url, method, params, source_rel)

    for rel in (
        "js/endpoints.json",
        "api/endpoints.json",
        "api/openapi-endpoints.json",
        "content-discovery/discovered-paths.json",
    ):
        ep_file = out_dir / rel
        if not ep_file.is_file():
            continue
        try:
            data = json.loads(ep_file.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(data, list):
            for entry in data:
                _from_item(entry, rel)
        elif isinstance(data, dict):
            if isinstance(data.get("endpoints"), list):
                for entry in data["endpoints"]:
                    _from_item(entry, rel)
            for key in ("interesting_routes", "paths_checked"):
                rows = data.get(key)
                if isinstance(rows, list):
                    for entry in rows:
                        if key == "paths_checked" and isinstance(entry, dict) and entry.get("status_code") in (None, 404):
                            continue
                        _from_item(entry, rel)

    return records


def _classify_workflow(record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    url_low = record["url"].lower()
    params_low = [p.lower() for p in record.get("parameters", [])]
    haystack = " ".join([url_low] + params_low)

    matched_rules: List[Dict[str, Any]] = []
    matched_keywords: List[str] = []
    for rule in _WORKFLOW_RULES:
        hits = [kw for kw in rule["keywords"] if kw in haystack]
        if hits:
            matched_rules.append(rule)
            for kw in hits:
                if kw not in matched_keywords:
                    matched_keywords.append(kw)

    if not matched_rules:
        return None

    primary = matched_rules[0]
    risk_indicators: List[str] = []
    for rule in matched_rules:
        for ind in rule["risk_indicators"]:
            if ind not in risk_indicators:
                risk_indicators.append(ind)

    tamper_params = [
        p for p in record.get("parameters", [])
        if p.lower() in _TAMPER_PARAM_NAMES or any(t in p.lower() for t in ("price", "qty", "quantity", "amount", "discount", "coupon", "role", "total"))
    ]
    if tamper_params and "parameter_tampering_surface" not in risk_indicators:
        risk_indicators.append("parameter_tampering_surface")

    severity = "HIGH" if any(r["severity"] == "HIGH" for r in matched_rules) or len(tamper_params) >= 2 else primary["severity"]
    return {
        "category": primary["category"],
        "cwe": primary["cwe"],
        "severity": severity,
        "matched_keywords": matched_keywords,
        "risk_indicators": risk_indicators,
        "tamper_parameters": tamper_params,
    }


def _select_tamper_payload(classification: Dict[str, Any], record: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
    params_low = {p.lower(): p for p in record.get("parameters", [])}
    for key in ("quantity", "qty", "count"):
        if key in params_low:
            orig = params_low[key]
            return {orig: -1}, f"negative quantity ({orig}=-1)"
    for key in ("price", "unit_price", "amount", "total", "subtotal"):
        if key in params_low:
            orig = params_low[key]
            return {orig: 0}, f"zero price/amount ({orig}=0)"

    keywords = set(classification.get("matched_keywords", []))
    if keywords & {"cart", "quantity", "qty", "checkout", "order"}:
        return {"quantity": -1}, "negative quantity (quantity=-1)"
    return {"price": 0}, "zero price (price=0)"


def _response_accepted_tamper(resp: Dict[str, Any]) -> Tuple[bool, str]:
    if resp.get("status") != "response":
        return False, ""
    code = int(resp.get("status_code", 0) or 0)
    if code not in (200, 201):
        return False, ""
    ct = str(resp.get("headers", {}).get("content-type", "")).lower()
    if "text/html" in ct:
        return False, ""
    body = (resp.get("body") or "").strip()
    if not body:
        return False, ""
    low_body = body.lower()
    if any(hint in low_body for hint in _REJECTION_HINTS):
        return False, ""
    try:
        parsed = json.loads(body)
        if isinstance(parsed, dict) and parsed.get("error"):
            return False, ""
    except Exception:
        pass
    return True, f"HTTP {code} accepted tamper payload without rejection: {body[:160]}"


def _enrich_with_llm(findings: List[Dict[str, Any]], target: str, log_file: Path) -> bool:
    """Optionally enrich workflow candidates with LLM reasoning; fail-safe offline."""
    if not findings:
        return False
    if os.environ.get("MOROS_LLM_PROVIDER", "").strip().lower() == "none":
        return False
    try:
        llm = LLMClient(provider="auto")
        if not llm.is_available():
            _append_log(log_file, "LLM enrichment skipped (no LLM provider available offline).")
            return False

        compact_surface = [
            {
                "url": f["url"],
                "method": f.get("method", "POST"),
                "category": f.get("category"),
                "risk_indicators": f.get("risk_indicators", []),
                "parameters": f.get("parameters", []),
            }
            for f in findings[:8]
        ]
        prompt = (
            f"Analyze these business workflow endpoints for {target} and return a JSON array of objects "
            "with keys 'url', 'abuse_scenario', and 'verification_step'. Keep each concise.\n"
            f"Endpoints:\n{json.dumps(compact_surface, indent=2)}"
        )
        raw = llm.complete(
            prompt,
            system_prompt="You are a security analyst reviewing business workflow state machines. Return concise JSON only.",
            temperature=0.1,
            max_tokens=1024,
            timeout=15,
        )
        if not raw:
            return False

        enriched = False
        cleaned = raw.strip()
        if cleaned.startswith("```"):
            lines = cleaned.splitlines()
            cleaned = "\n".join(line for line in lines if not line.strip().startswith("```")).strip()
        try:
            parsed = json.loads(cleaned)
            items = parsed if isinstance(parsed, list) else parsed.get("items", []) if isinstance(parsed, dict) else []
            by_url = {str(item.get("url", "")).strip(): item for item in items if isinstance(item, dict)}
            for f in findings:
                match = by_url.get(f["url"])
                if match:
                    f["llm_analysis"] = {
                        "abuse_scenario": str(match.get("abuse_scenario", ""))[:400],
                        "verification_step": str(match.get("verification_step", ""))[:400],
                    }
                    enriched = True
        except Exception:
            findings[0]["llm_analysis"] = {"summary": cleaned[:500]}
            enriched = True

        if enriched:
            _append_log(log_file, f"Enriched business-logic findings via {llm.provider}/{llm.model}.")
        return enriched
    except Exception as exc:
        _append_log(log_file, f"LLM enrichment skipped (non-fatal): {exc}")
        return False


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--target-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    target_dir = Path(args.target_dir)
    out_dir = Path(args.output_dir)
    findings_dir = out_dir / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)
    out_file = findings_dir / "candidates-business-logic.json"
    log_file = out_dir / "logs" / "business-logic" / "run.log"

    _append_log(log_file, f"Starting business-logic analysis for target={args.target}")

    endpoint_records = _load_endpoint_records(out_dir)
    workflow_items: List[Tuple[Dict[str, Any], Dict[str, Any]]] = []
    for rec in endpoint_records:
        classification = _classify_workflow(rec)
        if classification is not None:
            workflow_items.append((rec, classification))

    _append_log(
        log_file,
        f"Inspected {len(endpoint_records)} discovered endpoints; identified {len(workflow_items)} business-workflow routes.",
    )

    findings: List[Dict[str, Any]] = []
    req_budget = _parse_budget(10, 10)
    has_scope_file = any(target_dir.glob("scope-of-work.*")) or (target_dir / "scope.json").is_file()

    validator: Optional[ScopeValidator] = None
    base_url = (args.target if "://" in args.target else f"https://{args.target}").rstrip("/")

    if workflow_items:
        try:
            validator = ScopeValidator(args.target, target_dir=target_dir)
            probe_client = ScopedHttpClient(
                target=args.target,
                max_requests=max(1, req_budget),
                delay_seconds=0.2,
                timeout_seconds=5.0,
                scope_validator=validator,
            )
            base_url = probe_client.base_url.rstrip("/")
        except ValueError as exc:
            _append_log(log_file, f"Skipped HTTP client initialization (invalid target/scope): {exc}")
            workflow_items = []
            req_budget = 0

    active_allowed = bool(
        validator
        and has_scope_file
        and req_budget > 0
        and getattr(validator, "policy", {}).get("allow_active_vulnerability_checks", True)
    )
    get_client: Optional[ScopedHttpClient] = None
    post_client: Optional[ScopedHttpClient] = None
    cm: Optional[CheckpointManager] = None
    if active_allowed:
        get_client = ScopedHttpClient(
            target=args.target,
            max_requests=req_budget,
            delay_seconds=0.2,
            timeout_seconds=5.0,
            scope_validator=validator,
        )
        if is_gated_post_enabled():
            cm = CheckpointManager(args.target, target_dir)
    else:
        _append_log(log_file, "Running passive/offline workflow classification only (no active probes).")

    post_used = 0
    for rec, classification in workflow_items[:15]:
        ep_url = rec["url"]
        full_url = ep_url if "://" in ep_url else f"{base_url}/{ep_url.lstrip('/')}"
        method = rec["method"]
        params = rec["parameters"]
        tamper_confirmed = False
        evidence_parts = [
            f"Workflow '{classification['category']}' matched keywords {classification['matched_keywords']} "
            f"on {method} {ep_url}"
        ]
        if classification["tamper_parameters"]:
            evidence_parts.append(f"tamperable parameters={classification['tamper_parameters']}")

        # Safe GET inspection for GET workflow endpoints when active scope & budget permit
        if active_allowed and get_client is not None and method == "GET" and (get_client.request_count + post_used < req_budget):
            resp = get_client.get(full_url)
            if resp.get("status") == "response":
                evidence_parts.append(f"safe GET returned HTTP {resp.get('status_code')}")
            elif resp.get("status") in ("blocked_scope", "blocked"):
                _append_log(log_file, f"Stopped HTTP probing due to scope policy on {full_url}")
                active_allowed = False

        # Optional HITL-gated negative-quantity / zero-price POST probe
        if active_allowed and cm is not None and (get_client.request_count + post_used < req_budget):
            tamper_payload, tamper_desc = _select_tamper_payload(classification, rec)
            cp_type = "Business Logic Tamper Probe"
            reason = f"Send bounded HITL-gated {tamper_desc} check to {full_url}"
            if check_checkpoint_approval(cm, cp_type, full_url, method="POST", reason=reason, risk_level="MEDIUM"):
                if post_client is None:
                    remaining = max(1, req_budget - (get_client.request_count if get_client else 0))
                    post_client = ScopedHttpClient(
                        target=args.target,
                        max_requests=remaining,
                        delay_seconds=0.2,
                        timeout_seconds=5.0,
                        scope_validator=validator,
                        allow_state_changing=True,
                        approval_callback=lambda m, u, b: check_checkpoint_approval(
                            cm, cp_type, u, method=m, reason=reason, risk_level="MEDIUM"
                        ),
                    )
                post_resp = post_client.post(full_url, json_body=tamper_payload)
                post_used = post_client.request_count
                accepted, tamper_evidence = _response_accepted_tamper(post_resp)
                if accepted:
                    tamper_confirmed = True
                    evidence_parts.append(f"HITL-approved {tamper_desc}: {tamper_evidence}")
                elif post_resp.get("status") == "response":
                    evidence_parts.append(
                        f"HITL-approved {tamper_desc} returned HTTP {post_resp.get('status_code')}"
                    )

        severity = "HIGH" if tamper_confirmed else classification["severity"]
        title_prefix = "Potential Business Logic Tampering Accepted" if tamper_confirmed else f"Business Logic Workflow Surface ({classification['category']})"
        findings.append({
            "title": f"{title_prefix}: {ep_url[:60]}",
            "type": "Business Logic",
            "category": classification["category"],
            "severity": severity,
            "url": full_url,
            "method": method,
            "cwe": classification["cwe"],
            "parameters": params,
            "tamper_parameters": classification["tamper_parameters"],
            "risk_indicators": classification["risk_indicators"],
            "hitl_tamper_tested": tamper_confirmed,
            "source_artifact": rec["source_artifact"],
            "evidence": "; ".join(evidence_parts),
            "notes": (
                f"High-risk {classification['category']} endpoint with indicators: "
                f"{', '.join(classification['risk_indicators'])}."
            ),
            "status": "candidate",
            "validation_status": "unverified",
            "curl": f"curl -s -i -X {method} '{full_url}'",
        })

    llm_enriched = _enrich_with_llm(findings, args.target, log_file)

    payload = {
        "target": args.target,
        "skill": "business-logic",
        "title": "Business Logic Vulnerability Analyzer",
        "count": len(findings),
        "llm_enriched": llm_enriched,
        "findings": findings,
    }
    out_file.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    _append_log(
        log_file,
        f"Business Logic analysis finished: {len(findings)} candidate finding(s) saved to {out_file}.",
    )
    print(f"Business Logic analysis completed: {len(findings)} candidate findings recorded.")


if __name__ == "__main__":
    main()
