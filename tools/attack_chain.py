#!/usr/bin/env python3
"""
attack_chain.py — Correlated Attack Chain Engine for Moros AI (Phase 2).

Models relationships across assets, endpoints, identities, trust boundaries,
findings, evidence, attack steps, and remediations. Correlates findings using
explicit technical signals (shared host/endpoint/parameter/identity and
demonstrated prerequisite -> consequence transitions), distinguishes verified vs
inferred edges, reports missing prerequisites and uncertainty, and scores
attack paths independently of individual finding severities.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import parse_qs, urlsplit

try:
    from tools.finding_dedupe import finding_identity
except ImportError:
    from finding_dedupe import finding_identity


NODE_TYPES: Tuple[str, ...] = (
    "asset",
    "endpoint",
    "identity",
    "finding",
    "evidence",
    "attack_step",
    "remediation",
)

CONFIRMED_STATUSES: Set[str] = {"confirmed", "validated"}
INACTIVE_STATUSES: Set[str] = {"false_positive", "fixed", "verified_negative"}

# Severity ordering and baseline scores (0.0 - 10.0)
SEVERITY_ORDER: Dict[str, int] = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
    "NONE": 0,
}

# Technical primitive ranks enforce DAG direction (prerequisite -> consequence)
# so path search never introduces cycles.
PRIMITIVE_RANK: Dict[str, int] = {
    "secret_leak": 10,
    "open_redirect": 15,
    "cors_misconfig": 20,
    "xss": 25,
    "csrf": 28,
    "ssrf": 30,
    "path_traversal": 32,
    "xxe": 34,
    "ssti": 36,
    "sqli": 38,
    "auth_bypass": 50,
    "privilege_escalation": 55,
    "oauth_token_theft": 60,
    "token_theft": 60,
    "session_hijack": 65,
    "idor": 70,
    "admin_access": 80,
    "internal_access": 82,
    "data_exfil": 90,
    "rce": 95,
}

PRIMITIVE_IMPACT: Dict[str, float] = {
    "rce": 9.6,
    "admin_access": 9.1,
    "internal_access": 8.6,
    "data_exfil": 8.5,
    "auth_bypass": 8.4,
    "privilege_escalation": 8.5,
    "oauth_token_theft": 8.3,
    "token_theft": 8.0,
    "session_hijack": 8.1,
    "idor": 7.9,
    "ssrf": 8.2,
    "sqli": 8.8,
    "ssti": 9.0,
    "xxe": 8.2,
    "path_traversal": 7.6,
    "secret_leak": 7.4,
    "xss": 6.4,
    "cors_misconfig": 6.3,
    "csrf": 6.0,
    "open_redirect": 4.7,
}

# Explicit technical prerequisite -> consequence transition rules.
# Each entry: (source_primitive, target_primitive, relation, base_confidence,
#              anchor_mode, description, extra_prereq_check)
# anchor_mode:
#   "same_site"     -> same host or same registrable/root domain
#   "same_host"     -> exact same normalized host (or shared root when explicit target matches)
#   "same_endpoint" -> exact same (host, path) or shared parameter
TRANSITION_RULES: List[Dict[str, Any]] = [
    {
        "source": "secret_leak",
        "target": "auth_bypass",
        "relation": "ENABLES_AUTH_BYPASS",
        "base_confidence": 0.90,
        "anchor_mode": "same_site",
        "description": "Exposed credential/JWT/signing secret enables authentication bypass",
        "missing_if_unconfirmed": "Confirmed token forgery or credential replay accepted by auth endpoint",
    },
    {
        "source": "secret_leak",
        "target": "admin_access",
        "relation": "ENABLES_ADMIN_ACCESS",
        "base_confidence": 0.88,
        "anchor_mode": "same_site",
        "description": "Exposed privileged credential/token grants administrative access",
        "missing_if_unconfirmed": "Confirmed privileged token acceptance on administrative surface",
    },
    {
        "source": "secret_leak",
        "target": "idor",
        "relation": "ENABLES_ACCESS_PIVOT",
        "base_confidence": 0.80,
        "anchor_mode": "same_site",
        "description": "Exposed token/key provides authenticated context for cross-object access",
        "missing_if_unconfirmed": "Confirmed authenticated session derived from leaked secret",
    },
    {
        "source": "secret_leak",
        "target": "ssrf",
        "relation": "ENABLES_AUTHENTICATED_SSRF",
        "base_confidence": 0.78,
        "anchor_mode": "same_site",
        "description": "Exposed API/service credential unlocks authenticated SSRF-capable endpoint",
        "missing_if_unconfirmed": "Confirmed service invocation using leaked credential",
    },
    {
        "source": "secret_leak",
        "target": "data_exfil",
        "relation": "ENABLES_DATA_EXFILTRATION",
        "base_confidence": 0.82,
        "anchor_mode": "same_site",
        "description": "Exposed API key or token allows direct extraction of protected data",
        "missing_if_unconfirmed": "Confirmed API data retrieval using leaked credential",
    },
    {
        "source": "auth_bypass",
        "target": "idor",
        "relation": "ENABLES_IDOR",
        "base_confidence": 0.88,
        "anchor_mode": "same_site",
        "description": "Authentication bypass exposes object-level authorization flaw",
        "missing_if_unconfirmed": "Confirmed cross-tenant or cross-user object access post-bypass",
    },
    {
        "source": "auth_bypass",
        "target": "ssrf",
        "relation": "ENABLES_SSRF",
        "base_confidence": 0.84,
        "anchor_mode": "same_site",
        "description": "Authentication bypass reaches internal-fetching SSRF functionality",
        "missing_if_unconfirmed": "Confirmed SSRF trigger reachable without valid session",
    },
    {
        "source": "auth_bypass",
        "target": "admin_access",
        "relation": "ESCALATES_TO_ADMIN",
        "base_confidence": 0.92,
        "anchor_mode": "same_site",
        "description": "Authentication bypass reaches administrative operations",
        "missing_if_unconfirmed": "Confirmed administrative action execution after bypass",
    },
    {
        "source": "auth_bypass",
        "target": "data_exfil",
        "relation": "ENABLES_DATA_EXFILTRATION",
        "base_confidence": 0.86,
        "anchor_mode": "same_site",
        "description": "Authentication bypass permits unauthenticated retrieval of sensitive records",
        "missing_if_unconfirmed": "Confirmed sensitive record access without authorization",
    },
    {
        "source": "privilege_escalation",
        "target": "admin_access",
        "relation": "ESCALATES_TO_ADMIN",
        "base_confidence": 0.92,
        "anchor_mode": "same_site",
        "description": "Privilege escalation crosses into administrative trust boundary",
        "missing_if_unconfirmed": "Confirmed elevated privilege enforcement bypass",
    },
    {
        "source": "privilege_escalation",
        "target": "idor",
        "relation": "ENABLES_IDOR",
        "base_confidence": 0.84,
        "anchor_mode": "same_site",
        "description": "Elevated role facilitates unauthorized object access",
        "missing_if_unconfirmed": "Confirmed unauthorized object read/write using escalated role",
    },
    {
        "source": "open_redirect",
        "target": "oauth_token_theft",
        "relation": "ENABLES_OAUTH_TOKEN_THEFT",
        "base_confidence": 0.85,
        "anchor_mode": "same_site",
        "description": "Open redirect in trusted origin leaks OAuth authorization code/token via redirect_uri",
        "missing_if_unconfirmed": "Confirmed OAuth redirect_uri chain delivering code/token to redirect sink",
    },
    {
        "source": "open_redirect",
        "target": "token_theft",
        "relation": "ENABLES_TOKEN_THEFT",
        "base_confidence": 0.82,
        "anchor_mode": "same_site",
        "description": "Open redirect leaks bearer/callback token to attacker-controlled destination",
        "missing_if_unconfirmed": "Confirmed token parameter leakage across redirect target",
    },
    {
        "source": "open_redirect",
        "target": "xss",
        "relation": "CHAINS_TO_XSS",
        "base_confidence": 0.76,
        "anchor_mode": "same_host",
        "description": "Open redirect parameter flows into script/DOM navigation sink",
        "missing_if_unconfirmed": "Confirmed executable scheme or DOM sink reflection in redirect flow",
    },
    {
        "source": "open_redirect",
        "target": "ssrf",
        "relation": "BYPASSES_SSRF_ALLOWLIST",
        "base_confidence": 0.78,
        "anchor_mode": "same_site",
        "description": "Server-side fetcher follows open redirect on trusted host to restricted target",
        "missing_if_unconfirmed": "Confirmed SSRF fetcher following redirect to non-allowlisted host",
    },
    {
        "source": "oauth_token_theft",
        "target": "session_hijack",
        "relation": "ENABLES_SESSION_HIJACK",
        "base_confidence": 0.90,
        "anchor_mode": "same_site",
        "description": "Stolen OAuth token establishes victim session",
        "missing_if_unconfirmed": "Confirmed victim session exchange using intercepted OAuth token",
    },
    {
        "source": "oauth_token_theft",
        "target": "admin_access",
        "relation": "ESCALATES_TO_ADMIN",
        "base_confidence": 0.86,
        "anchor_mode": "same_site",
        "description": "Stolen privileged OAuth token accesses admin endpoints",
        "missing_if_unconfirmed": "Confirmed admin scope attached to intercepted OAuth token",
    },
    {
        "source": "token_theft",
        "target": "session_hijack",
        "relation": "ENABLES_SESSION_HIJACK",
        "base_confidence": 0.88,
        "anchor_mode": "same_site",
        "description": "Stolen token enables impersonation of victim session",
        "missing_if_unconfirmed": "Confirmed session impersonation via captured token",
    },
    {
        "source": "xss",
        "target": "session_hijack",
        "relation": "ENABLES_SESSION_HIJACK",
        "base_confidence": 0.86,
        "anchor_mode": "same_site",
        "description": "Script execution in origin captures session/token or drives authenticated requests",
        "missing_if_unconfirmed": "Confirmed unescaped script execution with accessible session/token state",
    },
    {
        "source": "xss",
        "target": "admin_access",
        "relation": "ENABLES_ADMIN_HIJACK",
        "base_confidence": 0.85,
        "anchor_mode": "same_site",
        "description": "XSS executing in privileged browser context drives administrative actions",
        "missing_if_unconfirmed": "Confirmed execution in admin-accessible origin/context",
    },
    {
        "source": "xss",
        "target": "token_theft",
        "relation": "ENABLES_TOKEN_THEFT",
        "base_confidence": 0.84,
        "anchor_mode": "same_site",
        "description": "Client-side script reads accessible storage/DOM token",
        "missing_if_unconfirmed": "Confirmed script access to client token storage",
    },
    {
        "source": "xss",
        "target": "csrf",
        "relation": "BYPASSES_CSRF_PROTECTION",
        "base_confidence": 0.82,
        "anchor_mode": "same_host",
        "description": "Same-origin script execution reads anti-CSRF tokens and submits forged actions",
        "missing_if_unconfirmed": "Confirmed same-origin anti-CSRF token extraction",
    },
    {
        "source": "cors_misconfig",
        "target": "data_exfil",
        "relation": "ENABLES_CORS_DATA_EXFIL",
        "base_confidence": 0.85,
        "anchor_mode": "same_site",
        "description": "Permissive CORS with credentials allows cross-origin reading of authenticated responses",
        "missing_if_unconfirmed": "Confirmed Access-Control-Allow-Credentials: true on sensitive authenticated endpoint",
    },
    {
        "source": "cors_misconfig",
        "target": "token_theft",
        "relation": "ENABLES_CORS_TOKEN_THEFT",
        "base_confidence": 0.83,
        "anchor_mode": "same_site",
        "description": "Credentialed CORS origin reflection exposes token/session endpoint across origins",
        "missing_if_unconfirmed": "Confirmed credentialed CORS reflection on token-issuing endpoint",
    },
    {
        "source": "cors_misconfig",
        "target": "idor",
        "relation": "ENABLES_CROSS_ORIGIN_IDOR",
        "base_confidence": 0.79,
        "anchor_mode": "same_site",
        "description": "Permissive CORS exposes victim-scoped object endpoint cross-origin",
        "missing_if_unconfirmed": "Confirmed credentialed cross-origin read of object endpoint",
    },
    {
        "source": "ssrf",
        "target": "secret_leak",
        "relation": "EXPOSES_INTERNAL_CREDENTIALS",
        "base_confidence": 0.86,
        "anchor_mode": "same_site",
        "description": "SSRF reaches internal/metadata service returning credentials",
        "missing_if_unconfirmed": "Confirmed internal metadata or secret response via SSRF",
    },
    {
        "source": "ssrf",
        "target": "internal_access",
        "relation": "CROSSES_INTERNAL_BOUNDARY",
        "base_confidence": 0.88,
        "anchor_mode": "same_site",
        "description": "SSRF bridges external boundary into internal network services",
        "missing_if_unconfirmed": "Confirmed reachability of internal service via SSRF",
    },
    {
        "source": "ssrf",
        "target": "data_exfil",
        "relation": "ENABLES_DATA_EXFILTRATION",
        "base_confidence": 0.84,
        "anchor_mode": "same_site",
        "description": "SSRF reads internal/restricted data resources",
        "missing_if_unconfirmed": "Confirmed sensitive data returned through SSRF response or OOB channel",
    },
    {
        "source": "session_hijack",
        "target": "admin_access",
        "relation": "ESCALATES_TO_ADMIN",
        "base_confidence": 0.88,
        "anchor_mode": "same_site",
        "description": "Hijacked privileged session accesses admin functionality",
        "missing_if_unconfirmed": "Confirmed victim session holds administrative privileges",
    },
    {
        "source": "session_hijack",
        "target": "idor",
        "relation": "ENABLES_IDOR",
        "base_confidence": 0.82,
        "anchor_mode": "same_site",
        "description": "Hijacked session unlocks authenticated object endpoints",
        "missing_if_unconfirmed": "Confirmed object access using hijacked session",
    },
    {
        "source": "session_hijack",
        "target": "data_exfil",
        "relation": "ENABLES_DATA_EXFILTRATION",
        "base_confidence": 0.86,
        "anchor_mode": "same_site",
        "description": "Hijacked session allows exfiltration of victim-accessible data",
        "missing_if_unconfirmed": "Confirmed sensitive data exposure under hijacked session",
    },
    {
        "source": "idor",
        "target": "data_exfil",
        "relation": "ENABLES_DATA_EXFILTRATION",
        "base_confidence": 0.88,
        "anchor_mode": "same_site",
        "description": "Broken object-level authorization permits bulk extraction of other users' records",
        "missing_if_unconfirmed": "Confirmed retrieval of another user's sensitive record",
    },
    {
        "source": "idor",
        "target": "admin_access",
        "relation": "ESCALATES_TO_ADMIN",
        "base_confidence": 0.82,
        "anchor_mode": "same_site",
        "description": "IDOR exposes administrative object/account modification",
        "missing_if_unconfirmed": "Confirmed modification or access to admin-owned object",
    },
    {
        "source": "sqli",
        "target": "auth_bypass",
        "relation": "ENABLES_AUTH_BYPASS",
        "base_confidence": 0.90,
        "anchor_mode": "same_site",
        "description": "SQL injection in authentication flow bypasses credential checks",
        "missing_if_unconfirmed": "Confirmed authentication query manipulation",
    },
    {
        "source": "sqli",
        "target": "data_exfil",
        "relation": "ENABLES_DATA_EXFILTRATION",
        "base_confidence": 0.92,
        "anchor_mode": "same_site",
        "description": "SQL injection enables arbitrary database read/extraction",
        "missing_if_unconfirmed": "Confirmed database record extraction",
    },
    {
        "source": "path_traversal",
        "target": "secret_leak",
        "relation": "EXPOSES_CONFIG_SECRETS",
        "base_confidence": 0.87,
        "anchor_mode": "same_site",
        "description": "Arbitrary file read exposes application secrets or configuration keys",
        "missing_if_unconfirmed": "Confirmed read of credential/configuration file",
    },
    {
        "source": "xxe",
        "target": "ssrf",
        "relation": "TRIGGERS_SSRF",
        "base_confidence": 0.86,
        "anchor_mode": "same_site",
        "description": "External entity resolution induces server-side outbound request",
        "missing_if_unconfirmed": "Confirmed external entity fetch from target parser",
    },
    {
        "source": "xxe",
        "target": "data_exfil",
        "relation": "ENABLES_DATA_EXFILTRATION",
        "base_confidence": 0.88,
        "anchor_mode": "same_site",
        "description": "XXE reads local files or internal resources",
        "missing_if_unconfirmed": "Confirmed local file or OOB exfiltration via XXE",
    },
    {
        "source": "ssti",
        "target": "rce",
        "relation": "ESCALATES_TO_RCE",
        "base_confidence": 0.92,
        "anchor_mode": "same_site",
        "description": "Server-side template injection escalates to code execution",
        "missing_if_unconfirmed": "Confirmed template expression execution beyond benign probe",
    },
]

_RULES_BY_PAIR: Dict[Tuple[str, str], Dict[str, Any]] = {
    (r["source"], r["target"]): r for r in TRANSITION_RULES
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_id(prefix: str, value: str, max_len: int = 48) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip()).strip("_")
    if len(slug) > max_len:
        digest = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:10]
        slug = f"{slug[:max_len - 11]}_{digest}"
    return f"{prefix}:{slug or 'unknown'}"


def _mermaid_id(node_id: str) -> str:
    return "n_" + re.sub(r"[^A-Za-z0-9_]", "_", node_id)


def _mermaid_label(text: str, max_len: int = 56) -> str:
    clean = re.sub(r"[\r\n\t]+", " ", str(text or "")).strip()
    clean = clean.replace('"', "'").replace("[", "(").replace("]", ")")
    if len(clean) > max_len:
        clean = clean[: max_len - 3] + "..."
    return clean or "item"


def _normalize_host(value: str) -> str:
    raw = str(value or "").strip().lower()
    if not raw:
        return ""
    if "://" in raw:
        parsed = urlsplit(raw)
        host = (parsed.hostname or "").lower().rstrip(".")
    else:
        host = raw.split("/", 1)[0].split(":", 1)[0].lower().rstrip(".")
    return host


def _root_domain(host: str) -> str:
    h = _normalize_host(host)
    if not h:
        return ""
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", h) or ":" in h:
        return h
    parts = [p for p in h.split(".") if p]
    if len(parts) <= 2:
        return h
    return ".".join(parts[-2:])


def _normalize_endpoint(url_or_path: str, default_host: str = "") -> Tuple[str, str, Set[str]]:
    """Return (host, path, query_param_names) from a URL or path."""
    raw = str(url_or_path or "").strip()
    if not raw:
        return _normalize_host(default_host), "", set()
    if "://" in raw:
        parsed = urlsplit(raw)
        host = (parsed.hostname or "").lower().rstrip(".") or _normalize_host(default_host)
        path = parsed.path or "/"
        params = set(parse_qs(parsed.query, keep_blank_values=True).keys())
        return host, path, params
    if raw.startswith("/"):
        parsed = urlsplit(raw)
        path = parsed.path or "/"
        params = set(parse_qs(parsed.query, keep_blank_values=True).keys())
        return _normalize_host(default_host), path, params
    if "." in raw.split("/", 1)[0] and " " not in raw.split("/", 1)[0]:
        parsed = urlsplit("https://" + raw)
        host = (parsed.hostname or "").lower().rstrip(".")
        path = parsed.path or "/"
        params = set(parse_qs(parsed.query, keep_blank_values=True).keys())
        return host, path, params
    return _normalize_host(default_host), "/" + raw.lstrip("/"), set()


def _extract_parameters(finding: Dict[str, Any], url_params: Set[str]) -> Set[str]:
    params: Set[str] = {p.strip().lower() for p in url_params if str(p).strip()}
    for key in ("parameter", "param"):
        val = finding.get(key)
        if isinstance(val, str) and val.strip():
            params.add(val.strip().lower())
    raw_list = finding.get("parameters")
    if isinstance(raw_list, list):
        for item in raw_list:
            if isinstance(item, dict):
                name = str(item.get("name", "")).strip().lower()
                if name:
                    params.add(name)
            elif isinstance(item, str) and item.strip():
                params.add(item.strip().lower())
    return params


def _extract_evidence_ids(finding: Dict[str, Any]) -> List[str]:
    ids: List[str] = []
    seen: Set[str] = set()

    def _add(val: Any) -> None:
        s = str(val or "").strip()
        if s and s not in seen:
            seen.add(s)
            ids.append(s)

    raw_ids = finding.get("evidence_ids")
    if isinstance(raw_ids, list):
        for item in raw_ids:
            _add(item)
    elif isinstance(raw_ids, str):
        _add(raw_ids)

    ev = finding.get("evidence")
    if isinstance(ev, list):
        for row in ev:
            if isinstance(row, dict):
                _add(row.get("evidence_id"))
    elif isinstance(ev, dict):
        _add(ev.get("evidence_id"))

    vr = finding.get("validation_record")
    if isinstance(vr, dict) and isinstance(vr.get("evidence_ids"), list):
        for item in vr["evidence_ids"]:
            _add(item)

    return ids


def _parse_confidence(raw: Any, is_confirmed: bool, has_evidence: bool) -> float:
    if isinstance(raw, (int, float)):
        val = float(raw)
        if val > 1.0:
            val = val / 100.0 if val <= 100.0 else 1.0
        return round(max(0.05, min(1.0, val)), 4)
    if isinstance(raw, str):
        s = raw.strip().lower()
        mapping = {"high": 0.85, "medium": 0.60, "low": 0.35, "confirmed": 0.95}
        if s in mapping:
            return mapping[s]
        try:
            return _parse_confidence(float(s), is_confirmed, has_evidence)
        except ValueError:
            pass
    if is_confirmed and has_evidence:
        return 0.92
    if is_confirmed:
        return 0.80
    if has_evidence:
        return 0.55
    return 0.40


def _is_finding_confirmed(finding: Dict[str, Any]) -> bool:
    status = str(finding.get("status", "")).strip().lower()
    vstatus = str(finding.get("validation_status", "")).strip().lower()
    if status in INACTIVE_STATUSES or vstatus in INACTIVE_STATUSES:
        return False
    if status in CONFIRMED_STATUSES or vstatus in CONFIRMED_STATUSES:
        return True
    vr = finding.get("validation_record")
    if isinstance(vr, dict):
        if str(vr.get("outcome", "")).strip().lower() == "reproduced" and vr.get("evidence_ids"):
            return True
    return False


def _is_finding_inactive(finding: Dict[str, Any]) -> bool:
    status = str(finding.get("status", "")).strip().lower()
    vstatus = str(finding.get("validation_status", "")).strip().lower()
    return status in INACTIVE_STATUSES or vstatus in INACTIVE_STATUSES


def _normalize_severity_label(raw: Any) -> str:
    text = str(raw or "").strip().upper()
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if level in text:
            return level
    return "UNASSESSED"


def _classify_primitive(finding: Dict[str, Any]) -> str:
    """Map finding metadata into a technical security primitive."""
    explicit = str(finding.get("primitive", finding.get("vuln_class", ""))).strip().lower().replace("-", "_")
    if explicit in PRIMITIVE_RANK:
        return explicit

    blob = " ".join([
        str(finding.get("type", "")),
        str(finding.get("category", "")),
        str(finding.get("skill", "")),
        str(finding.get("cwe", "")),
        str(finding.get("sink", "")),
        str(finding.get("title", "")),
        " ".join(str(t) for t in (finding.get("tags") or [])) if isinstance(finding.get("tags"), list) else "",
    ]).lower()

    if "oauth" in blob and ("token" in blob or "redirect" in blob or "code" in blob or "hijack" in blob):
        if "open redirect" in blob or "open_redirect" in blob or "cwe-601" in blob:
            return "open_redirect"
        return "oauth_token_theft"
    if "open redirect" in blob or "open-redirect" in blob or "open_redirect" in blob or "cwe-601" in blob:
        return "open_redirect"
    if "cors" in blob or "cwe-942" in blob:
        return "cors_misconfig"
    if "ssrf" in blob or "cwe-918" in blob or "server-side request forgery" in blob:
        return "ssrf"
    if "idor" in blob or "bola" in blob or "cwe-639" in blob or "broken object" in blob:
        return "idor"
    if "auth bypass" in blob or "auth-bypass" in blob or "auth_bypass" in blob or "authentication bypass" in blob or "cwe-287" in blob or "alg:none" in blob or "alg none" in blob:
        return "auth_bypass"
    if "privilege escalation" in blob or "privesc" in blob or "cwe-269" in blob:
        return "privilege_escalation"
    if "session hijack" in blob or "session_hijack" in blob or "session fixation" in blob or "cwe-384" in blob:
        return "session_hijack"
    if "token theft" in blob or "token_theft" in blob or "steal token" in blob:
        return "token_theft"
    if "admin" in blob and ("access" in blob or "takeover" in blob or "panel" in blob or "hijack" in blob):
        return "admin_access"
    if "secret" in blob or "api key" in blob or "apikey" in blob or "credential" in blob or "jwt" in blob or "cwe-798" in blob or "private key" in blob:
        return "secret_leak"
    if "xss" in blob or "cwe-79" in blob or "innerhtml" in blob:
        return "xss"
    if "csrf" in blob or "cwe-352" in blob:
        return "csrf"
    if "sqli" in blob or "sql injection" in blob or "cwe-89" in blob:
        return "sqli"
    if "ssti" in blob or "template injection" in blob or "cwe-1336" in blob:
        return "ssti"
    if "xxe" in blob or "cwe-611" in blob:
        return "xxe"
    if "path traversal" in blob or "path-traversal" in blob or "lfi" in blob or "cwe-22" in blob:
        return "path_traversal"
    if "rce" in blob or "command injection" in blob or "code execution" in blob or "cwe-78" in blob:
        return "rce"
    if "exfil" in blob or "data leak" in blob or "sensitive data exposure" in blob or "pii" in blob:
        return "data_exfil"
    if "internal" in blob and ("access" in blob or "metadata" in blob):
        return "internal_access"
    return "generic_finding"


def _make_edge(
    source: str,
    target: str,
    relation: str,
    evidence_ids: Optional[Sequence[str]] = None,
    confidence: float = 0.5,
    verified: bool = False,
    inferred: Optional[bool] = None,
    explanation: str = "",
    created_at: Optional[str] = None,
    source_component: str = "AttackChainEngine",
) -> Dict[str, Any]:
    is_verified = bool(verified)
    is_inferred = (not is_verified) if inferred is None else bool(inferred)
    if is_verified and is_inferred:
        is_inferred = False
    deduped_ev: List[str] = []
    for eid in (evidence_ids or []):
        s = str(eid or "").strip()
        if s and s not in deduped_ev:
            deduped_ev.append(s)
    return {
        "source": str(source),
        "target": str(target),
        "relation": str(relation),
        "evidence_ids": deduped_ev,
        "confidence": round(max(0.0, min(1.0, float(confidence))), 4),
        "verified": is_verified,
        "inferred": is_inferred,
        "explanation": str(explanation),
        "created_at": created_at or _utc_now(),
        "source_component": str(source_component),
    }


def _dedupe_findings_preserve_status(findings: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deduplicate findings using finding_identity while preserving confirmed state & evidence."""
    merged: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
    ordered: List[Dict[str, Any]] = []

    for raw in findings:
        if not isinstance(raw, dict):
            continue
        item = dict(raw)
        # Disambiguate different parameters on the same URL/type so distinct param findings don't collide
        param = str(item.get("parameter", item.get("param", ""))).strip().casefold()
        explicit_id = str(item.get("finding_id", item.get("id", ""))).strip()
        base_identity = finding_identity(item)
        identity = base_identity + (param,) if param else base_identity

        existing = merged.get(identity)
        if existing is None:
            item_copy = dict(item)
            item_copy["_duplicate_count"] = max(1, int(item.get("raw_record_count", 1) or 1))
            item_copy["_merged_finding_ids"] = [explicit_id] if explicit_id else []
            item_copy["evidence_ids"] = _extract_evidence_ids(item_copy)
            merged[identity] = item_copy
            ordered.append(item_copy)
            continue

        existing["_duplicate_count"] += max(1, int(item.get("raw_record_count", 1) or 1))
        if explicit_id and explicit_id not in existing["_merged_finding_ids"]:
            existing["_merged_finding_ids"].append(explicit_id)

        # Merge evidence_ids without duplicates
        existing_ev_ids = list(existing.get("evidence_ids", []))
        for eid in _extract_evidence_ids(item):
            if eid not in existing_ev_ids:
                existing_ev_ids.append(eid)
        existing["evidence_ids"] = existing_ev_ids

        # Merge evidence payloads
        for key in ("evidence", "source_artifacts", "occurrences"):
            incoming = item.get(key)
            if incoming is None:
                continue
            inc_list = incoming if isinstance(incoming, list) else [incoming]
            cur_list = existing.get(key)
            if cur_list is None:
                existing[key] = list(inc_list)
            elif isinstance(cur_list, list):
                for val in inc_list:
                    if val not in cur_list:
                        cur_list.append(val)

        # Preserve confirmed/validated state if either duplicate is confirmed
        if _is_finding_confirmed(item) and not _is_finding_confirmed(existing):
            existing["status"] = item.get("status", "confirmed")
            if item.get("validation_status"):
                existing["validation_status"] = item["validation_status"]
            if item.get("validation_record"):
                existing["validation_record"] = item["validation_record"]

        # Keep higher numeric confidence without losing original severity
        if isinstance(item.get("confidence"), (int, float)) and isinstance(existing.get("confidence"), (int, float)):
            existing["confidence"] = max(float(existing["confidence"]), float(item["confidence"]))
        elif existing.get("confidence") is None and item.get("confidence") is not None:
            existing["confidence"] = item["confidence"]

    return ordered


class FindingRelationshipGraph:
    """Typed entity/relationship graph for findings, assets, endpoints, identities, and evidence."""

    def __init__(self, target: str = "", source_component: str = "FindingRelationshipGraph"):
        self.target = _normalize_host(target) or str(target or "").strip()
        self.source_component = source_component
        self._nodes: Dict[str, Dict[str, Any]] = {}
        self._edges: List[Dict[str, Any]] = []
        self._edge_index: Dict[Tuple[str, str, str], int] = {}
        self.trust_boundaries: Dict[str, Dict[str, Any]] = {}
        self.finding_records: Dict[str, Dict[str, Any]] = {}
        self.duplicate_findings_collapsed: int = 0

        if self.target:
            self.ingest_asset(self.target, asset_type="root_domain", trust_boundary="external_internet")

    @property
    def nodes(self) -> List[Dict[str, Any]]:
        return list(self._nodes.values())

    @property
    def edges(self) -> List[Dict[str, Any]]:
        return list(self._edges)

    def add_node(
        self,
        node_id: str,
        label: str,
        node_type: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        if node_type not in NODE_TYPES:
            raise ValueError(f"Unsupported node_type '{node_type}'. Allowed: {NODE_TYPES}")
        existing = self._nodes.get(node_id)
        if existing is None:
            self._nodes[node_id] = {
                "id": node_id,
                "label": str(label),
                "type": node_type,
                "metadata": dict(metadata or {}),
            }
        elif metadata:
            existing["metadata"].update(metadata)
        return node_id

    def add_edge(
        self,
        source: str,
        target: str,
        relation: str,
        evidence_ids: Optional[Sequence[str]] = None,
        confidence: float = 0.5,
        verified: bool = False,
        inferred: Optional[bool] = None,
        explanation: str = "",
        created_at: Optional[str] = None,
        source_component: Optional[str] = None,
    ) -> Dict[str, Any]:
        edge = _make_edge(
            source=source,
            target=target,
            relation=relation,
            evidence_ids=evidence_ids,
            confidence=confidence,
            verified=verified,
            inferred=inferred,
            explanation=explanation,
            created_at=created_at,
            source_component=source_component or self.source_component,
        )
        key = (edge["source"], edge["target"], edge["relation"])
        existing_idx = self._edge_index.get(key)
        if existing_idx is None:
            self._edge_index[key] = len(self._edges)
            self._edges.append(edge)
            return edge

        existing = self._edges[existing_idx]
        for eid in edge["evidence_ids"]:
            if eid not in existing["evidence_ids"]:
                existing["evidence_ids"].append(eid)
        existing["confidence"] = max(existing["confidence"], edge["confidence"])
        if edge["verified"]:
            existing["verified"] = True
            existing["inferred"] = False
        return existing

    def ingest_trust_boundary(
        self,
        name: str,
        description: str = "",
        zone: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        key = str(name or "").strip().lower().replace(" ", "_") or "external_internet"
        entry = self.trust_boundaries.setdefault(
            key,
            {
                "name": key,
                "description": description or f"Trust boundary: {key}",
                "zone": zone or key,
                "metadata": dict(metadata or {}),
            },
        )
        if metadata:
            entry["metadata"].update(metadata)
        return key

    def ingest_asset(
        self,
        host: str,
        asset_type: str = "subdomain",
        trust_boundary: str = "external_internet",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        norm = _normalize_host(host) or str(host or "").strip()
        boundary = self.ingest_trust_boundary(trust_boundary)
        node_id = _safe_id("asset", norm)
        meta = {
            "host": norm,
            "root_domain": _root_domain(norm),
            "asset_type": asset_type,
            "trust_boundary": boundary,
        }
        if metadata:
            meta.update(metadata)
        self.add_node(node_id, norm, "asset", meta)

        if self.target and norm != self.target and _root_domain(norm) == _root_domain(self.target):
            root_id = _safe_id("asset", self.target)
            if root_id in self._nodes and root_id != node_id:
                self.add_edge(
                    root_id,
                    node_id,
                    "HOSTS",
                    confidence=0.95,
                    verified=True,
                    inferred=False,
                    explanation=f"Root domain {self.target} hosts asset {norm}",
                )
        return node_id

    def ingest_endpoint(
        self,
        url_or_path: str,
        method: str = "GET",
        parameters: Optional[Sequence[Any]] = None,
        host: str = "",
        security: Optional[Sequence[Any]] = None,
        trust_boundary: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        norm_host, path, url_params = _normalize_endpoint(url_or_path, default_host=host or self.target)
        param_names: Set[str] = set(url_params)
        for p in (parameters or []):
            if isinstance(p, dict):
                name = str(p.get("name", "")).strip()
                if name:
                    param_names.add(name)
            elif isinstance(p, str) and p.strip():
                param_names.add(p.strip())

        inferred_boundary = trust_boundary or (
            "admin_boundary" if "/admin" in path.lower() else
            "oauth_flow" if any(tok in path.lower() for tok in ("/oauth", "/auth", "/token", "/sso", "/login")) else
            "authenticated_user" if security else "external_internet"
        )
        boundary = self.ingest_trust_boundary(inferred_boundary)
        method_up = str(method or "GET").upper()
        canonical = f"{norm_host}{path}" if norm_host else path
        ep_id = _safe_id("endpoint", f"{method_up}_{canonical}")
        label = f"{method_up} {path}" if path else canonical

        meta: Dict[str, Any] = {
            "url": url_or_path,
            "host": norm_host,
            "path": path,
            "method": method_up,
            "parameters": sorted(param_names),
            "security": list(security or []),
            "trust_boundary": boundary,
        }
        if metadata:
            meta.update(metadata)
        self.add_node(ep_id, label, "endpoint", meta)

        if norm_host:
            asset_id = self.ingest_asset(norm_host, asset_type="host")
            self.add_edge(
                asset_id,
                ep_id,
                "EXPOSES",
                confidence=0.90,
                verified=True,
                inferred=False,
                explanation=f"Asset {norm_host} exposes {method_up} {path}",
            )
        return ep_id

    def ingest_identity(
        self,
        name: str,
        privilege_level: str = "user",
        trust_boundary: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        clean = str(name or "anonymous").strip().lower().replace(" ", "_")
        boundary = self.ingest_trust_boundary(
            trust_boundary or (
                "admin_boundary" if "admin" in clean or privilege_level == "admin" else
                "external_internet" if clean in {"anonymous", "unauthenticated", "public"} else
                "authenticated_user"
            )
        )
        ident_id = _safe_id("identity", clean)
        meta = {
            "identity": clean,
            "privilege_level": privilege_level,
            "trust_boundary": boundary,
        }
        if metadata:
            meta.update(metadata)
        self.add_node(ident_id, clean, "identity", meta)
        return ident_id

    def ingest_evidence(
        self,
        evidence_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        eid = str(evidence_id or "").strip()
        node_id = _safe_id("evidence", eid)
        meta = {"evidence_id": eid}
        if metadata:
            meta.update(metadata)
        ver_status = str(meta.get("verification_status", "")).lower()
        meta.setdefault("verified", ver_status in CONFIRMED_STATUSES or bool(meta.get("proof_verified")))
        self.add_node(node_id, eid, "evidence", meta)
        return node_id

    def ingest_finding(self, finding: Dict[str, Any]) -> str:
        """Ingest a single finding (without mutating the input dict) into typed graph nodes & edges."""
        deduped = _dedupe_findings_preserve_status([finding])
        return self._ingest_normalized_finding(deduped[0])

    def ingest_findings(self, findings: Iterable[Dict[str, Any]]) -> List[str]:
        """Deduplicate and ingest a collection of findings without mutating inputs."""
        raw_list = [f for f in findings if isinstance(f, dict)]
        deduped = _dedupe_findings_preserve_status(raw_list)
        self.duplicate_findings_collapsed += max(0, len(raw_list) - len(deduped))
        return [self._ingest_normalized_finding(item) for item in deduped]

    def _ingest_normalized_finding(self, item: Dict[str, Any]) -> str:
        title = str(item.get("title", item.get("type", "Finding"))).strip()
        explicit_id = str(item.get("finding_id", item.get("id", ""))).strip()
        raw_url = str(item.get("url", item.get("endpoint", ""))).strip()
        raw_host = str(item.get("host", item.get("asset", item.get("subdomain", "")))).strip()
        host, path, url_params = _normalize_endpoint(raw_url or item.get("path", ""), default_host=raw_host or self.target)
        params = _extract_parameters(item, url_params)
        evidence_ids = _extract_evidence_ids(item)
        confirmed = _is_finding_confirmed(item)
        inactive = _is_finding_inactive(item)
        has_evidence = len(evidence_ids) > 0
        confidence = _parse_confidence(item.get("confidence"), confirmed, has_evidence)
        primitive = _classify_primitive(item)
        orig_severity_raw = item.get("severity", "UNASSESSED")
        orig_severity = _normalize_severity_label(orig_severity_raw)

        # Deterministic finding node ID
        ident_seed = explicit_id or "|".join([
            primitive,
            title.casefold(),
            host,
            path,
            ",".join(sorted(params)),
        ])
        f_node_id = _safe_id("finding", ident_seed)

        # If already ingested via separate call, merge duplicate smoothly
        if f_node_id in self.finding_records:
            self.duplicate_findings_collapsed += 1
            existing_rec = self.finding_records[f_node_id]
            for eid in evidence_ids:
                if eid not in existing_rec["evidence_ids"]:
                    existing_rec["evidence_ids"].append(eid)
                    ev_node = self.ingest_evidence(eid)
                    self.add_edge(
                        f_node_id,
                        ev_node,
                        "SUPPORTED_BY",
                        evidence_ids=[eid],
                        confidence=confidence,
                        verified=confirmed,
                        explanation=f"Finding {title} supported by evidence {eid}",
                    )
            if confirmed and not existing_rec["confirmed"]:
                existing_rec["confirmed"] = True
                existing_rec["status"] = str(item.get("status", "confirmed"))
                self._nodes[f_node_id]["metadata"]["confirmed"] = True
                self._nodes[f_node_id]["metadata"]["status"] = existing_rec["status"]
            existing_rec["confidence"] = max(existing_rec["confidence"], confidence)
            return f_node_id

        # Identity & trust boundary extraction
        identity_name = str(
            item.get("identity")
            or item.get("privilege")
            or item.get("role")
            or item.get("auth_context")
            or ("anonymous" if item.get("requires_auth") is False else "")
            or ("admin" if primitive == "admin_access" or "/admin" in path.lower() else "anonymous")
        ).strip().lower()
        privilege_level = (
            "admin" if "admin" in identity_name else
            "service" if "service" in identity_name else
            "user" if identity_name not in {"anonymous", "unauthenticated", "public"} else
            "anonymous"
        )
        trust_boundary = str(
            item.get("trust_boundary")
            or item.get("boundary")
            or (
                "internal_network" if primitive in {"internal_access", "ssrf"} and "metadata" in title.lower() else
                "admin_boundary" if privilege_level == "admin" or primitive == "admin_access" else
                "cross_origin" if primitive == "cors_misconfig" else
                "oauth_flow" if primitive == "oauth_token_theft" or "oauth" in path.lower() else
                "authenticated_user" if privilege_level in {"user", "service"} else
                "external_internet"
            )
        )
        boundary = self.ingest_trust_boundary(trust_boundary)

        # Preserve original finding severity untouched
        finding_meta = {
            "finding_id": explicit_id or f_node_id,
            "title": title,
            "type": str(item.get("type", item.get("category", ""))),
            "skill": str(item.get("skill", "")),
            "cwe": str(item.get("cwe", "")),
            "primitive": primitive,
            "original_severity": orig_severity_raw,
            "normalized_severity": orig_severity,
            "status": str(item.get("status", "confirmed" if confirmed else "candidate")),
            "validation_status": str(item.get("validation_status", "validated" if confirmed else "unverified")),
            "confirmed": confirmed,
            "inactive": inactive,
            "confidence": confidence,
            "evidence_ids": evidence_ids,
            "host": host,
            "root_domain": _root_domain(host),
            "path": path,
            "url": raw_url,
            "parameters": sorted(params),
            "identity": identity_name,
            "privilege_level": privilege_level,
            "trust_boundary": boundary,
            "raw_record_count": int(item.get("_duplicate_count", item.get("raw_record_count", 1)) or 1),
            "allow_credentials": _has_cors_credentials_signal(item),
            "notes": str(item.get("notes", "")),
            "tags": list(item.get("tags", [])) if isinstance(item.get("tags"), list) else [],
            "metadata": dict(item.get("metadata", {})) if isinstance(item.get("metadata"), dict) else {},
        }
        self.add_node(f_node_id, title, "finding", finding_meta)
        self.finding_records[f_node_id] = finding_meta

        # Link to asset
        if host:
            asset_id = self.ingest_asset(host, trust_boundary=boundary)
            self.add_edge(
                asset_id,
                f_node_id,
                "AFFECTED_BY",
                evidence_ids=evidence_ids,
                confidence=confidence,
                verified=confirmed and has_evidence,
                explanation=f"Asset {host} is affected by {title}",
            )

        # Link to endpoint
        if path or raw_url:
            ep_id = self.ingest_endpoint(
                raw_url or path,
                method=str(item.get("method", "GET")),
                parameters=sorted(params),
                host=host,
                trust_boundary=boundary,
            )
            self.add_edge(
                ep_id,
                f_node_id,
                "VULNERABLE_TO",
                evidence_ids=evidence_ids,
                confidence=confidence,
                verified=confirmed and has_evidence,
                explanation=f"Endpoint {path or raw_url} exhibits {primitive}",
            )

        # Link to identity
        ident_id = self.ingest_identity(identity_name, privilege_level=privilege_level, trust_boundary=boundary)
        self.add_edge(
            f_node_id,
            ident_id,
            "TARGETS_IDENTITY" if primitive in {"admin_access", "session_hijack", "privilege_escalation", "oauth_token_theft"} else "REQUIRES_IDENTITY",
            evidence_ids=evidence_ids,
            confidence=confidence,
            verified=confirmed and has_evidence,
            explanation=f"Finding {title} operates within identity context '{identity_name}' ({boundary})",
        )

        # Link to evidence nodes
        for eid in evidence_ids:
            ev_id = self.ingest_evidence(eid)
            self.add_edge(
                f_node_id,
                ev_id,
                "SUPPORTED_BY",
                evidence_ids=[eid],
                confidence=confidence,
                verified=confirmed,
                explanation=f"Finding {title} references evidence {eid}",
            )

        # Link to remediation node if provided
        rem_text = str(item.get("remediation", item.get("recommended_fix", ""))).strip()
        if rem_text:
            rem_id = _safe_id("remediation", f"{primitive}_{rem_text[:40]}")
            self.add_node(rem_id, rem_text[:80], "remediation", {"recommendation": rem_text, "primitive": primitive})
            self.add_edge(
                f_node_id,
                rem_id,
                "MITIGATED_BY",
                evidence_ids=evidence_ids,
                confidence=0.90,
                verified=True,
                inferred=False,
                explanation=f"Remediation guidance for {title}",
            )

        return f_node_id

    def ingest_all(
        self,
        findings: Iterable[Dict[str, Any]] = (),
        assets: Iterable[str] = (),
        endpoints: Iterable[Any] = (),
        parameters: Iterable[Any] = (),
        identities: Iterable[Any] = (),
        trust_boundaries: Iterable[Any] = (),
        evidence_records: Iterable[Dict[str, Any]] = (),
    ) -> None:
        """Convenience method to populate all entity types into the graph."""
        for tb in trust_boundaries:
            if isinstance(tb, dict):
                self.ingest_trust_boundary(str(tb.get("name", "")), description=str(tb.get("description", "")), metadata=tb)
            elif isinstance(tb, str) and tb.strip():
                self.ingest_trust_boundary(tb)

        for asset in assets:
            if isinstance(asset, dict):
                self.ingest_asset(
                    str(asset.get("host", asset.get("name", ""))),
                    asset_type=str(asset.get("asset_type", "subdomain")),
                    trust_boundary=str(asset.get("trust_boundary", "external_internet")),
                    metadata=asset,
                )
            elif isinstance(asset, str) and asset.strip():
                self.ingest_asset(asset)

        param_map: Dict[str, List[str]] = {}
        for p in parameters:
            if isinstance(p, dict) and p.get("name"):
                for ep_ref in p.get("found_in_endpoints", []) or []:
                    param_map.setdefault(str(ep_ref), []).append(str(p["name"]))

        for ep in endpoints:
            if isinstance(ep, dict):
                url = str(ep.get("url") or (str(ep.get("base_url", "")).rstrip("/") + str(ep.get("path", ""))))
                ep_params = list(ep.get("parameters", []) or [])
                for pname in param_map.get(url, []):
                    if pname not in ep_params:
                        ep_params.append(pname)
                self.ingest_endpoint(
                    url,
                    method=str(ep.get("method", "GET")),
                    parameters=ep_params,
                    host=str(ep.get("host", "")),
                    security=ep.get("security") if isinstance(ep.get("security"), list) else None,
                    metadata=ep,
                )
            elif isinstance(ep, str) and ep.strip():
                self.ingest_endpoint(ep, parameters=param_map.get(ep, []))

        for ident in identities:
            if isinstance(ident, dict):
                self.ingest_identity(
                    str(ident.get("name", ident.get("identity", "user"))),
                    privilege_level=str(ident.get("privilege_level", "user")),
                    trust_boundary=str(ident.get("trust_boundary", "")),
                    metadata=ident,
                )
            elif isinstance(ident, str) and ident.strip():
                self.ingest_identity(ident)

        for ev in evidence_records:
            if isinstance(ev, dict) and ev.get("evidence_id"):
                self.ingest_evidence(str(ev["evidence_id"]), metadata=ev)

        self.ingest_findings(findings)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "total_nodes": len(self._nodes),
            "total_edges": len(self._edges),
            "nodes": self.nodes,
            "edges": self.edges,
            "trust_boundaries": list(self.trust_boundaries.values()),
            "duplicate_findings_collapsed": self.duplicate_findings_collapsed,
        }


def _has_cors_credentials_signal(finding: Dict[str, Any]) -> bool:
    meta = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
    if meta.get("allow_credentials") is True or finding.get("allow_credentials") is True:
        return True
    blob = json.dumps(
        {
            "title": finding.get("title", ""),
            "notes": finding.get("notes", ""),
            "evidence": finding.get("evidence", ""),
            "tags": finding.get("tags", []),
        },
        default=str,
    ).lower()
    return (
        "access-control-allow-credentials: true" in blob
        or "allow-credentials" in blob
        or "withcredentials" in blob
        or "credentials: true" in blob
        or "credentials=true" in blob
    )


def _has_unescaped_xss_blocker(finding: Dict[str, Any]) -> bool:
    meta = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
    if meta.get("marker_escaped") is True or finding.get("marker_escaped") is True:
        return True
    return False


class AttackPathAnalyzer:
    """
    Correlates findings strictly via explicit technical signals:
    - shared asset/host or same-site root domain with compatible trust boundary
    - shared endpoint or parameter
    - demonstrated prerequisite -> consequence transition
    Never correlates merely by matching titles or generic categories.
    """

    def __init__(self, graph: FindingRelationshipGraph, source_component: str = "AttackPathAnalyzer"):
        self.graph = graph
        self.source_component = source_component

    def _technical_anchor(
        self,
        src: Dict[str, Any],
        dst: Dict[str, Any],
        anchor_mode: str,
    ) -> Optional[Dict[str, Any]]:
        """Verify an explicit technical anchor connects src and dst; return signal metadata or None."""
        src_host, dst_host = src["host"], dst["host"]
        src_root, dst_root = src["root_domain"], dst["root_domain"]
        src_path, dst_path = src["path"], dst["path"]
        src_params = set(src.get("parameters", []))
        dst_params = set(dst.get("parameters", []))

        shared_params = sorted(src_params & dst_params)
        same_host = bool(src_host and dst_host and src_host == dst_host)
        same_site = bool(src_root and dst_root and src_root == dst_root)
        same_endpoint = same_host and bool(src_path and dst_path and src_path.rstrip("/") == dst_path.rstrip("/"))
        shared_identity = bool(
            src.get("identity")
            and dst.get("identity")
            and src["identity"] == dst["identity"]
            and src["identity"] != "anonymous"
        )

        # Explicit target_host/target_endpoint linkage in metadata (e.g. leaked JWT secret used by api host)
        src_targets = set(src.get("metadata", {}).get("applies_to_hosts", []) or [])
        explicit_bridge = bool(dst_host and dst_host in src_targets)

        if anchor_mode == "same_endpoint" and not (same_endpoint or (same_host and shared_params)):
            return None
        if anchor_mode == "same_host" and not (same_host or explicit_bridge or shared_identity):
            return None
        if anchor_mode == "same_site" and not (same_host or same_site or explicit_bridge or shared_identity):
            return None

        signals: List[str] = []
        if same_endpoint:
            signals.append(f"shared_endpoint:{src_host}{src_path}")
        elif same_host:
            signals.append(f"shared_host:{src_host}")
        elif same_site:
            signals.append(f"shared_root_domain:{src_root}")
        if shared_params:
            signals.append(f"shared_parameter:{','.join(shared_params)}")
        if shared_identity:
            signals.append(f"shared_identity:{src['identity']}")
        if explicit_bridge:
            signals.append(f"explicit_service_target:{dst_host}")

        if not signals:
            return None

        return {
            "signals": signals,
            "same_host": same_host,
            "same_site": same_site,
            "same_endpoint": same_endpoint,
            "shared_params": shared_params,
            "shared_identity": shared_identity,
            "cross_host_bridge": (not same_host) and same_site,
        }

    def evaluate_transition(
        self,
        src_id: str,
        dst_id: str,
    ) -> Optional[Dict[str, Any]]:
        """Determine whether src_id -> dst_id forms a valid technical attack transition."""
        if src_id == dst_id:
            return None
        src = self.graph.finding_records[src_id]
        dst = self.graph.finding_records[dst_id]

        if src.get("inactive") or dst.get("inactive"):
            return None

        p_src = src["primitive"]
        p_dst = dst["primitive"]
        rule = _RULES_BY_PAIR.get((p_src, p_dst))
        if rule is None:
            return None

        # Enforce strict acyclic rank order
        if PRIMITIVE_RANK.get(p_src, 999) >= PRIMITIVE_RANK.get(p_dst, 0):
            return None

        anchor = self._technical_anchor(src, dst, rule["anchor_mode"])
        if anchor is None:
            return None

        missing_prereqs: List[str] = []
        uncertainty: List[str] = []

        if not src["confirmed"]:
            missing_prereqs.append(f"Confirm prerequisite finding '{src['title']}' (currently {src['status']})")
            uncertainty.append(f"Prerequisite '{src['title']}' is unverified ({src['status']})")
        if not src["evidence_ids"]:
            missing_prereqs.append(f"Attach verifiable evidence_ids to prerequisite '{src['title']}'")
            uncertainty.append(f"Prerequisite '{src['title']}' lacks evidence_ids")

        if not dst["confirmed"]:
            missing_prereqs.append(f"Confirm downstream finding '{dst['title']}' (currently {dst['status']})")
            uncertainty.append(f"Downstream '{dst['title']}' is unverified ({dst['status']})")
        if not dst["evidence_ids"]:
            missing_prereqs.append(f"Attach verifiable evidence_ids to downstream '{dst['title']}'")
            uncertainty.append(f"Downstream '{dst['title']}' lacks evidence_ids")

        # Rule-specific technical prerequisite verification
        if p_src == "cors_misconfig" and not src.get("allow_credentials"):
            missing_prereqs.append(rule["missing_if_unconfirmed"])
            uncertainty.append("CORS finding does not confirm Access-Control-Allow-Credentials: true")

        if p_src == "xss" and _has_unescaped_xss_blocker(src):
            missing_prereqs.append("Demonstrate unescaped executable script context for XSS finding")
            uncertainty.append("XSS probe marker was HTML-escaped")

        if anchor["cross_host_bridge"]:
            # Cross-subdomain transition (e.g. app.lab.local -> api.lab.local or auth -> api)
            # Only considered fully verified if both sides are confirmed with evidence AND explicit bridge or shared token/auth context.
            has_explicit_bridge = bool(src.get("metadata", {}).get("applies_to_hosts")) or (
                p_src in {"secret_leak", "open_redirect", "oauth_token_theft", "xss", "cors_misconfig"}
                and src["confirmed"]
                and dst["confirmed"]
                and bool(src["evidence_ids"])
                and bool(dst["evidence_ids"])
            )
            if not has_explicit_bridge:
                missing_prereqs.append(
                    f"Demonstrate cross-subdomain trust bridge between {src['host']} and {dst['host']}"
                )
                uncertainty.append(
                    f"Cross-host pivot ({src['host']} -> {dst['host']}) inferred from shared root domain {src['root_domain']}"
                )

        verified = len(missing_prereqs) == 0
        inferred = not verified

        # Confidence combines rule confidence, endpoint/host match quality, and finding confidences
        base_conf = float(rule["base_confidence"])
        if anchor["same_endpoint"] or anchor["shared_params"]:
            base_conf = min(0.98, base_conf + 0.05)
        elif anchor["cross_host_bridge"]:
            base_conf = max(0.35, base_conf - 0.12)

        edge_conf = base_conf * ((src["confidence"] + dst["confidence"]) / 2.0)
        if inferred:
            edge_conf = min(edge_conf, 0.72)

        combined_evidence = []
        for eid in src["evidence_ids"] + dst["evidence_ids"]:
            if eid not in combined_evidence:
                combined_evidence.append(eid)

        explanation = (
            f"{rule['description']} via {', '.join(anchor['signals'])}"
            + (f" [inferred: {'; '.join(uncertainty)}]" if inferred and uncertainty else "")
        )

        return {
            "source": src_id,
            "target": dst_id,
            "relation": rule["relation"],
            "evidence_ids": combined_evidence,
            "confidence": round(max(0.05, min(1.0, edge_conf)), 4),
            "verified": verified,
            "inferred": inferred,
            "explanation": explanation,
            "source_component": self.source_component,
            "signals": anchor["signals"],
            "missing_prerequisites": missing_prereqs,
            "uncertainty": uncertainty,
        }

    def analyze(self, max_chain_length: int = 6) -> List[Dict[str, Any]]:
        """Discover all maximal correlated attack paths across active findings."""
        active_ids = [
            fid for fid, rec in self.graph.finding_records.items()
            if not rec.get("inactive")
        ]
        if not active_ids:
            return []

        transitions: Dict[str, List[Dict[str, Any]]] = {fid: [] for fid in active_ids}
        incoming_count: Dict[str, int] = {fid: 0 for fid in active_ids}

        for src_id in active_ids:
            for dst_id in active_ids:
                edge_info = self.evaluate_transition(src_id, dst_id)
                if edge_info is not None:
                    transitions[src_id].append(edge_info)
                    incoming_count[dst_id] += 1
                    # Record correlation edge directly in graph
                    self.graph.add_edge(
                        source=edge_info["source"],
                        target=edge_info["target"],
                        relation=edge_info["relation"],
                        evidence_ids=edge_info["evidence_ids"],
                        confidence=edge_info["confidence"],
                        verified=edge_info["verified"],
                        inferred=edge_info["inferred"],
                        explanation=edge_info["explanation"],
                        source_component=self.source_component,
                    )

        # Enumerate maximal paths starting at root prerequisites (in-degree == 0 with >= 1 outgoing)
        # Fallback to any node with outgoing edges if needed (graph is guaranteed acyclic by PRIMITIVE_RANK).
        chains: List[Dict[str, Any]] = []
        roots = [fid for fid in active_ids if incoming_count[fid] == 0 and transitions[fid]]
        if not roots:
            roots = [fid for fid in active_ids if transitions[fid]]

        def _dfs(current_id: str, node_path: List[str], edge_path: List[Dict[str, Any]]) -> None:
            outgoing = transitions.get(current_id, [])
            if not outgoing or len(node_path) >= max_chain_length:
                if edge_path:
                    chains.append(self._materialize_chain(len(chains) + 1, node_path, edge_path))
                return
            for edge in outgoing:
                nxt = edge["target"]
                if nxt in node_path:
                    continue
                _dfs(nxt, node_path + [nxt], edge_path + [edge])

        for root_id in sorted(roots):
            _dfs(root_id, [root_id], [])

        return chains

    def _materialize_chain(
        self,
        index: int,
        node_path: List[str],
        edge_path: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        missing_prereqs: List[str] = []
        uncertainty: List[str] = []
        evidence_ids: List[str] = []
        signals: List[str] = []
        trust_boundaries_crossed: List[str] = []

        for edge in edge_path:
            for item in edge.get("missing_prerequisites", []):
                if item not in missing_prereqs:
                    missing_prereqs.append(item)
            for item in edge.get("uncertainty", []):
                if item not in uncertainty:
                    uncertainty.append(item)
            for eid in edge.get("evidence_ids", []):
                if eid not in evidence_ids:
                    evidence_ids.append(eid)
            for sig in edge.get("signals", []):
                if sig not in signals:
                    signals.append(sig)

        steps: List[Dict[str, Any]] = []
        for step_num, fid in enumerate(node_path, 1):
            rec = self.graph.finding_records[fid]
            tb = rec.get("trust_boundary", "external_internet")
            if tb not in trust_boundaries_crossed:
                trust_boundaries_crossed.append(tb)
            step_node_id = _safe_id("attack_step", f"chain{index}_step{step_num}_{rec['primitive']}")
            self.graph.add_node(
                step_node_id,
                f"Step {step_num}: {rec['title']}",
                "attack_step",
                {
                    "chain_index": index,
                    "step_number": step_num,
                    "finding_node_id": fid,
                    "primitive": rec["primitive"],
                    "confirmed": rec["confirmed"],
                },
            )
            self.graph.add_edge(
                fid,
                step_node_id,
                "REALIZED_AS_STEP",
                evidence_ids=rec["evidence_ids"],
                confidence=rec["confidence"],
                verified=rec["confirmed"] and bool(rec["evidence_ids"]),
                explanation=f"Finding '{rec['title']}' forms step {step_num} of attack chain {index}",
                source_component=self.source_component,
            )
            steps.append({
                "step_number": step_num,
                "step_node_id": step_node_id,
                "finding_node_id": fid,
                "finding_id": rec["finding_id"],
                "title": rec["title"],
                "primitive": rec["primitive"],
                "original_severity": rec["original_severity"],
                "status": rec["status"],
                "confirmed": rec["confirmed"],
                "evidence_ids": list(rec["evidence_ids"]),
                "host": rec["host"],
                "path": rec["path"],
                "trust_boundary": tb,
            })

        verified_edges = sum(1 for e in edge_path if e["verified"])
        inferred_edges = sum(1 for e in edge_path if e["inferred"])
        chain_verified = verified_edges == len(edge_path) and len(missing_prereqs) == 0

        chain_edges = [
            _make_edge(
                source=e["source"],
                target=e["target"],
                relation=e["relation"],
                evidence_ids=e["evidence_ids"],
                confidence=e["confidence"],
                verified=e["verified"],
                inferred=e["inferred"],
                explanation=e["explanation"],
                source_component=self.source_component,
            )
            for e in edge_path
        ]

        chain_seed = "->".join(node_path)
        chain_id = f"chain-{hashlib.sha256(chain_seed.encode('utf-8')).hexdigest()[:12]}"

        return {
            "chain_id": chain_id,
            "name": " -> ".join(s["title"] for s in steps),
            "steps": steps,
            "edges": chain_edges,
            "step_count": len(steps),
            "verified": chain_verified,
            "inferred": not chain_verified,
            "verified_edge_count": verified_edges,
            "inferred_edge_count": inferred_edges,
            "missing_prerequisites": missing_prereqs,
            "uncertainty": uncertainty,
            "technical_signals": signals,
            "evidence_ids": evidence_ids,
            "trust_boundaries_crossed": trust_boundaries_crossed,
        }


class AttackPathScorer:
    """
    Scores correlated attack chains based on:
    - terminal/peak impact & trust boundary crossing
    - prerequisite chain completeness
    - correlation confidence
    - evidence quality
    Keeps original finding severities untouched and reported separately.
    """

    @staticmethod
    def score_chain(chain: Dict[str, Any], finding_records: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        steps = chain.get("steps", [])
        edges = chain.get("edges", [])
        if not steps:
            return {
                "path_risk_score": 0.0,
                "path_severity": "INFO",
                "impact_score": 0.0,
                "chain_completeness": 0.0,
                "confidence": 0.0,
                "evidence_quality": 0.0,
                "original_finding_severities": {},
            }

        # 1. Impact score
        peak_impact = max(
            PRIMITIVE_IMPACT.get(step.get("primitive", ""), 5.0)
            for step in steps
        )
        # Honor explicit confirmed critical/high severity on terminal steps as floor
        for step in steps:
            rec = finding_records.get(step["finding_node_id"], {})
            norm_sev = rec.get("normalized_severity", "UNASSESSED")
            if norm_sev == "CRITICAL":
                peak_impact = max(peak_impact, 9.0)
            elif norm_sev == "HIGH":
                peak_impact = max(peak_impact, 7.6)

        boundaries = chain.get("trust_boundaries_crossed", [])
        boundary_bonus = 0.0
        if len(boundaries) > 1:
            boundary_bonus = min(0.7, 0.25 * (len(boundaries) - 1))
        if "admin_boundary" in boundaries or "internal_network" in boundaries:
            boundary_bonus = max(boundary_bonus, 0.5)
        impact_score = min(10.0, peak_impact + boundary_bonus)

        # 2. Prerequisite chain completeness
        total_edges = max(1, len(edges))
        verified_count = sum(1 for e in edges if e.get("verified"))
        inferred_count = sum(1 for e in edges if e.get("inferred"))
        missing_count = len(chain.get("missing_prerequisites", []))
        completeness = (verified_count + 0.45 * inferred_count) / (total_edges + 0.35 * missing_count)
        completeness = max(0.0, min(1.0, completeness))

        # 3. Confidence
        if edges:
            edge_conf = sum(float(e.get("confidence", 0.5)) for e in edges) / len(edges)
        else:
            edge_conf = 0.5
        step_confs = [
            float(finding_records.get(s["finding_node_id"], {}).get("confidence", 0.5))
            for s in steps
        ]
        step_conf = sum(step_confs) / len(step_confs)
        confidence = max(0.0, min(1.0, (0.6 * edge_conf) + (0.4 * step_conf)))

        # 4. Evidence quality
        ev_scores: List[float] = []
        for s in steps:
            rec = finding_records.get(s["finding_node_id"], {})
            has_ev = bool(rec.get("evidence_ids"))
            confirmed = bool(rec.get("confirmed"))
            if confirmed and has_ev:
                ev_scores.append(1.0)
            elif confirmed:
                ev_scores.append(0.65)
            elif has_ev:
                ev_scores.append(0.45)
            else:
                ev_scores.append(0.20)
        evidence_quality = sum(ev_scores) / len(ev_scores)

        readiness = (0.40 * completeness) + (0.30 * confidence) + (0.30 * evidence_quality)
        path_risk_score = round(min(10.0, impact_score * (0.55 + 0.45 * readiness)), 2)

        if path_risk_score >= 9.0:
            path_severity = "CRITICAL"
        elif path_risk_score >= 7.0:
            path_severity = "HIGH"
        elif path_risk_score >= 4.0:
            path_severity = "MEDIUM"
        elif path_risk_score > 0.0:
            path_severity = "LOW"
        else:
            path_severity = "INFO"

        original_severities = {
            s["finding_id"]: s["original_severity"]
            for s in steps
        }

        return {
            "path_risk_score": path_risk_score,
            "path_severity": path_severity,
            "impact_score": round(impact_score, 2),
            "chain_completeness": round(completeness, 4),
            "confidence": round(confidence, 4),
            "evidence_quality": round(evidence_quality, 4),
            "original_finding_severities": original_severities,
        }


class AttackChainEngine:
    """High-level orchestrator for attack graph construction, path correlation, scoring, and export."""

    def __init__(self, target: str = ""):
        self.target = _normalize_host(target) or str(target or "").strip()

    def build_from_inputs(
        self,
        findings: Iterable[Dict[str, Any]] = (),
        assets: Iterable[Any] = (),
        endpoints: Iterable[Any] = (),
        parameters: Iterable[Any] = (),
        identities: Iterable[Any] = (),
        trust_boundaries: Iterable[Any] = (),
        evidence_records: Iterable[Dict[str, Any]] = (),
        max_chain_length: int = 6,
    ) -> Dict[str, Any]:
        graph = FindingRelationshipGraph(target=self.target)
        graph.ingest_all(
            findings=findings,
            assets=assets,
            endpoints=endpoints,
            parameters=parameters,
            identities=identities,
            trust_boundaries=trust_boundaries,
            evidence_records=evidence_records,
        )
        analyzer = AttackPathAnalyzer(graph)
        chains = analyzer.analyze(max_chain_length=max_chain_length)

        scored_chains: List[Dict[str, Any]] = []
        for chain in chains:
            score_info = AttackPathScorer.score_chain(chain, graph.finding_records)
            scored = dict(chain)
            scored.update(score_info)
            scored_chains.append(scored)

        scored_chains.sort(key=lambda c: (c["verified"], c["path_risk_score"], c["step_count"]), reverse=True)

        correlated_finding_ids: Set[str] = {
            step["finding_node_id"]
            for chain in scored_chains
            for step in chain.get("steps", [])
        }
        max_score = max((c["path_risk_score"] for c in scored_chains), default=0.0)
        max_sev = "INFO"
        for c in scored_chains:
            if SEVERITY_ORDER.get(c["path_severity"], 0) > SEVERITY_ORDER.get(max_sev, 0):
                max_sev = c["path_severity"]

        graph_dict = graph.to_dict()
        mermaid = self.render_mermaid(graph_dict["nodes"], graph_dict["edges"], scored_chains)

        return {
            "target": self.target,
            "generated_at": _utc_now(),
            "graph": graph_dict,
            "attack_chains": scored_chains,
            "chain_summary": {
                "total_chains": len(scored_chains),
                "verified_chains": sum(1 for c in scored_chains if c["verified"]),
                "inferred_chains": sum(1 for c in scored_chains if c["inferred"]),
                "max_path_risk_score": max_score,
                "max_path_severity": max_sev,
                "total_findings_ingested": len(graph.finding_records),
                "correlated_findings": len(correlated_finding_ids),
                "uncorrelated_findings": len(graph.finding_records) - len(correlated_finding_ids),
                "duplicate_findings_collapsed": graph.duplicate_findings_collapsed,
                "missing_prerequisites_count": sum(len(c.get("missing_prerequisites", [])) for c in scored_chains),
            },
            "mermaid": mermaid,
        }

    def build_from_target_dir(
        self,
        target_dir: Path,
        write_report: bool = False,
    ) -> Dict[str, Any]:
        """Load SkillRunner + legacy artifacts from target_dir and build attack chain report."""
        artifacts = load_target_artifacts(Path(target_dir))
        report = self.build_from_inputs(
            findings=artifacts["findings"],
            assets=artifacts["subdomains"],
            endpoints=artifacts["endpoints"],
            parameters=artifacts["parameters"],
            evidence_records=artifacts["evidence_records"],
        )
        if write_report:
            self.export_report(Path(target_dir) / "output" / "report" / "attack-chains.json", report)
        return report

    def export_report(self, output_path: Path, report: Dict[str, Any]) -> Path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2), encoding="utf-8")
        return out

    @staticmethod
    def render_mermaid(
        nodes: List[Dict[str, Any]],
        edges: List[Dict[str, Any]],
        chains: Optional[List[Dict[str, Any]]] = None,
        max_nodes: int = 50,
        max_edges: int = 60,
    ) -> str:
        """Render typed nodes and verified/inferred edges as a Mermaid flowchart."""
        lines = ["graph TD"]
        included_ids: Set[str] = set()

        # Prioritize finding, attack_step, asset, endpoint nodes when truncating
        priority = {"finding": 0, "attack_step": 1, "asset": 2, "endpoint": 3, "identity": 4, "evidence": 5, "remediation": 6}
        ordered_nodes = sorted(nodes, key=lambda n: priority.get(n.get("type", ""), 9))[:max_nodes]

        for node in ordered_nodes:
            nid = node["id"]
            included_ids.add(nid)
            mid = _mermaid_id(nid)
            ntype = node.get("type", "node")
            lbl = _mermaid_label(node.get("label", nid))
            if ntype == "finding":
                lines.append(f'    {mid}["[{ntype}] {lbl}"]')
            elif ntype == "attack_step":
                lines.append(f'    {mid}(("{lbl}"))')
            else:
                lines.append(f'    {mid}["{lbl}"]')

        emitted = 0
        # Render chain correlation edges first so chains are always visible
        chain_relations = {r["relation"] for r in TRANSITION_RULES}
        ordered_edges = sorted(
            edges,
            key=lambda e: (0 if e.get("relation") in chain_relations else 1, -float(e.get("confidence", 0.0))),
        )
        for edge in ordered_edges:
            if emitted >= max_edges:
                break
            if edge["source"] not in included_ids or edge["target"] not in included_ids:
                continue
            s = _mermaid_id(edge["source"])
            t = _mermaid_id(edge["target"])
            rel = _mermaid_label(edge.get("relation", "LINKS"), max_len=36)
            if edge.get("verified"):
                lines.append(f"    {s} -->|{rel}| {t}")
            else:
                lines.append(f"    {s} -.->|{rel} [inferred]| {t}")
            emitted += 1

        if chains:
            top = chains[0]
            lines.append(f'    %% Top chain: {_mermaid_label(top.get("name", ""), max_len=80)} ({top.get("path_severity")} {top.get("path_risk_score")})')

        return "\n".join(lines)


def _read_lines_dedup(paths: Sequence[Path]) -> List[str]:
    seen: Set[str] = set()
    items: List[str] = []
    for path in paths:
        if not path.is_file():
            continue
        try:
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                val = line.strip()
                if val and val not in seen:
                    seen.add(val)
                    items.append(val)
        except OSError:
            continue
    return items


def _normalize_endpoint_entry(raw: Any, source_name: str) -> Optional[Dict[str, Any]]:
    if isinstance(raw, str):
        val = raw.strip()
        return {"url": val, "method": "GET", "parameters": [], "source": source_name} if val else None
    if isinstance(raw, dict):
        url = str(raw.get("url") or "").strip()
        if not url:
            base = str(raw.get("base_url", "")).rstrip("/")
            path = str(raw.get("path", "")).strip()
            url = f"{base}{path}" if (base or path) else ""
        if not url:
            return None
        entry = dict(raw)
        entry["url"] = url
        entry.setdefault("method", "GET")
        entry.setdefault("parameters", [])
        entry.setdefault("source", source_name)
        return entry
    return None


def load_target_artifacts(target_dir: Path) -> Dict[str, List[Any]]:
    """
    Load subdomains, endpoints, parameters, findings, and evidence ledger
    from both actual SkillRunner outputs and legacy paths.
    """
    output_dir = Path(target_dir) / "output"

    # Subdomains: SkillRunner (recon/subdomains-all.txt) + legacy (recon/subdomains.txt, subdomains-passive.txt)
    subdomains = _read_lines_dedup([
        output_dir / "recon" / "subdomains-all.txt",
        output_dir / "recon" / "subdomains.txt",
        output_dir / "recon" / "subdomains-passive.txt",
    ])

    # Endpoints: SkillRunner (js/endpoints.json, api/endpoints.json) + legacy paths
    endpoints: List[Dict[str, Any]] = []
    seen_ep_keys: Set[Tuple[str, str]] = set()
    ep_files = [
        output_dir / "js" / "endpoints.json",
        output_dir / "api" / "endpoints.json",
        output_dir / "api" / "openapi-endpoints.json",
        output_dir / "recon" / "endpoints.txt",
        output_dir / "content" / "discovered-endpoints.txt",
    ]
    for ep_file in ep_files:
        if not ep_file.is_file():
            continue
        try:
            if ep_file.suffix == ".json":
                raw_data = json.loads(ep_file.read_text(encoding="utf-8", errors="replace"))
                if isinstance(raw_data, dict):
                    raw_items = raw_data.get("endpoints", [])
                    if not raw_items and not any(k in raw_data for k in ("endpoints", "total_endpoints")):
                        raw_items = list(raw_data.keys())
                elif isinstance(raw_data, list):
                    raw_items = raw_data
                else:
                    raw_items = []
            else:
                raw_items = [line.strip() for line in ep_file.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]

            for item in raw_items:
                norm = _normalize_endpoint_entry(item, ep_file.name)
                if norm is None:
                    continue
                key = (str(norm.get("method", "GET")).upper(), norm["url"])
                if key not in seen_ep_keys:
                    seen_ep_keys.add(key)
                    endpoints.append(norm)
        except (OSError, json.JSONDecodeError):
            continue

    # Parameters: SkillRunner (js/parameters.json)
    parameters: List[Dict[str, Any]] = []
    params_file = output_dir / "js" / "parameters.json"
    if params_file.is_file():
        try:
            raw_params = json.loads(params_file.read_text(encoding="utf-8", errors="replace"))
            if isinstance(raw_params, dict):
                param_items = raw_params.get("parameters", [])
                if isinstance(param_items, list):
                    parameters.extend(p for p in param_items if isinstance(p, dict))
            elif isinstance(raw_params, list):
                parameters.extend(p for p in raw_params if isinstance(p, dict))
        except (OSError, json.JSONDecodeError):
            pass

    # Findings: candidates-*.json, confirmed-*.json, validated-*.json
    findings: List[Dict[str, Any]] = []
    findings_dir = output_dir / "findings"
    if findings_dir.is_dir():
        finding_files: List[Path] = []
        for pattern in ("confirmed-*.json", "validated-*.json", "candidates-*.json"):
            finding_files.extend(sorted(findings_dir.rglob(pattern)))
        seen_files: Set[Path] = set()
        for f_file in finding_files:
            if f_file in seen_files:
                continue
            seen_files.add(f_file)
            try:
                data = json.loads(f_file.read_text(encoding="utf-8", errors="replace"))
                rows = data if isinstance(data, list) else data.get("findings", [])
                if isinstance(rows, list):
                    for row in rows:
                        if isinstance(row, dict):
                            findings.append(row)
            except (OSError, json.JSONDecodeError):
                continue

    # Evidence ledger
    evidence_records: List[Dict[str, Any]] = []
    ledger_file = output_dir / "evidence" / "ledger.jsonl"
    if ledger_file.is_file():
        try:
            for line in ledger_file.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    if isinstance(entry, dict):
                        evidence_records.append(entry)
                except json.JSONDecodeError:
                    continue
        except OSError:
            pass

    return {
        "subdomains": subdomains,
        "endpoints": endpoints,
        "parameters": parameters,
        "findings": findings,
        "evidence_records": evidence_records,
    }
