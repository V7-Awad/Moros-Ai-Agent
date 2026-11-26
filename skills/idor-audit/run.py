#!/usr/bin/env python3
"""
run.py — Executable Runner for IDOR / BOLA Audit in Moros AI.
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path

# Add tools to sys.path
_skill_dir = Path(__file__).parent.resolve()
_project_root = _skill_dir
while _project_root != _project_root.parent:
    if (_project_root / "tools").is_dir() and (_project_root / "run.py").is_file():
        break
    _project_root = _project_root.parent
sys.path.insert(0, str(_project_root / "tools"))

from scope_validator import ScopeValidator
from scoped_http import ScopedHttpClient, check_checkpoint_approval, is_gated_post_enabled
from checkpoint_manager import CheckpointManager
from auth_diff import AuthDiffChecker, SessionContext


_ID_PARAM_NAMES = {"id", "user_id", "account_id", "order_id", "doc_id", "uid", "profile_id", "invoice_id"}
_DESTRUCTIVE_KEYWORDS = ("delete", "remove", "destroy", "drop", "reset", "pay", "transfer", "charge", "cancel")
_SENSITIVE_FIELD_KEYWORDS = (
    "email", "phone", "address", "ssn", "balance", "account",
    "invoice", "order", "token", "secret", "dob", "birth", "credit", "salary",
)
_ERROR_ONLY_KEYS = {"error", "errors", "message", "detail", "details", "status", "code", "ok", "success"}


def _parse_budget(default: int, cap: int) -> int:
    raw = os.environ.get("MOROS_HTTP_REQUESTS_REMAINING")
    if raw is None or not raw.strip():
        return min(default, cap)
    try:
        return min(max(0, int(raw.strip())), cap)
    except ValueError:
        return min(default, cap)


def _load_endpoints(out_dir: Path) -> tuple[list[str], list[tuple[str, str]]]:
    endpoints: list[str] = []
    post_candidates: list[tuple[str, str]] = []
    seen: set[str] = set()
    seen_post: set[tuple[str, str]] = set()

    def _add(ep: str) -> None:
        val = (ep or "").strip()
        if val and val not in seen:
            seen.add(val)
            endpoints.append(val)

    def _from_item(item) -> None:
        if isinstance(item, str):
            _add(item)
        elif isinstance(item, dict):
            url = str(item.get("url") or "").strip()
            if not url:
                path = str(item.get("path") or "").strip()
                base = str(item.get("base_url") or "").strip().rstrip("/")
                url = f"{base}/{path.lstrip('/')}" if base and path else path
            if not url:
                return
            method = str(item.get("method") or "GET").upper()
            params = item.get("parameters") or []
            param_names = []
            if isinstance(params, list):
                for p in params:
                    name = p.get("name") if isinstance(p, dict) else p
                    if name:
                        param_names.append(str(name).strip())
            if method == "POST":
                id_param = next((n for n in param_names if n.lower() in _ID_PARAM_NAMES), "")
                if id_param and not any(bad in url.lower() for bad in _DESTRUCTIVE_KEYWORDS):
                    key = (url, id_param)
                    if key not in seen_post:
                        seen_post.add(key)
                        post_candidates.append(key)
            if param_names and "?" not in url:
                qs = "&".join(f"{name}=1" for name in param_names[:4])
                _add(f"{url}?{qs}")
            _add(url)

    for rel in [
        "js/endpoints.json",
        "api/endpoints.json",
        "api/openapi-endpoints.json",
        "content-discovery/discovered-paths.json",
        "recon/endpoints.txt",
        "content/discovered-endpoints.txt",
    ]:
        ep_file = out_dir / rel
        if not ep_file.exists():
            continue
        try:
            if ep_file.suffix == ".json":
                data = json.loads(ep_file.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    for item in data:
                        _from_item(item)
                elif isinstance(data, dict):
                    if isinstance(data.get("endpoints"), list):
                        for item in data["endpoints"]:
                            _from_item(item)
                    elif isinstance(data.get("interesting_routes"), list) or isinstance(data.get("paths_checked"), list):
                        for item in (data.get("interesting_routes") or []):
                            _from_item(item)
                        for item in (data.get("paths_checked") or []):
                            if isinstance(item, dict) and item.get("status_code") not in (None, 404):
                                _from_item(item)
            else:
                for line in ep_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                    _add(line)
        except Exception:
            continue
    return endpoints, post_candidates


def _is_valid_json_object(resp: dict) -> tuple[bool, object]:
    """Return (True, parsed_json) only for non-HTML, non-error structured JSON payloads."""
    status = resp.get("status_code", 0)
    if status not in (200, 201):
        return False, None
    ct = str(resp.get("headers", {}).get("content-type", "")).lower()
    if "text/html" in ct:
        return False, None
    body = (resp.get("body", "") or "").strip()
    if len(body) <= 2:
        return False, None
    try:
        parsed = json.loads(body)
    except Exception:
        return False, None
    if isinstance(parsed, dict):
        if not parsed:
            return False, None
        lowered_keys = {str(k).lower() for k in parsed.keys()}
        if lowered_keys <= _ERROR_ONLY_KEYS:
            return False, None
        if parsed.get("error") and len(lowered_keys - _ERROR_ONLY_KEYS) == 0:
            return False, None
        return True, parsed
    if isinstance(parsed, list) and len(parsed) > 0:
        return True, parsed
    return False, None


def _has_sensitive_fields(payload: object) -> bool:
    if isinstance(payload, dict):
        for k, v in payload.items():
            k_low = str(k).lower()
            if any(kw in k_low for kw in _SENSITIVE_FIELD_KEYWORDS):
                return True
            if _has_sensitive_fields(v):
                return True
    elif isinstance(payload, list):
        return any(_has_sensitive_fields(item) for item in payload[:10])
    return False


def _mutate_id_url(url: str) -> str:
    """Produce a second URL with an adjacent numeric or mutated UUID object identifier."""
    def _bump_num(raw_id: str) -> str:
        if raw_id.isdigit():
            val = int(raw_id)
            return str(2 if val == 1 else val + 1)
        # Flip last hex char for UUID/hex tokens
        last = raw_id[-1].lower()
        replacement = "0" if last != "0" else "1"
        return raw_id[:-1] + replacement

    q_pat = re.compile(r"([?&](?:id|user_id|account_id|order_id|doc_id|uid)=)(\d+|[0-9a-fA-F-]{8,})", re.IGNORECASE)
    if q_pat.search(url):
        return q_pat.sub(lambda m: m.group(1) + _bump_num(m.group(2)), url, count=1)

    p_pat = re.compile(r"(/(?:users|accounts|orders|invoices|documents|messages|profiles|items)/)(\d+|[0-9a-fA-F-]{8,})", re.IGNORECASE)
    if p_pat.search(url):
        return p_pat.sub(lambda m: m.group(1) + _bump_num(m.group(2)), url, count=1)
    return ""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--target-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    findings_dir = out_dir / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)
    out_file = findings_dir / "candidates-idor-audit.json"

    endpoints, post_candidates = _load_endpoints(out_dir)

    id_patterns = [
        re.compile(r"/(?:users|accounts|orders|invoices|documents|messages|profiles|items)/([0-9a-fA-F-]+|\d+)", re.IGNORECASE),
        re.compile(r"[?&](?:id|user_id|account_id|order_id|doc_id|uid)=(\d+|[0-9a-fA-F-]+)", re.IGNORECASE),
    ]

    candidate_eps = []
    for ep in endpoints:
        for pat in id_patterns:
            if pat.search(ep):
                candidate_eps.append(ep)
                break

    findings = []
    req_budget = _parse_budget(15, 15)

    if req_budget > 0 and (candidate_eps or (is_gated_post_enabled() and post_candidates)):
        try:
            validator = ScopeValidator(args.target, target_dir=Path(args.target_dir))
            client = ScopedHttpClient(
                target=args.target,
                max_requests=req_budget,
                delay_seconds=0.2,
                scope_validator=validator,
            )
            base_url = client.base_url.rstrip("/")
            unauth = not client.auth_headers and not client.cookies
            cm = CheckpointManager(args.target, Path(args.target_dir)) if is_gated_post_enabled() else None
            post_client = None
            post_used = 0

            for ep in candidate_eps[:6]:
                if client.request_count + post_used + 1 >= req_budget:
                    break
                full_url = ep if "://" in ep else f"{base_url}/{ep.lstrip('/')}"
                alt_url = _mutate_id_url(full_url)
                if not alt_url or alt_url == full_url:
                    continue

                resp = client.get(full_url)
                if resp.get("status") in ("budget_exhausted", "blocked_scope", "blocked"):
                    break
                ok_base, parsed_base = _is_valid_json_object(resp)
                if not ok_base:
                    continue

                alt_resp = client.get(alt_url)
                if alt_resp.get("status") in ("budget_exhausted", "blocked_scope", "blocked"):
                    break
                ok_alt, parsed_alt = _is_valid_json_object(alt_resp)
                if not ok_alt:
                    continue

                base_hash = resp.get("body_sha256", "")
                alt_hash = alt_resp.get("body_sha256", "")
                # Require distinct object bodies across two different IDs to reduce static/public false positives
                if base_hash and alt_hash and base_hash != alt_hash:
                    has_sensitive = _has_sensitive_fields(parsed_base) or _has_sensitive_fields(parsed_alt)
                    severity = "HIGH" if (unauth and has_sensitive) else "MEDIUM"
                    findings.append({
                        "title": f"Potential IDOR / BOLA on {ep[:60]}",
                        "severity": severity,
                        "url": full_url,
                        "cwe": "CWE-639",
                        "evidence": (
                            f"Differential ID comparison returned distinct JSON payloads: "
                            f"{full_url} (HTTP {resp.get('status_code')}, sha256={base_hash[:12]}) vs "
                            f"{alt_url} (HTTP {alt_resp.get('status_code')}, sha256={alt_hash[:12]})."
                        ),
                        "notes": "Two different object identifiers returned distinct structured JSON objects without access denial.",
                        "status": "candidate",
                        "validation_status": "unverified",
                        "curl": f"curl -s -i '{full_url}'",
                    })

            if cm is not None and post_candidates:
                for post_ep, id_param in post_candidates[:3]:
                    if client.request_count + post_used + 1 >= req_budget:
                        break
                    full_url = post_ep if "://" in post_ep else f"{base_url}/{post_ep.lstrip('/')}"
                    cp_type = "IDOR POST Comparison"
                    reason = f"Send non-destructive POST ID comparison probes to {full_url}"
                    if not check_checkpoint_approval(cm, cp_type, full_url, method="POST", reason=reason, risk_level="MEDIUM"):
                        continue
                    if post_client is None:
                        remaining = max(1, req_budget - client.request_count)
                        post_client = ScopedHttpClient(
                            target=args.target,
                            max_requests=remaining,
                            delay_seconds=0.2,
                            scope_validator=validator,
                            allow_state_changing=True,
                            approval_callback=lambda m, u, b: check_checkpoint_approval(
                                cm, cp_type, u, method=m, reason=reason, risk_level="MEDIUM"
                            ),
                        )
                    r1 = post_client.post(full_url, json_body={id_param: 1})
                    post_used = post_client.request_count
                    if r1.get("status") != "response":
                        continue
                    ok1, p1 = _is_valid_json_object(r1)
                    if not ok1 or (client.request_count + post_used >= req_budget):
                        continue
                    r2 = post_client.post(full_url, json_body={id_param: 2})
                    post_used = post_client.request_count
                    if r2.get("status") != "response":
                        continue
                    ok2, p2 = _is_valid_json_object(r2)
                    if ok2 and r1.get("body_sha256") != r2.get("body_sha256"):
                        has_sensitive = _has_sensitive_fields(p1) or _has_sensitive_fields(p2)
                        severity = "HIGH" if (unauth and has_sensitive) else "MEDIUM"
                        findings.append({
                            "title": f"Potential POST IDOR / BOLA on {post_ep[:60]}",
                            "severity": severity,
                            "url": full_url,
                            "cwe": "CWE-639",
                            "evidence": (
                                f"POST differential ID comparison ({id_param}=1 vs {id_param}=2) returned distinct "
                                f"JSON objects (sha256={r1.get('body_sha256', '')[:12]} vs {r2.get('body_sha256', '')[:12]})."
                            ),
                            "notes": "HITL-approved non-destructive POST comparison returned distinct objects across IDs.",
                            "status": "candidate",
                            "validation_status": "unverified",
                            "curl": f"curl -s -i -X POST '{full_url}'",
                        })
        except ValueError as e:
            print(f"IDOR Audit skipped (invalid target/scope): {e}")
        except Exception as e:
            print(f"IDOR Audit notice: {e}")

        # Dual-session multi-role IDOR/BOLA diffing when secondary session credentials exist
        cookie_b = os.environ.get("MOROS_AUTH_COOKIE_B", "").strip()
        auth_header_b = os.environ.get("MOROS_AUTH_HEADER_B", "").strip()
        if (cookie_b or auth_header_b) and endpoints and req_budget > 0:
            try:
                user_b_headers = {}
                if auth_header_b and ":" in auth_header_b:
                    hk, hv = auth_header_b.split(":", 1)
                    user_b_headers[hk.strip()] = hv.strip()
                elif auth_header_b:
                    user_b_headers["Authorization"] = auth_header_b

                cookie_a = os.environ.get("MOROS_AUTH_COOKIE", "").strip()
                auth_header_a = os.environ.get("MOROS_AUTH_HEADER", "").strip()
                user_a_headers = {}
                if auth_header_a and ":" in auth_header_a:
                    hk, hv = auth_header_a.split(":", 1)
                    user_a_headers[hk.strip()] = hv.strip()
                elif auth_header_a:
                    user_a_headers["Authorization"] = auth_header_a

                diff_checker = AuthDiffChecker(
                    target=args.target,
                    scope_validator=ScopeValidator(args.target, target_dir=Path(args.target_dir)),
                    user_a=SessionContext(name="user_a", role="owner", auth_headers=user_a_headers, cookies=cookie_a),
                    user_b=SessionContext(name="user_b", role="peer", auth_headers=user_b_headers, cookies=cookie_b),
                    max_requests_per_session=max(2, min(6, req_budget)),
                    delay_seconds=0.2,
                )
                diff_targets = (candidate_eps or endpoints)[:4]
                diff_results = diff_checker.check_batch(diff_targets)
                seen_urls = {f.get("url") for f in findings}
                for dr in diff_results:
                    if not dr.get("vulnerable"):
                        continue
                    finding_url = dr.get("url", "")
                    if finding_url in seen_urls and dr.get("cwe") == "CWE-639":
                        continue
                    findings.append({
                        "title": dr.get("title") or f"Dual-Session Auth Differential ({dr.get('finding_type')}) on {finding_url}",
                        "severity": dr.get("severity", "HIGH"),
                        "url": finding_url,
                        "cwe": dr.get("cwe", "CWE-639"),
                        "evidence": dr.get("evidence", "Secondary user session accessed primary user resource."),
                        "notes": dr.get("notes", "Confirmed via User A vs User B vs Unauthenticated response diffing."),
                        "status": "candidate",
                        "validation_status": "unverified",
                        "curl": f"curl -s -i '{finding_url}'",
                    })
            except Exception as exc:
                print(f"Dual-session AuthDiff notice: {exc}")

    out_file.write_text(json.dumps({"findings": findings, "count": len(findings)}, indent=2), encoding="utf-8")
    print(f"IDOR Audit completed: {len(findings)} candidate findings recorded.")


if __name__ == "__main__":
    main()
