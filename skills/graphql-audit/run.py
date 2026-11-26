#!/usr/bin/env python3
"""
run.py — Executable Runner for GraphQL Audit Skill in Moros AI.
"""

import argparse
import json
import os
import sys
from pathlib import Path

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


def _parse_budget(default: int, cap: int) -> int:
    raw = os.environ.get("MOROS_HTTP_REQUESTS_REMAINING")
    if raw is None or not raw.strip():
        return min(default, cap)
    try:
        return min(max(0, int(raw.strip())), cap)
    except ValueError:
        return min(default, cap)


def _load_endpoints(out_dir: Path) -> list[str]:
    endpoints: list[str] = []
    seen: set[str] = set()

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
    return endpoints


def _inspect_graphql_response(resp: dict) -> tuple[str, str]:
    """Classify a GraphQL HTTP response without HTML-reflection false positives."""
    status_code = resp.get("status_code", 0)
    body = resp.get("body", "") or ""
    ct = str(resp.get("headers", {}).get("content-type", "")).lower()
    if status_code not in (200, 400) or "text/html" in ct:
        return "", ""
    try:
        parsed = json.loads(body)
    except Exception:
        parsed = None

    if isinstance(parsed, dict):
        data = parsed.get("data")
        if status_code == 200 and isinstance(data, dict) and isinstance(data.get("__schema"), dict):
            types = data["__schema"].get("types")
            if isinstance(types, list):
                return "introspection", f"HTTP 200 JSON introspection returned {len(types)} schema types: {body[:160]}"
        errors = parsed.get("errors")
        if isinstance(errors, list) and any(isinstance(err, dict) and "message" in err for err in errors):
            return "active", f"HTTP {status_code} GraphQL error payload: {body[:150]}"

    if "json" in ct and any(k in body.lower() for k in ["must provide query", "graphql"]):
        return "active", f"HTTP {status_code} JSON GraphQL response: {body[:150]}"
    return "", ""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--target-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    findings_dir = out_dir / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)
    out_file = findings_dir / "candidates-graphql-audit.json"

    findings = []
    seen_urls: set[str] = set()
    graphql_paths = ["/graphql", "/api/graphql", "/v1/graphql", "/query", "/api/query"]

    for ep in _load_endpoints(out_dir):
        if "graphql" in ep.lower() and ep not in graphql_paths:
            graphql_paths.append(ep)

    req_budget = _parse_budget(15, 15)
    if req_budget > 0:
        try:
            validator = ScopeValidator(args.target, target_dir=Path(args.target_dir))
            client = ScopedHttpClient(
                target=args.target,
                max_requests=req_budget,
                delay_seconds=0.2,
                scope_validator=validator,
            )
            allow_headers = getattr(validator, "policy", {}).get("allow_authentication", True)
            intro_query = "?query=%7B__schema%7Btypes%7Bname%7D%7D%7D"
            base_url = client.base_url.rstrip("/")
            cm = CheckpointManager(args.target, Path(args.target_dir)) if is_gated_post_enabled() else None
            post_client = None
            post_used = 0

            for gp in graphql_paths[:8]:
                if client.request_count + post_used >= req_budget:
                    break
                full_url = gp if "://" in gp else f"{base_url}/{gp.lstrip('/')}"
                test_url = full_url + intro_query if "?" not in full_url else full_url + "&query=%7B__schema%7Btypes%7Bname%7D%7D%7D"
                resp = client.get(test_url, headers={"Accept": "application/json"}) if allow_headers else client.get(test_url)
                if resp.get("status") in ("budget_exhausted", "blocked_scope", "blocked"):
                    break

                kind, evidence = _inspect_graphql_response(resp)
                if kind == "introspection":
                    seen_urls.add(full_url)
                    findings.append({
                        "title": f"GraphQL Schema Introspection Enabled: {gp}",
                        "severity": "MEDIUM",
                        "url": full_url,
                        "cwe": "CWE-200",
                        "evidence": evidence,
                        "notes": "GraphQL introspection is enabled in production, exposing internal schema, types, and queries.",
                        "status": "candidate",
                        "validation_status": "unverified"
                    })
                    continue

                # Optional HITL-gated POST introspection check when GET did not confirm introspection
                if cm is not None and (client.request_count + post_used < req_budget):
                    cp_type = "GraphQL POST Introspection"
                    reason = f"Send non-destructive GraphQL schema introspection POST probe to {full_url}"
                    if check_checkpoint_approval(cm, cp_type, full_url, method="POST", reason=reason, risk_level="LOW"):
                        if post_client is None:
                            remaining = max(1, req_budget - client.request_count)
                            post_client = ScopedHttpClient(
                                target=args.target,
                                max_requests=remaining,
                                delay_seconds=0.2,
                                scope_validator=validator,
                                allow_state_changing=True,
                                approval_callback=lambda m, u, b: check_checkpoint_approval(
                                    cm, cp_type, u, method=m, reason=reason, risk_level="LOW"
                                ),
                            )
                        post_resp = post_client.post(
                            full_url,
                            json_body={"query": "{ __schema { types { name } } }"},
                            headers={"Accept": "application/json"} if allow_headers else None,
                        )
                        post_used = post_client.request_count
                        if post_resp.get("status") == "response":
                            post_kind, post_evidence = _inspect_graphql_response(post_resp)
                            if post_kind:
                                kind, evidence = post_kind, f"POST probe: {post_evidence}"

                if kind == "introspection" and full_url not in seen_urls:
                    seen_urls.add(full_url)
                    findings.append({
                        "title": f"GraphQL Schema Introspection Enabled: {gp}",
                        "severity": "MEDIUM",
                        "url": full_url,
                        "cwe": "CWE-200",
                        "evidence": evidence,
                        "notes": "GraphQL introspection is enabled via POST, exposing internal schema, types, and queries.",
                        "status": "candidate",
                        "validation_status": "unverified"
                    })
                elif kind == "active" and full_url not in seen_urls:
                    seen_urls.add(full_url)
                    findings.append({
                        "title": f"Active GraphQL Endpoint Discovered: {gp}",
                        "severity": "LOW",
                        "url": full_url,
                        "cwe": "CWE-200",
                        "evidence": evidence,
                        "notes": "GraphQL service endpoint confirmed active.",
                        "status": "candidate",
                        "validation_status": "unverified"
                    })
        except ValueError as e:
            print(f"GraphQL check skipped (invalid target/scope): {e}")
        except Exception as e:
            print(f"GraphQL check notice: {e}")

    out_file.write_text(json.dumps({
        "target": args.target,
        "skill": "graphql-audit",
        "title": "GraphQL Security Auditor",
        "findings": findings
    }, indent=2), encoding="utf-8")
    print(f"GraphQL Audit completed: {len(findings)} candidates found.")


if __name__ == "__main__":
    main()
