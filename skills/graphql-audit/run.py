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
from scoped_http import ScopedHttpClient


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

            for gp in graphql_paths[:8]:
                full_url = gp if "://" in gp else f"{base_url}/{gp.lstrip('/')}"
                test_url = full_url + intro_query if "?" not in full_url else full_url + "&query=%7B__schema%7Btypes%7Bname%7D%7D%7D"
                resp = client.get(test_url, headers={"Accept": "application/json"}) if allow_headers else client.get(test_url)
                if resp.get("status") in ("budget_exhausted", "blocked_scope"):
                    break
                body = resp.get("body", "")

                if "__schema" in body and "types" in body:
                    findings.append({
                        "title": f"GraphQL Schema Introspection Enabled: {gp}",
                        "severity": "MEDIUM",
                        "url": full_url,
                        "cwe": "CWE-200",
                        "evidence": body[:200],
                        "notes": "GraphQL introspection is enabled in production, exposing internal schema, types, and queries.",
                        "status": "candidate",
                        "validation_status": "unverified"
                    })
                elif resp.get("status_code") in (200, 400) and any(k in body.lower() for k in ["graphql", "syntax error", "must provide query"]):
                    findings.append({
                        "title": f"Active GraphQL Endpoint Discovered: {gp}",
                        "severity": "LOW",
                        "url": full_url,
                        "cwe": "CWE-200",
                        "evidence": f"HTTP {resp.get('status_code')}: {body[:150]}",
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
