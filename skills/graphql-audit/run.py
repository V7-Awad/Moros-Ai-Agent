#!/usr/bin/env python3
"""
run.py — Executable Runner for GraphQL Audit Skill in Moros AI.
"""

import argparse
import json
import sys
from pathlib import Path

_skill_dir = Path(__file__).parent.resolve()
_project_root = _skill_dir
while _project_root != _project_root.parent:
    if (_project_root / "tools").is_dir() and (_project_root / "run.py").is_file():
        break
    _project_root = _project_root.parent
sys.path.insert(0, str(_project_root / "tools"))
from scoped_http import ScopedHttpClient


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

    # Also check discovered endpoints
    ep_file = out_dir / "recon" / "endpoints.txt"
    if ep_file.exists():
        for line in ep_file.read_text(encoding="utf-8").splitlines():
            if "graphql" in line.lower() and line.strip() not in graphql_paths:
                graphql_paths.append(line.strip())

    try:
        client = ScopedHttpClient(target=args.target, max_requests=15, delay_seconds=0.2)
        intro_query = "?query=%7B__schema%7Btypes%7Bname%7D%7D%7D"

        for gp in graphql_paths[:8]:
            full_url = gp if "://" in gp else f"https://{args.target}{gp if gp.startswith('/') else '/' + gp}"
            test_url = full_url + intro_query if "?" not in full_url else full_url + "&query=%7B__schema%7Btypes%7Bname%7D%7D%7D"
            resp = client.get(test_url, headers={"Accept": "application/json"})
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
