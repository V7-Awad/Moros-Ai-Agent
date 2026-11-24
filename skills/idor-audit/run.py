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
    out_file = findings_dir / "candidates-idor-audit.json"

    endpoints = []
    for ep_rel in ["recon/endpoints.txt", "content/discovered-endpoints.txt", "api/openapi-endpoints.json"]:
        ep_file = out_dir / ep_rel
        if ep_file.exists():
            try:
                if ep_file.suffix == ".json":
                    data = json.loads(ep_file.read_text(encoding="utf-8"))
                    endpoints.extend([str(item.get("path", item)) for item in data] if isinstance(data, list) else list(data.keys()))
                else:
                    endpoints.extend([l.strip() for l in ep_file.read_text(encoding="utf-8").splitlines() if l.strip()])
            except Exception:
                pass

    id_patterns = [
        re.compile(r"/(?:users|accounts|orders|invoices|documents|messages|profiles|items)/([0-9a-fA-F-]+|\d+)", re.IGNORECASE),
        re.compile(r"[?&](?:id|user_id|account_id|order_id|doc_id|uid)=(\d+|[0-9a-fA-F-]+)", re.IGNORECASE),
    ]

    candidate_eps = []
    for ep in set(endpoints):
        for pat in id_patterns:
            if pat.search(ep):
                candidate_eps.append(ep)
                break

    findings = []
    req_budget = min(15, int(os.environ.get("MOROS_HTTP_REQUESTS_REMAINING", "15")))
    client = ScopedHttpClient(target=args.target, max_requests=max(1, req_budget), delay_seconds=0.2)

    for ep in candidate_eps[:10]:
        full_url = ep if "://" in ep else f"https://{args.target}{ep if ep.startswith('/') else '/' + ep}"
        resp = client.get(full_url)
        status = resp.get("status_code", 0)
        body = resp.get("body", "")

        # Check if endpoint returned data without authorization
        if status in (200, 201) and len(body) > 20 and ("json" in resp.get("headers", {}).get("content-type", "") or "{" in body):
            findings.append({
                "title": f"Potential IDOR / BOLA on {ep[:60]}",
                "severity": "HIGH",
                "url": full_url,
                "cwe": "CWE-639",
                "evidence": body[:200],
                "notes": f"Endpoint with object identifier returned HTTP {status} with structured payload without explicit authorization check.",
                "status": "candidate",
                "validation_status": "unverified",
                "curl": f"curl -s -i '{full_url}'",
            })

    out_file.write_text(json.dumps({"findings": findings, "count": len(findings)}, indent=2), encoding="utf-8")
    print(f"IDOR Audit completed: {len(findings)} candidate findings recorded.")


if __name__ == "__main__":
    main()
