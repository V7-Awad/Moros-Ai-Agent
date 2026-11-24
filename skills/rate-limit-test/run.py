#!/usr/bin/env python3
"""
run.py — Executable Runner for Rate Limiting Tests in Moros AI.
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
    out_file = findings_dir / "candidates-rate-limit-test.json"

    endpoints = []
    ep_file = out_dir / "content" / "discovered-endpoints.txt"
    if not ep_file.exists():
        ep_file = out_dir / "recon" / "endpoints.txt"
    if ep_file.exists():
        endpoints = [l.strip() for l in ep_file.read_text(encoding="utf-8").splitlines() if l.strip()]

    auth_eps = [e for e in endpoints if any(k in e.lower() for k in ["login", "signin", "auth", "token", "password", "otp"])]
    if not auth_eps:
        auth_eps = [f"https://{args.target}/login", f"https://{args.target}/api/login"]

    findings = []
    req_budget = min(15, int(os.environ.get("MOROS_HTTP_REQUESTS_REMAINING", "15")))
    client = ScopedHttpClient(target=args.target, max_requests=max(1, req_budget), delay_seconds=0.1)

    for ep in auth_eps[:2]:
        full_url = ep if "://" in ep else f"https://{args.target}{ep if ep.startswith('/') else '/' + ep}"
        responses = []
        for _ in range(5):
            resp = client.get(full_url)
            responses.append(resp.get("status_code", 0))

        # If all 5 requests succeeded with 200 without 429
        if all(code in (200, 401, 403) and code != 429 for code in responses) and len(responses) == 5:
            findings.append({
                "title": f"Missing Rate Limiting on {ep[:50]}",
                "severity": "LOW",
                "url": full_url,
                "cwe": "CWE-770",
                "evidence": f"Burst of 5 requests returned status codes: {responses}",
                "notes": "No HTTP 429 Too Many Requests or rate limiting headers detected on authentication endpoint.",
                "status": "candidate",
                "validation_status": "unverified",
                "curl": f"curl -s -i '{full_url}'",
            })

    out_file.write_text(json.dumps({"findings": findings, "count": len(findings)}, indent=2), encoding="utf-8")
    print(f"Rate Limiting test completed: {len(findings)} candidate findings recorded.")


if __name__ == "__main__":
    main()
