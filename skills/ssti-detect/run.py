#!/usr/bin/env python3
"""
run.py — Executable Runner for SSTI Detection in Moros AI.
"""

import argparse
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlencode, parse_qs, urlsplit, urlunsplit

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
    out_file = findings_dir / "candidates-ssti-detect.json"

    endpoints = []
    ep_file = out_dir / "content" / "discovered-endpoints.txt"
    if not ep_file.exists():
        ep_file = out_dir / "recon" / "endpoints.txt"
    if ep_file.exists():
        endpoints = [l.strip() for l in ep_file.read_text(encoding="utf-8").splitlines() if "?" in l]

    if not endpoints:
        endpoints = [f"https://{args.target}/search?q=test", f"https://{args.target}/?name=test"]

    ssti_payloads = [
        ("{{7*7}}", "49"),
        ("${7*7}", "49"),
        ("<%= 7*7 %>", "49"),
    ]

    findings = []
    req_budget = min(15, int(os.environ.get("MOROS_HTTP_REQUESTS_REMAINING", "15")))
    client = ScopedHttpClient(target=args.target, max_requests=max(1, req_budget), delay_seconds=0.2)

    for ep in endpoints[:5]:
        full_url = ep if "://" in ep else f"https://{args.target}{ep if ep.startswith('/') else '/' + ep}"
        parsed = urlsplit(full_url)
        params = parse_qs(parsed.query)
        if not params:
            continue

        for param_name in list(params.keys())[:2]:
            for payload, expected in ssti_payloads:
                test_params = dict(params)
                test_params[param_name] = [payload]
                test_query = urlencode(test_params, doseq=True)
                test_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, test_query, ""))

                resp = client.get(test_url)
                body = resp.get("body", "")

                if expected in body and payload not in body:
                    findings.append({
                        "title": f"Server-Side Template Injection (SSTI) in parameter '{param_name}'",
                        "severity": "CRITICAL",
                        "url": test_url,
                        "cwe": "CWE-1336",
                        "evidence": f"Injected '{payload}' and evaluated to '{expected}' in response body.",
                        "notes": "Expression evaluation observed on server side without raw string reflection.",
                        "status": "candidate",
                        "validation_status": "unverified",
                        "curl": f"curl -s -i '{test_url}'",
                    })
                    break

    out_file.write_text(json.dumps({"findings": findings, "count": len(findings)}, indent=2), encoding="utf-8")
    print(f"SSTI Detection completed: {len(findings)} candidate findings recorded.")


if __name__ == "__main__":
    main()
