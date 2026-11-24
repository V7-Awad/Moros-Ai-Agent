#!/usr/bin/env python3
"""
run.py — Executable Runner for CRLF Injection in Moros AI.
"""

import argparse
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

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
    out_file = findings_dir / "candidates-crlf-injection.json"

    findings = []
    test_urls = [
        f"https://{args.target}/%0d%0aX-Moros-Injected:%20true",
        f"https://{args.target}/?redirect=%0d%0aSet-Cookie:%20moros_test=1",
    ]

    req_budget = min(10, int(os.environ.get("MOROS_HTTP_REQUESTS_REMAINING", "10")))
    client = ScopedHttpClient(target=args.target, max_requests=max(1, req_budget), delay_seconds=0.2)

    for test_url in test_urls:
        resp = client.get(test_url)
        headers = resp.get("headers", {})

        injected = (
            "x-moros-injected" in headers or
            "moros_test=1" in headers.get("set-cookie", "")
        )

        if injected:
            findings.append({
                "title": "CRLF Injection / HTTP Response Splitting",
                "severity": "MEDIUM",
                "url": test_url,
                "cwe": "CWE-93",
                "evidence": str(headers),
                "notes": "Injected CRLF header reflected directly in server response headers.",
                "status": "candidate",
                "validation_status": "unverified",
                "curl": f"curl -s -I '{test_url}'",
            })

    out_file.write_text(json.dumps({"findings": findings, "count": len(findings)}, indent=2), encoding="utf-8")
    print(f"CRLF Injection audit completed: {len(findings)} candidate findings recorded.")


if __name__ == "__main__":
    main()
