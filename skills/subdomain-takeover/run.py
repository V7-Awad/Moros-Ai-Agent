#!/usr/bin/env python3
"""
run.py — Executable Runner for Subdomain Takeover in Moros AI.
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
    out_file = findings_dir / "candidates-subdomain-takeover.json"

    subdomains = []
    sub_file = out_dir / "recon" / "subdomains.txt"
    if sub_file.exists():
        subdomains = [l.strip() for l in sub_file.read_text(encoding="utf-8").splitlines() if l.strip()]

    takeover_fingerprints = [
        ("github", "There isn't a GitHub Pages site here"),
        ("heroku", "There's nothing here, yet"),
        ("aws-s3", "The specified bucket does not exist"),
        ("aws-s3", "NoSuchBucket"),
        ("zendesk", "Help Center Closed"),
        ("fastly", "Fastly error: unknown domain"),
    ]

    findings = []
    req_budget = min(15, int(os.environ.get("MOROS_HTTP_REQUESTS_REMAINING", "15")))
    client = ScopedHttpClient(target=args.target, max_requests=max(1, req_budget), delay_seconds=0.2)

    for sub in subdomains[:10]:
        target_url = f"https://{sub}"
        resp = client.get(target_url)
        body = resp.get("body", "")

        for provider, fingerprint in takeover_fingerprints:
            if fingerprint.lower() in body.lower():
                findings.append({
                    "title": f"Subdomain Takeover on {sub} ({provider})",
                    "severity": "HIGH",
                    "url": target_url,
                    "cwe": "CWE-284",
                    "evidence": body[:200],
                    "notes": f"Detected dangling DNS record matching signature '{fingerprint}' for provider '{provider}'.",
                    "status": "candidate",
                    "validation_status": "unverified",
                    "curl": f"curl -s -i '{target_url}'",
                })
                break

    out_file.write_text(json.dumps({"findings": findings, "count": len(findings)}, indent=2), encoding="utf-8")
    print(f"Subdomain Takeover audit completed: {len(findings)} candidate findings recorded.")


if __name__ == "__main__":
    main()
