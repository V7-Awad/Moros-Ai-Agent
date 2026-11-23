#!/usr/bin/env python3
"""
run.py — Executable Runner for Open Redirect Hunter in Moros AI.
"""

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "tools"))
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
    out_file = findings_dir / "candidates-open-redirect.json"

    findings = []
    redirect_params = ["redirect", "redirect_url", "url", "next", "return_to", "return", "dest", "target", "goto", "r"]

    # Gather endpoints
    ep_file = out_dir / "recon" / "endpoints.txt"
    if not ep_file.exists():
        ep_file = out_dir / "content" / "discovered-endpoints.txt"

    endpoints = []
    if ep_file.exists():
        endpoints = [line.strip() for line in ep_file.read_text(encoding="utf-8").splitlines() if line.strip()]

    # Also search JS files for redirect parameter references
    js_dir = out_dir / "js"
    if js_dir.exists():
        for js_file in list(js_dir.rglob("*.js"))[:10]:
            try:
                content = js_file.read_text(encoding="utf-8", errors="ignore")
                for p in redirect_params:
                    if f"?{p}=" in content or f"&{p}=" in content:
                        findings.append({
                            "title": f"Candidate Redirect Parameter '{p}' in {js_file.name}",
                            "severity": "LOW",
                            "url": f"https://{args.target}/{js_file.name}",
                            "cwe": "CWE-601",
                            "evidence": f"Parameter '{p}' observed in client-side navigation logic.",
                            "notes": f"Potential client-side open redirect or redirect parameter detected.",
                            "status": "candidate",
                            "validation_status": "unverified"
                        })
                        if len(findings) >= 5:
                            break
            except Exception:
                continue

    # Test candidate endpoints
    candidate_eps = [e for e in endpoints if any(f"{p}=" in e.lower() for p in redirect_params)]
    try:
        client = ScopedHttpClient(target=args.target, max_requests=10, delay_seconds=0.2)
        test_dest = "https://example.com"

        for ep in candidate_eps[:5]:
            full_url = ep if "://" in ep else f"https://{args.target}{ep if ep.startswith('/') else '/' + ep}"
            resp = client.get(full_url)
            loc = resp.get("headers", {}).get("Location", resp.get("headers", {}).get("location", ""))
            if "example.com" in loc:
                findings.append({
                    "title": f"Unvalidated Open Redirect: {ep}",
                    "severity": "MEDIUM",
                    "url": full_url,
                    "cwe": "CWE-601",
                    "evidence": f"Location: {loc}",
                    "notes": f"Server redirected to untrusted destination '{loc}'.",
                    "status": "candidate",
                    "validation_status": "unverified"
                })
    except Exception as e:
        print(f"Open redirect check notice: {e}")

    out_file.write_text(json.dumps({
        "target": args.target,
        "skill": "open-redirect",
        "title": "Open Redirect Hunter",
        "findings": findings
    }, indent=2), encoding="utf-8")
    print(f"Open Redirect scan completed: {len(findings)} candidates found.")


if __name__ == "__main__":
    main()
