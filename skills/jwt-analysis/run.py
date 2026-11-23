#!/usr/bin/env python3
"""
run.py — Executable Runner for JWT Analysis Skill in Moros AI.
"""

import argparse
import base64
import json
import re
import sys
from pathlib import Path


def b64_decode(data: str) -> str:
    padding = len(data) % 4
    if padding:
        data += "=" * (4 - padding)
    try:
        return base64.urlsafe_b64decode(data).decode("utf-8", errors="ignore")
    except Exception:
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
    out_file = findings_dir / "candidates-jwt-analysis.json"

    findings = []
    jwt_regex = re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]*")

    # Search in JS files
    js_dir = out_dir / "js"
    if js_dir.exists():
        for js_file in js_dir.rglob("*.js"):
            if js_file.stat().st_size > 10_000_000:
                continue
            try:
                content = js_file.read_text(encoding="utf-8", errors="ignore")
                matches = jwt_regex.findall(content)
                for token in set(matches[:5]):
                    parts = token.split(".")
                    if len(parts) >= 2:
                        header = b64_decode(parts[0])
                        payload = b64_decode(parts[1])
                        
                        # Check none algorithm
                        if '"alg":"none"' in header.lower().replace(" ", ""):
                            findings.append({
                                "title": f"JWT 'none' Algorithm Vulnerability in {js_file.name}",
                                "severity": "HIGH",
                                "url": f"https://{args.target}/{js_file.name}",
                                "cwe": "CWE-347",
                                "evidence": token[:40] + "...",
                                "notes": f"Decoded Header: {header}. Algorithm 'none' is accepted or defined.",
                                "status": "candidate",
                                "validation_status": "unverified"
                            })
                        else:
                            findings.append({
                                "title": f"Hardcoded or Leaked JWT Token in {js_file.name}",
                                "severity": "MEDIUM",
                                "url": f"https://{args.target}/{js_file.name}",
                                "cwe": "CWE-522",
                                "evidence": token[:35] + "...",
                                "notes": f"Decoded Header: {header} | Payload claims: {payload[:150]}",
                                "status": "candidate",
                                "validation_status": "unverified"
                            })
            except Exception:
                continue

    # Also check endpoints
    ep_file = out_dir / "recon" / "endpoints.txt"
    if ep_file.exists():
        for line in ep_file.read_text(encoding="utf-8").splitlines():
            if any(k in line.lower() for k in ["jwt", "token", "auth/verify", "oauth/token"]):
                findings.append({
                    "title": f"Candidate JWT Auth Endpoint: {line.strip()}",
                    "severity": "LOW",
                    "url": line.strip() if "://" in line else f"https://{args.target}{line.strip()}",
                    "cwe": "CWE-287",
                    "evidence": line.strip(),
                    "notes": "Authentication or token verification endpoint discovered for JWT inspection.",
                    "status": "candidate",
                    "validation_status": "unverified"
                })

    out_file.write_text(json.dumps({
        "target": args.target,
        "skill": "jwt-analysis",
        "title": "JWT Security Analysis",
        "findings": findings
    }, indent=2), encoding="utf-8")
    print(f"JWT Analysis completed: {len(findings)} candidates found.")


if __name__ == "__main__":
    main()
