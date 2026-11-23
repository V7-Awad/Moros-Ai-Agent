#!/usr/bin/env python3
"""
run.py — Executable Runner for CORS Audit Skill in Moros AI.
"""

import argparse
import json
import sys
from pathlib import Path

# Add tools to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "tools"))
from scoped_http import ScopedHttpClient, is_in_target_scope


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--target-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    findings_dir = out_dir / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)
    out_file = findings_dir / "candidates-cors-audit.json"

    findings = []
    ep_file = out_dir / "recon" / "endpoints.txt"
    if not ep_file.exists():
        ep_file = out_dir / "content" / "discovered-endpoints.txt"

    endpoints = []
    if ep_file.exists():
        endpoints = [line.strip() for line in ep_file.read_text(encoding="utf-8").splitlines() if line.strip()]

    # Filter to API or sensitive routes
    target_eps = [e for e in endpoints if any(k in e.lower() for k in ["api", "user", "v1", "v2", "profile", "account", "auth"])]
    if not target_eps:
        target_eps = endpoints[:5]

    try:
        client = ScopedHttpClient(target=args.target, max_requests=20, delay_seconds=0.2)
        test_origin = "https://evil-attacker.com"

        for ep in target_eps[:10]:
            full_url = ep if "://" in ep else f"https://{args.target}{ep if ep.startswith('/') else '/' + ep}"
            resp = client.get(full_url, headers={"Origin": test_origin})
            headers = resp.get("headers", {})
            acao = headers.get("Access-Control-Allow-Origin", headers.get("access-control-allow-origin", ""))
            acac = headers.get("Access-Control-Allow-Credentials", headers.get("access-control-allow-credentials", ""))

            if test_origin in acao:
                severity = "HIGH" if "true" in acac.lower() else "MEDIUM"
                findings.append({
                    "title": f"CORS Arbitrary Origin Reflection: {ep}",
                    "severity": severity,
                    "url": full_url,
                    "cwe": "CWE-942",
                    "evidence": f"ACAO: {acao} | ACAC: {acac}",
                    "notes": f"Server reflected arbitrary origin '{test_origin}'. Credentials allowed: {acac}",
                    "status": "candidate",
                    "validation_status": "unverified"
                })
            elif "null" in acao.lower():
                findings.append({
                    "title": f"CORS Null Origin Trust: {ep}",
                    "severity": "MEDIUM",
                    "url": full_url,
                    "cwe": "CWE-942",
                    "evidence": f"ACAO: {acao}",
                    "notes": "Server allows 'null' origin, potentially exploitable via sandboxed iframes.",
                    "status": "candidate",
                    "validation_status": "unverified"
                })
    except Exception as e:
        print(f"CORS probing notice: {e}")

    out_file.write_text(json.dumps({
        "target": args.target,
        "skill": "cors-audit",
        "title": "CORS Misconfiguration Auditor",
        "findings": findings
    }, indent=2), encoding="utf-8")
    print(f"CORS Audit completed: {len(findings)} candidates found.")


if __name__ == "__main__":
    main()
