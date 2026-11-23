#!/usr/bin/env python3
"""
run.py — Executable Runner for WebSocket Security Auditor in Moros AI.
"""

import argparse
import json
import re
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--target-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    findings_dir = out_dir / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)
    out_file = findings_dir / "candidates-websocket-audit.json"

    findings = []
    ws_regex = re.compile(r"wss?://[a-zA-Z0-9_\-\.:/]+")

    js_dir = out_dir / "js"
    if js_dir.exists():
        for js_file in js_dir.rglob("*.js"):
            if js_file.stat().st_size > 10_000_000:
                continue
            try:
                content = js_file.read_text(encoding="utf-8", errors="ignore")
                matches = ws_regex.findall(content)
                for ws_url in set(matches[:5]):
                    findings.append({
                        "title": f"WebSocket Endpoint Discovered: {ws_url}",
                        "severity": "LOW",
                        "url": ws_url,
                        "cwe": "CWE-1385",
                        "evidence": f"Found in {js_file.name}",
                        "notes": "WebSocket endpoint discovered in client-side JavaScript. Origin validation during handshake requires auditing.",
                        "status": "candidate",
                        "validation_status": "unverified"
                    })
                    if len(findings) >= 10:
                        break
            except Exception:
                continue

    out_file.write_text(json.dumps({
        "target": args.target,
        "skill": "websocket-audit",
        "title": "WebSocket Security Auditor",
        "findings": findings
    }, indent=2), encoding="utf-8")
    print(f"WebSocket scan completed: {len(findings)} candidates found.")


if __name__ == "__main__":
    main()
