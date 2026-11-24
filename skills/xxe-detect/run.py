#!/usr/bin/env python3
"""
run.py — Executable Runner for XXE Detection in Moros AI.
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
    out_file = findings_dir / "candidates-xxe-detect.json"

    endpoints = []
    ep_file = out_dir / "content" / "discovered-endpoints.txt"
    if not ep_file.exists():
        ep_file = out_dir / "recon" / "endpoints.txt"
    if ep_file.exists():
        endpoints = [l.strip() for l in ep_file.read_text(encoding="utf-8").splitlines() if any(k in l.lower() for k in ["xml", "soap", "saml", "import"])]

    findings = []
    # If XML endpoint discovered, record candidate for agent ReAct inspection
    for ep in endpoints[:5]:
        full_url = ep if "://" in ep else f"https://{args.target}{ep if ep.startswith('/') else '/' + ep}"
        findings.append({
            "title": f"XML-Accepting Endpoint Detected: {ep[:50]}",
            "severity": "LOW",
            "url": full_url,
            "cwe": "CWE-611",
            "evidence": f"Endpoint {ep} identified as XML/SOAP consumer.",
            "notes": "Candidate for authenticated XXE entity resolution testing.",
            "status": "candidate",
            "validation_status": "unverified",
            "curl": f"curl -s -i '{full_url}'",
        })

    out_file.write_text(json.dumps({"findings": findings, "count": len(findings)}, indent=2), encoding="utf-8")
    print(f"XXE Detection completed: {len(findings)} candidate findings recorded.")


if __name__ == "__main__":
    main()
