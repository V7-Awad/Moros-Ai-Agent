#!/usr/bin/env python3
"""
run.py — Executable Runner for SQL Injection Heuristic Auditor in Moros AI.
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
    out_file = findings_dir / "candidates-sqli-heuristic.json"

    findings = []
    sql_error_patterns = [
        (re.compile(r"you have an error in your sql syntax", re.I), "MySQL"),
        (re.compile(r"syntax error at or near", re.I), "PostgreSQL"),
        (re.compile(r"unclosed quotation mark before the character string", re.I), "MSSQL"),
        (re.compile(r"ora-[0-9]{4,5}", re.I), "Oracle"),
        (re.compile(r"sqlite3::SQLException", re.I), "SQLite"),
        (re.compile(r"CLI Driver.*DB2", re.I), "IBM DB2"),
    ]

    ep_file = out_dir / "recon" / "endpoints.txt"
    if not ep_file.exists():
        ep_file = out_dir / "content" / "discovered-endpoints.txt"

    endpoints = []
    if ep_file.exists():
        endpoints = [line.strip() for line in ep_file.read_text(encoding="utf-8").splitlines() if line.strip()]

    # Filter endpoints with query parameters
    param_eps = [e for e in endpoints if "?" in e and "=" in e]

    try:
        client = ScopedHttpClient(target=args.target, max_requests=10, delay_seconds=0.2)
        for ep in param_eps[:5]:
            full_url = ep if "://" in ep else f"https://{args.target}{ep if ep.startswith('/') else '/' + ep}"
            probe_url = full_url + "'"
            resp = client.get(probe_url)
            body = resp.get("body", "")

            for pat, dbms in sql_error_patterns:
                if pat.search(body):
                    findings.append({
                        "title": f"SQL Syntax Error Fingerprint ({dbms}): {ep}",
                        "severity": "HIGH",
                        "url": full_url,
                        "cwe": "CWE-89",
                        "evidence": pat.search(body).group(0),
                        "notes": f"Detected database syntax error reflection from {dbms} when appending quote anomaly.",
                        "status": "candidate",
                        "validation_status": "unverified"
                    })
                    break
    except Exception as e:
        print(f"SQLi heuristic notice: {e}")

    out_file.write_text(json.dumps({
        "target": args.target,
        "skill": "sqli-heuristic",
        "title": "SQL Injection Heuristic Auditor",
        "findings": findings
    }, indent=2), encoding="utf-8")
    print(f"SQLi Heuristic scan completed: {len(findings)} candidates found.")


if __name__ == "__main__":
    main()
