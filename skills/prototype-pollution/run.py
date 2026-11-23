#!/usr/bin/env python3
"""
run.py — Executable Runner for Prototype Pollution Hunter in Moros AI.
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
    out_file = findings_dir / "candidates-prototype-pollution.json"

    findings = []
    gadget_patterns = [
        (re.compile(r"(\w+\[['\"]__proto__['\"]\]\s*=\s*)"), "Direct __proto__ Assignment"),
        (re.compile(r"(Object\.prototype\s*\[[^\]]+\]\s*=)"), "Object.prototype Modification"),
        (re.compile(r"(constructor\.prototype\s*\[[^\]]+\]\s*=)"), "constructor.prototype Modification"),
        (re.compile(r"(\b(?:deepMerge|merge|extend|deepExtend)\s*\([^)]+\))"), "Recursive Merge/Extend Function"),
    ]

    js_dir = out_dir / "js"
    if js_dir.exists():
        for js_file in js_dir.rglob("*.js"):
            if js_file.stat().st_size > 10_000_000:
                continue
            try:
                content = js_file.read_text(encoding="utf-8", errors="ignore")
                for line_num, line in enumerate(content.splitlines(), start=1):
                    for pat, desc in gadget_patterns:
                        m = pat.search(line)
                        if m:
                            findings.append({
                                "title": f"Prototype Pollution Gadget: {desc} in {js_file.name}",
                                "severity": "MEDIUM",
                                "url": f"https://{args.target}/{js_file.name}#L{line_num}",
                                "cwe": "CWE-1321",
                                "evidence": line.strip()[:180],
                                "notes": f"Detected potential prototype pollution sink '{desc}' at line {line_num}.",
                                "status": "candidate",
                                "validation_status": "unverified"
                            })
                            if len(findings) >= 20:
                                break
                    if len(findings) >= 20:
                        break
            except Exception:
                continue

    out_file.write_text(json.dumps({
        "target": args.target,
        "skill": "prototype-pollution",
        "title": "Prototype Pollution Hunter",
        "findings": findings
    }, indent=2), encoding="utf-8")
    print(f"Prototype Pollution scan completed: {len(findings)} candidates found.")


if __name__ == "__main__":
    main()
