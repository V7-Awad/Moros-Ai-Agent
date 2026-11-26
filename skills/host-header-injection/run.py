#!/usr/bin/env python3
"""
run.py — Executable Runner for Host Header Injection in Moros AI.
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

from scope_validator import ScopeValidator
from scoped_http import ScopedHttpClient


def _parse_budget(default: int, cap: int) -> int:
    raw = os.environ.get("MOROS_HTTP_REQUESTS_REMAINING")
    if raw is None or not raw.strip():
        return min(default, cap)
    try:
        return min(max(0, int(raw.strip())), cap)
    except ValueError:
        return min(default, cap)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--target-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    findings_dir = out_dir / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)
    out_file = findings_dir / "candidates-host-header-injection.json"

    findings = []
    test_origin = "attacker-controlled-host.com"
    req_budget = _parse_budget(10, 10)

    if req_budget > 0:
        try:
            validator = ScopeValidator(args.target, target_dir=Path(args.target_dir))
            client = ScopedHttpClient(
                target=args.target,
                max_requests=req_budget,
                delay_seconds=0.2,
                scope_validator=validator,
            )
            if not getattr(validator, "policy", {}).get("allow_authentication", True):
                print("Host Header Injection audit skipped: custom headers disabled by scope policy.")
            else:
                full_url = f"{client.base_url.rstrip('/')}/"
                resp = client.get(full_url, headers={"X-Forwarded-Host": test_origin})
                body = resp.get("body", "")
                headers = resp.get("headers", {})

                if test_origin in body or test_origin in headers.get("location", ""):
                    findings.append({
                        "title": "Host Header Injection / X-Forwarded-Host Reflection",
                        "severity": "MEDIUM",
                        "url": full_url,
                        "cwe": "CWE-20",
                        "evidence": f"Reflected '{test_origin}' in response body or Location header.",
                        "notes": "Application accepted and reflected unvalidated X-Forwarded-Host header, enabling cache poisoning or password reset poisoning.",
                        "status": "candidate",
                        "validation_status": "unverified",
                        "curl": f"curl -s -i -H 'X-Forwarded-Host: {test_origin}' '{full_url}'",
                    })
        except ValueError as e:
            print(f"Host Header Injection audit skipped (invalid target/scope): {e}")
        except Exception as e:
            print(f"Host Header Injection audit notice: {e}")

    out_file.write_text(json.dumps({"findings": findings, "count": len(findings)}, indent=2), encoding="utf-8")
    print(f"Host Header Injection audit completed: {len(findings)} candidate findings recorded.")


if __name__ == "__main__":
    main()
