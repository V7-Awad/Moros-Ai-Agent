#!/usr/bin/env python3
"""
run.py — Executable Runner for CRLF Injection in Moros AI.
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
    out_file = findings_dir / "candidates-crlf-injection.json"

    findings = []
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
            base_url = client.base_url.rstrip("/")
            test_urls = [
                f"{base_url}/%0d%0aSet-Cookie:%20moros_test=1",
                f"{base_url}/?redirect=%0d%0aSet-Cookie:%20moros_test=1",
            ]

            for test_url in test_urls:
                resp = client.get(test_url)
                if resp.get("status") in ("budget_exhausted", "blocked_scope"):
                    break
                if resp.get("status") != "response":
                    continue
                headers = resp.get("headers", {})
                set_cookie = headers.get("set-cookie", "")
                location = headers.get("location", "")

                injected = (
                    "moros_test=1" in set_cookie.lower()
                    or "\r" in location
                    or "\n" in location
                    or "\r" in set_cookie
                    or "\n" in set_cookie
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
        except ValueError as e:
            print(f"CRLF Injection audit skipped (invalid target/scope): {e}")
        except Exception as e:
            print(f"CRLF Injection audit notice: {e}")

    out_file.write_text(json.dumps({"findings": findings, "count": len(findings)}, indent=2), encoding="utf-8")
    print(f"CRLF Injection audit completed: {len(findings)} candidate findings recorded.")


if __name__ == "__main__":
    main()
