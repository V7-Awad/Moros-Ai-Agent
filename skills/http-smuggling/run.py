#!/usr/bin/env python3
"""
run.py — Executable Runner for HTTP Request Smuggling Detection in Moros AI.
"""

import argparse
import json
import os
import sys
import time
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


def _parse_delay(default: float = 0.5) -> float:
    raw = os.environ.get("MOROS_REQUEST_DELAY")
    if raw is None or not raw.strip():
        return default
    try:
        return max(0.0, float(raw.strip()))
    except ValueError:
        return default


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--target-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    findings_dir = out_dir / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)
    out_file = findings_dir / "candidates-http-smuggling.json"

    findings = []
    budget = _parse_budget(30, 30)
    delay = _parse_delay(0.5)

    if budget > 0:
        try:
            validator = ScopeValidator(args.target, target_dir=Path(args.target_dir))
            client = ScopedHttpClient(
                target=args.target,
                max_requests=budget,
                delay_seconds=delay,
                scope_validator=validator,
            )
        except ValueError as e:
            print(f"HTTP smuggling check skipped (invalid target/scope): {e}")
            client = None

        if client is not None:
            allow_custom_headers = getattr(validator, "policy", {}).get("allow_authentication", True)
            base_url = client.base_url.rstrip("/")
            test_paths = ["/", "/api", "/login", "/search"]

            for path in test_paths:
                full_url = f"{base_url}{path}"
                resp_normal = {}
                t_normal = 0.0

                try:
                    t_start = time.monotonic()
                    resp_normal = client.get(full_url)
                    t_normal = time.monotonic() - t_start
                except Exception:
                    continue

                if resp_normal.get("status") in ("budget_exhausted", "blocked_scope", "blocked"):
                    break
                if resp_normal.get("status") != "response":
                    continue

                normal_code = resp_normal.get("status_code")

                # Safe HEAD baseline comparison
                try:
                    t_start = time.monotonic()
                    resp_head = client.head(full_url)
                    t_head = time.monotonic() - t_start
                except Exception:
                    resp_head = {}
                    t_head = 0.0

                if resp_head.get("status") in ("budget_exhausted", "blocked_scope"):
                    break

                if resp_head.get("status") == "response":
                    head_code = resp_head.get("status_code")
                    if t_head > t_normal + 5.0 or (normal_code == 200 and head_code in (500, 502, 504)):
                        findings.append({
                            "title": f"HTTP Method/Proxy Timing Anomaly at {path}",
                            "url": full_url,
                            "severity": "MEDIUM",
                            "cwe": "CWE-444",
                            "evidence": json.dumps({
                                "normal_time": round(t_normal, 3),
                                "head_time": round(t_head, 3),
                                "normal_status": normal_code,
                                "head_status": head_code,
                                "differential_seconds": round(t_head - t_normal, 3),
                            }),
                            "status": "candidate",
                            "validation_status": "unverified",
                            "recommendation": "Verify front-end proxy and back-end server HTTP framing consistency (CL/TE and HTTP/2 downgrade).",
                        })

                # Safe GET probe with Transfer-Encoding header when custom headers are permitted
                if allow_custom_headers:
                    try:
                        t_start = time.monotonic()
                        resp_te = client.get(full_url, headers={"Transfer-Encoding": "chunked"})
                        t_te = time.monotonic() - t_start
                    except Exception:
                        resp_te = {}
                        t_te = 0.0

                    if resp_te.get("status") in ("budget_exhausted", "blocked_scope"):
                        break

                    if resp_te.get("status") == "response":
                        te_code = resp_te.get("status_code")
                        if t_te > t_normal + 5.0 or (normal_code is not None and normal_code < 500 and te_code in (500, 502, 504)):
                            findings.append({
                                "title": f"Potential Transfer-Encoding Desync Anomaly at {path}",
                                "url": full_url,
                                "severity": "HIGH",
                                "cwe": "CWE-444",
                                "evidence": json.dumps({
                                    "normal_time": round(t_normal, 3),
                                    "te_time": round(t_te, 3),
                                    "normal_status": normal_code,
                                    "te_status": te_code,
                                    "differential_seconds": round(t_te - t_normal, 3),
                                }),
                                "status": "candidate",
                                "validation_status": "unverified",
                                "recommendation": "Normalize Transfer-Encoding header handling between front-end proxy and back-end server. Reject ambiguous requests.",
                            })

    out_file.write_text(json.dumps({
        "target": args.target,
        "skill": "http-smuggling",
        "title": "HTTP Request Smuggling Detector",
        "findings": findings,
        "count": len(findings),
    }, indent=2), encoding="utf-8")
    print(json.dumps({"status": "OK", "findings_count": len(findings), "output": str(out_file)}))


if __name__ == "__main__":
    main()
