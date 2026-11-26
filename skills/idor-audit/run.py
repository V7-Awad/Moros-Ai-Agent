#!/usr/bin/env python3
"""
run.py — Executable Runner for IDOR / BOLA Audit in Moros AI.
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path

# Add tools to sys.path
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


def _load_endpoints(out_dir: Path) -> list[str]:
    endpoints: list[str] = []
    seen: set[str] = set()

    def _add(ep: str) -> None:
        val = (ep or "").strip()
        if val and val not in seen:
            seen.add(val)
            endpoints.append(val)

    def _from_item(item) -> None:
        if isinstance(item, str):
            _add(item)
        elif isinstance(item, dict):
            url = str(item.get("url") or "").strip()
            if not url:
                path = str(item.get("path") or "").strip()
                base = str(item.get("base_url") or "").strip().rstrip("/")
                url = f"{base}/{path.lstrip('/')}" if base and path else path
            if not url:
                return
            params = item.get("parameters") or []
            param_names = []
            if isinstance(params, list):
                for p in params:
                    name = p.get("name") if isinstance(p, dict) else p
                    if name:
                        param_names.append(str(name).strip())
            if param_names and "?" not in url:
                qs = "&".join(f"{name}=1" for name in param_names[:4])
                _add(f"{url}?{qs}")
            _add(url)

    for rel in [
        "js/endpoints.json",
        "api/endpoints.json",
        "api/openapi-endpoints.json",
        "content-discovery/discovered-paths.json",
        "recon/endpoints.txt",
        "content/discovered-endpoints.txt",
    ]:
        ep_file = out_dir / rel
        if not ep_file.exists():
            continue
        try:
            if ep_file.suffix == ".json":
                data = json.loads(ep_file.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    for item in data:
                        _from_item(item)
                elif isinstance(data, dict):
                    if isinstance(data.get("endpoints"), list):
                        for item in data["endpoints"]:
                            _from_item(item)
                    elif isinstance(data.get("interesting_routes"), list) or isinstance(data.get("paths_checked"), list):
                        for item in (data.get("interesting_routes") or []):
                            _from_item(item)
                        for item in (data.get("paths_checked") or []):
                            if isinstance(item, dict) and item.get("status_code") not in (None, 404):
                                _from_item(item)
            else:
                for line in ep_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                    _add(line)
        except Exception:
            continue
    return endpoints


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--target-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    findings_dir = out_dir / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)
    out_file = findings_dir / "candidates-idor-audit.json"

    endpoints = _load_endpoints(out_dir)

    id_patterns = [
        re.compile(r"/(?:users|accounts|orders|invoices|documents|messages|profiles|items)/([0-9a-fA-F-]+|\d+)", re.IGNORECASE),
        re.compile(r"[?&](?:id|user_id|account_id|order_id|doc_id|uid)=(\d+|[0-9a-fA-F-]+)", re.IGNORECASE),
    ]

    candidate_eps = []
    for ep in endpoints:
        for pat in id_patterns:
            if pat.search(ep):
                candidate_eps.append(ep)
                break

    findings = []
    req_budget = _parse_budget(15, 15)

    if req_budget > 0 and candidate_eps:
        try:
            validator = ScopeValidator(args.target, target_dir=Path(args.target_dir))
            client = ScopedHttpClient(
                target=args.target,
                max_requests=req_budget,
                delay_seconds=0.2,
                scope_validator=validator,
            )
            base_url = client.base_url.rstrip("/")

            for ep in candidate_eps[:10]:
                full_url = ep if "://" in ep else f"{base_url}/{ep.lstrip('/')}"
                resp = client.get(full_url)
                if resp.get("status") in ("budget_exhausted", "blocked_scope"):
                    break
                status = resp.get("status_code", 0)
                body = resp.get("body", "")

                # Check if endpoint returned data without authorization
                if status in (200, 201) and len(body) > 20 and ("json" in resp.get("headers", {}).get("content-type", "") or "{" in body):
                    findings.append({
                        "title": f"Potential IDOR / BOLA on {ep[:60]}",
                        "severity": "HIGH",
                        "url": full_url,
                        "cwe": "CWE-639",
                        "evidence": body[:200],
                        "notes": f"Endpoint with object identifier returned HTTP {status} with structured payload without explicit authorization check.",
                        "status": "candidate",
                        "validation_status": "unverified",
                        "curl": f"curl -s -i '{full_url}'",
                    })
        except ValueError as e:
            print(f"IDOR Audit skipped (invalid target/scope): {e}")
        except Exception as e:
            print(f"IDOR Audit notice: {e}")

    out_file.write_text(json.dumps({"findings": findings, "count": len(findings)}, indent=2), encoding="utf-8")
    print(f"IDOR Audit completed: {len(findings)} candidate findings recorded.")


if __name__ == "__main__":
    main()
