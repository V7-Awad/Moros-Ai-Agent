#!/usr/bin/env python3
"""
run.py — Executable Runner for SQL Injection Heuristic Auditor in Moros AI.
"""

import argparse
import json
import os
import re
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
                qs = "&".join(f"{name}=test" for name in param_names[:4])
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

    endpoints = _load_endpoints(out_dir)

    # Filter endpoints with query parameters
    param_eps = [e for e in endpoints if "?" in e and "=" in e]
    req_budget = _parse_budget(10, 10)

    if req_budget > 0 and param_eps:
        try:
            validator = ScopeValidator(args.target, target_dir=Path(args.target_dir))
            client = ScopedHttpClient(
                target=args.target,
                max_requests=req_budget,
                delay_seconds=0.2,
                scope_validator=validator,
            )
            base_url = client.base_url.rstrip("/")

            for ep in param_eps[:5]:
                full_url = ep if "://" in ep else f"{base_url}/{ep.lstrip('/')}"
                probe_url = full_url + "'"
                resp = client.get(probe_url)
                if resp.get("status") in ("budget_exhausted", "blocked_scope"):
                    break
                body = resp.get("body", "")

                for pat, dbms in sql_error_patterns:
                    m = pat.search(body)
                    if m:
                        findings.append({
                            "title": f"SQL Syntax Error Fingerprint ({dbms}): {ep}",
                            "severity": "HIGH",
                            "url": full_url,
                            "cwe": "CWE-89",
                            "evidence": m.group(0),
                            "notes": f"Detected database syntax error reflection from {dbms} when appending quote anomaly.",
                            "status": "candidate",
                            "validation_status": "unverified"
                        })
                        break
        except ValueError as e:
            print(f"SQLi heuristic skipped (invalid target/scope): {e}")
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
