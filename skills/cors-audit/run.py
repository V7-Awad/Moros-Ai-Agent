#!/usr/bin/env python3
"""
run.py — Executable Runner for CORS Audit Skill in Moros AI.
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
    out_file = findings_dir / "candidates-cors-audit.json"

    findings = []
    endpoints = _load_endpoints(out_dir)

    # Filter to API or sensitive routes
    target_eps = [e for e in endpoints if any(k in e.lower() for k in ["api", "user", "v1", "v2", "profile", "account", "auth"])]
    if not target_eps:
        target_eps = endpoints[:5]

    req_budget = _parse_budget(20, 20)
    if req_budget > 0 and target_eps:
        try:
            validator = ScopeValidator(args.target, target_dir=Path(args.target_dir))
            client = ScopedHttpClient(
                target=args.target,
                max_requests=req_budget,
                delay_seconds=0.2,
                scope_validator=validator,
            )
            if not getattr(validator, "policy", {}).get("allow_authentication", True):
                print("CORS probing skipped: custom headers disabled by scope policy.")
            else:
                test_origin = "https://evil-attacker.com"
                base_url = client.base_url.rstrip("/")

                for ep in target_eps[:10]:
                    full_url = ep if "://" in ep else f"{base_url}/{ep.lstrip('/')}"
                    resp = client.get(full_url, headers={"Origin": test_origin})
                    if resp.get("status") in ("budget_exhausted", "blocked_scope"):
                        break
                    headers = resp.get("headers", {})
                    acao = headers.get("Access-Control-Allow-Origin", headers.get("access-control-allow-origin", ""))
                    acac = headers.get("Access-Control-Allow-Credentials", headers.get("access-control-allow-credentials", ""))

                    if test_origin in acao:
                        severity = "HIGH" if "true" in acac.lower() else "MEDIUM"
                        findings.append({
                            "title": f"CORS Arbitrary Origin Reflection: {ep}",
                            "severity": severity,
                            "url": full_url,
                            "cwe": "CWE-942",
                            "evidence": f"ACAO: {acao} | ACAC: {acac}",
                            "notes": f"Server reflected arbitrary origin '{test_origin}'. Credentials allowed: {acac}",
                            "status": "candidate",
                            "validation_status": "unverified"
                        })
                    elif acao.strip().lower() == "null":
                        findings.append({
                            "title": f"CORS Null Origin Trust: {ep}",
                            "severity": "MEDIUM",
                            "url": full_url,
                            "cwe": "CWE-942",
                            "evidence": f"ACAO: {acao}",
                            "notes": "Server allows 'null' origin, potentially exploitable via sandboxed iframes.",
                            "status": "candidate",
                            "validation_status": "unverified"
                        })
        except ValueError as e:
            print(f"CORS probing skipped (invalid target/scope): {e}")
        except Exception as e:
            print(f"CORS probing notice: {e}")

    out_file.write_text(json.dumps({
        "target": args.target,
        "skill": "cors-audit",
        "title": "CORS Misconfiguration Auditor",
        "findings": findings
    }, indent=2), encoding="utf-8")
    print(f"CORS Audit completed: {len(findings)} candidates found.")


if __name__ == "__main__":
    main()
