#!/usr/bin/env python3
"""
run.py — Executable Runner for Open Redirect Hunter in Moros AI.
"""

import argparse
import json
import os
import sys
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

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


def _inject_redirect_dest(url: str, redirect_params: list[str], dest: str) -> str:
    parsed = urlsplit(url)
    query_items = parse_qsl(parsed.query, keep_blank_values=True)
    redirect_set = set(redirect_params)
    updated = []
    replaced = False
    for k, v in query_items:
        if k.lower() in redirect_set:
            updated.append((k, dest))
            replaced = True
        else:
            updated.append((k, v))
    if not replaced:
        return url
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(updated, doseq=True), ""))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--target-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    findings_dir = out_dir / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)
    out_file = findings_dir / "candidates-open-redirect.json"

    findings = []
    redirect_params = ["redirect", "redirect_url", "url", "next", "return_to", "return", "dest", "target", "goto", "r"]

    endpoints = _load_endpoints(out_dir)

    # Also search JS files for redirect parameter references
    target_base = (args.target if "://" in args.target else f"https://{args.target}").rstrip("/")
    js_dir = out_dir / "js"
    if js_dir.exists():
        for js_file in list(js_dir.rglob("*.js"))[:10]:
            try:
                content = js_file.read_text(encoding="utf-8", errors="ignore")
                for p in redirect_params:
                    if f"?{p}=" in content or f"&{p}=" in content:
                        findings.append({
                            "title": f"Candidate Redirect Parameter '{p}' in {js_file.name}",
                            "severity": "LOW",
                            "url": f"{target_base}/{js_file.name}",
                            "cwe": "CWE-601",
                            "evidence": f"Parameter '{p}' observed in client-side navigation logic.",
                            "notes": "Potential client-side open redirect or redirect parameter detected.",
                            "status": "candidate",
                            "validation_status": "unverified"
                        })
                        if len(findings) >= 5:
                            break
            except Exception:
                continue
            if len(findings) >= 5:
                break

    # Test candidate endpoints
    candidate_eps = [e for e in endpoints if any(f"{p}=" in e.lower() for p in redirect_params)]
    req_budget = _parse_budget(10, 10)

    if req_budget > 0 and candidate_eps:
        try:
            validator = ScopeValidator(args.target, target_dir=Path(args.target_dir))
            client = ScopedHttpClient(
                target=args.target,
                max_requests=req_budget,
                delay_seconds=0.2,
                scope_validator=validator,
            )
            test_dest = "https://moros-redirect-test.example"
            base_url = client.base_url.rstrip("/")

            for ep in candidate_eps[:5]:
                full_url = ep if "://" in ep else f"{base_url}/{ep.lstrip('/')}"
                probe_url = _inject_redirect_dest(full_url, redirect_params, test_dest)
                resp = client.get(probe_url)
                loc = resp.get("headers", {}).get("Location", resp.get("headers", {}).get("location", ""))
                if "moros-redirect-test.example" in loc.lower():
                    findings.append({
                        "title": f"Unvalidated Open Redirect: {ep}",
                        "severity": "MEDIUM",
                        "url": probe_url,
                        "cwe": "CWE-601",
                        "evidence": f"Location: {loc}",
                        "notes": f"Server redirected to untrusted destination '{loc}'.",
                        "status": "candidate",
                        "validation_status": "unverified"
                    })
                if resp.get("status") in ("budget_exhausted", "blocked_scope"):
                    break
        except ValueError as e:
            print(f"Open redirect check skipped (invalid target/scope): {e}")
        except Exception as e:
            print(f"Open redirect check notice: {e}")

    out_file.write_text(json.dumps({
        "target": args.target,
        "skill": "open-redirect",
        "title": "Open Redirect Hunter",
        "findings": findings
    }, indent=2), encoding="utf-8")
    print(f"Open Redirect scan completed: {len(findings)} candidates found.")


if __name__ == "__main__":
    main()
