#!/usr/bin/env python3
"""
run.py — Executable Runner for XXE Detection in Moros AI.
"""

import argparse
import json
from pathlib import Path


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
    return [ep for ep in endpoints if any(k in ep.lower() for k in ["xml", "soap", "saml", "import"])]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--target-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    findings_dir = out_dir / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)
    out_file = findings_dir / "candidates-xxe-detect.json"

    endpoints = _load_endpoints(out_dir)
    target_base = (args.target if "://" in args.target else f"https://{args.target}").rstrip("/")

    findings = []
    # If XML endpoint discovered, record candidate for agent ReAct inspection
    for ep in endpoints[:5]:
        full_url = ep if "://" in ep else f"{target_base}/{ep.lstrip('/')}"
        findings.append({
            "title": f"XML-Accepting Endpoint Detected: {ep[:50]}",
            "severity": "LOW",
            "url": full_url,
            "cwe": "CWE-611",
            "evidence": f"Endpoint {ep} identified as XML/SOAP consumer.",
            "notes": "Candidate for authenticated XXE entity resolution testing.",
            "status": "candidate",
            "validation_status": "unverified",
            "curl": f"curl -s -i '{full_url}'",
        })

    out_file.write_text(json.dumps({"findings": findings, "count": len(findings)}, indent=2), encoding="utf-8")
    print(f"XXE Detection completed: {len(findings)} candidate findings recorded.")


if __name__ == "__main__":
    main()
