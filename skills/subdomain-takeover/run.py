#!/usr/bin/env python3
"""
run.py — Executable Runner for Subdomain Takeover in Moros AI.
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
    out_file = findings_dir / "candidates-subdomain-takeover.json"

    subdomains = []
    seen_subs = set()
    for sub_rel in ["recon/subdomains.txt", "recon/subdomains-all.txt", "recon/subdomains-passive.txt"]:
        sub_file = out_dir / sub_rel
        if sub_file.exists():
            try:
                for line in sub_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                    sub = line.strip()
                    if sub and sub not in seen_subs:
                        seen_subs.add(sub)
                        subdomains.append(sub)
            except OSError:
                pass

    takeover_fingerprints = [
        ("github", "There isn't a GitHub Pages site here"),
        ("heroku", "There's nothing here, yet"),
        ("aws-s3", "The specified bucket does not exist"),
        ("aws-s3", "NoSuchBucket"),
        ("zendesk", "Help Center Closed"),
        ("fastly", "Fastly error: unknown domain"),
    ]

    findings = []
    req_budget = _parse_budget(15, 15)

    if req_budget > 0 and subdomains:
        try:
            validator = ScopeValidator(args.target, target_dir=Path(args.target_dir))
            client = ScopedHttpClient(
                target=args.target,
                max_requests=req_budget,
                delay_seconds=0.2,
                scope_validator=validator,
            )

            for sub in subdomains[:10]:
                target_url = sub if "://" in sub else f"https://{sub}"
                resp = client.get(target_url)
                if resp.get("status") in ("budget_exhausted", "blocked_scope"):
                    break
                if resp.get("status") != "response":
                    continue
                body = resp.get("body", "")

                for provider, fingerprint in takeover_fingerprints:
                    if fingerprint.lower() in body.lower():
                        findings.append({
                            "title": f"Subdomain Takeover on {sub} ({provider})",
                            "severity": "HIGH",
                            "url": target_url,
                            "cwe": "CWE-284",
                            "evidence": body[:200],
                            "notes": f"Detected dangling DNS record matching signature '{fingerprint}' for provider '{provider}'.",
                            "status": "candidate",
                            "validation_status": "unverified",
                            "curl": f"curl -s -i '{target_url}'",
                        })
                        break
        except ValueError as e:
            print(f"Subdomain Takeover audit skipped (invalid target/scope): {e}")
        except Exception as e:
            print(f"Subdomain Takeover audit notice: {e}")

    out_file.write_text(json.dumps({"findings": findings, "count": len(findings)}, indent=2), encoding="utf-8")
    print(f"Subdomain Takeover audit completed: {len(findings)} candidate findings recorded.")


if __name__ == "__main__":
    main()
