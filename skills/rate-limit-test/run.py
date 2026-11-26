#!/usr/bin/env python3
"""
run.py — Executable Runner for Rate Limiting Tests in Moros AI.
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
from scoped_http import ScopedHttpClient, check_checkpoint_approval, is_gated_post_enabled
from checkpoint_manager import CheckpointManager


_RATE_LIMIT_HEADER_KEYS = {
    "retry-after",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "ratelimit-limit",
    "ratelimit-remaining",
    "ratelimit-reset",
}


def _has_rate_limit_headers(headers: dict) -> bool:
    if not isinstance(headers, dict):
        return False
    return any(str(k).lower() in _RATE_LIMIT_HEADER_KEYS for k in headers)


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
    out_file = findings_dir / "candidates-rate-limit-test.json"

    endpoints = _load_endpoints(out_dir)

    auth_eps = [e for e in endpoints if any(k in e.lower() for k in ["login", "signin", "auth", "token", "password", "otp"])]
    if not auth_eps:
        auth_eps = ["/login", "/api/login"]

    findings = []
    req_budget = _parse_budget(15, 15)

    if req_budget > 0:
        try:
            validator = ScopeValidator(args.target, target_dir=Path(args.target_dir))
            client = ScopedHttpClient(
                target=args.target,
                max_requests=req_budget,
                delay_seconds=0.1,
                scope_validator=validator,
            )
            base_url = client.base_url.rstrip("/")
            cm = CheckpointManager(args.target, Path(args.target_dir)) if is_gated_post_enabled() else None
            post_client = None
            post_used = 0

            for ep in auth_eps[:2]:
                if client.request_count + post_used >= req_budget:
                    break
                full_url = ep if "://" in ep else f"{base_url}/{ep.lstrip('/')}"

                # Prefer HITL-gated POST burst when explicitly enabled and approved
                tested_post = False
                if cm is not None and (req_budget - (client.request_count + post_used)) >= 3:
                    cp_type = "Rate Limit POST Burst"
                    reason = f"Send bounded non-destructive POST burst to check rate-limiting on {full_url}"
                    if check_checkpoint_approval(cm, cp_type, full_url, method="POST", reason=reason, risk_level="LOW"):
                        tested_post = True
                        if post_client is None:
                            remaining = max(1, req_budget - client.request_count)
                            post_client = ScopedHttpClient(
                                target=args.target,
                                max_requests=remaining,
                                delay_seconds=0.1,
                                scope_validator=validator,
                                allow_state_changing=True,
                                approval_callback=lambda m, u, b: check_checkpoint_approval(
                                    cm, cp_type, u, method=m, reason=reason, risk_level="LOW"
                                ),
                            )
                        post_codes = []
                        saw_rl_headers = False
                        stopped = False
                        for _ in range(5):
                            if client.request_count + post_used >= req_budget:
                                break
                            resp = post_client.post(
                                full_url,
                                json_body={"username": "moros_ratelimit_probe", "password": "moros_invalid_probe"},
                            )
                            post_used = post_client.request_count
                            if resp.get("status") in ("budget_exhausted", "blocked_scope", "blocked"):
                                stopped = True
                                break
                            post_codes.append(resp.get("status_code", 0))
                            if _has_rate_limit_headers(resp.get("headers", {})):
                                saw_rl_headers = True
                        if (
                            len(post_codes) == 5
                            and not saw_rl_headers
                            and all(code in (200, 401, 403) for code in post_codes)
                        ):
                            findings.append({
                                "title": f"Missing Rate Limiting on {ep[:50]}",
                                "severity": "MEDIUM",
                                "url": full_url,
                                "cwe": "CWE-770",
                                "evidence": f"Bounded POST burst of 5 requests returned status codes {post_codes} without rate-limit headers.",
                                "notes": "No HTTP 429 Too Many Requests or rate-limiting headers detected on authentication POST endpoint.",
                                "status": "candidate",
                                "validation_status": "unverified",
                                "curl": f"curl -s -i -X POST '{full_url}'",
                            })
                        if stopped:
                            break

                if tested_post:
                    continue

                responses = []
                saw_rl_headers = False
                stopped = False
                for _ in range(5):
                    if client.request_count + post_used >= req_budget:
                        break
                    resp = client.get(full_url)
                    if resp.get("status") in ("budget_exhausted", "blocked_scope", "blocked"):
                        stopped = True
                        break
                    responses.append(resp.get("status_code", 0))
                    if _has_rate_limit_headers(resp.get("headers", {})):
                        saw_rl_headers = True

                # Only flag if all 5 requests returned 200/401/403 with no 429 and no rate-limit headers
                if (
                    len(responses) == 5
                    and not saw_rl_headers
                    and all(code in (200, 401, 403) for code in responses)
                ):
                    findings.append({
                        "title": f"Missing Rate Limiting on {ep[:50]}",
                        "severity": "LOW",
                        "url": full_url,
                        "cwe": "CWE-770",
                        "evidence": f"Burst of 5 GET requests returned status codes {responses} without rate-limit headers.",
                        "notes": "No HTTP 429 Too Many Requests or rate limiting headers detected on authentication endpoint.",
                        "status": "candidate",
                        "validation_status": "unverified",
                        "curl": f"curl -s -i '{full_url}'",
                    })
                if stopped:
                    break
        except ValueError as e:
            print(f"Rate Limiting test skipped (invalid target/scope): {e}")
        except Exception as e:
            print(f"Rate Limiting test notice: {e}")

    out_file.write_text(json.dumps({"findings": findings, "count": len(findings)}, indent=2), encoding="utf-8")
    print(f"Rate Limiting test completed: {len(findings)} candidate findings recorded.")


if __name__ == "__main__":
    main()
