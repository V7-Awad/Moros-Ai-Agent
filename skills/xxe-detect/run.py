#!/usr/bin/env python3
"""
run.py — Executable Runner for XXE Detection in Moros AI.
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


def _parse_budget(default: int, cap: int) -> int:
    raw = os.environ.get("MOROS_HTTP_REQUESTS_REMAINING")
    if raw is None or not raw.strip():
        return min(default, cap)
    try:
        return min(max(0, int(raw.strip())), cap)
    except ValueError:
        return min(default, cap)


_STATIC_EXTS = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".woff", ".woff2", ".ico", ".map")


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
    return [
        ep for ep in endpoints
        if any(k in ep.lower() for k in ["xml", "soap", "saml", "import"])
        and not ep.lower().split("?", 1)[0].endswith(_STATIC_EXTS)
    ]


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
    findings = []
    req_budget = _parse_budget(10, 10)

    try:
        validator = ScopeValidator(args.target, target_dir=Path(args.target_dir))
        if req_budget > 0 and endpoints:
            get_client = ScopedHttpClient(
                target=args.target,
                max_requests=req_budget,
                delay_seconds=0.2,
                scope_validator=validator,
            )
            base_url = get_client.base_url.rstrip("/")
            cm = CheckpointManager(args.target, Path(args.target_dir)) if is_gated_post_enabled() else None
            post_client = None
            post_used = 0
            allow_headers = getattr(validator, "policy", {}).get("allow_authentication", True)
            oob_url = (os.environ.get("MOROS_OOB_URL") or os.environ.get("MOROS_CALLBACK_URL") or "").strip()

            for ep in endpoints[:5]:
                if get_client.request_count + post_used >= req_budget:
                    break
                full_url = ep if "://" in ep else f"{base_url}/{ep.lstrip('/')}"
                resp = get_client.get(full_url)
                if resp.get("status") in ("budget_exhausted", "blocked_scope", "blocked"):
                    break
                status_code = resp.get("status_code", 0)
                if status_code == 404:
                    continue

                probe_recorded = False
                if cm is not None and (get_client.request_count + post_used < req_budget):
                    cp_type = "XXE Benign Inline Entity Probe"
                    reason = f"Send non-destructive inline XML entity check to {full_url}"
                    if check_checkpoint_approval(cm, cp_type, full_url, method="POST", reason=reason, risk_level="MEDIUM"):
                        if post_client is None:
                            remaining = max(1, req_budget - get_client.request_count)
                            post_client = ScopedHttpClient(
                                target=args.target,
                                max_requests=remaining,
                                delay_seconds=0.2,
                                scope_validator=validator,
                                allow_state_changing=True,
                                approval_callback=lambda m, u, b: check_checkpoint_approval(
                                    cm, cp_type, u, method=m, reason=reason, risk_level="MEDIUM"
                                ),
                            )
                        canary_xml = (
                            '<?xml version="1.0" encoding="UTF-8"?>'
                            '<!DOCTYPE probe [<!ENTITY moros "moros_entity_resolved">]>'
                            "<probe>&moros;</probe>"
                        )
                        post_resp = post_client.post(
                            full_url,
                            data=canary_xml,
                            headers={"Content-Type": "application/xml"} if allow_headers else None,
                        )
                        post_used = post_client.request_count
                        if post_resp.get("status") == "response":
                            p_code = post_resp.get("status_code", 0)
                            p_body = post_resp.get("body", "")
                            if p_code in (200, 400, 500) and "moros_entity_resolved" in p_body and "&moros;" not in p_body:
                                findings.append({
                                    "title": f"XML Entity Resolution Enabled (Potential XXE): {ep[:50]}",
                                    "severity": "HIGH",
                                    "url": full_url,
                                    "cwe": "CWE-611",
                                    "evidence": f"POST HTTP {p_code} resolved benign inline entity: {p_body[:180]}",
                                    "notes": "HITL-approved non-destructive XML entity probe resolved an inline DOCTYPE entity.",
                                    "status": "candidate",
                                    "validation_status": "unverified",
                                    "curl": f"curl -s -i '{full_url}'",
                                })
                                probe_recorded = True
                        if oob_url and (get_client.request_count + post_used < req_budget):
                            oob_token = f"xxe-{len(findings)+1}-{abs(hash(full_url)) % 100000:05d}"
                            canary_dtd = f"{oob_url.rstrip('/')}/{oob_token}"
                            oob_xml = (
                                '<?xml version="1.0" encoding="UTF-8"?>'
                                f'<!DOCTYPE probe SYSTEM "{canary_dtd}">'
                                "<probe>moros-oob-check</probe>"
                            )
                            post_client.post(
                                full_url,
                                data=oob_xml,
                                headers={"Content-Type": "application/xml"} if allow_headers else None,
                            )
                            post_used = post_client.request_count

                if not probe_recorded and status_code in (200, 400, 405, 415):
                    ct = resp.get("headers", {}).get("content-type", "")
                    findings.append({
                        "title": f"XML-Accepting Endpoint Detected: {ep[:50]}",
                        "severity": "LOW",
                        "url": full_url,
                        "cwe": "CWE-611",
                        "callback_listener_configured": bool(oob_url),
                        "oob_callback_base": oob_url or None,
                        "evidence": f"Safe GET probe returned HTTP {status_code} (content-type={ct or 'unknown'}).",
                        "notes": "Candidate for HITL-approved XML entity resolution testing.",
                        "status": "candidate",
                        "validation_status": "unverified",
                        "curl": f"curl -s -i '{full_url}'",
                    })
        elif endpoints:
            # Passive offline discovery when request budget is 0, still validating target URL format.
            probe_client = ScopedHttpClient(target=args.target, max_requests=1, scope_validator=validator)
            target_base = probe_client.base_url.rstrip("/")
            for ep in endpoints[:5]:
                full_url = ep if "://" in ep else f"{target_base}/{ep.lstrip('/')}"
                findings.append({
                    "title": f"XML-Accepting Endpoint Detected: {ep[:50]}",
                    "severity": "LOW",
                    "url": full_url,
                    "cwe": "CWE-611",
                    "evidence": f"Endpoint {ep} identified as XML/SOAP consumer (passive mode).",
                    "notes": "Candidate for authenticated XXE entity resolution testing.",
                    "status": "candidate",
                    "validation_status": "unverified",
                    "curl": f"curl -s -i '{full_url}'",
                })
    except ValueError as e:
        print(f"XXE detection skipped (invalid target/scope): {e}")
    except Exception as e:
        print(f"XXE detection notice: {e}")

    out_file.write_text(json.dumps({"findings": findings, "count": len(findings)}, indent=2), encoding="utf-8")
    print(f"XXE Detection completed: {len(findings)} candidate findings recorded.")


if __name__ == "__main__":
    main()
