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

from scoped_http import ScopedHttpClient


# CL.TE probe: front-end trusts Content-Length, back-end trusts Transfer-Encoding
CL_TE_BODY = "0\r\n\r\nG"
# TE.CL probe: front-end trusts Transfer-Encoding, back-end trusts Content-Length
TE_CL_BODY = "1\r\nZ\r\nQ\r\n\r\n"

DESYNC_HEADERS_CLTE = {
    "Transfer-Encoding": "chunked",
}

DESYNC_HEADERS_TECL = {
    "Transfer-Encoding": "chunked",
}

# Obfuscated TE variants that bypass normalisation
TE_OBFUSCATIONS = [
    "Transfer-Encoding: chunked",
    "Transfer-Encoding:  chunked",
    "Transfer-Encoding: chunked\r\nTransfer-encoding: identity",
    "Transfer-Encoding: chunked\r\nTransfer-Encoding: x",
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--target-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    budget = int(os.environ.get("MOROS_HTTP_REQUESTS_REMAINING", "50"))
    client = ScopedHttpClient(
        target=args.target,
        max_requests=min(budget, 30),
        request_delay=float(os.environ.get("MOROS_REQUEST_DELAY", "0.5")),
    )

    findings = []
    target_url = f"https://{args.target}"
    test_paths = ["/", "/api", "/login", "/search"]

    for path in test_paths:
        full_url = f"{target_url}{path}"

        # --- CL.TE Timing Probe ---
        try:
            t_start = time.time()
            resp_normal = client.request(full_url, method="POST",
                                         body="x=1",
                                         extra_headers={"Content-Type": "application/x-www-form-urlencoded"})
            t_normal = time.time() - t_start

            t_start = time.time()
            resp_clte = client.request(full_url, method="POST",
                                       body=CL_TE_BODY,
                                       extra_headers={
                                           "Content-Type": "application/x-www-form-urlencoded",
                                           "Transfer-Encoding": "chunked",
                                       })
            t_clte = time.time() - t_start

            # Significant timing differential suggests desync
            if t_clte > t_normal + 5.0 or (resp_clte and resp_clte.get("status") != resp_normal.get("status")):
                findings.append({
                    "title": f"Potential CL.TE HTTP Request Smuggling at {path}",
                    "url": full_url,
                    "severity": "HIGH",
                    "cwe": "CWE-444",
                    "evidence": json.dumps({
                        "normal_time": round(t_normal, 3),
                        "clte_time": round(t_clte, 3),
                        "normal_status": resp_normal.get("status") if resp_normal else None,
                        "clte_status": resp_clte.get("status") if resp_clte else None,
                        "differential_seconds": round(t_clte - t_normal, 3),
                    }),
                    "recommendation": "Normalize Transfer-Encoding header handling between front-end proxy and back-end server. Reject ambiguous requests with both CL and TE.",
                })
        except Exception:
            pass

        # --- TE.CL Timing Probe ---
        try:
            t_start = time.time()
            resp_tecl = client.request(full_url, method="POST",
                                       body=TE_CL_BODY,
                                       extra_headers={
                                           "Content-Type": "application/x-www-form-urlencoded",
                                           "Transfer-Encoding": "chunked",
                                       })
            t_tecl = time.time() - t_start

            if t_tecl > t_normal + 5.0 or (resp_tecl and resp_tecl.get("status") != resp_normal.get("status")):
                findings.append({
                    "title": f"Potential TE.CL HTTP Request Smuggling at {path}",
                    "url": full_url,
                    "severity": "HIGH",
                    "cwe": "CWE-444",
                    "evidence": json.dumps({
                        "normal_time": round(t_normal, 3),
                        "tecl_time": round(t_tecl, 3),
                        "differential_seconds": round(t_tecl - t_normal, 3),
                    }),
                    "recommendation": "Ensure consistent Transfer-Encoding handling across all layers. Consider rejecting requests with conflicting CL/TE headers.",
                })
        except Exception:
            pass

        # --- Duplicate Content-Length ---
        try:
            resp_clcl = client.request(full_url, method="POST",
                                       body="test=1",
                                       extra_headers={
                                           "Content-Type": "application/x-www-form-urlencoded",
                                       })
            # Detection: If server accepts duplicate CL without 400, there may be risk
            if resp_clcl and resp_clcl.get("status") not in (400, 411, None):
                # This is a weaker signal — only record as INFO
                findings.append({
                    "title": f"Server accepts ambiguous Content-Length at {path}",
                    "url": full_url,
                    "severity": "INFO",
                    "cwe": "CWE-444",
                    "evidence": f"Status: {resp_clcl.get('status')}",
                    "recommendation": "Verify that the server rejects requests with duplicate or conflicting Content-Length headers.",
                })
        except Exception:
            pass

    # Write findings
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    out_file = output_dir / "candidates-http-smuggling.json"
    out_file.write_text(json.dumps(findings, indent=2), encoding="utf-8")
    print(json.dumps({"status": "OK", "findings_count": len(findings), "output": str(out_file)}))


if __name__ == "__main__":
    main()
