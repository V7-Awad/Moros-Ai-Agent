#!/usr/bin/env python3
"""
poc_generator.py — Automated Proof-of-Concept (PoC) Script Generator for Moros AI.

Generates reproducible cURL bash scripts (.sh) and standalone Python reproduction
scripts (.py) for all discovered candidate vulnerabilities.
"""

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional


class PoCGenerator:
    def __init__(self, target: str, output_dir: Path):
        self.target = target
        self.output_dir = Path(output_dir)
        self.pocs_dir = self.output_dir / "pocs"
        self.pocs_dir.mkdir(parents=True, exist_ok=True)

    def _sanitize_name(self, text: str) -> str:
        clean = re.sub(r"[^a-zA-Z0-9_\-]", "_", text.lower()).strip("_")
        return clean[:45]

    def generate_poc(self, finding: Dict[str, Any], custom_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Generate both .sh and .py reproduction files for a finding."""
        title = finding.get("title", "security-finding")
        url = finding.get("url", f"https://{self.target}")
        severity = finding.get("severity", "MEDIUM")
        cwe = finding.get("cwe", "CWE-200")
        notes = finding.get("notes", "")
        evidence = finding.get("evidence", "")

        # Unique finding identifier
        unique_sig = f"{title}_{url}"
        sig_hash = hashlib.sha256(unique_sig.encode("utf-8")).hexdigest()[:8]
        base_name = f"poc_{self._sanitize_name(title)}_{sig_hash}"

        sh_path = self.pocs_dir / f"{base_name}.sh"
        py_path = self.pocs_dir / f"{base_name}.py"

        headers = custom_headers or {}
        header_curl_lines = [f"  -H '{k}: {v}' \\" for k, v in headers.items()]
        header_curl_block = "\n".join(header_curl_lines) if header_curl_lines else "  -H 'User-Agent: MorosAI-Security-Auditor/1.0' \\"

        # 1. Generate cURL PoC (.sh)
        sh_content = f"""#!/usr/bin/env bash
# ==============================================================================
# Moros AI Auto-Generated Proof-of-Concept (PoC)
# Target: {self.target}
# Vulnerability: {title}
# Severity: {severity} | CWE: {cwe}
# Details: {notes}
# ==============================================================================

echo "[*] Reproducing {title} on {url}..."

curl -i -s -k -X GET '{url}' \\
{header_curl_block}
  -w "\\n[*] Response HTTP Code: %{{http_code}} | Time: %{{time_total}}s\\n"

echo "[+] Reproduction request finished."
"""
        sh_path.write_text(sh_content, encoding="utf-8")

        # 2. Generate Python PoC (.py)
        py_content = f'''#!/usr/bin/env python3
"""
==============================================================================
Moros AI Auto-Generated Proof-of-Concept (PoC)
Target: {self.target}
Vulnerability: {title}
Severity: {severity} | CWE: {cwe}
Evidence: {evidence}
Notes: {notes}
==============================================================================
"""

import ssl
import sys
import urllib.request
import urllib.error

TARGET_URL = "{url}"
HEADERS = {json.dumps(headers or {"User-Agent": "MorosAI-Security-Auditor/1.0"}, indent=4)}

def reproduce():
    print(f"[*] Sending reproduction request to: {{TARGET_URL}}")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(TARGET_URL, headers=HEADERS, method="GET")
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
            print(f"[+] HTTP Status: {{resp.status}}")
            print(f"[+] Headers: {{dict(resp.headers)}}")
            body = resp.read(2048).decode("utf-8", errors="replace")
            print(f"[+] Body Preview:\\n{{body}}")
            print("[+] Reproduction successful.")
    except urllib.error.HTTPError as e:
        print(f"[!] Target returned HTTP {{e.code}}: {{e.reason}}")
        body = e.read(1024).decode("utf-8", errors="replace")
        print(f"[!] Error body: {{body}}")
    except Exception as e:
        print(f"[-] Connection error: {{e}}")

if __name__ == "__main__":
    reproduce()
'''
        py_path.write_text(py_content, encoding="utf-8")

        rel_sh = f"output/pocs/{sh_path.name}"
        rel_py = f"output/pocs/{py_path.name}"

        return {
            "poc_sh": rel_sh,
            "poc_py": rel_py,
            "poc_sh_abs": str(sh_path),
            "poc_py_abs": str(py_path),
        }
