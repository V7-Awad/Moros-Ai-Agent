#!/usr/bin/env python3
"""
poc_generator.py — Automated Proof-of-Concept (PoC) Script Generator for Moros AI.

Generates reproducible cURL bash scripts (.sh) and standalone Python reproduction
scripts (.py) for all discovered candidate vulnerabilities.
"""

import hashlib
import json
import re
import urllib.parse
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

try:
    from llm_client import redact_secrets
except ImportError:
    from tools.llm_client import redact_secrets

try:
    from finding_dedupe import resolve_finding_lifecycle
except ImportError:
    from tools.finding_dedupe import resolve_finding_lifecycle

_SUPPORTED_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})
_SENSITIVE_HEADER_KEYWORDS = (
    "auth", "token", "secret", "key", "cookie", "session", "password", "credential",
)
_SENSITIVE_PARAM_KEYS = frozenset({
    "token", "api_key", "apikey", "secret", "password", "passwd", "pass",
    "access_token", "refresh_token", "id_token", "auth", "session", "session_id",
    "jwt", "key", "sig", "signature", "client_secret", "private_key", "credential",
})


def _shell_single_quote(value: str) -> str:
    return "'" + str(value).replace("'", "'\"'\"'") + "'"


def _redact_header_value(name: str, value: Any) -> str:
    k_low = str(name or "").strip().lower()
    val_str = str(value or "")
    if any(kw in k_low for kw in _SENSITIVE_HEADER_KEYWORDS):
        if k_low == "authorization":
            low = val_str.strip().lower()
            if low.startswith("bearer "):
                return "Bearer <REDACTED_TOKEN>"
            if low.startswith("basic "):
                return "Basic <REDACTED_CREDENTIALS>"
            return "<REDACTED_AUTH>"
        if k_low in ("cookie", "set-cookie"):
            parts = []
            for seg in val_str.split(";"):
                seg = seg.strip()
                if "=" in seg:
                    cname, _ = seg.split("=", 1)
                    parts.append(f"{cname.strip()}=<REDACTED_COOKIE>")
                elif seg:
                    parts.append("<REDACTED_COOKIE>")
            return "; ".join(parts) if parts else "<REDACTED_COOKIE>"
        return "<REDACTED_SECRET>"
    return redact_secrets(val_str)


def _redact_mapping(obj: Any) -> Any:
    if isinstance(obj, dict):
        cleaned: Dict[str, Any] = {}
        for k, v in obj.items():
            k_low = str(k).strip().lower()
            if k_low in _SENSITIVE_PARAM_KEYS or any(kw in k_low for kw in ("secret", "password", "passwd", "token", "api_key", "apikey", "private_key", "credential")):
                cleaned[k] = "<REDACTED_SECRET>"
            else:
                cleaned[k] = _redact_mapping(v)
        return cleaned
    if isinstance(obj, list):
        return [_redact_mapping(item) for item in obj]
    if isinstance(obj, str):
        return redact_secrets(obj)
    return obj


def _redact_url_and_merge_params(raw_url: str, params: Optional[Dict[str, Any]]) -> str:
    parsed = urllib.parse.urlsplit(str(raw_url or ""))
    netloc = parsed.netloc
    if "@" in netloc and parsed.hostname:
        host_part = parsed.hostname
        if parsed.port is not None:
            host_part = f"{host_part}:{parsed.port}"
        netloc = f"<REDACTED_USER>:<REDACTED_PASSWORD>@{host_part}"

    query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    if isinstance(params, dict) and params:
        override_keys = {str(k) for k in params.keys()}
        query_pairs = [(k, v) for k, v in query_pairs if k not in override_keys]
        for k, v in params.items():
            if isinstance(v, (list, tuple)):
                for item in v:
                    query_pairs.append((str(k), str(item)))
            else:
                query_pairs.append((str(k), str(v)))

    redacted_pairs = []
    for k, v in query_pairs:
        if k.strip().lower() in _SENSITIVE_PARAM_KEYS:
            redacted_pairs.append((k, "<REDACTED_TOKEN>"))
        else:
            redacted_pairs.append((k, redact_secrets(v)))

    new_query = urllib.parse.urlencode(redacted_pairs, doseq=True)
    rebuilt = urllib.parse.urlunsplit((parsed.scheme, netloc, parsed.path, new_query, parsed.fragment))
    return redact_secrets(rebuilt)


class PoCGenerator:
    def __init__(self, target: str, output_dir: Path):
        self.target = target
        self.output_dir = Path(output_dir)
        self.pocs_dir = self.output_dir / "pocs"
        self.pocs_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def is_poc_eligible(finding: Dict[str, Any]) -> bool:
        """Return True when finding is machine-confirmed or human-validated."""
        if not isinstance(finding, dict):
            return False
        status, val_status = resolve_finding_lifecycle(finding)
        return status in ("confirmed", "validated") or val_status in ("confirmed", "validated")

    def _sanitize_name(self, text: str) -> str:
        clean = re.sub(r"[^a-zA-Z0-9_\-]", "_", text.lower()).strip("_")
        return clean[:45]

    def generate_for_findings(
        self,
        findings: Iterable[Dict[str, Any]],
        custom_headers: Optional[Dict[str, str]] = None,
        include_candidates: bool = False,
    ) -> List[Dict[str, Any]]:
        """Generate PoCs for confirmed and human-validated findings (and optionally candidates)."""
        generated: List[Dict[str, Any]] = []
        for finding in findings:
            if not isinstance(finding, dict) or not finding.get("url"):
                continue
            if not include_candidates and not self.is_poc_eligible(finding):
                continue
            pocs = self.generate_poc(finding, custom_headers=custom_headers)
            finding["poc_sh"] = pocs["poc_sh"]
            finding["poc_py"] = pocs["poc_py"]
            generated.append({"finding": finding.get("title"), **pocs})
        return generated

    def generate_poc(self, finding: Dict[str, Any], custom_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Generate both .sh and .py reproduction files for a finding (GET/POST/PUT/headers/params/body)."""
        title = str(finding.get("title", "security-finding"))
        vr = finding.get("validation_result") if isinstance(finding.get("validation_result"), dict) else {}
        vr_req = vr.get("request") if isinstance(vr.get("request"), dict) else {}

        raw_url = str(
            finding.get("url")
            or vr_req.get("url")
            or finding.get("affected_url")
            or finding.get("endpoint")
            or f"https://{self.target}"
        )
        raw_method = str(
            finding.get("method")
            or finding.get("http_method")
            or vr_req.get("method")
            or "GET"
        ).strip().upper()
        method = raw_method if raw_method in _SUPPORTED_METHODS else "GET"

        params = finding.get("params") or finding.get("query_params") or vr_req.get("params")
        url = _redact_url_and_merge_params(raw_url, params if isinstance(params, dict) else None)

        severity = str(finding.get("severity", "MEDIUM"))
        cwe = str(finding.get("cwe", "CWE-200"))
        notes = redact_secrets(str(finding.get("notes", "")))
        evidence = redact_secrets(str(finding.get("evidence", "")))
        lifecycle_status, val_status = resolve_finding_lifecycle(finding)
        if lifecycle_status == "candidate" and finding.get("validation_status"):
            val_status = str(finding.get("validation_status"))

        # Merge headers: finding headers -> validation_result headers -> custom_headers
        raw_headers: Dict[str, Any] = {}
        for src in (finding.get("headers"), finding.get("request_headers"), vr_req.get("headers"), custom_headers):
            if isinstance(src, dict):
                raw_headers.update(src)

        headers: Dict[str, str] = {
            str(k): _redact_header_value(str(k), v)
            for k, v in raw_headers.items()
        }
        if not headers:
            headers = {"User-Agent": "MorosAI-Security-Auditor/1.0"}

        # Extract and redact request body / json_body / data
        raw_json_body = finding.get("json_body") if finding.get("json_body") is not None else vr_req.get("json_body")
        if raw_json_body is None and finding.get("json") is not None:
            raw_json_body = finding.get("json")
        raw_body = finding.get("body") if finding.get("body") is not None else finding.get("data")
        if raw_body is None:
            raw_body = vr_req.get("body") if vr_req.get("body") is not None else vr_req.get("data")

        body_str: Optional[str] = None
        has_ct = any(k.lower() == "content-type" for k in headers)
        if raw_json_body is not None:
            redacted_json = _redact_mapping(raw_json_body)
            body_str = json.dumps(redacted_json, ensure_ascii=False)
            if not has_ct:
                headers["Content-Type"] = "application/json"
        elif isinstance(raw_body, dict):
            redacted_dict = _redact_mapping(raw_body)
            ct_val = next((v.lower() for k, v in headers.items() if k.lower() == "content-type"), "")
            if "json" in ct_val:
                body_str = json.dumps(redacted_dict, ensure_ascii=False)
            else:
                body_str = urllib.parse.urlencode(
                    {str(k): str(v) for k, v in redacted_dict.items()},
                    doseq=True,
                )
                if not has_ct:
                    headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif raw_body is not None and str(raw_body) != "":
            raw_body_text = str(raw_body)
            try:
                parsed_json = json.loads(raw_body_text)
                if isinstance(parsed_json, (dict, list)):
                    body_str = json.dumps(_redact_mapping(parsed_json), ensure_ascii=False)
                else:
                    body_str = redact_secrets(raw_body_text)
            except (json.JSONDecodeError, TypeError):
                body_str = redact_secrets(raw_body_text)

        # Unique finding identifier (preserve GET signature compatibility)
        unique_sig = f"{title}_{raw_url}" if method == "GET" else f"{method}_{title}_{raw_url}"
        sig_hash = hashlib.sha256(unique_sig.encode("utf-8")).hexdigest()[:8]
        base_name = f"poc_{self._sanitize_name(title)}_{sig_hash}"

        sh_path = self.pocs_dir / f"{base_name}.sh"
        py_path = self.pocs_dir / f"{base_name}.py"

        header_curl_lines = [
            f"  -H {_shell_single_quote(f'{k}: {v}')} \\"
            for k, v in headers.items()
        ]
        if body_str is not None:
            header_curl_lines.append(f"  --data-raw {_shell_single_quote(body_str)} \\")
        header_curl_block = "\n".join(header_curl_lines)

        # 1. Generate cURL PoC (.sh)
        sh_content = f"""#!/usr/bin/env bash
# ==============================================================================
# Moros AI Auto-Generated Proof-of-Concept (PoC)
# Target: {self.target}
# Vulnerability: {title}
# Method: {method} | Severity: {severity} | CWE: {cwe} | Status: {lifecycle_status} ({val_status})
# Details: {notes}
# ==============================================================================

echo "[*] Reproducing {title} ({method}) on {url}..."

curl -i -s -k -X {method} {_shell_single_quote(url)} \\
{header_curl_block}
  -w "\\n[*] Response HTTP Code: %{{http_code}} | Time: %{{time_total}}s\\n"

echo "[+] Reproduction request finished."
"""
        sh_path.write_text(sh_content, encoding="utf-8")

        # 2. Generate Python PoC (.py)
        body_literal = json.dumps(body_str) if body_str is not None else "None"
        py_content = f'''#!/usr/bin/env python3
"""
==============================================================================
Moros AI Auto-Generated Proof-of-Concept (PoC)
Target: {self.target}
Vulnerability: {title}
Method: {method} | Severity: {severity} | CWE: {cwe} | Status: {lifecycle_status} ({val_status})
Evidence: {evidence}
Notes: {notes}
==============================================================================
"""

import ssl
import sys
import urllib.request
import urllib.error

TARGET_URL = {json.dumps(url)}
METHOD = {json.dumps(method)}
HEADERS = {json.dumps(headers, indent=4)}
BODY = {body_literal}

def reproduce():
    print(f"[*] Sending {{METHOD}} reproduction request to: {{TARGET_URL}}")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    payload_bytes = BODY.encode("utf-8") if BODY is not None else None
    req = urllib.request.Request(TARGET_URL, data=payload_bytes, headers=HEADERS, method=METHOD)
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
            "method": method,
            "status": lifecycle_status,
        }
