#!/usr/bin/env python3
"""
sarif_exporter.py — Standard OASIS SARIF 2.1.0 Exporter for Moros AI.

Generates GitHub Code Scanning compatible SARIF 2.1.0 documents from Moros AI
findings for direct integration with CI/CD pipelines (github/codeql-action/upload-sarif),
ASPM platforms, and enterprise security dashboards.

Schema: SARIF 2.1.0 (OASIS)
https://json.schemastore.org/sarif-2.1.0.json
"""

import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("sarif-exporter")

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "Moros AI"
TOOL_INFORMATION_URI = "https://github.com/V7-Awad/Moros-Ai-Agent"

_SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
    "informational": "note",
}

_SEVERITY_TO_SCORE = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "3.0",
    "info": "1.0",
}

_CWE_TO_STRIDE: Dict[str, Tuple[str, ...]] = {
    # Spoofing — authentication / identity
    "287": ("S",),
    "290": ("S",),
    "306": ("S", "E"),
    "384": ("S",),
    "521": ("S",),
    "798": ("S", "I"),
    # Tampering — integrity
    "20": ("T",),
    "78": ("T", "E"),
    "79": ("T", "I"),
    "89": ("T",),
    "94": ("T", "E"),
    "352": ("T", "S"),
    "362": ("T", "E"),  # Race condition
    "434": ("T",),
    "502": ("T", "E"),
    "918": ("T", "I"),  # SSRF
    # Repudiation — audit / logging
    "117": ("R",),
    "778": ("R",),
    # Information disclosure — confidentiality
    "200": ("I",),
    "209": ("I",),
    "319": ("I",),
    "538": ("I",),
    # Denial of service — availability
    "400": ("D",),
    "770": ("D",),  # Rate limiting
    # Elevation of privilege — authorization
    "269": ("E",),
    "284": ("E",),
    "285": ("E",),
    "639": ("E",),  # IDOR
    "862": ("E",),
    "863": ("E",),
}

_DEFAULT_STRIDE_LEGS: Tuple[str, ...] = ("T", "I")


def _extract_cwe(finding: Dict[str, Any]) -> str:
    """Extract or infer CWE identifier from finding."""
    cwe = finding.get("cwe") or finding.get("cwe_id")
    if cwe:
        digits = "".join(c for c in str(cwe) if c.isdigit())
        if digits:
            return f"CWE-{digits}"

    # Infer from title or skill
    title = str(finding.get("title", "")).lower()
    skill = str(finding.get("skill", "")).lower()

    if "xss" in title or "xss" in skill or "cross-site scripting" in title or "cross site scripting" in title:
        return "CWE-79"
    elif "ssrf" in title or "ssrf" in skill or "server-side request forgery" in title or "server side request forgery" in title or "request forgery" in title:
        return "CWE-918"
    elif "secret" in title or "credential" in title or "token" in title or "api key" in title:
        return "CWE-798"
    elif "race" in title or "race" in skill or "concurrency" in title:
        return "CWE-362"
    elif "rate limit" in title or "rate-limit" in skill:
        return "CWE-770"
    elif "auth" in title or "bypass" in title:
        return "CWE-306"
    elif "idor" in title or "access control" in title:
        return "CWE-639"
    elif "disclosure" in title or "leak" in title:
        return "CWE-200"
    
    return "CWE-200"


def _normalize_severity(sev_str: Any) -> str:
    s = str(sev_str).lower()
    if "critical" in s:
        return "critical"
    if "high" in s:
        return "high"
    if "medium" in s:
        return "medium"
    if "low" in s:
        return "low"
    return "info"


def _stride_legs(cwe_id: str) -> Tuple[str, ...]:
    digits = "".join(c for c in cwe_id if c.isdigit())
    return _CWE_TO_STRIDE.get(digits, _DEFAULT_STRIDE_LEGS)


def _build_rule(rule_id: str, finding: Dict[str, Any]) -> Dict[str, Any]:
    title = finding.get("title") or rule_id
    cwe_id = _extract_cwe(finding)
    severity_norm = _normalize_severity(finding.get("severity", "medium"))
    level = _SEVERITY_TO_LEVEL.get(severity_norm, "warning")
    score = _SEVERITY_TO_SCORE.get(severity_norm, "5.5")

    legs = _stride_legs(cwe_id)
    tags = ["security", f"external/cwe/{cwe_id.lower()}"]
    for leg in legs:
        tags.append(f"stride:{leg}")

    desc = finding.get("notes") or finding.get("description") or title

    return {
        "id": rule_id,
        "name": re.sub(r"[^a-zA-Z0-9_-]", "_", title),
        "shortDescription": {"text": title},
        "fullDescription": {"text": desc},
        "defaultConfiguration": {"level": level},
        "help": {
            "text": f"Vulnerability: {title}\nCWE: {cwe_id}\nSeverity: {severity_norm.upper()}\n\nRemediation:\n{finding.get('remediation', 'Sanitize and validate inputs, enforce strict server-side authorization controls.')}",
            "markdown": f"### {title}\n\n**CWE:** `{cwe_id}` | **Severity:** `{severity_norm.upper()}`\n\n#### Description\n{desc}\n\n#### Remediation\n{finding.get('remediation', 'Implement strict server-side validation and authorization gates.')}"
        },
        "properties": {
            "security-severity": score,
            "tags": tags,
            "cwe": [cwe_id],
        }
    }


def _build_locations(finding: Dict[str, Any], target: str) -> List[Dict[str, Any]]:
    locations = []
    url = finding.get("url") or finding.get("affected_url") or finding.get("target")

    if url and str(url).startswith(("http://", "https://")):
        locations.append({
            "logicalLocations": [
                {
                    "name": str(url),
                    "kind": "endpoint",
                    "fullyQualifiedName": str(url)
                }
            ],
            "physicalLocation": {
                "artifactLocation": {
                    "uri": "SECURITY.md",
                    "uriBaseId": "%SRCROOT%"
                },
                "region": {
                    "startLine": 1,
                    "startColumn": 1
                }
            }
        })
    elif url and not str(url).startswith(("http://", "https://")):
        # Relative file path (e.g. js file)
        clean_path = str(url).replace("\\", "/").lstrip("/")
        locations.append({
            "physicalLocation": {
                "artifactLocation": {
                    "uri": clean_path,
                    "uriBaseId": "%SRCROOT%"
                },
                "region": {
                    "startLine": int(finding.get("line", 1)),
                    "startColumn": 1
                }
            }
        })
    else:
        # Synthetic fallback location
        locations.append({
            "physicalLocation": {
                "artifactLocation": {
                    "uri": "SECURITY.md",
                    "uriBaseId": "%SRCROOT%"
                },
                "region": {
                    "startLine": 1,
                    "startColumn": 1
                }
            }
        })

    return locations


def build_sarif_report(
    findings: List[Dict[str, Any]],
    target: str = "target",
    tool_version: str = "2.0.0",
    repository_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Convert Moros AI findings into standard SARIF 2.1.0 document."""
    rules_by_id: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for idx, f in enumerate(findings):
        cwe_id = _extract_cwe(f)
        title_slug = re.sub(r"[^a-zA-Z0-9]", "-", str(f.get("title", f"finding-{idx}")).lower()).strip("-")
        rule_id = f"{cwe_id}/{title_slug}" if cwe_id else f"MOROS-{idx+1:04d}"

        if rule_id not in rules_by_id:
            rules_by_id[rule_id] = _build_rule(rule_id, f)

        rule = rules_by_id[rule_id]
        severity_norm = _normalize_severity(f.get("severity", "medium"))
        level = _SEVERITY_TO_LEVEL.get(severity_norm, "warning")

        message_text = f.get("notes") or f.get("title") or "Security finding identified by Moros AI."
        if f.get("validation_status") == "validated":
            message_text = f"[VALIDATED] {message_text}"
        elif f.get("status") == "candidate":
            message_text = f"[CANDIDATE] {message_text}"

        res_item: Dict[str, Any] = {
            "ruleId": rule_id,
            "ruleIndex": list(rules_by_id.keys()).index(rule_id),
            "level": level,
            "message": {
                "text": message_text
            },
            "locations": _build_locations(f, target),
            "properties": {
                "moros": {
                    "status": f.get("status", "candidate"),
                    "validation_status": f.get("validation_status", "unverified"),
                    "confidence": f.get("confidence", "medium"),
                    "skill": f.get("skill", "security-assessment"),
                    "target": target,
                }
            }
        }

        if f.get("curl"):
            res_item["properties"]["moros"]["reproduction_curl"] = f.get("curl")

        if f.get("poc_sh") or f.get("poc_py"):
            res_item["properties"]["moros"]["poc_scripts"] = {
                "bash": f.get("poc_sh", ""),
                "python": f.get("poc_py", ""),
            }

        results.append(res_item)

    driver: Dict[str, Any] = {
        "name": TOOL_NAME,
        "version": tool_version,
        "informationUri": TOOL_INFORMATION_URI,
        "rules": list(rules_by_id.values()),
    }

    run: Dict[str, Any] = {
        "tool": {"driver": driver},
        "results": results,
        "invocations": [
            {
                "executionSuccessful": True,
                "endTimeUtc": datetime.now(timezone.utc).isoformat(),
            }
        ],
        "properties": {
            "target": target,
            "totalFindings": len(results),
            "validatedFindings": sum(1 for f in findings if f.get("validation_status") == "validated"),
            "candidateFindings": sum(1 for f in findings if f.get("validation_status") != "validated"),
        }
    }

    if repository_context:
        repo_uri = repository_context.get("repositoryUri")
        if repo_uri:
            run["versionControlProvenance"] = [{
                "repositoryUri": repo_uri,
                "revisionId": repository_context.get("commitSha", "HEAD"),
                "branch": repository_context.get("branch", "main"),
            }]

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [run],
    }


def write_sarif_report(
    output_path: Path,
    findings: List[Dict[str, Any]],
    target: str = "target",
    tool_version: str = "2.0.0",
    repository_context: Optional[Dict[str, Any]] = None,
) -> Path:
    """Atomic write of SARIF 2.1.0 document."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    sarif_doc = build_sarif_report(
        findings=findings,
        target=target,
        tool_version=tool_version,
        repository_context=repository_context,
    )

    tmp_path = output_path.with_name(f"{output_path.name}.{os.getpid()}.tmp")
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(sarif_doc, f, indent=2, ensure_ascii=False)
            f.write("\n")
        tmp_path.replace(output_path)
    finally:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass

    logger.info(f"Wrote SARIF 2.1.0 report: {output_path} ({len(findings)} findings)")
    return output_path
