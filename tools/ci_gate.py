#!/usr/bin/env python3
"""
ci_gate.py — Configurable CI/CD Policy Gate, Scope Guard, SARIF Validator,
and PR Summary Generator for Moros AI.

Exit Codes:
    0 — Pass (no gate violations)
    2 — Finding or policy gate triggered
    3 — Scope or authorization violation
    4 — Invalid configuration or missing artifacts
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
import math
import os
from pathlib import Path
import re
import sys
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

import yaml

TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

try:
    from llm_client import redact_secrets as _base_redact_secrets
except ImportError:  # pragma: no cover
    from tools.llm_client import redact_secrets as _base_redact_secrets

try:
    from scope_validator import ScopeValidator
except ImportError:  # pragma: no cover
    from tools.scope_validator import ScopeValidator


EXIT_PASS = 0
EXIT_GATE_TRIGGERED = 2
EXIT_SCOPE_VIOLATION = 3
EXIT_INVALID_CONFIG = 4

VALID_SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_RANK: Dict[str, int] = {
    "info": 0,
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
CONFIDENCE_LABEL_MAP: Dict[str, float] = {
    "critical": 0.95,
    "confirmed": 0.95,
    "high": 0.85,
    "medium": 0.60,
    "moderate": 0.60,
    "low": 0.30,
    "info": 0.10,
    "unverified": 0.40,
}

CONFIRMED_STATUSES = {"confirmed", "validated"}
RESOLVED_STATUSES = {"false_positive", "fixed", "accepted_risk"}
BLOCKED_STATUSES = {"blocked_scope"}
VALID_SARIF_LEVELS = {"error", "warning", "note", "none"}

_EXTRA_SECRET_PATTERNS: Tuple[Tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "[REDACTED_JWT]"),
    (re.compile(r"((?:cookie|set-cookie)\s*:\s*)[^\r\n]+", re.IGNORECASE), r"\g<1>[REDACTED]"),
    (re.compile(r"(authorization\s*:\s*)[^\r\n]+", re.IGNORECASE), r"\g<1>[REDACTED]"),
    (re.compile(r"(https?://)[^/@\s:]+:[^/@\s]+@", re.IGNORECASE), r"\g<1>[REDACTED]@"),
    (
        re.compile(
            r"([?&](?:key|api_key|apikey|token|access_token|auth|secret|password)=)[^&\s'\"]+",
            re.IGNORECASE,
        ),
        r"\g<1>[REDACTED]",
    ),
    (
        re.compile(
            r"\b((?:password|secret|api_key|access_token|auth_token)\s*[=:]\s*)['\"]?[^\s,;'\"]{6,}['\"]?",
            re.IGNORECASE,
        ),
        r"\g<1>[REDACTED]",
    ),
)

_AUTHORIZATION_KEYWORDS = (
    "authorized",
    "authorization",
    "bug bounty",
    "penetration testing",
    "rules of engagement",
    "in scope",
    "written permission",
    "signed",
)


class InvalidGateConfigError(ValueError):
    """Raised when gate configuration or target artifacts are invalid/missing."""


@dataclass
class GateConfig:
    """Threshold and policy configuration for the CI security gate."""

    min_severity: str = "high"
    fail_on_candidate: bool = False
    fail_on_confirmed: bool = True
    min_confidence: float = 0.0
    require_validation: bool = False

    def validate(self) -> "GateConfig":
        """Normalize and validate all gate configuration values."""
        sev = str(self.min_severity or "").strip().lower()
        if sev == "informational":
            sev = "info"
        if sev not in VALID_SEVERITIES:
            raise InvalidGateConfigError(
                f"Invalid min_severity '{self.min_severity}'. Must be one of: {', '.join(VALID_SEVERITIES)}."
            )
        self.min_severity = sev

        if isinstance(self.min_confidence, bool) or not isinstance(self.min_confidence, (int, float)):
            try:
                self.min_confidence = float(self.min_confidence)
            except (TypeError, ValueError) as exc:
                raise InvalidGateConfigError(f"Invalid min_confidence '{self.min_confidence}'.") from exc
        else:
            self.min_confidence = float(self.min_confidence)

        if math.isnan(self.min_confidence) or self.min_confidence < 0.0 or self.min_confidence > 1.0:
            raise InvalidGateConfigError(
                f"Invalid min_confidence '{self.min_confidence}'. Must be between 0.0 and 1.0."
            )

        for field_name in ("fail_on_candidate", "fail_on_confirmed", "require_validation"):
            val = getattr(self, field_name)
            if not isinstance(val, bool):
                setattr(self, field_name, _parse_bool(val, field_name))

        return self


def _parse_bool(value: Any, field_name: str = "flag") -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
    raise InvalidGateConfigError(f"Invalid boolean value for '{field_name}': {value!r}")


def redact_sensitive_text(text: Optional[str]) -> str:
    """Redact API keys, tokens, cookies, credentials, and auth headers."""
    if not text:
        return ""
    cleaned = _base_redact_secrets(str(text))
    for pattern, replacement in _EXTRA_SECRET_PATTERNS:
        cleaned = pattern.sub(replacement, cleaned)
    return cleaned


def load_gate_config(
    config_path: Optional[Path] = None,
    overrides: Optional[Dict[str, Any]] = None,
) -> GateConfig:
    """Load gate thresholds from JSON/YAML file (if supplied) and apply overrides."""
    raw: Dict[str, Any] = {}
    if config_path is not None:
        cfg_file = Path(config_path)
        if not cfg_file.is_file():
            raise InvalidGateConfigError(f"Gate config file not found: {cfg_file}")
        try:
            text = cfg_file.read_text(encoding="utf-8")
            if cfg_file.suffix.lower() in {".yaml", ".yml"}:
                loaded = yaml.safe_load(text)
            else:
                try:
                    loaded = json.loads(text)
                except json.JSONDecodeError:
                    loaded = yaml.safe_load(text)
        except Exception as exc:
            raise InvalidGateConfigError(f"Failed to parse gate config '{cfg_file}': {exc}") from exc

        if not isinstance(loaded, dict):
            raise InvalidGateConfigError(f"Gate config '{cfg_file}' must be a JSON/YAML object.")

        section = loaded.get("ci_gate") if isinstance(loaded.get("ci_gate"), dict) else loaded
        key_aliases = {
            "min-severity": "min_severity",
            "fail-on-candidate": "fail_on_candidate",
            "fail-on-confirmed": "fail_on_confirmed",
            "min-confidence": "min_confidence",
            "require-validation": "require_validation",
        }
        for k, v in section.items():
            norm_k = key_aliases.get(str(k), str(k))
            if norm_k in {"min_severity", "fail_on_candidate", "fail_on_confirmed", "min_confidence", "require_validation"}:
                raw[norm_k] = v

    if overrides:
        for k, v in overrides.items():
            if v is not None:
                raw[k] = v

    return GateConfig(**raw).validate()


def normalize_severity(value: Any) -> str:
    """Normalize Moros severity strings into info|low|medium|high|critical."""
    text = str(value or "").strip().lower()
    if "critical" in text:
        return "critical"
    if "high" in text:
        return "high"
    if "medium" in text:
        return "medium"
    if "low" in text:
        return "low"
    return "info"


def normalize_confidence(value: Any) -> float:
    """Normalize numeric (0..1 or 0..100) or label confidence into 0.0..1.0."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        num = float(value)
        if math.isnan(num):
            return 0.5
        if num > 1.0 and num <= 100.0:
            num = num / 100.0
        return max(0.0, min(1.0, round(num, 4)))

    text = str(value or "").strip().lower()
    if not text:
        return 0.5
    try:
        return normalize_confidence(float(text))
    except ValueError:
        pass
    for label, score in CONFIDENCE_LABEL_MAP.items():
        if label in text:
            return score
    return 0.5


def classify_finding_status(finding: Dict[str, Any]) -> str:
    """Determine normalized lifecycle state for a finding."""
    val_result = finding.get("validation_result")
    val_result_status = str(val_result.get("status", "")).strip().lower() if isinstance(val_result, dict) else ""
    status = str(finding.get("status", "")).strip().lower()
    val_status = str(finding.get("validation_status", "")).strip().lower()
    val_record = finding.get("validation_record")
    has_human_record = (
        isinstance(val_record, dict)
        and str(val_record.get("verified_by", "")).startswith("human:")
        and val_record.get("outcome") == "reproduced"
    )

    if status in BLOCKED_STATUSES or val_status in BLOCKED_STATUSES:
        return "blocked_scope"
    if status in RESOLVED_STATUSES:
        return status
    if val_status in RESOLVED_STATUSES:
        return val_status
    if val_result_status in RESOLVED_STATUSES:
        return val_result_status

    if val_status == "validated" or status == "validated" or has_human_record:
        return "validated"
    if status == "confirmed" or val_status == "confirmed" or val_result_status == "confirmed":
        return "confirmed"
    if status in {"validating", "inconclusive"}:
        return status
    return "candidate"


def _resolve_output_dir(path: Path) -> Path:
    """Resolve either `<target>/output` or `<target>` containing `output/`."""
    candidate = Path(path)
    if (candidate / "output").is_dir() and not any(
        (candidate / sub).exists() for sub in ("report", "findings", "logs", "runs")
    ):
        return candidate / "output"
    return candidate


def _read_json_safe(path: Path) -> Optional[Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _discover_artifacts(output_dir: Path) -> Dict[str, Any]:
    report_dir = output_dir / "report"
    logs_dir = output_dir / "logs"
    findings_dir = output_dir / "findings"
    runs_dir = output_dir / "runs"

    report_jsons = sorted(
        report_dir.glob("hackbot-report-*.json"),
        key=lambda p: (p.stat().st_mtime, p.name),
        reverse=True,
    ) if report_dir.is_dir() else []
    report_mds = sorted(
        [p for p in report_dir.glob("hackbot-report-*.md") if not p.name.endswith("-ar.md")],
        key=lambda p: (p.stat().st_mtime, p.name),
        reverse=True,
    ) if report_dir.is_dir() else []
    sarif_file = report_dir / "findings.sarif"
    scope_audit_file = logs_dir / "scope-audit-latest.json"
    orch_log_file = logs_dir / "orchestration-log.json"
    finding_files = sorted(findings_dir.rglob("*.json")) if findings_dir.is_dir() else []
    run_files = sorted(runs_dir.glob("*/run.json")) if runs_dir.is_dir() else []

    return {
        "report_json": report_jsons[0] if report_jsons else None,
        "report_md": report_mds[0] if report_mds else None,
        "sarif": sarif_file if sarif_file.is_file() else None,
        "scope_audit": scope_audit_file if scope_audit_file.is_file() else None,
        "orchestration_log": orch_log_file if orch_log_file.is_file() else None,
        "finding_files": finding_files,
        "run_files": run_files,
    }


def _findings_from_sarif(sarif_doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    extracted: List[Dict[str, Any]] = []
    runs = sarif_doc.get("runs")
    if not isinstance(runs, list):
        return extracted
    level_to_sev = {"error": "high", "warning": "medium", "note": "low", "none": "info"}
    for run in runs:
        if not isinstance(run, dict):
            continue
        rules_map: Dict[str, Dict[str, Any]] = {}
        driver = (run.get("tool") or {}).get("driver") or {}
        for rule in driver.get("rules") or []:
            if isinstance(rule, dict) and rule.get("id"):
                rules_map[str(rule["id"])] = rule
        for res in run.get("results") or []:
            if not isinstance(res, dict):
                continue
            rule_id = str(res.get("ruleId", ""))
            rule = rules_map.get(rule_id, {})
            moros_meta = ((res.get("properties") or {}).get("moros") or {})
            sec_sev = (rule.get("properties") or {}).get("security-severity")
            sev = level_to_sev.get(str(res.get("level", "warning")).lower(), "medium")
            if sec_sev is not None:
                try:
                    score = float(sec_sev)
                    if score >= 9.0:
                        sev = "critical"
                    elif score >= 7.0:
                        sev = "high"
                    elif score >= 4.0:
                        sev = "medium"
                    elif score > 0:
                        sev = "low"
                except (TypeError, ValueError):
                    pass
            loc_url = ""
            locs = res.get("locations") or []
            if locs and isinstance(locs[0], dict):
                logical = locs[0].get("logicalLocations") or []
                if logical and isinstance(logical[0], dict):
                    loc_url = str(logical[0].get("fullyQualifiedName") or logical[0].get("name") or "")
                else:
                    loc_url = str((((locs[0].get("physicalLocation") or {}).get("artifactLocation") or {}).get("uri")) or "")
            extracted.append({
                "title": ((rule.get("shortDescription") or {}).get("text")) or rule_id or "SARIF Finding",
                "severity": sev,
                "url": loc_url,
                "notes": ((res.get("message") or {}).get("text")) or "",
                "status": moros_meta.get("status", "candidate"),
                "validation_status": moros_meta.get("validation_status", "unverified"),
                "confidence": moros_meta.get("confidence", "medium"),
                "skill": moros_meta.get("skill", "sarif"),
            })
    return extracted


def validate_sarif_document(doc: Any) -> Tuple[bool, List[str]]:
    """Validate an OASIS SARIF 2.1.0 document structure and secret hygiene."""
    errors: List[str] = []
    if not isinstance(doc, dict):
        return False, ["SARIF root must be a JSON object."]

    if doc.get("version") != "2.1.0":
        errors.append(f"Expected SARIF version '2.1.0', got {doc.get('version')!r}.")

    runs = doc.get("runs")
    if not isinstance(runs, list) or not runs:
        errors.append("SARIF 'runs' must be a non-empty list.")
        return False, errors

    for run_idx, run in enumerate(runs):
        if not isinstance(run, dict):
            errors.append(f"runs[{run_idx}] must be an object.")
            continue
        driver = (run.get("tool") or {}).get("driver")
        if not isinstance(driver, dict) or not str(driver.get("name", "")).strip():
            errors.append(f"runs[{run_idx}].tool.driver.name is required.")
        results = run.get("results")
        if not isinstance(results, list):
            errors.append(f"runs[{run_idx}].results must be a list.")
            continue
        for res_idx, res in enumerate(results):
            if not isinstance(res, dict):
                errors.append(f"runs[{run_idx}].results[{res_idx}] must be an object.")
                continue
            if not str(res.get("ruleId", "")).strip():
                errors.append(f"runs[{run_idx}].results[{res_idx}].ruleId is required.")
            level = str(res.get("level", "")).lower()
            if level not in VALID_SARIF_LEVELS:
                errors.append(f"runs[{run_idx}].results[{res_idx}].level invalid: {level!r}.")
            msg_text = ((res.get("message") or {}).get("text")) if isinstance(res.get("message"), dict) else None
            if not isinstance(msg_text, str) or not msg_text.strip():
                errors.append(f"runs[{run_idx}].results[{res_idx}].message.text is required.")
            elif redact_sensitive_text(msg_text) != msg_text:
                errors.append(f"runs[{run_idx}].results[{res_idx}].message.text contains unredacted secret material.")
            locs = res.get("locations")
            if not isinstance(locs, list) or not locs:
                errors.append(f"runs[{run_idx}].results[{res_idx}].locations must be a non-empty list.")

    return (len(errors) == 0), errors


def validate_sarif_file(sarif_path: Path) -> Tuple[bool, List[str]]:
    """Load and validate a SARIF 2.1.0 file from disk."""
    path = Path(sarif_path)
    if not path.is_file():
        return False, [f"SARIF file not found: {path}"]
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return False, [f"Malformed SARIF JSON in {path}: {exc}"]
    return validate_sarif_document(doc)


def validate_authorized_scope(
    target: str,
    target_dir: Optional[Path] = None,
    scan_mode: str = "quick",
    in_scope: Optional[List[str]] = None,
    out_of_scope: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Validate explicit target authorization before active CI/CD testing.

    Passive mode only validates target syntax and scope allowlists; active modes
    additionally require a readable scope-of-work.* authorization file.
    """
    clean_target = (target or "").strip().lower().rstrip(".")
    if not clean_target or ".." in clean_target or not re.fullmatch(
        r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", clean_target
    ):
        return {
            "authorized": False,
            "exit_code": EXIT_SCOPE_VIOLATION,
            "reason": f"Invalid or unsafe target hostname: {target!r}",
        }

    resolved_dir = Path(target_dir) if target_dir else (TOOLS_DIR.parent / "targets" / clean_target)
    mode = (scan_mode or "quick").strip().lower()

    if mode != "passive":
        scope_files = sorted(resolved_dir.glob("scope-of-work.*")) if resolved_dir.is_dir() else []
        if not scope_files:
            return {
                "authorized": False,
                "exit_code": EXIT_SCOPE_VIOLATION,
                "reason": f"Active scan blocked: missing scope-of-work.* authorization file in {resolved_dir}",
            }
        scope_text = ""
        for sf in scope_files:
            try:
                scope_text = sf.read_text(encoding="utf-8", errors="ignore")
                if scope_text.strip():
                    break
            except OSError:
                continue
        lowered = scope_text.lower()
        bare = clean_target.removeprefix("www.")
        if bare not in lowered or not any(kw in lowered for kw in _AUTHORIZATION_KEYWORDS):
            return {
                "authorized": False,
                "exit_code": EXIT_SCOPE_VIOLATION,
                "reason": (
                    f"Active scan blocked: scope-of-work file for '{clean_target}' "
                    "does not contain explicit target domain and authorization wording."
                ),
            }

    validator = ScopeValidator(
        clean_target,
        in_scope=in_scope,
        out_of_scope=out_of_scope,
        target_dir=resolved_dir if resolved_dir.is_dir() else None,
    )
    allowed, msg = validator.is_allowed(clean_target)
    if not allowed:
        return {
            "authorized": False,
            "exit_code": EXIT_SCOPE_VIOLATION,
            "reason": msg,
        }
    if mode != "passive" and validator.policy.get("allow_active_vulnerability_checks") is False:
        return {
            "authorized": False,
            "exit_code": EXIT_SCOPE_VIOLATION,
            "reason": "Active scan blocked: scope policy forbids active vulnerability checks.",
        }

    return {
        "authorized": True,
        "exit_code": EXIT_PASS,
        "target": clean_target,
        "target_dir": str(resolved_dir),
        "reason": msg,
    }


def _collect_scope_state(artifacts: Dict[str, Any], findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    scope_audit: Dict[str, Any] = {}
    if artifacts["scope_audit"] is not None:
        loaded = _read_json_safe(artifacts["scope_audit"])
        if isinstance(loaded, dict):
            scope_audit = loaded

    orch_log: Dict[str, Any] = {}
    if artifacts["orchestration_log"] is not None:
        loaded = _read_json_safe(artifacts["orchestration_log"])
        if isinstance(loaded, dict):
            orch_log = loaded

    run_blocked = False
    for rf in artifacts["run_files"]:
        run_data = _read_json_safe(rf)
        if isinstance(run_data, dict) and str(run_data.get("status", "")).lower() in {"blocked", "blocked_scope"}:
            run_blocked = True
            break

    out_of_scope_hosts = scope_audit.get("out_of_scope_hosts") or {}
    out_of_policy_requests = scope_audit.get("out_of_policy_requests") or []
    policy_violations = scope_audit.get("policy_violations") or []
    stopped_by_policy = bool(scope_audit.get("stopped_by_policy"))
    deviation_detected = bool(scope_audit.get("deviation_detected"))
    orch_blocked = str(orch_log.get("status", "")).upper() == "BLOCKED_SCOPE"
    finding_blocked = any(classify_finding_status(f) == "blocked_scope" for f in findings)

    violation_detected = bool(
        deviation_detected
        or stopped_by_policy
        or out_of_scope_hosts
        or out_of_policy_requests
        or policy_violations
        or orch_blocked
        or run_blocked
        or finding_blocked
    )

    return {
        "violation_detected": violation_detected,
        "stopped_by_policy": stopped_by_policy,
        "deviation_detected": deviation_detected,
        "orchestration_blocked": orch_blocked,
        "out_of_scope_hosts": out_of_scope_hosts,
        "policy_violations_count": len(policy_violations),
    }


def _load_findings(artifacts: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], Optional[str], List[str]]:
    errors: List[str] = []
    if artifacts["report_json"] is not None:
        data = _read_json_safe(artifacts["report_json"])
        if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
            errors.append(f"Invalid report JSON format: {artifacts['report_json']}")
            return [], None, errors
        return [f for f in data["findings"] if isinstance(f, dict)], data.get("target"), errors

    if artifacts["finding_files"]:
        collected: List[Dict[str, Any]] = []
        target_name: Optional[str] = None
        for ff in artifacts["finding_files"]:
            payload = _read_json_safe(ff)
            if payload is None:
                errors.append(f"Malformed finding JSON artifact: {ff}")
                continue
            if isinstance(payload, dict):
                target_name = target_name or payload.get("target")
                rows = payload.get("findings")
                if isinstance(rows, list):
                    collected.extend(r for r in rows if isinstance(r, dict))
        return collected, target_name, errors

    if artifacts["sarif"] is not None:
        sarif_doc = _read_json_safe(artifacts["sarif"])
        if not isinstance(sarif_doc, dict):
            errors.append(f"Malformed SARIF artifact: {artifacts['sarif']}")
            return [], None, errors
        target_name = None
        runs = sarif_doc.get("runs") or []
        if runs and isinstance(runs[0], dict):
            target_name = ((runs[0].get("properties") or {}).get("target"))
        return _findings_from_sarif(sarif_doc), target_name, errors

    return [], None, errors


def _sanitize_finding_summary(finding: Dict[str, Any], status: str, severity: str, confidence: float, reason: Optional[str] = None) -> Dict[str, Any]:
    raw_url = finding.get("url") or finding.get("affected_url") or finding.get("endpoint") or ""
    entry: Dict[str, Any] = {
        "title": redact_sensitive_text(str(finding.get("title") or "Untitled Finding")),
        "status": status,
        "severity": severity,
        "confidence": confidence,
        "url": redact_sensitive_text(str(raw_url)),
        "skill": redact_sensitive_text(str(finding.get("skill") or "unknown")),
    }
    if reason:
        entry["gate_reason"] = reason
    return entry


def evaluate_gate(
    output_dir: Path,
    config: Optional[GateConfig] = None,
    config_path: Optional[Path] = None,
    target: Optional[str] = None,
    strict_sarif: bool = False,
) -> Dict[str, Any]:
    """Evaluate Moros output artifacts against CI gate policies and thresholds."""
    try:
        resolved_cfg = config.validate() if config is not None else load_gate_config(config_path=config_path)
    except InvalidGateConfigError as exc:
        return {
            "status": "invalid_config",
            "passed": False,
            "exit_code": EXIT_INVALID_CONFIG,
            "target": target or "",
            "output_dir": str(output_dir),
            "config": {},
            "scope": {},
            "counts": {},
            "triggering_findings": [],
            "all_findings_summary": [],
            "artifacts": {},
            "errors": [str(exc)],
        }

    base_path = Path(output_dir)
    if not base_path.exists() or not base_path.is_dir():
        return {
            "status": "invalid_config",
            "passed": False,
            "exit_code": EXIT_INVALID_CONFIG,
            "target": target or "",
            "output_dir": str(base_path),
            "config": asdict(resolved_cfg),
            "scope": {},
            "counts": {},
            "triggering_findings": [],
            "all_findings_summary": [],
            "artifacts": {},
            "errors": [f"Target output directory not found: {base_path}"],
        }

    resolved_output = _resolve_output_dir(base_path)
    artifacts = _discover_artifacts(resolved_output)
    has_any_artifact = any([
        artifacts["report_json"],
        artifacts["sarif"],
        artifacts["scope_audit"],
        artifacts["orchestration_log"],
        artifacts["finding_files"],
        artifacts["run_files"],
    ])
    if not has_any_artifact:
        return {
            "status": "invalid_config",
            "passed": False,
            "exit_code": EXIT_INVALID_CONFIG,
            "target": target or "",
            "output_dir": str(resolved_output),
            "config": asdict(resolved_cfg),
            "scope": {},
            "counts": {},
            "triggering_findings": [],
            "all_findings_summary": [],
            "artifacts": {},
            "errors": [f"No Moros scan artifacts found in {resolved_output}"],
        }

    findings, detected_target, load_errors = _load_findings(artifacts)
    resolved_target = target or detected_target or resolved_output.parent.name

    sarif_valid: Optional[bool] = None
    sarif_errors: List[str] = []
    if artifacts["sarif"] is not None:
        sarif_valid, sarif_errors = validate_sarif_file(artifacts["sarif"])
        if strict_sarif and not sarif_valid:
            load_errors.extend(sarif_errors)

    if load_errors:
        return {
            "status": "invalid_config",
            "passed": False,
            "exit_code": EXIT_INVALID_CONFIG,
            "target": resolved_target,
            "output_dir": str(resolved_output),
            "config": asdict(resolved_cfg),
            "scope": {},
            "counts": {},
            "triggering_findings": [],
            "all_findings_summary": [],
            "artifacts": {
                "report_json": str(artifacts["report_json"]) if artifacts["report_json"] else None,
                "report_md": str(artifacts["report_md"]) if artifacts["report_md"] else None,
                "sarif": str(artifacts["sarif"]) if artifacts["sarif"] else None,
                "sarif_valid": sarif_valid,
                "sarif_errors": sarif_errors,
                "scope_audit": str(artifacts["scope_audit"]) if artifacts["scope_audit"] else None,
            },
            "errors": load_errors,
        }

    scope_state = _collect_scope_state(artifacts, findings)
    counts = {
        "total_findings": len(findings),
        "confirmed": 0,
        "validated": 0,
        "candidate": 0,
        "false_positive": 0,
        "fixed": 0,
        "accepted_risk": 0,
        "triggering": 0,
    }
    triggering: List[Dict[str, Any]] = []
    all_summaries: List[Dict[str, Any]] = []
    min_rank = SEVERITY_RANK[resolved_cfg.min_severity]

    for finding in findings:
        status = classify_finding_status(finding)
        sev = normalize_severity(finding.get("severity"))
        conf = normalize_confidence(finding.get("confidence"))

        if status in counts:
            counts[status] += 1
        elif status in {"validating", "inconclusive"}:
            counts["candidate"] += 1

        all_summaries.append(_sanitize_finding_summary(finding, status, sev, conf))

        if status in RESOLVED_STATUSES or status == "blocked_scope":
            continue

        meets_severity = SEVERITY_RANK[sev] >= min_rank
        meets_confidence = conf >= resolved_cfg.min_confidence
        if not (meets_severity and meets_confidence):
            continue

        reason: Optional[str] = None
        if status in CONFIRMED_STATUSES and resolved_cfg.fail_on_confirmed:
            reason = f"{status}_finding_above_threshold"
        elif status not in CONFIRMED_STATUSES:
            if resolved_cfg.fail_on_candidate:
                reason = "candidate_finding_blocked"
            elif resolved_cfg.require_validation:
                reason = "unvalidated_finding_requires_validation"

        if reason:
            triggering.append(_sanitize_finding_summary(finding, status, sev, conf, reason=reason))

    counts["triggering"] = len(triggering)

    if scope_state["violation_detected"]:
        final_status = "scope_violation"
        exit_code = EXIT_SCOPE_VIOLATION
        passed = False
    elif triggering:
        final_status = "gate_triggered"
        exit_code = EXIT_GATE_TRIGGERED
        passed = False
    else:
        final_status = "pass"
        exit_code = EXIT_PASS
        passed = True

    return {
        "status": final_status,
        "passed": passed,
        "exit_code": exit_code,
        "target": redact_sensitive_text(resolved_target),
        "output_dir": str(resolved_output),
        "config": asdict(resolved_cfg),
        "scope": scope_state,
        "counts": counts,
        "triggering_findings": triggering,
        "all_findings_summary": all_summaries,
        "artifacts": {
            "report_json": str(artifacts["report_json"]) if artifacts["report_json"] else None,
            "report_md": str(artifacts["report_md"]) if artifacts["report_md"] else None,
            "sarif": str(artifacts["sarif"]) if artifacts["sarif"] else None,
            "sarif_valid": sarif_valid,
            "sarif_errors": sarif_errors,
            "scope_audit": str(artifacts["scope_audit"]) if artifacts["scope_audit"] else None,
        },
        "errors": [],
    }


def generate_pr_summary(
    evaluation: Dict[str, Any],
    report_links: Optional[Dict[str, str]] = None,
    max_findings: int = 20,
) -> str:
    """Generate a secret-redacted Markdown PR summary for CI comments and step summaries."""
    exit_code = int(evaluation.get("exit_code", EXIT_INVALID_CONFIG))
    status = str(evaluation.get("status", "unknown"))
    target = redact_sensitive_text(str(evaluation.get("target") or "unknown-target"))
    counts = evaluation.get("counts") or {}
    cfg = evaluation.get("config") or {}
    artifacts = evaluation.get("artifacts") or {}

    badge_map = {
        EXIT_PASS: "PASS",
        EXIT_GATE_TRIGGERED: "FAIL — Policy Gate Triggered",
        EXIT_SCOPE_VIOLATION: "BLOCKED — Scope Violation",
        EXIT_INVALID_CONFIG: "ERROR — Invalid Config / Missing Artifacts",
    }
    heading_status = badge_map.get(exit_code, status.upper())

    lines: List[str] = [
        f"## Moros AI Security Gate — {heading_status}",
        "",
        f"- **Target:** `{target}`",
        f"- **Exit Code:** `{exit_code}` (`{status}`)",
        (
            f"- **Gate Policy:** `min_severity={cfg.get('min_severity', 'n/a')}`, "
            f"`min_confidence={cfg.get('min_confidence', 'n/a')}`, "
            f"`fail_on_confirmed={cfg.get('fail_on_confirmed', 'n/a')}`, "
            f"`fail_on_candidate={cfg.get('fail_on_candidate', 'n/a')}`, "
            f"`require_validation={cfg.get('require_validation', 'n/a')}`"
        ),
        "",
        "### Finding Summary",
        "",
        "| Confirmed | Validated | Candidate | False Positive | Fixed | Accepted Risk | Triggering |",
        "|---:|---:|---:|---:|---:|---:|---:|",
        (
            f"| {counts.get('confirmed', 0)} | {counts.get('validated', 0)} | "
            f"{counts.get('candidate', 0)} | {counts.get('false_positive', 0)} | "
            f"{counts.get('fixed', 0)} | {counts.get('accepted_risk', 0)} | "
            f"{counts.get('triggering', 0)} |"
        ),
    ]

    errors = evaluation.get("errors") or []
    if errors:
        lines.extend(["", "### Errors", ""])
        for err in errors:
            lines.append(f"- {redact_sensitive_text(str(err))}")

    scope = evaluation.get("scope") or {}
    if scope.get("violation_detected"):
        lines.extend([
            "",
            "### Scope Policy Alert",
            "",
            f"- Out-of-scope hosts: `{redact_sensitive_text(json.dumps(scope.get('out_of_scope_hosts', {}), sort_keys=True))}`",
            f"- Stopped by policy: `{scope.get('stopped_by_policy', False)}` | Deviation detected: `{scope.get('deviation_detected', False)}`",
        ])

    findings_to_show = evaluation.get("triggering_findings") or evaluation.get("all_findings_summary") or []
    if findings_to_show:
        section_title = "Triggering Findings" if evaluation.get("triggering_findings") else "Observed Findings"
        lines.extend([
            "",
            f"### {section_title}",
            "",
            "| Title | Status | Severity | Confidence | Location |",
            "|---|---|---|---:|---|",
        ])
        for item in findings_to_show[:max(1, int(max_findings))]:
            title = redact_sensitive_text(str(item.get("title", "Finding"))).replace("|", "\\|")
            f_status = redact_sensitive_text(str(item.get("status", "candidate")))
            sev = redact_sensitive_text(str(item.get("severity", "info"))).upper()
            conf = item.get("confidence", 0.0)
            loc = redact_sensitive_text(str(item.get("url") or "-")).replace("|", "\\|")
            lines.append(f"| {title} | `{f_status}` | `{sev}` | `{conf}` | `{loc}` |")
        if len(findings_to_show) > max_findings:
            lines.append(f"\n_Showing first {max_findings} of {len(findings_to_show)} findings._")

    links: Dict[str, str] = {}
    if report_links:
        for label, url in report_links.items():
            if url:
                links[str(label)] = redact_sensitive_text(str(url))
    for art_key, label in (("report_md", "Markdown Report"), ("report_json", "JSON Report"), ("sarif", "SARIF 2.1.0")):
        if artifacts.get(art_key) and label not in links:
            links[label] = redact_sensitive_text(str(artifacts[art_key]))

    if links:
        lines.extend(["", "### Reports & Artifacts", ""])
        for label, ref in links.items():
            safe_label = redact_sensitive_text(label)
            if ref.startswith(("http://", "https://")):
                lines.append(f"- [{safe_label}]({ref})")
            else:
                lines.append(f"- **{safe_label}:** `{ref}`")

    return redact_sensitive_text("\n".join(lines) + "\n")


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Moros AI CI/CD Security Gate & PR Summary Tool")
    parser.add_argument("--output-dir", default=None, help="Path to Moros target or target/output directory")
    parser.add_argument("--target", default=None, help="Target domain name")
    parser.add_argument("--target-dir", default=None, help="Target directory (for --check-scope)")
    parser.add_argument("--config", default=None, help="Optional JSON/YAML gate config file")
    parser.add_argument("--min-severity", default=None, help="Minimum severity threshold (info|low|medium|high|critical)")
    parser.add_argument("--fail-on-candidate", nargs="?", const="true", default=None, help="Fail on unverified candidates")
    parser.add_argument("--fail-on-confirmed", nargs="?", const="true", default=None, help="Fail on confirmed/validated findings")
    parser.add_argument("--min-confidence", type=float, default=None, help="Minimum confidence threshold (0.0-1.0)")
    parser.add_argument("--require-validation", nargs="?", const="true", default=None, help="Fail when unvalidated findings remain")
    parser.add_argument("--summary-out", default=None, help="Write PR summary Markdown to path")
    parser.add_argument("--json-out", default=None, help="Write evaluation JSON to path")
    parser.add_argument("--report-url", default=None, help="Optional CI report URL for PR summary")
    parser.add_argument("--artifact-url", default=None, help="Optional CI artifacts URL for PR summary")
    parser.add_argument("--strict-sarif", action="store_true", help="Fail with exit 4 if findings.sarif is invalid")
    parser.add_argument("--validate-sarif", default=None, help="Validate a SARIF 2.1.0 file directly and exit")
    parser.add_argument("--check-scope", action="store_true", help="Validate explicit target scope authorization before active testing")
    parser.add_argument("--scan-mode", default="quick", help="Scan mode for --check-scope (quick|deep|full|passive)")
    parser.add_argument("--in-scope", default=None, help="Comma-separated in-scope patterns for --check-scope")
    parser.add_argument("--out-of-scope", default=None, help="Comma-separated out-of-scope patterns for --check-scope")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    if args.validate_sarif:
        ok, errs = validate_sarif_file(Path(args.validate_sarif))
        payload = {"valid": ok, "path": str(args.validate_sarif), "errors": errs}
        print(json.dumps(payload, indent=2))
        return EXIT_PASS if ok else EXIT_INVALID_CONFIG

    if args.check_scope:
        in_list = [s.strip() for s in args.in_scope.split(",") if s.strip()] if args.in_scope else None
        out_list = [s.strip() for s in args.out_of_scope.split(",") if s.strip()] if args.out_of_scope else None
        res = validate_authorized_scope(
            target=args.target or "",
            target_dir=Path(args.target_dir) if args.target_dir else None,
            scan_mode=args.scan_mode,
            in_scope=in_list,
            out_of_scope=out_list,
        )
        print(json.dumps(res, indent=2))
        return int(res.get("exit_code", EXIT_SCOPE_VIOLATION))

    if not args.output_dir:
        err_payload = {
            "status": "invalid_config",
            "passed": False,
            "exit_code": EXIT_INVALID_CONFIG,
            "errors": ["--output-dir is required unless --check-scope or --validate-sarif is used."],
        }
        print(json.dumps(err_payload, indent=2))
        return EXIT_INVALID_CONFIG

    overrides: Dict[str, Any] = {}
    if args.min_severity is not None:
        overrides["min_severity"] = args.min_severity
    if args.fail_on_candidate is not None:
        overrides["fail_on_candidate"] = args.fail_on_candidate
    if args.fail_on_confirmed is not None:
        overrides["fail_on_confirmed"] = args.fail_on_confirmed
    if args.min_confidence is not None:
        overrides["min_confidence"] = args.min_confidence
    if args.require_validation is not None:
        overrides["require_validation"] = args.require_validation

    try:
        cfg = load_gate_config(
            config_path=Path(args.config) if args.config else None,
            overrides=overrides,
        )
    except InvalidGateConfigError as exc:
        err_payload = {
            "status": "invalid_config",
            "passed": False,
            "exit_code": EXIT_INVALID_CONFIG,
            "target": args.target or "",
            "output_dir": str(args.output_dir),
            "errors": [str(exc)],
        }
        print(json.dumps(err_payload, indent=2))
        return EXIT_INVALID_CONFIG

    result = evaluate_gate(
        output_dir=Path(args.output_dir),
        config=cfg,
        target=args.target,
        strict_sarif=args.strict_sarif,
    )

    if args.json_out:
        out_p = Path(args.json_out)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(json.dumps(result, indent=2), encoding="utf-8")

    if args.summary_out:
        links: Dict[str, str] = {}
        if args.report_url:
            links["CI Report"] = args.report_url
        if args.artifact_url:
            links["Workflow Artifacts"] = args.artifact_url
        summary_md = generate_pr_summary(result, report_links=links or None)
        sum_p = Path(args.summary_out)
        sum_p.parent.mkdir(parents=True, exist_ok=True)
        sum_p.write_text(summary_md, encoding="utf-8")

    print(json.dumps(result, indent=2))
    return int(result.get("exit_code", EXIT_INVALID_CONFIG))


if __name__ == "__main__":
    sys.exit(main())
