#!/usr/bin/env python3
"""
retest_engine.py — Phase 4 Retesting Engine for Moros AI.

Provides deterministic, scope-enforced, HITL-gated remediation verification:
- RetestPlan & RetestResult: structured immutable plan/result records
- RetestPlanner: builds safe retest plans from findings, original validation
  proofs, remediation metadata, and environment context while preserving all
  original evidence references and SHA-256 ledger provenance
- BeforeAfterComparator: deterministically compares original proof/baseline
  exchanges against retest responses without inflating claims
- RegressionAnalyzer: executes bounded non-destructive regression checks on the
  target endpoint and related routes via ScopedHttpClient
- RetestRunner / RetestEngine: re-executes the original safe validation
  strategy via ReproductionRunner / ValidationStrategyRegistry under strict
  ScopeValidator, ScopedHttpClient, and CheckpointManager HITL gates, persisting
  RetestResult artifacts under output/evidence/retests/<retest_id>.json
- update_finding_lifecycle: updates finding lifecycle state while preserving
  historical evidence_ids, proof_artifact, and validation_result
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import secrets
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

try:
    from tools.agent_security import detect_injection
    from tools.auth_diff import AuthDiffChecker, compute_response_similarity
    from tools.checkpoint_manager import CheckpointManager
    from tools.exploit_validator import (
        _SQL_ERROR_PATTERNS,
        ProofRecorder,
        ReproductionRunner,
        ValidationResult,
        ValidationStrategyRegistry,
        _confidence_label,
        _deterministic_token,
        _normalize_confidence,
        _normalize_target_base,
        _resolve_url,
        _sanitize_structure,
        _sanitize_text,
        _utc_iso,
    )
    from tools.fp_filter import FalsePositiveFilter
    from tools.oob_server import OOBServer
    from tools.scope_validator import ScopeValidator
    from tools.scoped_http import (
        SAFE_METHODS,
        STATE_CHANGING_METHODS,
        ScopedHttpClient,
        check_checkpoint_approval,
        is_gated_post_enabled,
        redact_headers,
    )
except ImportError:
    from agent_security import detect_injection
    from auth_diff import AuthDiffChecker, compute_response_similarity
    from checkpoint_manager import CheckpointManager
    from exploit_validator import (
        _SQL_ERROR_PATTERNS,
        ProofRecorder,
        ReproductionRunner,
        ValidationResult,
        ValidationStrategyRegistry,
        _confidence_label,
        _deterministic_token,
        _normalize_confidence,
        _normalize_target_base,
        _resolve_url,
        _sanitize_structure,
        _sanitize_text,
        _utc_iso,
    )
    from fp_filter import FalsePositiveFilter
    from oob_server import OOBServer
    from scope_validator import ScopeValidator
    from scoped_http import (
        SAFE_METHODS,
        STATE_CHANGING_METHODS,
        ScopedHttpClient,
        check_checkpoint_approval,
        is_gated_post_enabled,
        redact_headers,
    )


VALID_RETEST_OUTCOMES = frozenset({
    "fixed",
    "still_vulnerable",
    "regression_detected",
    "inconclusive",
    "blocked_scope",
})

FIXED_LIMITATION_NOTE = (
    "Does not prove the entire application is secure; only that the specific "
    "tested issue was not reproduced under the recorded conditions"
)

_TRAVERSAL_INDICATORS: Tuple[str, ...] = (
    "root:x:0:0:",
    "/bin/bash",
    "/sbin/nologin",
    "[extensions]",
    "[fonts]",
    "[mci extensions]",
)

_STACK_TRACE_PATTERNS: Tuple[re.Pattern[str], ...] = (
    re.compile(r"traceback \(most recent call last\)", re.I),
    re.compile(r"\b(?:nullpointerexception|unhandledpromiserejection|referenceerror|typeerror)\b", re.I),
    re.compile(r"\b(?:internal server error|application error|unhandled exception)\b", re.I),
    re.compile(r"\b(?:sqlstate\[|fatal error:.*on line \d+)\b", re.I),
)

_BASELINE_LABELS = {
    "xss_baseline",
    "sqli_baseline",
    "redirect_baseline",
    "traversal_baseline",
    "ssti_baseline",
    "crlf_baseline",
}

_PROBE_LABELS = {
    "xss_probe",
    "sqli_quote_probe",
    "sqli_bool_true",
    "sqli_bool_false",
    "redirect_probe",
    "cors_arbitrary_origin",
    "cors_null_origin",
    "ssrf_oob_probe",
    "crlf_probe",
    "generic_replay",
    "idor_unauth_probe",
}


def _dedupe_strs(items: Iterable[Any]) -> List[str]:
    seen: set[str] = set()
    out: List[str] = []
    for item in items:
        val = str(item or "").strip()
        if val and val not in seen:
            seen.add(val)
            out.append(val)
    return out


def _normalize_path(path_value: Any) -> str:
    return str(path_value or "").strip().replace("\\", "/")


def _is_scope_or_hitl_limitation(text: str) -> bool:
    low = str(text or "").lower()
    markers = (
        "out-of-scope",
        "out of scope",
        "scope policy",
        "scope-policy",
        "blocked by scope",
        "moros_allow_gated_post",
        "hitl",
        "checkpointmanager",
        "disallowed port",
        "invalid scheme",
        "not permitted by validation policy",
        "state-changing checks are disabled",
    )
    return any(m in low for m in markers)


def _strip_exploit_query(url: str) -> str:
    """Build a clean route URL by replacing query values with benign defaults."""
    parsed = urllib.parse.urlsplit(url)
    if not parsed.query:
        return url
    items = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    cleaned: List[Tuple[str, str]] = []
    for k, v in items:
        v_str = str(v or "")
        if any(tok in v_str.lower() for tok in ("<", ">", "'", "\"", "{{", "${", "../", "..\\", "%0d", "%0a", "http://", "https://")):
            cleaned.append((k, "1" if k.lower() in {"id", "page_id", "item"} else "test"))
        else:
            cleaned.append((k, v_str))
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(cleaned, doseq=True), ""))


@dataclass
class RetestPlan:
    """Structured plan linking a finding and its original proof to a bounded retest."""

    plan_id: str
    finding_id: str
    target: str
    base_url: str
    endpoint: str
    method: str = "GET"
    strategy: str = "generic-replay"
    strategy_version: str = "1.0.0"
    remediation_id: str = ""
    code_version: str = ""
    environment: Dict[str, Any] = field(default_factory=dict)
    original_status: str = ""
    original_validation_run_id: str = ""
    original_evidence_ids: List[str] = field(default_factory=list)
    original_proof_artifact: str = ""
    original_proof_sha256: str = ""
    original_proof_integrity: Dict[str, Any] = field(default_factory=dict)
    original_proof_bundle: Dict[str, Any] = field(default_factory=dict)
    regression_routes: List[str] = field(default_factory=list)
    expected_baseline: Dict[str, Any] = field(default_factory=dict)
    requires_hitl_approval: bool = False
    limitations: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=_utc_iso)

    def __post_init__(self) -> None:
        self.method = str(self.method or "GET").upper()
        self.original_evidence_ids = _dedupe_strs(self.original_evidence_ids)
        self.original_proof_artifact = _normalize_path(self.original_proof_artifact)
        self.regression_routes = _dedupe_strs(self.regression_routes)
        self.limitations = _dedupe_strs(self.limitations)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "finding_id": self.finding_id,
            "target": self.target,
            "base_url": self.base_url,
            "endpoint": self.endpoint,
            "method": self.method,
            "strategy": self.strategy,
            "strategy_version": self.strategy_version,
            "remediation_id": self.remediation_id,
            "code_version": self.code_version,
            "environment": dict(self.environment),
            "original_status": self.original_status,
            "original_validation_run_id": self.original_validation_run_id,
            "original_evidence_ids": list(self.original_evidence_ids),
            "original_proof_artifact": self.original_proof_artifact,
            "original_proof_sha256": self.original_proof_sha256,
            "original_proof_integrity": dict(self.original_proof_integrity),
            "original_proof_bundle": copy.deepcopy(self.original_proof_bundle),
            "regression_routes": list(self.regression_routes),
            "expected_baseline": dict(self.expected_baseline),
            "requires_hitl_approval": bool(self.requires_hitl_approval),
            "limitations": list(self.limitations),
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RetestPlan":
        return cls(
            plan_id=str(data.get("plan_id", "")),
            finding_id=str(data.get("finding_id", "")),
            target=str(data.get("target", "")),
            base_url=str(data.get("base_url", "")),
            endpoint=str(data.get("endpoint", "")),
            method=str(data.get("method", "GET")),
            strategy=str(data.get("strategy", "generic-replay")),
            strategy_version=str(data.get("strategy_version", "1.0.0")),
            remediation_id=str(data.get("remediation_id", "")),
            code_version=str(data.get("code_version", "")),
            environment=dict(data.get("environment") or {}),
            original_status=str(data.get("original_status", "")),
            original_validation_run_id=str(data.get("original_validation_run_id", "")),
            original_evidence_ids=list(data.get("original_evidence_ids") or []),
            original_proof_artifact=str(data.get("original_proof_artifact", "")),
            original_proof_sha256=str(data.get("original_proof_sha256", "")),
            original_proof_integrity=dict(data.get("original_proof_integrity") or {}),
            original_proof_bundle=dict(data.get("original_proof_bundle") or {}),
            regression_routes=list(data.get("regression_routes") or []),
            expected_baseline=dict(data.get("expected_baseline") or {}),
            requires_hitl_approval=bool(data.get("requires_hitl_approval", False)),
            limitations=list(data.get("limitations") or []),
            created_at=str(data.get("created_at") or _utc_iso()),
        )

    def get(self, key: str, default: Any = None) -> Any:
        return self.to_dict().get(key, default)

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]

    def __contains__(self, key: object) -> bool:
        return isinstance(key, str) and key in self.to_dict()


@dataclass
class RetestResult:
    """Structured Phase 4 retest outcome record persisted under output/evidence/retests/."""

    retest_id: str
    plan_id: str
    finding_id: str
    target: str
    endpoint: str
    method: str = "GET"
    strategy: str = "generic-replay"
    strategy_version: str = "1.0.0"
    outcome: str = "inconclusive"
    confidence: float = 0.0
    remediation_id: str = ""
    code_version: str = ""
    environment: Dict[str, Any] = field(default_factory=dict)
    limitations: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=_utc_iso)
    original_validation_run_id: str = ""
    original_evidence_ids: List[str] = field(default_factory=list)
    original_proof_artifact: str = ""
    original_proof_sha256: str = ""
    retest_validation_run_id: str = ""
    retest_proof_artifact: str = ""
    retest_evidence_ids: List[str] = field(default_factory=list)
    retest_artifact: str = ""
    retest_evidence_id: str = ""
    before_after: Dict[str, Any] = field(default_factory=dict)
    regression_report: Dict[str, Any] = field(default_factory=dict)
    requests_used: int = 0
    details: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.outcome not in VALID_RETEST_OUTCOMES:
            raise ValueError(
                f"Invalid retest outcome '{self.outcome}'. Must be one of: {sorted(VALID_RETEST_OUTCOMES)}"
            )
        self.method = str(self.method or "GET").upper()
        self.confidence = _normalize_confidence(self.confidence)
        if isinstance(self.limitations, str):
            self.limitations = [self.limitations] if self.limitations.strip() else []
        else:
            self.limitations = _dedupe_strs(self.limitations or [])
        if self.outcome == "fixed" and FIXED_LIMITATION_NOTE not in self.limitations:
            self.limitations.append(FIXED_LIMITATION_NOTE)
        self.original_evidence_ids = _dedupe_strs(self.original_evidence_ids)
        self.retest_evidence_ids = _dedupe_strs(self.retest_evidence_ids)
        self.original_proof_artifact = _normalize_path(self.original_proof_artifact)
        self.retest_proof_artifact = _normalize_path(self.retest_proof_artifact)
        self.retest_artifact = _normalize_path(self.retest_artifact)
        self.requests_used = max(0, int(self.requests_used or 0))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "retest_id": self.retest_id,
            "plan_id": self.plan_id,
            "finding_id": self.finding_id,
            "target": self.target,
            "endpoint": self.endpoint,
            "method": self.method,
            "strategy": self.strategy,
            "strategy_version": self.strategy_version,
            "outcome": self.outcome,
            "confidence": self.confidence,
            "remediation_id": self.remediation_id,
            "code_version": self.code_version,
            "environment": dict(self.environment),
            "limitations": list(self.limitations),
            "timestamp": self.timestamp,
            "original_validation_run_id": self.original_validation_run_id,
            "original_evidence_ids": list(self.original_evidence_ids),
            "original_proof_artifact": self.original_proof_artifact,
            "original_proof_sha256": self.original_proof_sha256,
            "retest_validation_run_id": self.retest_validation_run_id,
            "retest_proof_artifact": self.retest_proof_artifact,
            "retest_evidence_ids": list(self.retest_evidence_ids),
            "retest_artifact": self.retest_artifact,
            "retest_evidence_id": self.retest_evidence_id,
            "before_after": copy.deepcopy(self.before_after),
            "regression_report": copy.deepcopy(self.regression_report),
            "requests_used": self.requests_used,
            "details": copy.deepcopy(self.details),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RetestResult":
        return cls(
            retest_id=str(data.get("retest_id", "")),
            plan_id=str(data.get("plan_id", "")),
            finding_id=str(data.get("finding_id", "")),
            target=str(data.get("target", "")),
            endpoint=str(data.get("endpoint", "")),
            method=str(data.get("method", "GET")),
            strategy=str(data.get("strategy", "generic-replay")),
            strategy_version=str(data.get("strategy_version", "1.0.0")),
            outcome=str(data.get("outcome", "inconclusive")),
            confidence=data.get("confidence", 0.0),
            remediation_id=str(data.get("remediation_id", "")),
            code_version=str(data.get("code_version", "")),
            environment=dict(data.get("environment") or {}),
            limitations=data.get("limitations") or [],
            timestamp=str(data.get("timestamp") or _utc_iso()),
            original_validation_run_id=str(data.get("original_validation_run_id", "")),
            original_evidence_ids=list(data.get("original_evidence_ids") or []),
            original_proof_artifact=str(data.get("original_proof_artifact", "")),
            original_proof_sha256=str(data.get("original_proof_sha256", "")),
            retest_validation_run_id=str(data.get("retest_validation_run_id", "")),
            retest_proof_artifact=str(data.get("retest_proof_artifact", "")),
            retest_evidence_ids=list(data.get("retest_evidence_ids") or []),
            retest_artifact=str(data.get("retest_artifact", "")),
            retest_evidence_id=str(data.get("retest_evidence_id", "")),
            before_after=dict(data.get("before_after") or {}),
            regression_report=dict(data.get("regression_report") or {}),
            requests_used=int(data.get("requests_used") or 0),
            details=dict(data.get("details") or {}),
        )

    def get(self, key: str, default: Any = None) -> Any:
        return self.to_dict().get(key, default)

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]

    def __contains__(self, key: object) -> bool:
        return isinstance(key, str) and key in self.to_dict()


class RetestPlanner:
    """
    Builds a safe, deterministic retest plan from a finding and its original
    validation_result / proof_artifact while preserving original evidence IDs
    and SHA-256 ledger provenance references.
    """

    def __init__(
        self,
        target: str,
        target_dir: Optional[Union[str, Path]] = None,
        output_dir: Optional[Union[str, Path]] = None,
        proof_recorder: Optional[ProofRecorder] = None,
        registry: Optional[ValidationStrategyRegistry] = None,
    ):
        self.target, self.base_url = _normalize_target_base(target)
        self.target_dir = Path(target_dir).resolve() if target_dir else None
        if output_dir is not None:
            self.output_dir = Path(output_dir).resolve()
        elif self.target_dir is not None:
            self.output_dir = self.target_dir / "output"
        else:
            self.output_dir = None

        if proof_recorder is not None:
            self.proof_recorder = proof_recorder
        elif self.output_dir is not None:
            self.proof_recorder = ProofRecorder(
                self.target, target_dir=self.target_dir, output_dir=self.output_dir
            )
        else:
            self.proof_recorder = None

        self.registry = registry or ValidationStrategyRegistry()

    def _lookup_ledger_entry(
        self,
        proof_ref: str,
        validation_run_id: str,
    ) -> Optional[Dict[str, Any]]:
        if self.proof_recorder is None or not self.proof_recorder.ledger_path.is_file():
            return None
        norm_ref = _normalize_path(proof_ref)
        try:
            lines = self.proof_recorder.ledger_path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return None
        for line in lines:
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(entry, dict):
                continue
            art = _normalize_path(entry.get("source_artifact", ""))
            if (validation_run_id and entry.get("validation_run_id") == validation_run_id) or (
                norm_ref and art == norm_ref
            ):
                return entry
        return None

    def _derive_finding_id(self, finding: Dict[str, Any], strategy: str) -> str:
        existing = str(finding.get("finding_id") or finding.get("id") or "").strip()
        if existing:
            return existing
        endpoint = str(finding.get("url") or finding.get("endpoint") or "")
        param = str(finding.get("parameter") or "")
        title = str(finding.get("title") or "")
        return "fnd-" + _deterministic_token(self.target, strategy, endpoint, param, title, length=12)

    def build_plan(
        self,
        finding: Dict[str, Any],
        *,
        validation_result: Optional[Union[ValidationResult, Dict[str, Any]]] = None,
        proof_artifact: Optional[Union[str, Path]] = None,
        remediation_id: str = "",
        code_version: str = "",
        environment: Optional[Dict[str, Any]] = None,
        regression_routes: Optional[List[str]] = None,
    ) -> RetestPlan:
        """Build a bounded RetestPlan preserving all historical proof and ledger references."""
        raw_vr = validation_result if validation_result is not None else finding.get("validation_result")
        vr_dict: Dict[str, Any] = (
            raw_vr.to_dict() if isinstance(raw_vr, ValidationResult) else dict(raw_vr or {})
        )

        orig_proof_ref = _normalize_path(
            proof_artifact
            or vr_dict.get("proof_artifact")
            or finding.get("proof_artifact")
            or ""
        )

        proof_bundle: Dict[str, Any] = {}
        proof_integrity: Dict[str, Any] = {}
        proof_sha256 = ""
        limitations: List[str] = []

        if orig_proof_ref and self.proof_recorder is not None:
            proof_path = self.proof_recorder.resolve_proof_path(orig_proof_ref)
            proof_integrity = self.proof_recorder.verify_proof_integrity(proof_path)
            proof_sha256 = str(
                proof_integrity.get("expected_sha256")
                or proof_integrity.get("actual_sha256")
                or ""
            )
            if proof_path.is_file():
                try:
                    loaded = json.loads(proof_path.read_text(encoding="utf-8"))
                    if isinstance(loaded, dict):
                        proof_bundle = loaded
                except (OSError, json.JSONDecodeError) as exc:
                    limitations.append(f"Failed to parse original proof bundle: {exc}")
            if not proof_integrity.get("valid"):
                limitations.append(
                    f"Original proof integrity warning: {proof_integrity.get('reason', 'unknown')}"
                )

        orig_run_id = str(
            vr_dict.get("validation_run_id")
            or finding.get("validation_run_id")
            or proof_bundle.get("validation_run_id")
            or ""
        )

        ledger_entry = self._lookup_ledger_entry(orig_proof_ref, orig_run_id)
        if not proof_sha256 and ledger_entry:
            proof_sha256 = str(ledger_entry.get("source_sha256") or "")

        strategy_hint = (
            vr_dict.get("strategy")
            or proof_bundle.get("strategy")
            or finding.get("strategy")
            or self.registry.resolve_strategy_name(finding)
        )
        strategy_name, strategy_version, _ = self.registry.get(str(strategy_hint))

        finding_id = (
            str(vr_dict.get("finding_id") or proof_bundle.get("finding_id") or "")
            or self._derive_finding_id(finding, strategy_name)
        )

        raw_endpoint = str(
            finding.get("url")
            or finding.get("endpoint")
            or vr_dict.get("endpoint")
            or proof_bundle.get("endpoint")
            or ""
        ).strip()
        endpoint = _resolve_url(self.base_url, raw_endpoint) if raw_endpoint else ""
        method = str(
            finding.get("method")
            or vr_dict.get("method")
            or proof_bundle.get("method")
            or "GET"
        ).upper()

        evidence_ids = _dedupe_strs(
            list(finding.get("evidence_ids") or [])
            + list(vr_dict.get("evidence_ids") or [])
            + ([proof_integrity.get("evidence_id")] if proof_integrity.get("evidence_id") else [])
            + ([ledger_entry.get("evidence_id")] if ledger_entry and ledger_entry.get("evidence_id") else [])
        )

        orig_status = str(
            vr_dict.get("status")
            or proof_bundle.get("status")
            or finding.get("status")
            or ""
        ).strip().lower()
        if not orig_status:
            vrec = finding.get("validation_record")
            if isinstance(vrec, dict) and str(vrec.get("verified_by", "")).startswith("human:"):
                if str(vrec.get("outcome", "")).lower() == "reproduced":
                    orig_status = "validated"

        merged_env: Dict[str, Any] = {}
        orig_env = dict(vr_dict.get("environment") or proof_bundle.get("environment") or {})
        if orig_env:
            merged_env["original"] = _sanitize_structure(orig_env)
        retest_env = dict(environment or {})
        merged_env.update(_sanitize_structure(retest_env))
        if remediation_id:
            merged_env["remediation_id"] = str(remediation_id)
        if code_version:
            merged_env["code_version"] = str(code_version)
        merged_env.setdefault("target", self.target)
        merged_env.setdefault("base_url", self.base_url)

        # Collect bounded regression routes
        candidate_routes: List[str] = []
        for route in (regression_routes or []):
            candidate_routes.append(_resolve_url(self.base_url, str(route)))
        for route in (finding.get("regression_routes") or finding.get("related_routes") or []):
            candidate_routes.append(_resolve_url(self.base_url, str(route)))
        if endpoint:
            candidate_routes.append(_strip_exploit_query(endpoint))

        expected_baseline: Dict[str, Any] = {}
        if isinstance(finding.get("expected_baseline"), dict):
            expected_baseline = dict(finding["expected_baseline"])

        plan_nonce = secrets.token_hex(4)
        plan_id = "plan-" + _deterministic_token(
            finding_id, orig_run_id, remediation_id, code_version, _utc_iso(), plan_nonce, length=12
        )

        return RetestPlan(
            plan_id=plan_id,
            finding_id=finding_id,
            target=self.target,
            base_url=self.base_url,
            endpoint=endpoint,
            method=method,
            strategy=strategy_name,
            strategy_version=strategy_version,
            remediation_id=str(remediation_id or ""),
            code_version=str(code_version or ""),
            environment=merged_env,
            original_status=orig_status,
            original_validation_run_id=orig_run_id,
            original_evidence_ids=evidence_ids,
            original_proof_artifact=orig_proof_ref,
            original_proof_sha256=proof_sha256,
            original_proof_integrity=proof_integrity,
            original_proof_bundle=proof_bundle,
            regression_routes=_dedupe_strs(candidate_routes),
            expected_baseline=expected_baseline,
            requires_hitl_approval=(method in STATE_CHANGING_METHODS),
            limitations=limitations,
        )


class BeforeAfterComparator:
    """
    Deterministically compares original proof/baseline responses against
    retest responses without inflating claims.
    """

    @staticmethod
    def _select_exchange(
        bundle: Optional[Dict[str, Any]],
        labels: set[str],
        fallback_last: bool = True,
    ) -> Optional[Dict[str, Any]]:
        if not isinstance(bundle, dict):
            return None
        exchanges = bundle.get("exchanges") or []
        if not isinstance(exchanges, list) or not exchanges:
            return None
        for ex in reversed(exchanges):
            if isinstance(ex, dict) and str(ex.get("label", "")) in labels:
                return ex
        if fallback_last and isinstance(exchanges[-1], dict):
            return exchanges[-1]
        return None

    @staticmethod
    def _extract_signals(exchange: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        if not isinstance(exchange, dict):
            return {
                "present": False,
                "status_code": None,
                "headers": {},
                "body_preview": "",
                "body_sha256": "",
                "reflection_marker": False,
                "sql_errors": [],
                "traversal_indicators": [],
                "location": "",
                "acao": "",
                "acac": "",
                "set_cookie": "",
                "has_5xx": False,
                "has_404": False,
                "network_error": False,
                "blocked_scope": False,
            }
        resp = exchange.get("response") or {}
        headers = {str(k).lower(): str(v) for k, v in (resp.get("headers") or {}).items()}
        body = str(resp.get("body_preview") if "body_preview" in resp else resp.get("body", "") or "")
        body_low = body.lower()
        code_raw = resp.get("status_code")
        code = int(code_raw) if isinstance(code_raw, (int, float)) and code_raw else None
        status_str = str(resp.get("status", "")).lower()

        sql_matches = [dbms for pat, dbms in _SQL_ERROR_PATTERNS if pat.search(body)]
        trav_matches = [ind for ind in _TRAVERSAL_INDICATORS if ind in body_low]
        reflection = "<moros-probe" in body_low and "morosxss" in body_low
        set_cookie = str(headers.get("set-cookie", ""))
        location = str(headers.get("location", ""))
        acao = str(headers.get("access-control-allow-origin", ""))
        acac = str(headers.get("access-control-allow-credentials", ""))

        red_headers = redact_headers(headers)
        return {
            "present": True,
            "label": str(exchange.get("label", "")),
            "status_code": code,
            "headers": red_headers,
            "body_preview": _sanitize_text(body, 2000),
            "body_sha256": str(resp.get("body_sha256") or ""),
            "reflection_marker": reflection,
            "sql_errors": sql_matches,
            "traversal_indicators": trav_matches,
            "location": _sanitize_text(location, 500),
            "acao": _sanitize_text(acao, 300),
            "acac": _sanitize_text(acac, 100),
            "set_cookie": red_headers.get("set-cookie", ""),
            "crlf_canary_present": "moros_crlf=" in set_cookie.lower(),
            "has_5xx": bool(code is not None and code >= 500),
            "has_404": bool(code in (404, 410)),
            "network_error": status_str == "network_error",
            "blocked_scope": status_str in ("blocked", "blocked_scope"),
        }

    @staticmethod
    def _detect_env_or_endpoint_mismatch(
        plan: RetestPlan,
        retest_vr: Dict[str, Any],
        orig_bundle: Dict[str, Any],
        retest_bundle: Dict[str, Any],
        before_probe: Dict[str, Any],
        after_probe: Dict[str, Any],
        after_base: Dict[str, Any],
    ) -> List[str]:
        reasons: List[str] = []

        # 1. Explicit endpoint path/host mismatch against recorded proof
        orig_ep = str(orig_bundle.get("endpoint") or "").strip()
        if orig_ep and plan.endpoint:
            p_orig = urllib.parse.urlsplit(orig_ep)
            p_new = urllib.parse.urlsplit(plan.endpoint)
            if p_orig.path != p_new.path:
                reasons.append(
                    f"Endpoint path mismatch: original proof targeted '{p_orig.path}' vs retest '{p_new.path}'."
                )

        # 2. Explicit environment mismatch flags or incompatible service/target identifiers
        env = plan.environment or {}
        orig_env = env.get("original") if isinstance(env.get("original"), dict) else (orig_bundle.get("environment") or {})
        if env.get("expected_target") and str(env["expected_target"]).lower().rstrip(".") != plan.target:
            reasons.append(
                f"Target mismatch: expected '{env['expected_target']}' but retest ran against '{plan.target}'."
            )
        if env.get("expected_base_url") and str(env["expected_base_url"]).rstrip("/") != plan.base_url.rstrip("/"):
            reasons.append(
                f"Base URL mismatch: expected '{env['expected_base_url']}' but got '{plan.base_url}'."
            )
        for key in ("service", "app", "application", "expected_env"):
            if key in env and key in orig_env and env[key] and orig_env[key] and str(env[key]) != str(orig_env[key]):
                reasons.append(
                    f"Environment '{key}' mismatch: original='{orig_env[key]}' vs retest='{env[key]}'."
                )
        if env.get("strict_environment_match") and orig_env.get("env") and env.get("env") and str(orig_env["env"]) != str(env["env"]):
            reasons.append(
                f"Strict environment mismatch: original env='{orig_env['env']}' vs retest env='{env['env']}'."
            )

        # 3. 404 / 410 on retest when original endpoint existed (non-404)
        before_code = before_probe.get("status_code")
        after_code = after_probe.get("status_code")
        after_base_code = after_base.get("status_code")
        not_found_code = next((c for c in (after_code, after_base_code) if c in (404, 410)), None)
        if not_found_code is not None and before_code not in (404, 410):
            reasons.append(
                f"Retest endpoint returned HTTP {not_found_code} (not found), indicating an environment or route mismatch."
            )

        # 4. Network error / unreachable endpoint on retest
        if after_probe.get("network_error") or after_base.get("network_error"):
            reasons.append("Retest endpoint unreachable (network error or timeout).")

        # 5. Baseline expectation mismatch if caller explicitly specified expected_baseline
        exp = plan.expected_baseline or {}
        if exp and after_base.get("present"):
            if exp.get("status_code") is not None and after_base.get("status_code") != int(exp["status_code"]):
                reasons.append(
                    f"Baseline status mismatch: expected HTTP {exp['status_code']} vs got HTTP {after_base.get('status_code')}."
                )
            if exp.get("content_type") and str(exp["content_type"]).lower() not in str(after_base["headers"].get("content-type", "")).lower():
                reasons.append(
                    f"Baseline content-type mismatch: expected '{exp['content_type']}'."
                )

        # 6. Retest validation limitations explicitly noting 404/unreachable/missing params
        for lim in (retest_vr.get("limitations") or []):
            low = str(lim).lower()
            if any(k in low for k in ("returned http 404", "returned http 502", "returned http 503", "returned http 504", "timed out", "network error")):
                reasons.append(str(lim))

        return _dedupe_strs(reasons)

    def compare(
        self,
        plan: RetestPlan,
        retest_validation: Union[ValidationResult, Dict[str, Any]],
        *,
        original_bundle: Optional[Dict[str, Any]] = None,
        retest_bundle: Optional[Dict[str, Any]] = None,
        finding: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Compare original proof vs retest exchanges deterministically."""
        retest_vr = (
            retest_validation.to_dict()
            if isinstance(retest_validation, ValidationResult)
            else dict(retest_validation or {})
        )
        orig_b = original_bundle if original_bundle is not None else (plan.original_proof_bundle or {})
        ret_b = retest_bundle or {}

        before_probe = self._extract_signals(self._select_exchange(orig_b, _PROBE_LABELS, fallback_last=True))
        after_probe = self._extract_signals(self._select_exchange(ret_b, _PROBE_LABELS, fallback_last=True))
        before_base = self._extract_signals(self._select_exchange(orig_b, _BASELINE_LABELS, fallback_last=False))
        after_base = self._extract_signals(self._select_exchange(ret_b, _BASELINE_LABELS, fallback_last=False))

        orig_oob = list(orig_b.get("oob_callbacks") or [])
        ret_oob = list(ret_b.get("oob_callbacks") or [])
        orig_auth = orig_b.get("auth_diff")
        ret_auth = ret_b.get("auth_diff")

        similarity: Optional[float] = None
        if before_probe["body_preview"] and after_probe["body_preview"]:
            similarity = round(
                compute_response_similarity(before_probe["body_preview"], after_probe["body_preview"]),
                4,
            )

        # Track header differentials across security-relevant headers
        header_keys = (
            "location",
            "access-control-allow-origin",
            "access-control-allow-credentials",
            "set-cookie",
            "content-type",
        )
        headers_diff: Dict[str, Dict[str, str]] = {}
        for hk in header_keys:
            b_val = str(before_probe["headers"].get(hk, ""))
            a_val = str(after_probe["headers"].get(hk, ""))
            if b_val != a_val:
                headers_diff[hk] = {"before": b_val, "after": a_val}

        # Check finding assertions (for generic-replay or predicate findings)
        assertion_checks: Dict[str, Any] = {}
        if isinstance(finding, dict):
            exp_ind = str(finding.get("expected_indicator") or "").strip()
            exp_status = finding.get("expected_status")
            if exp_ind:
                assertion_checks["expected_indicator_present_after"] = exp_ind in after_probe["body_preview"]
            if exp_status is not None and after_probe["status_code"] is not None:
                assertion_checks["expected_status_matched_after"] = after_probe["status_code"] == int(exp_status)

        limitations = list(plan.limitations)
        retest_status = str(retest_vr.get("status") or "inconclusive").lower()
        retest_lims = [str(x) for x in (retest_vr.get("limitations") or [])]

        # Scope / HITL blocks take precedence
        if (
            after_probe.get("blocked_scope")
            or after_base.get("blocked_scope")
            or any(_is_scope_or_hitl_limitation(l) for l in retest_lims)
        ):
            limitations.extend(retest_lims)
            return {
                "before": before_probe,
                "after": after_probe,
                "status_code_before": before_probe.get("status_code"),
                "status_code_after": after_probe.get("status_code"),
                "status_changed": before_probe.get("status_code") != after_probe.get("status_code"),
                "headers_diff": headers_diff,
                "body_similarity": similarity,
                "oob_callbacks_before": len(orig_oob),
                "oob_callbacks_after": len(ret_oob),
                "auth_diff_before": orig_auth.get("vulnerable") if isinstance(orig_auth, dict) else None,
                "auth_diff_after": ret_auth.get("vulnerable") if isinstance(ret_auth, dict) else None,
                "assertion_checks": assertion_checks,
                "environment_mismatch": False,
                "mismatch_reasons": [],
                "original_verified": plan.original_status in ("confirmed", "validated") or orig_b.get("status") == "confirmed",
                "suggested_outcome": "blocked_scope",
                "confidence": 1.0,
                "limitations": _dedupe_strs(limitations),
            }

        mismatch_reasons = self._detect_env_or_endpoint_mismatch(
            plan, retest_vr, orig_b, ret_b, before_probe, after_probe, after_base
        )
        env_mismatch = bool(mismatch_reasons)
        original_verified = (
            plan.original_status in ("confirmed", "validated")
            or str(orig_b.get("status", "")).lower() == "confirmed"
        )

        if retest_status == "confirmed":
            suggested_outcome = "still_vulnerable"
            confidence = max(0.80, float(retest_vr.get("confidence") or 0.85))
            limitations.extend(retest_lims)
        elif env_mismatch or retest_status == "inconclusive":
            suggested_outcome = "inconclusive"
            confidence = min(0.45, float(retest_vr.get("confidence") or 0.30))
            limitations.extend(mismatch_reasons)
            limitations.extend(retest_lims)
        elif retest_status == "false_positive":
            if not original_verified:
                suggested_outcome = "inconclusive"
                confidence = 0.40
                limitations.append(
                    "Original finding was not deterministically confirmed or human-validated; "
                    "non-reproduction cannot be claimed as 'fixed' without inflating certainty."
                )
                limitations.extend(retest_lims)
            else:
                suggested_outcome = "fixed"
                confidence = max(0.80, float(retest_vr.get("confidence") or 0.85))
                limitations.extend(retest_lims)
                limitations.append(FIXED_LIMITATION_NOTE)
        else:
            suggested_outcome = "inconclusive"
            confidence = 0.25
            limitations.extend(retest_lims)

        return {
            "before": before_probe,
            "after": after_probe,
            "status_code_before": before_probe.get("status_code"),
            "status_code_after": after_probe.get("status_code"),
            "status_changed": before_probe.get("status_code") != after_probe.get("status_code"),
            "headers_diff": headers_diff,
            "body_similarity": similarity,
            "oob_callbacks_before": len(orig_oob),
            "oob_callbacks_after": len(ret_oob),
            "auth_diff_before": orig_auth.get("vulnerable") if isinstance(orig_auth, dict) else None,
            "auth_diff_after": ret_auth.get("vulnerable") if isinstance(ret_auth, dict) else None,
            "assertion_checks": assertion_checks,
            "environment_mismatch": env_mismatch,
            "mismatch_reasons": mismatch_reasons,
            "original_verified": original_verified,
            "suggested_outcome": suggested_outcome,
            "confidence": round(confidence, 4),
            "limitations": _dedupe_strs(limitations),
        }


class RegressionAnalyzer:
    """
    Executes bounded, non-destructive GET regression checks on the target
    endpoint and related routes using ScopedHttpClient, detecting HTTP 5xx
    breakage, assertion failures, stack traces, and reintroduced vulnerability signals.
    """

    def __init__(
        self,
        target: str,
        target_dir: Optional[Union[str, Path]] = None,
        scope_validator: Optional[ScopeValidator] = None,
        http_client: Optional[ScopedHttpClient] = None,
        fp_filter: Optional[FalsePositiveFilter] = None,
        max_requests: int = 10,
        timeout_seconds: float = 15.0,
        delay_seconds: float = 0.05,
    ):
        self.target, self.base_url = _normalize_target_base(target)
        self.target_dir = Path(target_dir).resolve() if target_dir else None
        self.scope_validator = scope_validator or ScopeValidator(self.target, target_dir=self.target_dir)
        self.injected_http_client = http_client
        self.fp_filter = fp_filter or FalsePositiveFilter()
        self.max_requests = max(1, int(max_requests))
        self.timeout_seconds = max(1.0, float(timeout_seconds))
        self.delay_seconds = max(0.0, float(delay_seconds))

        policy_max = getattr(self.scope_validator, "policy", {}).get("max_requests")
        if policy_max:
            self.max_requests = min(self.max_requests, int(policy_max))

    def _build_client(self, budget: int) -> ScopedHttpClient:
        if self.injected_http_client is not None:
            return self.injected_http_client
        return ScopedHttpClient(
            target=self.base_url,
            max_requests=max(1, budget),
            delay_seconds=self.delay_seconds,
            timeout_seconds=self.timeout_seconds,
            scope_validator=self.scope_validator,
            allow_state_changing=False,
        )

    @staticmethod
    def _inspect_response_for_regression(
        route: str,
        resp: Dict[str, Any],
        *,
        expected_status: Optional[int] = None,
        expected_indicator: Optional[str] = None,
        allow_sql_error_as_primary: bool = False,
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        if resp.get("status") != "response":
            return findings

        code = int(resp.get("status_code") or 0)
        body = str(resp.get("body_preview") if "body_preview" in resp else resp.get("body", "") or "")
        body_low = body.lower()
        headers = {str(k).lower(): str(v) for k, v in (resp.get("headers") or {}).items()}

        sql_hits = [dbms for pat, dbms in _SQL_ERROR_PATTERNS if pat.search(body)]
        if sql_hits and not allow_sql_error_as_primary:
            findings.append({
                "kind": "reintroduced_vulnerability",
                "route": route,
                "status_code": code,
                "detail": f"SQL error signature detected ({', '.join(sql_hits)}) on route.",
            })

        if "<moros-probe" in body_low and "morosxss" in body_low:
            findings.append({
                "kind": "reintroduced_vulnerability",
                "route": route,
                "status_code": code,
                "detail": "Unescaped <moros-probe> XSS marker reflected on route.",
            })

        acao = str(headers.get("access-control-allow-origin", "")).strip()
        if acao == "https://moros-cors-test.example":
            findings.append({
                "kind": "reintroduced_vulnerability",
                "route": route,
                "status_code": code,
                "detail": "Arbitrary untrusted Origin reflected in Access-Control-Allow-Origin.",
            })

        if code >= 500 and not (allow_sql_error_as_primary and sql_hits):
            findings.append({
                "kind": "http_5xx",
                "route": route,
                "status_code": code,
                "detail": f"Route returned HTTP {code} (server error / breakage).",
            })
        elif code >= 400 or any(pat.search(body) for pat in _STACK_TRACE_PATTERNS):
            for pat in _STACK_TRACE_PATTERNS:
                m = pat.search(body)
                if m:
                    findings.append({
                        "kind": "stack_trace",
                        "route": route,
                        "status_code": code,
                        "detail": f"Unhandled application error marker '{m.group(0)[:100]}' observed.",
                    })
                    break

        if expected_status is not None and code != int(expected_status):
            findings.append({
                "kind": "functionality_breakage",
                "route": route,
                "status_code": code,
                "detail": f"Expected HTTP {expected_status} on '{route}', received HTTP {code}.",
            })

        if expected_indicator and expected_indicator not in body:
            findings.append({
                "kind": "functionality_breakage",
                "route": route,
                "status_code": code,
                "detail": f"Expected content indicator '{expected_indicator}' missing from '{route}'.",
            })

        return findings

    def analyze(
        self,
        plan: RetestPlan,
        *,
        retest_bundle: Optional[Dict[str, Any]] = None,
        retest_status: str = "",
        routes: Optional[List[Union[str, Dict[str, Any]]]] = None,
        expected_routes: Optional[Dict[str, Dict[str, Any]]] = None,
        check_reintroduced_vulns: bool = False,
        remaining_budget: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Run bounded non-destructive regression checks and inspect retest exchanges."""
        regressions: List[Dict[str, Any]] = []
        checked_routes: List[Dict[str, Any]] = []
        blocked_routes: List[Dict[str, Any]] = []

        # 1. Inspect retest exchanges already captured (0 extra HTTP requests)
        for ex in (retest_bundle or {}).get("exchanges") or []:
            if not isinstance(ex, dict):
                continue
            label = str(ex.get("label", ""))
            req = ex.get("request") or {}
            resp = ex.get("response") or {}
            route = str(req.get("url") or plan.endpoint)
            is_baseline = label in _BASELINE_LABELS
            allow_sql = (plan.strategy == "sqli-heuristic" and not is_baseline and retest_status == "confirmed")
            if is_baseline or retest_status != "confirmed":
                # Check baseline 5xx or unexpected 5xx when vulnerability itself wasn't confirmed
                found = self._inspect_response_for_regression(
                    route,
                    resp,
                    allow_sql_error_as_primary=allow_sql,
                )
                for item in found:
                    # Don't double-report if primary probe returned 404 (handled as inconclusive mismatch)
                    regressions.append(item)

        # 2. Build bounded route list for active non-destructive GET checks
        route_specs: List[Dict[str, Any]] = []
        seen_urls: set[str] = set()

        def _add_spec(spec: Union[str, Dict[str, Any]]) -> None:
            if isinstance(spec, dict):
                raw_u = str(spec.get("url") or spec.get("route") or "").strip()
                if not raw_u:
                    return
                full_u = _resolve_url(self.base_url, raw_u)
                exp_s = spec.get("expected_status")
                exp_i = spec.get("expected_indicator")
            else:
                full_u = _resolve_url(self.base_url, str(spec))
                exp_s = None
                exp_i = None
            if full_u in seen_urls:
                return
            seen_urls.add(full_u)
            exp_cfg = (expected_routes or {}).get(full_u) or (expected_routes or {}).get(urllib.parse.urlsplit(full_u).path) or {}
            route_specs.append({
                "url": full_u,
                "expected_status": exp_s if exp_s is not None else exp_cfg.get("expected_status"),
                "expected_indicator": exp_i if exp_i is not None else exp_cfg.get("expected_indicator"),
            })

        for r in (routes if routes is not None else plan.regression_routes):
            _add_spec(r)
        if expected_routes:
            for r_key in expected_routes:
                _add_spec(r_key)

        budget = self.max_requests if remaining_budget is None else min(self.max_requests, max(0, int(remaining_budget)))
        if not route_specs or budget <= 0:
            deduped_regs = self._dedupe_regressions(regressions)
            return {
                "checked_routes": checked_routes,
                "blocked_routes": blocked_routes,
                "regressions": deduped_regs,
                "regression_detected": bool(deduped_regs),
                "requests_used": 0,
                "status": "regression_detected" if deduped_regs else "passed",
                "summary": self._summarize(deduped_regs, checked_routes, blocked_routes),
            }

        client = self._build_client(budget)
        req_before = getattr(client, "request_count", 0)
        extra_hdrs = {"Origin": "https://moros-cors-test.example"} if plan.strategy == "cors-audit" else None

        for spec in route_specs:
            used_now = max(0, getattr(client, "request_count", 0) - req_before)
            if used_now >= budget:
                break
            url = spec["url"]
            parsed = urllib.parse.urlparse(url)
            allowed, reason = self.scope_validator.is_allowed(parsed.hostname or "")
            if not allowed:
                blocked_routes.append({"route": url, "reason": reason})
                continue

            resp = client.get(url, headers=extra_hdrs)
            if resp.get("status") in ("blocked", "blocked_scope"):
                blocked_routes.append({"route": url, "reason": resp.get("reason", "Blocked by ScopedHttpClient")})
                continue
            if resp.get("status") == "budget_exhausted":
                break

            checked_routes.append({
                "route": _sanitize_text(url, 1024),
                "status": resp.get("status"),
                "status_code": resp.get("status_code"),
            })
            regressions.extend(
                self._inspect_response_for_regression(
                    url,
                    resp,
                    expected_status=spec["expected_status"],
                    expected_indicator=spec["expected_indicator"],
                    allow_sql_error_as_primary=False,
                )
            )

            # Optional bounded probe for reintroduced XSS/SQLi on query-parameterized related routes
            if check_reintroduced_vulns:
                used_now = max(0, getattr(client, "request_count", 0) - req_before)
                if used_now < budget:
                    self._run_bounded_reintro_probe(client, url, plan, regressions, checked_routes)

        requests_used = max(0, getattr(client, "request_count", 0) - req_before)
        deduped_regs = self._dedupe_regressions(regressions)
        status = "regression_detected" if deduped_regs else ("blocked_scope" if blocked_routes and not checked_routes else "passed")

        return {
            "checked_routes": checked_routes,
            "blocked_routes": blocked_routes,
            "regressions": deduped_regs,
            "regression_detected": bool(deduped_regs),
            "requests_used": requests_used,
            "status": status,
            "summary": self._summarize(deduped_regs, checked_routes, blocked_routes),
        }

    def _run_bounded_reintro_probe(
        self,
        client: ScopedHttpClient,
        url: str,
        plan: RetestPlan,
        regressions: List[Dict[str, Any]],
        checked_routes: List[Dict[str, Any]],
    ) -> None:
        parsed = urllib.parse.urlsplit(url)
        items = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        if not items:
            return
        param = items[0][0]
        if plan.strategy == "xss-reflected":
            tok = _deterministic_token(self.target, url, "reg-xss", length=8)
            marker = f"MOROSXSS{tok}"
            payload = f'<moros-probe data-id="{marker}">{marker}</moros-probe>'
        elif plan.strategy == "sqli-heuristic":
            payload = f"{items[0][1] or '1'}'"
        else:
            return

        updated = [(param, payload)] + items[1:]
        probe_url = urllib.parse.urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(updated, doseq=True), "")
        )
        resp = client.get(probe_url)
        if resp.get("status") != "response":
            return
        checked_routes.append({
            "route": _sanitize_text(probe_url, 1024),
            "status": resp.get("status"),
            "status_code": resp.get("status_code"),
            "probe": True,
        })
        regressions.extend(
            self._inspect_response_for_regression(
                probe_url,
                resp,
                allow_sql_error_as_primary=False,
            )
        )

    @staticmethod
    def _dedupe_regressions(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen: set[Tuple[str, str, str]] = set()
        out: List[Dict[str, Any]] = []
        for item in items:
            key = (
                str(item.get("kind", "")),
                str(item.get("route", "")),
                str(item.get("detail", "")),
            )
            if key not in seen:
                seen.add(key)
                out.append(item)
        return out

    @staticmethod
    def _summarize(
        regressions: List[Dict[str, Any]],
        checked: List[Dict[str, Any]],
        blocked: List[Dict[str, Any]],
    ) -> str:
        if regressions:
            kinds = ", ".join(sorted({str(r.get("kind", "unknown")) for r in regressions}))
            return f"Detected {len(regressions)} regression(s) ({kinds}) across {len(checked)} checked route(s)."
        if blocked and not checked:
            return f"All {len(blocked)} regression route(s) blocked by scope policy."
        return f"No regressions detected across {len(checked)} checked route(s)."


class RetestRunner:
    """
    Re-executes the original safe validation strategy against the authorized
    test environment, strictly enforcing ScopeValidator, ScopedHttpClient, and
    CheckpointManager HITL gates, and persists RetestResult JSON records under
    output/evidence/retests/<retest_id>.json.
    """

    def __init__(
        self,
        target: str,
        target_dir: Optional[Union[str, Path]] = None,
        output_dir: Optional[Union[str, Path]] = None,
        scope_validator: Optional[ScopeValidator] = None,
        http_client: Optional[ScopedHttpClient] = None,
        checkpoint_manager: Optional[CheckpointManager] = None,
        oob_server: Optional[OOBServer] = None,
        auth_diff_checker: Optional[AuthDiffChecker] = None,
        fp_filter: Optional[FalsePositiveFilter] = None,
        registry: Optional[ValidationStrategyRegistry] = None,
        proof_recorder: Optional[ProofRecorder] = None,
        comparator: Optional[BeforeAfterComparator] = None,
        regression_analyzer: Optional[RegressionAnalyzer] = None,
        max_requests: int = 40,
        regression_max_requests: int = 10,
        timeout_seconds: float = 15.0,
        max_duration_seconds: float = 60.0,
        delay_seconds: float = 0.05,
        oob_wait_seconds: float = 1.5,
    ):
        self.target, self.base_url = _normalize_target_base(target)
        self.target_dir = Path(target_dir).resolve() if target_dir else None
        if output_dir is not None:
            self.output_dir = Path(output_dir).resolve()
        elif self.target_dir is not None:
            self.output_dir = self.target_dir / "output"
        else:
            raise ValueError("Either target_dir or output_dir must be provided to RetestRunner")

        self.scope_validator = scope_validator or ScopeValidator(self.target, target_dir=self.target_dir)
        self.injected_http_client = http_client
        self.checkpoint_manager = checkpoint_manager
        self.registry = registry or ValidationStrategyRegistry()
        self.proof_recorder = proof_recorder or ProofRecorder(
            self.target, target_dir=self.target_dir, output_dir=self.output_dir
        )
        self.retests_dir = self.output_dir / "evidence" / "retests"
        self.retests_dir.mkdir(parents=True, exist_ok=True)

        self.comparator = comparator or BeforeAfterComparator()
        self.max_requests = max(1, int(max_requests))
        policy_max = getattr(self.scope_validator, "policy", {}).get("max_requests")
        if policy_max:
            self.max_requests = min(self.max_requests, int(policy_max))
        self.regression_max_requests = max(1, int(regression_max_requests))

        self.reproduction_runner = ReproductionRunner(
            target=self.base_url,
            target_dir=self.target_dir,
            output_dir=self.output_dir,
            scope_validator=self.scope_validator,
            http_client=http_client,
            checkpoint_manager=checkpoint_manager,
            oob_server=oob_server,
            auth_diff_checker=auth_diff_checker,
            fp_filter=fp_filter,
            registry=self.registry,
            max_requests=self.max_requests,
            timeout_seconds=timeout_seconds,
            max_duration_seconds=max_duration_seconds,
            delay_seconds=delay_seconds,
            oob_wait_seconds=oob_wait_seconds,
        )
        self.regression_analyzer = regression_analyzer or RegressionAnalyzer(
            target=self.base_url,
            target_dir=self.target_dir,
            scope_validator=self.scope_validator,
            http_client=http_client,
            fp_filter=fp_filter,
            max_requests=self.regression_max_requests,
            timeout_seconds=timeout_seconds,
            delay_seconds=delay_seconds,
        )
        self._run_counter = 0

    def _new_retest_id(self, finding_id: str) -> str:
        self._run_counter += 1
        nonce = secrets.token_hex(4)
        return "ret-" + _deterministic_token(finding_id, _utc_iso(), str(self._run_counter), nonce, length=12)

    def _new_validation_run_id(self, retest_id: str) -> str:
        return "rval-" + _deterministic_token(retest_id, _utc_iso(), secrets.token_hex(4), length=12)

    def _preflight_scope_and_hitl(self, plan: RetestPlan) -> Optional[str]:
        """Return a block reason string if scope or HITL policy forbids execution."""
        if not plan.endpoint:
            return None  # Let missing endpoint classify as inconclusive rather than scope block

        parsed = urllib.parse.urlparse(plan.endpoint)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.port not in {None, 80, 443}
        ):
            return "Blocked by scope policy: disallowed port, credentials in URL, or invalid scheme."

        allowed, scope_reason = self.scope_validator.is_allowed(parsed.hostname)
        if not allowed:
            return f"Blocked by scope policy: {scope_reason}"

        method = plan.method.upper()
        if method in STATE_CHANGING_METHODS:
            if not getattr(self.scope_validator, "policy", {}).get("allow_active_vulnerability_checks", True):
                return "Blocked by scope policy: state-changing checks are disabled."
            if not is_gated_post_enabled():
                return f"Blocked by HITL policy: MOROS_ALLOW_GATED_POST is not enabled for {method} retest."
            if self.checkpoint_manager is None:
                return f"Blocked by HITL policy: CheckpointManager approval is required for {method} retest."
            approved = check_checkpoint_approval(
                self.checkpoint_manager,
                checkpoint_type=f"retest_validation_{plan.strategy}",
                target_url=plan.endpoint,
                method=method,
                reason=f"Retest ({plan.strategy}) requests state-changing {method} probe",
                risk_level="MEDIUM",
            )
            if not approved:
                return f"Blocked by HITL policy: approval denied or pending for {method} retest."
        elif method not in SAFE_METHODS:
            return f"Blocked by scope policy: HTTP method '{method}' is not permitted."

        return None

    def _persist_retest_result(self, result: RetestResult) -> RetestResult:
        """Persist sanitized RetestResult JSON under output/evidence/retests/<retest_id>.json and ledger.jsonl."""
        self.retests_dir.mkdir(parents=True, exist_ok=True)
        out_path = self.retests_dir / f"{result.retest_id}.json"

        payload = _sanitize_structure(result.to_dict())
        payload["schema_version"] = "1.0"
        out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        artifact_hash = hashlib.sha256(out_path.read_bytes()).hexdigest()

        target_root = self.target_dir if self.target_dir is not None else self.output_dir.parent
        try:
            rel_path = str(out_path.relative_to(target_root)).replace("\\", "/")
        except ValueError:
            rel_path = f"output/evidence/retests/{out_path.name}"

        identity = "|".join([
            self.target,
            result.strategy,
            result.retest_id,
            result.finding_id,
            artifact_hash,
        ])
        ev_id = "ev-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]

        result.retest_artifact = rel_path
        result.retest_evidence_id = ev_id
        if ev_id not in result.retest_evidence_ids:
            result.retest_evidence_ids.append(ev_id)

        # Update persisted file with self-referential artifact path & evidence ID
        payload["retest_artifact"] = rel_path
        payload["retest_evidence_id"] = ev_id
        payload["retest_evidence_ids"] = list(result.retest_evidence_ids)
        out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        final_hash = hashlib.sha256(out_path.read_bytes()).hexdigest()

        ledger_entry = {
            "target": self.target,
            "skill": result.strategy,
            "finding_type": result.strategy,
            "finding_id": result.finding_id,
            "retest_id": result.retest_id,
            "remediation_id": result.remediation_id,
            "code_version": result.code_version,
            "evidence_id": ev_id,
            "evidence_type": "retest_result",
            "source_artifact": rel_path,
            "source_sha256": final_hash,
            "source_available": True,
            "claim": (
                f"Retest {result.retest_id} via '{result.strategy}' produced outcome "
                f"'{result.outcome}' (confidence={result.confidence:.2f})."
            ),
            "limitations": "; ".join(result.limitations) if result.limitations else "None",
            "verification_status": result.outcome,
            "confidence": result.confidence,
            "recorded_at": result.timestamp,
        }
        existing_ids = self.proof_recorder._load_existing_ids()
        if ev_id not in existing_ids:
            self.proof_recorder.ledger_path.parent.mkdir(parents=True, exist_ok=True)
            with self.proof_recorder.ledger_path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(ledger_entry, ensure_ascii=False) + "\n")
            existing_ids.add(ev_id)

        return result

    def verify_retest_integrity(self, retest_ref: Union[str, Path]) -> Dict[str, Any]:
        """Verify persisted RetestResult JSON exists and matches its SHA-256 entry in ledger.jsonl."""
        ref_str = str(retest_ref or "").strip()
        candidate = Path(ref_str)
        if candidate.is_file():
            retest_path = candidate
        else:
            norm = _normalize_path(ref_str)
            target_root = self.target_dir if self.target_dir is not None else self.output_dir.parent
            if norm.startswith("output/") and (target_root / norm).is_file():
                retest_path = target_root / norm
            else:
                retest_path = self.retests_dir / (ref_str if ref_str.endswith(".json") else f"{ref_str}.json")

        if not retest_path.is_file():
            return {
                "valid": False,
                "exists": False,
                "reason": f"Retest artifact not found: {retest_path}",
                "expected_sha256": None,
                "actual_sha256": None,
            }

        actual_sha256 = hashlib.sha256(retest_path.read_bytes()).hexdigest()
        try:
            data = json.loads(retest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return {
                "valid": False,
                "exists": True,
                "reason": f"Corrupt retest JSON: {exc}",
                "expected_sha256": None,
                "actual_sha256": actual_sha256,
            }

        rid = str(data.get("retest_id", ""))
        target_root = self.target_dir if self.target_dir is not None else self.output_dir.parent
        try:
            rel_norm = str(retest_path.relative_to(target_root)).replace("\\", "/")
        except ValueError:
            rel_norm = f"output/evidence/retests/{retest_path.name}"

        matched: Optional[Dict[str, Any]] = None
        if self.proof_recorder.ledger_path.is_file():
            for line in self.proof_recorder.ledger_path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(entry, dict):
                    continue
                art = _normalize_path(entry.get("source_artifact", ""))
                if (rid and entry.get("retest_id") == rid) or art == rel_norm:
                    matched = entry
                    break

        if matched is None:
            return {
                "valid": False,
                "exists": True,
                "reason": "No matching provenance entry in ledger.jsonl",
                "expected_sha256": None,
                "actual_sha256": actual_sha256,
            }

        expected_sha256 = str(matched.get("source_sha256", ""))
        valid = bool(expected_sha256) and expected_sha256 == actual_sha256
        return {
            "valid": valid,
            "exists": True,
            "reason": "SHA-256 matches ledger provenance" if valid else "SHA-256 mismatch with ledger provenance",
            "expected_sha256": expected_sha256,
            "actual_sha256": actual_sha256,
            "evidence_id": matched.get("evidence_id", ""),
        }

    def run_plan(
        self,
        plan: RetestPlan,
        finding: Optional[Dict[str, Any]] = None,
        *,
        retest_id: Optional[str] = None,
        remaining_budget: Optional[int] = None,
        regression_routes: Optional[List[Union[str, Dict[str, Any]]]] = None,
        expected_routes: Optional[Dict[str, Dict[str, Any]]] = None,
        check_reintroduced_vulns: bool = False,
    ) -> RetestResult:
        """Execute a RetestPlan and persist a structured RetestResult."""
        rid = retest_id or self._new_retest_id(plan.finding_id)
        budget_cap = self.max_requests if remaining_budget is None else max(0, int(remaining_budget))

        # 1. Enforce scope & HITL gates before sending any traffic
        block_reason = self._preflight_scope_and_hitl(plan)
        if block_reason:
            res = RetestResult(
                retest_id=rid,
                plan_id=plan.plan_id,
                finding_id=plan.finding_id,
                target=plan.target,
                endpoint=_sanitize_text(plan.endpoint, 2048),
                method=plan.method,
                strategy=plan.strategy,
                strategy_version=plan.strategy_version,
                outcome="blocked_scope",
                confidence=1.0,
                remediation_id=plan.remediation_id,
                code_version=plan.code_version,
                environment=dict(plan.environment),
                limitations=_dedupe_strs(list(plan.limitations) + [block_reason]),
                original_validation_run_id=plan.original_validation_run_id,
                original_evidence_ids=list(plan.original_evidence_ids),
                original_proof_artifact=plan.original_proof_artifact,
                original_proof_sha256=plan.original_proof_sha256,
                requests_used=0,
                details={"blocked_reason": block_reason},
            )
            return self._persist_retest_result(res)

        # 2. Construct deterministic probe finding payload from plan + original finding
        probe_finding: Dict[str, Any] = dict(finding or {})
        probe_finding["finding_id"] = plan.finding_id
        probe_finding["url"] = plan.endpoint
        probe_finding["method"] = plan.method
        probe_finding["strategy"] = plan.strategy
        if not probe_finding.get("parameter") and isinstance(plan.original_proof_bundle.get("finding"), dict):
            orig_param = plan.original_proof_bundle["finding"].get("parameter")
            if orig_param:
                probe_finding["parameter"] = orig_param

        # 3. Re-run original safe validation strategy via Phase 1 ReproductionRunner
        val_run_id = self._new_validation_run_id(rid)
        retest_vr, retest_bundle = self.reproduction_runner.run(
            probe_finding,
            finding_id=plan.finding_id,
            validation_run_id=val_run_id,
            remaining_budget=budget_cap,
        )
        proof_rel, val_ev_id = self.proof_recorder.record_proof(
            result=retest_vr,
            finding=probe_finding,
            exchanges=retest_bundle.get("exchanges"),
            oob_callbacks=retest_bundle.get("oob_callbacks"),
            auth_diff=retest_bundle.get("auth_diff"),
        )
        retest_vr.proof_artifact = proof_rel
        if val_ev_id not in retest_vr.evidence_ids:
            retest_vr.evidence_ids.append(val_ev_id)

        # 4. Deterministic before/after comparison
        before_after = self.comparator.compare(
            plan,
            retest_vr,
            original_bundle=plan.original_proof_bundle,
            retest_bundle=retest_bundle,
            finding=probe_finding,
        )

        # 5. Bounded non-destructive regression checks (unless blocked by scope)
        rem_for_reg = max(0, budget_cap - retest_vr.requests_used)
        if before_after["suggested_outcome"] == "blocked_scope":
            regression_report: Dict[str, Any] = {
                "checked_routes": [],
                "blocked_routes": [{"route": plan.endpoint, "reason": "Blocked by scope/HITL policy"}],
                "regressions": [],
                "regression_detected": False,
                "requests_used": 0,
                "status": "blocked_scope",
                "summary": "Regression analysis skipped because primary retest was blocked by scope policy.",
            }
        else:
            regression_report = self.regression_analyzer.analyze(
                plan,
                retest_bundle=retest_bundle,
                retest_status=retest_vr.status,
                routes=regression_routes,
                expected_routes=expected_routes,
                check_reintroduced_vulns=check_reintroduced_vulns,
                remaining_budget=rem_for_reg,
            )

        total_requests = retest_vr.requests_used + int(regression_report.get("requests_used") or 0)

        # 6. Derive final outcome deterministically without inflating claims
        suggested = before_after["suggested_outcome"]
        if suggested == "blocked_scope":
            outcome = "blocked_scope"
            confidence = 1.0
        elif suggested == "still_vulnerable":
            outcome = "still_vulnerable"
            confidence = before_after["confidence"]
        elif regression_report.get("regression_detected"):
            outcome = "regression_detected"
            confidence = 0.90
        elif suggested == "inconclusive":
            outcome = "inconclusive"
            confidence = before_after["confidence"]
        elif suggested == "fixed":
            outcome = "fixed"
            confidence = before_after["confidence"]
        else:
            outcome = "inconclusive"
            confidence = 0.25

        limitations = list(before_after.get("limitations") or [])
        if outcome == "regression_detected":
            limitations.append(str(regression_report.get("summary") or "Regression detected during retest."))
        if outcome == "fixed" and FIXED_LIMITATION_NOTE not in limitations:
            limitations.append(FIXED_LIMITATION_NOTE)

        result = RetestResult(
            retest_id=rid,
            plan_id=plan.plan_id,
            finding_id=plan.finding_id,
            target=plan.target,
            endpoint=_sanitize_text(plan.endpoint, 2048),
            method=plan.method,
            strategy=plan.strategy,
            strategy_version=plan.strategy_version,
            outcome=outcome,
            confidence=confidence,
            remediation_id=plan.remediation_id,
            code_version=plan.code_version,
            environment=dict(plan.environment),
            limitations=_dedupe_strs(limitations),
            original_validation_run_id=plan.original_validation_run_id,
            original_evidence_ids=list(plan.original_evidence_ids),
            original_proof_artifact=plan.original_proof_artifact,
            original_proof_sha256=plan.original_proof_sha256,
            retest_validation_run_id=retest_vr.validation_run_id,
            retest_proof_artifact=proof_rel,
            retest_evidence_ids=list(retest_vr.evidence_ids),
            before_after=before_after,
            regression_report=regression_report,
            requests_used=total_requests,
            details={
                "retest_validation_status": retest_vr.status,
                "retest_validation_details": retest_vr.details,
                "original_proof_integrity": plan.original_proof_integrity,
            },
        )
        return self._persist_retest_result(result)


def update_finding_lifecycle(
    finding: Dict[str, Any],
    retest_result: Union[RetestResult, Dict[str, Any]],
    *,
    mutate: bool = False,
) -> Dict[str, Any]:
    """
    Update finding lifecycle state from a RetestResult while NEVER deleting
    historical evidence_ids, proof_artifact, or prior validation_result.
    Appends an immutable entry to finding['retest_history'].
    """
    target_finding = finding if mutate else copy.deepcopy(finding)
    rr = retest_result.to_dict() if isinstance(retest_result, RetestResult) else dict(retest_result or {})

    outcome = str(rr.get("outcome") or "inconclusive").strip().lower()
    prior_status = str(target_finding.get("status") or "").strip().lower()
    prior_vr = target_finding.get("validation_result")
    prior_vr_status = str(prior_vr.get("status", "")).strip().lower() if isinstance(prior_vr, dict) else ""

    if outcome == "fixed":
        new_status = "fixed"
        new_val_status = "fixed"
    elif outcome in ("still_vulnerable", "regression_detected"):
        if prior_status in ("confirmed", "validated", "validating"):
            new_status = prior_status
        elif prior_vr_status == "confirmed":
            new_status = "confirmed"
        else:
            new_status = "validating"
        new_val_status = new_status
    elif outcome == "inconclusive":
        new_status = "inconclusive"
        new_val_status = "inconclusive"
    elif outcome == "blocked_scope":
        if prior_status in ("confirmed", "validated", "validating"):
            new_status = prior_status
            new_val_status = prior_status
        else:
            new_status = "blocked_scope"
            new_val_status = "blocked_scope"
    else:
        new_status = "inconclusive"
        new_val_status = "inconclusive"

    target_finding["status"] = new_status
    target_finding["validation_status"] = new_val_status
    if rr.get("finding_id") and not target_finding.get("finding_id"):
        target_finding["finding_id"] = rr["finding_id"]

    # Preserve ALL historical evidence_ids and append new retest evidence IDs
    preserved_ids = list(target_finding.get("evidence_ids") or [])
    for eid in (rr.get("original_evidence_ids") or []):
        if eid and eid not in preserved_ids:
            preserved_ids.append(eid)
    for eid in (rr.get("retest_evidence_ids") or []):
        if eid and eid not in preserved_ids:
            preserved_ids.append(eid)
    retest_ev_id = str(rr.get("retest_evidence_id") or "").strip()
    if retest_ev_id and retest_ev_id not in preserved_ids:
        preserved_ids.append(retest_ev_id)
    target_finding["evidence_ids"] = preserved_ids

    # Never delete/overwrite historical proof_artifact or validation_result;
    # populate proof_artifact only if it was previously empty and an original exists.
    if not target_finding.get("proof_artifact") and rr.get("original_proof_artifact"):
        target_finding["proof_artifact"] = rr["original_proof_artifact"]

    history = target_finding.get("retest_history")
    if not isinstance(history, list):
        history = []
    history_entry = {
        "retest_id": rr.get("retest_id", ""),
        "plan_id": rr.get("plan_id", ""),
        "outcome": outcome,
        "confidence": rr.get("confidence", 0.0),
        "timestamp": rr.get("timestamp", _utc_iso()),
        "remediation_id": rr.get("remediation_id", ""),
        "code_version": rr.get("code_version", ""),
        "retest_artifact": rr.get("retest_artifact", ""),
        "retest_proof_artifact": rr.get("retest_proof_artifact", ""),
        "retest_evidence_id": retest_ev_id,
        "original_validation_run_id": rr.get("original_validation_run_id", ""),
        "original_proof_artifact": rr.get("original_proof_artifact", ""),
        "original_proof_sha256": rr.get("original_proof_sha256", ""),
        "limitations": list(rr.get("limitations") or []),
        "regression_detected": bool((rr.get("regression_report") or {}).get("regression_detected", False)),
    }
    history.append(history_entry)
    target_finding["retest_history"] = history
    target_finding["latest_retest"] = history_entry
    target_finding["retest_outcome"] = outcome
    target_finding["confidence_score"] = rr.get("confidence", target_finding.get("confidence_score", 0.0))
    if outcome == "fixed":
        target_finding["confidence"] = _confidence_label(float(rr.get("confidence") or 0.8))

    return target_finding


class RetestEngine:
    """High-level Phase 4 coordinator combining planning, execution, comparison, regression analysis, and lifecycle updates."""

    def __init__(
        self,
        target: str,
        target_dir: Optional[Union[str, Path]] = None,
        output_dir: Optional[Union[str, Path]] = None,
        scope_validator: Optional[ScopeValidator] = None,
        http_client: Optional[ScopedHttpClient] = None,
        checkpoint_manager: Optional[CheckpointManager] = None,
        oob_server: Optional[OOBServer] = None,
        auth_diff_checker: Optional[AuthDiffChecker] = None,
        fp_filter: Optional[FalsePositiveFilter] = None,
        registry: Optional[ValidationStrategyRegistry] = None,
        proof_recorder: Optional[ProofRecorder] = None,
        max_requests: int = 50,
        regression_max_requests: int = 10,
        timeout_seconds: float = 15.0,
        max_duration_seconds: float = 60.0,
        delay_seconds: float = 0.05,
        oob_wait_seconds: float = 1.5,
    ):
        self.target, self.base_url = _normalize_target_base(target)
        self.target_dir = Path(target_dir).resolve() if target_dir else None
        if output_dir is not None:
            self.output_dir = Path(output_dir).resolve()
        elif self.target_dir is not None:
            self.output_dir = self.target_dir / "output"
        else:
            raise ValueError("Either target_dir or output_dir must be provided to RetestEngine")

        self.scope_validator = scope_validator or ScopeValidator(self.target, target_dir=self.target_dir)
        self.registry = registry or ValidationStrategyRegistry()
        self.proof_recorder = proof_recorder or ProofRecorder(
            self.target, target_dir=self.target_dir, output_dir=self.output_dir
        )
        self.planner = RetestPlanner(
            target=self.base_url,
            target_dir=self.target_dir,
            output_dir=self.output_dir,
            proof_recorder=self.proof_recorder,
            registry=self.registry,
        )
        self.comparator = BeforeAfterComparator()
        self.regression_analyzer = RegressionAnalyzer(
            target=self.base_url,
            target_dir=self.target_dir,
            scope_validator=self.scope_validator,
            http_client=http_client,
            fp_filter=fp_filter,
            max_requests=regression_max_requests,
            timeout_seconds=timeout_seconds,
            delay_seconds=delay_seconds,
        )
        self.runner = RetestRunner(
            target=self.base_url,
            target_dir=self.target_dir,
            output_dir=self.output_dir,
            scope_validator=self.scope_validator,
            http_client=http_client,
            checkpoint_manager=checkpoint_manager,
            oob_server=oob_server,
            auth_diff_checker=auth_diff_checker,
            fp_filter=fp_filter,
            registry=self.registry,
            proof_recorder=self.proof_recorder,
            comparator=self.comparator,
            regression_analyzer=self.regression_analyzer,
            max_requests=max_requests,
            regression_max_requests=regression_max_requests,
            timeout_seconds=timeout_seconds,
            max_duration_seconds=max_duration_seconds,
            delay_seconds=delay_seconds,
            oob_wait_seconds=oob_wait_seconds,
        )
        self.max_requests = self.runner.max_requests
        self._total_requests_used = 0

    def plan_retest(
        self,
        finding: Dict[str, Any],
        *,
        validation_result: Optional[Union[ValidationResult, Dict[str, Any]]] = None,
        proof_artifact: Optional[Union[str, Path]] = None,
        remediation_id: str = "",
        code_version: str = "",
        environment: Optional[Dict[str, Any]] = None,
        regression_routes: Optional[List[str]] = None,
    ) -> RetestPlan:
        return self.planner.build_plan(
            finding,
            validation_result=validation_result,
            proof_artifact=proof_artifact,
            remediation_id=remediation_id,
            code_version=code_version,
            environment=environment,
            regression_routes=regression_routes,
        )

    def retest_finding(
        self,
        finding: Dict[str, Any],
        *,
        validation_result: Optional[Union[ValidationResult, Dict[str, Any]]] = None,
        proof_artifact: Optional[Union[str, Path]] = None,
        remediation_id: str = "",
        code_version: str = "",
        environment: Optional[Dict[str, Any]] = None,
        regression_routes: Optional[List[Union[str, Dict[str, Any]]]] = None,
        expected_routes: Optional[Dict[str, Dict[str, Any]]] = None,
        check_reintroduced_vulns: bool = False,
        mutate_finding: bool = True,
        retest_id: Optional[str] = None,
    ) -> RetestResult:
        """Plan, execute, compare, analyze regressions, persist result, and optionally update finding lifecycle."""
        plan_routes: Optional[List[str]] = None
        if regression_routes is not None:
            plan_routes = [
                str(r.get("url") or r.get("route") or "") if isinstance(r, dict) else str(r)
                for r in regression_routes
            ]
        plan = self.plan_retest(
            finding,
            validation_result=validation_result,
            proof_artifact=proof_artifact,
            remediation_id=remediation_id,
            code_version=code_version,
            environment=environment,
            regression_routes=plan_routes,
        )
        remaining = max(0, self.max_requests - self._total_requests_used)
        result = self.runner.run_plan(
            plan,
            finding=finding,
            retest_id=retest_id,
            remaining_budget=remaining,
            regression_routes=regression_routes,
            expected_routes=expected_routes,
            check_reintroduced_vulns=check_reintroduced_vulns,
        )
        self._total_requests_used += result.requests_used

        if mutate_finding:
            update_finding_lifecycle(finding, result, mutate=True)

        return result

    def retest_findings(
        self,
        findings: Iterable[Dict[str, Any]],
        *,
        remediation_id: str = "",
        code_version: str = "",
        environment: Optional[Dict[str, Any]] = None,
        regression_routes: Optional[List[Union[str, Dict[str, Any]]]] = None,
        expected_routes: Optional[Dict[str, Dict[str, Any]]] = None,
        check_reintroduced_vulns: bool = False,
        mutate_findings: bool = True,
        skip_accepted_risk: bool = True,
    ) -> List[RetestResult]:
        results: List[RetestResult] = []
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            if skip_accepted_risk and finding.get("status") == "accepted_risk":
                continue
            results.append(
                self.retest_finding(
                    finding,
                    remediation_id=remediation_id,
                    code_version=code_version,
                    environment=environment,
                    regression_routes=regression_routes,
                    expected_routes=expected_routes,
                    check_reintroduced_vulns=check_reintroduced_vulns,
                    mutate_finding=mutate_findings,
                )
            )
        return results

    def verify_retest_integrity(self, retest_ref: Union[str, Path]) -> Dict[str, Any]:
        return self.runner.verify_retest_integrity(retest_ref)

    @staticmethod
    def update_finding_lifecycle(
        finding: Dict[str, Any],
        retest_result: Union[RetestResult, Dict[str, Any]],
        *,
        mutate: bool = False,
    ) -> Dict[str, Any]:
        return update_finding_lifecycle(finding, retest_result, mutate=mutate)
