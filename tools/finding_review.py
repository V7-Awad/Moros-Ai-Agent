"""Evidence integrity and adversarial review for generated candidate findings.

These stages are deliberately non-invasive: they inspect saved artifacts only.
They never promote a candidate to a validated vulnerability; that requires an
authorized, reproducible verification step.
"""

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlparse

try:
    from scope_validator import ScopeValidator
except ImportError:
    from tools.scope_validator import ScopeValidator

try:
    from finding_dedupe import LIFECYCLE_STATES, resolve_finding_lifecycle
except ImportError:
    from tools.finding_dedupe import LIFECYCLE_STATES, resolve_finding_lifecycle

try:
    from cvss_calculator import score_finding
except ImportError:
    from tools.cvss_calculator import score_finding

try:
    from fp_filter import FalsePositiveFilter
except ImportError:
    from tools.fp_filter import FalsePositiveFilter


def _artifact_path(target_dir: Path, value: str) -> Path:
    candidate = Path(str(value or ""))
    if candidate.is_absolute():
        return candidate
    normalized = str(value or "").replace("\\", "/")
    if normalized.startswith("targets/"):
        # Project-root relative artifacts are resolved from the target directory's
        # parent (targets/<name> -> project root).
        return target_dir.parent.parent / Path(normalized)
    if normalized.startswith("output/"):
        return target_dir / Path(normalized)
    return target_dir / "output" / candidate


def review_candidates(target: str, target_dir: Path, findings: List[Dict[str, Any]],
                      active_checks_allowed: bool) -> Dict[str, Any]:
    """Attach evidence-integrity results and skeptical objections to candidates."""
    policy = ScopeValidator(target, target_dir=target_dir).policy
    out_of_host_requests = {}
    audit_file = target_dir / "output" / "logs" / "scope-audit-latest.json"
    audit_data = {}
    if audit_file.is_file():
        try:
            audit_data = json.loads(audit_file.read_text(encoding="utf-8"))
            out_of_host_requests.update(audit_data.get("out_of_scope_hosts", {}))
        except (OSError, json.JSONDecodeError, AttributeError):
            pass
    traffic_log = target_dir / "output" / "js" / "traffic-log.json"
    if not audit_data and policy.get("same_host_only") and traffic_log.is_file():
        try:
            traffic = json.loads(traffic_log.read_text(encoding="utf-8"))
            for request in traffic if isinstance(traffic, list) else []:
                host = (urlparse(str(request.get("url", ""))).hostname or "").lower().rstrip(".")
                if host and host != target.lower().rstrip("."):
                    out_of_host_requests[host] = out_of_host_requests.get(host, 0) + 1
        except (OSError, json.JSONDecodeError):
            pass
    # A rejected redirect records an attempted destination, not a request sent
    # there. Only an observed out-of-scope request should taint attribution.
    scope_deviation = bool(
        audit_data.get("deviation_detected", bool(out_of_host_requests))
        or out_of_host_requests
    )
    fp_filter = FalsePositiveFilter()
    lifecycle_counts: Dict[str, int] = {state: 0 for state in sorted(LIFECYCLE_STATES)}
    reviewed = []
    for index, item in enumerate(findings, 1):
        finding = dict(item)
        evidence_rows = finding.get("evidence", [])
        if not isinstance(evidence_rows, list):
            evidence_rows = []
        source = finding.get("source_artifact", "")
        if not source and evidence_rows and isinstance(evidence_rows[0], dict):
            source = evidence_rows[0].get("source_artifact", "")
        path = _artifact_path(target_dir, source) if source else None
        exists = bool(path and path.is_file())
        expected_hash = ""
        if evidence_rows and isinstance(evidence_rows[0], dict):
            expected_hash = str(evidence_rows[0].get("source_sha256", ""))
        actual_hash = ""
        if exists:
            try:
                actual_hash = hashlib.sha256(path.read_bytes()).hexdigest()
            except OSError:
                exists = False
        hash_matches = bool(expected_hash and actual_hash and expected_hash == actual_hash)

        vr = finding.get("validation_result")
        proof_ref = vr.get("proof_artifact") if isinstance(vr, dict) else finding.get("proof_artifact")
        proof_path = _artifact_path(target_dir, str(proof_ref)) if proof_ref else None
        proof_exists = bool(proof_path and proof_path.is_file())

        kind = str(finding.get("type", finding.get("category", ""))).casefold()
        title = str(finding.get("title", "Candidate finding"))
        if "xss" in kind or "xss" in title.casefold():
            objection = (
                "Static sink evidence alone does not show attacker-controlled input reaching an executable context; "
                "source-to-sink flow and runtime reproduction are missing."
            )
        elif "secret" in kind or "secret" in title.casefold() or "credential" in title.casefold():
            objection = (
                "A pattern match or fingerprint does not establish that a value is a live credential, "
                "privileged, or accepted by the service. Do not expose or test the value automatically."
            )
        else:
            objection = (
                "The saved artifact is a lead, not proof of security impact; a reproducible impact chain "
                "and program-safe verification evidence are still required."
            )

        status, validation_status = resolve_finding_lifecycle(finding)
        lifecycle_counts[status] = lifecycle_counts.get(status, 0) + 1

        if status == "confirmed":
            scope_attr = "unreliable_due_to_scope_deviation" if scope_deviation else "machine_verified"
            disposition = "machine_confirmed"
            review_objection = "Deterministically verified via ProofRecorder evidence; human sign-off recommended before remediation."
            next_step = "remediation or human triage sign-off"
        elif status == "validated":
            scope_attr = "unreliable_due_to_scope_deviation" if scope_deviation else "human_verified"
            disposition = "human_validated"
            review_objection = "Reproduced and validated by a human reviewer."
            next_step = "remediation"
        elif status in ("validating", "inconclusive", "false_positive", "fixed", "accepted_risk"):
            scope_attr = "unreliable_due_to_scope_deviation" if scope_deviation else status
            disposition = status
            review_objection = objection if status in ("validating", "inconclusive") else f"Finding lifecycle state recorded as '{status}'."
            next_step = {
                "validating": "await validation completion",
                "inconclusive": "manual or targeted follow-up verification",
                "false_positive": "none (suppressed as false positive)",
                "fixed": "closed (verified fixed on retest)",
                "accepted_risk": "tracked under human-accepted risk",
            }[status]
        else:
            scope_attr = "unreliable_due_to_scope_deviation" if scope_deviation else "not_independently_verified"
            disposition = "not_proven"
            review_objection = objection
            next_step = "authorized reproducible verification" if active_checks_allowed else "blocked by saved scope policy"

        cvss_data = finding.get("cvss") if isinstance(finding.get("cvss"), dict) else score_finding(finding)
        fp_analysis = fp_filter.check_finding(finding)

        finding["validation_status"] = validation_status
        finding["status"] = status
        finding["scope_attribution"] = scope_attr
        finding["cvss"] = cvss_data
        finding["fp_analysis"] = fp_analysis
        finding["evidence_review"] = {
            "source_artifact": str(source) if source else None,
            "source_exists": exists,
            "expected_sha256_present": bool(expected_hash),
            "sha256_matches": hash_matches if expected_hash else None,
            "proof_artifact": str(proof_ref) if proof_ref else None,
            "proof_exists": proof_exists if proof_ref else None,
            "result": "integrity_pass" if exists and (not expected_hash or hash_matches) else "integrity_incomplete",
        }
        finding["skeptical_review"] = {
            "disposition": disposition,
            "objection": review_objection,
            "required_next_step": next_step,
        }
        item.update({
            "validation_status": finding["validation_status"],
            "status": finding["status"],
            "scope_attribution": finding["scope_attribution"],
            "evidence_review": finding["evidence_review"],
            "skeptical_review": finding["skeptical_review"],
            "cvss": finding["cvss"],
            "fp_analysis": finding["fp_analysis"],
        })
        reviewed.append({
            "finding_index": index,
            "title": title,
            "type": finding.get("type", finding.get("category", "unknown")),
            "status": finding["status"],
            "validation_status": finding["validation_status"],
            "evidence_review": finding["evidence_review"],
            "skeptical_review": finding["skeptical_review"],
            "cvss": finding["cvss"],
            "fp_analysis": finding["fp_analysis"],
        })

    confirmed_count = lifecycle_counts.get("confirmed", 0)
    human_validated_count = lifecycle_counts.get("validated", 0)
    candidate_count = lifecycle_counts.get("candidate", 0)

    return {
        "target": target,
        "review_type": "saved_artifact_integrity_and_adversarial_triage",
        "network_requests": 0,
        "validated_findings": confirmed_count + human_validated_count,
        "confirmed_findings": confirmed_count,
        "human_validated_findings": human_validated_count,
        "unverified_candidates": candidate_count,
        "lifecycle_counts": lifecycle_counts,
        "scope_blocks_reproduction": not active_checks_allowed,
        "scope_execution_audit": {
            "deviation_detected": scope_deviation,
            "stopped_by_policy": bool(audit_data.get("stopped_by_policy")),
            "out_of_host_request_counts": out_of_host_requests,
            "finding_attribution": "unreliable_due_to_scope_deviation" if scope_deviation else "not_independently_verified",
        },
        "findings": reviewed,
    }
