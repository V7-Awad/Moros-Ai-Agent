"""Validation and normalization of learning-engine payloads."""

from __future__ import annotations

import json
import re

from .config import (
    LIFECYCLE_VERDICT_MAP,
    REMEDIATION_OUTCOMES,
    RETEST_OUTCOMES,
    SEVERITIES,
    VALIDATION_OUTCOMES,
    VERDICTS,
)

_ID_RE = re.compile(r"[^a-z0-9_.-]+")
_FINDING_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]*$")


def normalize_target(target: str) -> str:
    t = str(target or "").strip().lower()
    if not t:
        raise ValueError("target must be non-empty")
    return t.rstrip("/")


def normalize_vuln_class(vuln_class: str) -> str:
    v = str(vuln_class or "").strip().lower()
    normalized = _ID_RE.sub("-", v).strip("-")
    if not normalized:
        raise ValueError("vuln_class must be non-empty")
    return normalized


def normalize_finding_id(finding_id: str) -> str:
    f = str(finding_id or "").strip().lower()
    if not _FINDING_ID_RE.match(f):
        raise ValueError(
            f"invalid finding_id {f!r}: lowercase letters, digits, '.', '_', '-' only"
        )
    return f


def validate_severity(severity: str) -> str:
    s = str(severity or "").strip().lower()
    if s not in SEVERITIES:
        raise ValueError(f"severity must be one of {SEVERITIES}, got {s!r}")
    return s


def validate_confidence(confidence: float) -> float:
    c = float(confidence)
    if not (0.0 <= c <= 1.0):
        raise ValueError(f"confidence must be within [0, 1], got {c}")
    return c


def validate_verdict(verdict: str) -> str:
    v = str(verdict or "").strip().lower()
    if v not in VERDICTS:
        raise ValueError(f"verdict must be one of {VERDICTS}, got {v!r}")
    return v


def validate_signals(signals: dict | None) -> dict:
    if not signals:
        return {}
    if not isinstance(signals, dict):
        raise TypeError("signals must be a dict of signal key -> truthy value")
    out: dict = {}
    for key, value in signals.items():
        k = str(key).strip().lower()
        if not k:
            continue
        if isinstance(value, (int, float, bool, str)):
            out[k] = value
    return out


def parse_signals_json(raw: str | None) -> dict:
    """Safely parse a JSON-encoded signals dict, returning {} on invalid/null values."""
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def validate_validation_outcome(outcome: str) -> str:
    """Validate an extended validation outcome (confirmed, false_positive, inconclusive, unverified)."""
    o = str(outcome or "").strip().lower()
    if o not in VALIDATION_OUTCOMES:
        raise ValueError(f"validation outcome must be one of {VALIDATION_OUTCOMES}, got {o!r}")
    return o


def validate_remediation_outcome(outcome: str) -> str:
    """Validate a remediation lifecycle outcome."""
    o = str(outcome or "").strip().lower()
    if o not in REMEDIATION_OUTCOMES:
        raise ValueError(f"remediation outcome must be one of {REMEDIATION_OUTCOMES}, got {o!r}")
    return o


def validate_retest_outcome(outcome: str) -> str:
    """Validate a retest lifecycle outcome (fixed, still_vulnerable, regression_detected, inconclusive)."""
    o = str(outcome or "").strip().lower()
    if o not in RETEST_OUTCOMES:
        raise ValueError(f"retest outcome must be one of {RETEST_OUTCOMES}, got {o!r}")
    return o


def map_outcome_to_verdict(outcome: str) -> str:
    """Map an extended lifecycle outcome onto the canonical VERDICTS tuple."""
    o = str(outcome or "").strip().lower()
    return LIFECYCLE_VERDICT_MAP.get(o, "unverified")


def normalize_tech_name(tech: str) -> str:
    """Normalize a technology fingerprint name (lowercase, stripped)."""
    t = str(tech or "").strip().lower()
    if not t:
        raise ValueError("technology name must be non-empty")
    return t


def validate_evidence_ids(evidence_ids: list[str] | tuple[str, ...] | None) -> list[str]:
    """Normalize a sequence of evidence IDs into unique non-empty strings."""
    if not evidence_ids:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for item in evidence_ids:
        val = str(item or "").strip()
        if val and val not in seen:
            seen.add(val)
            out.append(val)
    return out


def validate_metadata(metadata: dict | None) -> dict:
    """Validate optional metadata dict, returning {} if None."""
    if not metadata:
        return {}
    if not isinstance(metadata, dict):
        raise TypeError("metadata must be a dict")
    return dict(metadata)


def parse_json_list(raw: str | None) -> list:
    """Safely parse a JSON-encoded list, returning [] on invalid/null values."""
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError, ValueError):
        return []
    return parsed if isinstance(parsed, list) else []


def parse_json_dict(raw: str | None) -> dict:
    """Safely parse a JSON-encoded dict, returning {} on invalid/null values."""
    return parse_signals_json(raw)