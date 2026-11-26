"""Shared candidate-finding identity and aggregation for API, reports, and UI."""

import hashlib
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple
from urllib.parse import urlsplit, urlunsplit


LIFECYCLE_STATES = frozenset({
    "candidate",
    "validating",
    "confirmed",
    "validated",
    "inconclusive",
    "false_positive",
    "fixed",
    "accepted_risk",
})

_LIFECYCLE_PRECEDENCE: Dict[str, int] = {
    "accepted_risk": 7,
    "fixed": 6,
    "false_positive": 5,
    "validated": 4,
    "confirmed": 3,
    "validating": 2,
    "inconclusive": 1,
    "candidate": 0,
}


def _resolve_human_record(item: Dict[str, Any]) -> Tuple[bool, str, str]:
    record = item.get("validation_record")
    if not isinstance(record, dict):
        return False, "candidate", "unverified"
    if not str(record.get("verified_by", "")).strip().startswith("human:"):
        return False, "candidate", "unverified"
    outcome = str(record.get("outcome", "")).strip().lower()
    req_status = str(item.get("status", "")).strip().lower()
    if outcome == "accepted_risk" or req_status == "accepted_risk":
        return True, "accepted_risk", "accepted_risk"
    if outcome == "fixed":
        return True, "fixed", "fixed"
    if outcome in ("false_positive", "not_reproduced"):
        return True, "false_positive", "false_positive"
    if outcome == "inconclusive":
        return True, "inconclusive", "inconclusive"
    if outcome == "reproduced" and bool(record.get("method")) and bool(record.get("evidence_ids")):
        return True, "validated", "validated"
    return False, "candidate", "unverified"


def _resolve_machine_result(item: Dict[str, Any]) -> Tuple[bool, str, str]:
    vr = item.get("validation_result")
    if not isinstance(vr, dict):
        return False, "candidate", "unverified"
    if (
        vr.get("deterministic") is False
        or vr.get("llm_only") is True
        or str(vr.get("method", "")).strip().lower() == "llm_only"
    ):
        return False, "candidate", "unverified"
    vr_status = str(vr.get("status", "")).strip().lower()
    if vr_status == "confirmed":
        has_evidence = bool(vr.get("evidence_ids"))
        has_proof = bool(str(vr.get("proof_artifact", "")).strip())
        if has_evidence and has_proof:
            return True, "confirmed", "confirmed"
        return False, "candidate", "unverified"
    if vr_status in ("validating", "inconclusive", "false_positive", "fixed"):
        return True, vr_status, vr_status
    return False, "candidate", "unverified"


def resolve_finding_lifecycle(item: Dict[str, Any]) -> Tuple[str, str]:
    """
    Resolve (status, validation_status) from validated proof records.

    Preserves additive lifecycle states only when backed by a valid
    machine-verified validation_result or human validation_record; forces
    unverified findings without proof to ("candidate", "unverified").
    """
    if not isinstance(item, dict):
        return "candidate", "unverified"
    human_ok, human_status, human_val = _resolve_human_record(item)
    machine_ok, machine_status, machine_val = _resolve_machine_result(item)

    if human_ok:
        if human_status == "validated" and machine_ok and machine_status == "fixed":
            return "fixed", "fixed"
        return human_status, human_val
    if machine_ok:
        return machine_status, machine_val
    return "candidate", "unverified"


def _sink(item: Dict[str, Any]) -> str:
    value = str(item.get("sink", "")).strip()
    if not value:
        match = re.search(r"(?:DOM XSS Sink|DOM Sink Gadget|Dangerous Sink)\s*['\"]?([^'\"]+)",
                          str(item.get("title", "")), re.IGNORECASE)
        value = match.group(1).strip() if match else ""
    return value.lstrip(": ").casefold().replace(" assignment", "").replace(" redirect", "")


def finding_identity(item: Dict[str, Any]) -> Tuple[Any, ...]:
    """Return a stable identity that avoids collapsing different bug classes."""
    title = str(item.get("title", item.get("type", "Finding"))).strip()
    category = str(item.get("type", item.get("category", ""))).strip().casefold()
    url = str(item.get("url", item.get("endpoint", ""))).strip()
    parsed = urlsplit(url)
    normalized_url = urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path, parsed.query, "")) if parsed.scheme else url.split("#", 1)[0]
    source = str(item.get("source_file", "")).replace("\\", "/")
    source_name = Path(source).name.casefold()
    sink = _sink(item)
    is_dom = "dom" in category or "xss" in category or "dom" in title.casefold() or bool(sink)

    if "secret" in title.casefold() or "secret" in category:
        fingerprint = str(item.get("evidence_fingerprint", item.get("value_fingerprint", ""))).strip()
        if fingerprint:
            return ("secret", category, fingerprint.casefold())
    if is_dom and sink:
        source_hint = source_name or Path(parsed.path).name.casefold()
        if not source_hint:
            source_hint = Path(str(item.get("source_artifact", ""))).name.casefold()
        if "potential dom xss sink" in title.casefold():
            snippet = str(item.get("snippet", ""))
            snippet_key = hashlib.sha256(snippet.encode("utf-8", errors="replace")).hexdigest() if snippet else ""
            line = str(item.get("line", ""))
            return ("dom-candidate", sink, line, snippet_key)
        # Group gadget hints by source and sink; they are not separate findings.
        return ("dom-sink", source_hint, sink)
    return ("finding", category, title.casefold(), normalized_url)


def deduplicate_findings(findings: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Merge duplicate records while retaining occurrence and evidence provenance."""
    merged: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
    ordered: List[Dict[str, Any]] = []
    for raw in findings:
        if not isinstance(raw, dict):
            continue
        item = dict(raw)
        identity = finding_identity(item)
        existing = merged.get(identity)
        raw_count = max(1, int(item.get("raw_record_count", 1) or 1))
        if existing is None:
            item["raw_record_count"] = raw_count
            item.setdefault("occurrences", [])
            status, val_status = resolve_finding_lifecycle(item)
            item["status"] = status
            item["validation_status"] = val_status
            merged[identity] = item
            ordered.append(item)
            continue

        existing["raw_record_count"] = int(existing.get("raw_record_count", 1)) + raw_count
        for key in ("evidence", "evidence_ids", "occurrences", "source_artifacts"):
            incoming = item.get(key)
            if incoming is None:
                continue
            if not isinstance(incoming, list):
                incoming = [incoming]
            current = existing.setdefault(key, [])
            if not isinstance(current, list):
                current = [current]
                existing[key] = current
            for value in incoming:
                if value not in current:
                    current.append(value)
        for source in (item.get("source_artifact"), item.get("source_file")):
            if source:
                sources = existing.setdefault("source_artifacts", [])
                if source not in sources:
                    sources.append(source)
        # Preserve richer details and higher-precedence verified lifecycle evidence.
        if not existing.get("notes") and item.get("notes"):
            existing["notes"] = item["notes"]
        if not existing.get("proof_artifact") and item.get("proof_artifact"):
            existing["proof_artifact"] = item["proof_artifact"]
        if not existing.get("cvss") and isinstance(item.get("cvss"), dict):
            existing["cvss"] = dict(item["cvss"])

        cur_status, _ = resolve_finding_lifecycle(existing)
        inc_status, _ = resolve_finding_lifecycle(item)
        if _LIFECYCLE_PRECEDENCE.get(inc_status, 0) > _LIFECYCLE_PRECEDENCE.get(cur_status, 0):
            if isinstance(item.get("validation_record"), dict):
                existing["validation_record"] = dict(item["validation_record"])
            if isinstance(item.get("validation_result"), dict):
                existing["validation_result"] = dict(item["validation_result"])
        else:
            if not isinstance(existing.get("validation_record"), dict) and isinstance(item.get("validation_record"), dict):
                existing["validation_record"] = dict(item["validation_record"])
            if not isinstance(existing.get("validation_result"), dict) and isinstance(item.get("validation_result"), dict):
                existing["validation_result"] = dict(item["validation_result"])

        status, val_status = resolve_finding_lifecycle(existing)
        existing["status"] = status
        existing["validation_status"] = val_status
    return ordered
