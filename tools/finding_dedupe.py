"""Shared candidate-finding identity and aggregation for API, reports, and UI."""

import hashlib
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple
from urllib.parse import urlsplit, urlunsplit


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
        # Preserve richer details and the more conservative validation state.
        if not existing.get("notes") and item.get("notes"):
            existing["notes"] = item["notes"]
        if item.get("validation_status") != "validated":
            existing["validation_status"] = "unverified"
            existing["status"] = "candidate"
    return ordered
