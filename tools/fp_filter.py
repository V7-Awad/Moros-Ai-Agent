#!/usr/bin/env python3
"""
fp_filter.py — Cryptographic Signature-Hash False Positive Filter for Moros AI.

Implements the official signature-hash matching algorithm against memory/FALSE_POSITIVE_DB.md
to prevent repetitive scanning loops and noisy false-positive alerting.
"""

from __future__ import annotations
import hashlib
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


PROJECT_ROOT = Path(__file__).resolve().parent.parent
FP_DB_PATH = PROJECT_ROOT / "memory" / "FALSE_POSITIVE_DB.md"


def compute_signature_hash(status_code: int, body: str) -> str:
    """
    Computes official 8-char signature-hash:
    SHA256(status:body-length:body-substring)[:8]
    """
    body_str = str(body or "")
    body_len = len(body_str)

    # Extract stable 64-char substring from middle of body (skips transient header/tokens)
    midpoint = max(0, body_len // 2 - 32)
    stable_sub = body_str[midpoint:midpoint + 64]

    raw_signature = f"{status_code}:{body_len}:{stable_sub}"
    return hashlib.sha256(raw_signature.encode("utf-8")).hexdigest()[:8]


class FalsePositiveFilter:
    """Matches candidate findings against known false-positive signatures."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = Path(db_path) if db_path else FP_DB_PATH
        self.known_hashes: Set[str] = set()
        self.known_patterns: List[Dict[str, str]] = []
        self._load_fp_db()

    def _load_fp_db(self):
        if not self.db_path.is_file():
            return

        try:
            content = self.db_path.read_text(encoding="utf-8")
            # Parse table rows: | Pattern | Class | Benign explanation | Confuser | Date | Hash | Hits |
            table_matches = re.findall(
                r"^\|\s*([^|]+)\s*\|\s*([^|]+)\s*\|\s*([^|]+)\s*\|\s*([^|]+)\s*\|\s*([^|]+)\s*\|\s*([a-fA-F0-9]{8}|—)\s*\|\s*(\d+)\s*\|",
                content,
                re.MULTILINE
            )
            for row in table_matches:
                sig_hash = row[5].strip().lower()
                if sig_hash and sig_hash != "—":
                    self.known_hashes.add(sig_hash)
                self.known_patterns.append({
                    "pattern": row[0].strip(),
                    "vuln_class": row[1].strip(),
                    "explanation": row[2].strip(),
                    "hash": sig_hash
                })
        except Exception:
            pass

    def is_known_false_positive(self, status_code: int, body: str, vuln_class: str = "") -> Tuple[bool, str]:
        """Check whether an attack response matches a known false positive entry."""
        sig_hash = compute_signature_hash(status_code, body)

        if sig_hash in self.known_hashes:
            return True, f"Matched known FP signature-hash '{sig_hash}' in FALSE_POSITIVE_DB.md"

        # Check for generic confusers
        body_lower = body.lower()
        if status_code == 403 and "access denied" in body_lower and vuln_class in ("sqli", "xss"):
            return True, "WAF block page mistakenly flagged as vulnerability reflection"

        if status_code == 200 and len(body) < 5 and vuln_class == "sqli":
            return True, "Empty response body without valid SQL syntax indicators"

        return False, f"Signature hash '{sig_hash}' verified as unique lead"

    def check_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Safely evaluate a finding dict against known false-positive signatures without mutating status."""
        if not isinstance(finding, dict):
            return {"is_known_fp": False, "reason": "invalid_finding", "signature_hash": None}

        status_code: Optional[int] = None
        body: str = ""

        candidates = [finding]
        if isinstance(finding.get("response"), dict):
            candidates.append(finding["response"])
        if isinstance(finding.get("validation_result"), dict):
            vr = finding["validation_result"]
            candidates.append(vr)
            if isinstance(vr.get("response"), dict):
                candidates.append(vr["response"])
        for ev in finding.get("evidence", []) if isinstance(finding.get("evidence"), list) else []:
            if isinstance(ev, dict):
                candidates.append(ev)

        for src in candidates:
            if status_code is None and src.get("status_code") is not None:
                try:
                    status_code = int(src["status_code"])
                except (TypeError, ValueError):
                    pass
            if not body:
                raw_body = src.get("response_body") or src.get("body")
                if isinstance(raw_body, str) and raw_body:
                    body = raw_body

        if status_code is None or not body:
            return {"is_known_fp": False, "reason": "no_response_signature", "signature_hash": None}

        vuln_class = str(
            finding.get("skill") or finding.get("type") or finding.get("category") or ""
        ).strip().lower()
        sig_hash = compute_signature_hash(status_code, body)
        is_fp, reason = self.is_known_false_positive(status_code, body, vuln_class=vuln_class)
        return {
            "is_known_fp": is_fp,
            "reason": reason,
            "signature_hash": sig_hash,
        }
