#!/usr/bin/env python3
"""
secret-scanner.py — Secret and API key scanner for JavaScript files.

Scans JS files using both regex pattern matching (for known key formats)
and Shannon entropy analysis (for unknown secret formats).

Usage:
    python tools/secret-scanner.py \
        --input-dir "targets/example.com/output/js/beautified/" \
        --output "targets/example.com/output/js/secrets-findings.json"
"""

import argparse
import json
import logging
import math
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S"
)
logger = logging.getLogger("secret-scanner")

# Known secret patterns
SECRET_PATTERNS = {
    "aws_access_key": r"(?:AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
    "aws_secret_key": r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
    "gcp_api_key": r"AIza[0-9A-Za-z\-_]{35}",
    "gcp_service_account": r'"type"\s*:\s*"service_account"',
    "stripe_publishable": r"pk_(live|test)_[A-Za-z0-9]{20,}",
    "stripe_secret": r"sk_(live|test)_[A-Za-z0-9]{20,}",
    "github_token": r"gh[pousr]_[A-Za-z0-9_]{36,}",
    "github_pat_fine": r"github_pat_[A-Za-z0-9_]{22,}",
    "slack_token": r"xox[bporas]-[A-Za-z0-9\-]{10,}",
    "slack_webhook": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
    "jwt_token": r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*",
    "private_key_pem": r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
    "sendgrid_key": r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
    "twilio_key": r"SK[a-f0-9]{32}",
    "mailchimp_key": r"[a-f0-9]{32}-us\d{1,2}",
    "firebase_url": r"https://[a-z0-9-]+\.firebaseio\.com",
    "firebase_key": r"(?:firebase|FIREBASE)\w*\s*[:=]\s*['\"]?([A-Za-z0-9_-]{20,})['\"]?",
    "azure_connection_string": r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]+",
    "generic_api_key": r"(?:api[_-]?key|apikey|api_secret|api_token)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]",
    "generic_secret": r"(?:secret|password|passwd|token)\s*[:=]\s*['\"]([A-Za-z0-9_\-!@#$%^&*]{8,})['\"]",
    "oauth_client_secret": r"(?:client_secret|clientSecret)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]",
    "database_url": r"(?:postgres|mysql|mongodb|redis)://[^\s'\"]+",
    "heroku_api_key": r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
}

# Patterns that look like secrets but are benign
BENIGN_PATTERNS = [
    r"^[0-9a-f]{32}$",           # MD5 hashes used as identifiers
    r"^[0-9a-f]{40}$",           # SHA1 hashes
    r"^[0-9a-f]{64}$",           # SHA256 hashes
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",  # UUIDs
    r"^data:image/",              # Data URIs
    r"^https?://",                # Regular URLs
    r"^[A-Z_]{10,}$",            # ALL_CAPS_CONSTANTS
]


def shannon_entropy(string: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not string:
        return 0.0
    freq = {}
    for c in string:
        freq[c] = freq.get(c, 0) + 1
    length = len(string)
    entropy = -sum((count / length) * math.log2(count / length)
                    for count in freq.values())
    return entropy


def is_benign(value: str) -> bool:
    """Check if a string matches known benign patterns."""
    for pattern in BENIGN_PATTERNS:
        if re.match(pattern, value, re.IGNORECASE):
            return True
    return False


def scan_file(filepath: Path, min_entropy: float = 4.5,
              min_length: int = 16, max_length: int = 500) -> list:
    """Scan a single file for secrets."""
    findings = []

    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        logger.error(f"Error reading {filepath}: {e}")
        return findings

    lines = content.split("\n")

    # Method 1: Regex pattern matching
    for pattern_name, pattern in SECRET_PATTERNS.items():
        for match in re.finditer(pattern, content):
            line_num = content[:match.start()].count("\n") + 1
            value = match.group()
            value_preview = value[:20] + "..." if len(value) > 20 else value

            findings.append({
                "type": pattern_name,
                "detection_method": "regex",
                "pattern_name": pattern_name,
                "value_preview": value_preview,
                "source_file": str(filepath),
                "line_number": line_num,
                "context": lines[line_num - 1].strip()[:200] if line_num <= len(lines) else "",
                "severity": "Triage Severity: MEDIUM — pending human review",
            })

    # Method 2: High-entropy string detection
    # Find quoted strings
    string_pattern = re.compile(r"""(['"])([^'"]{16,500})\1""")
    for match in string_pattern.finditer(content):
        value = match.group(2)

        if len(value) < min_length or len(value) > max_length:
            continue

        if is_benign(value):
            continue

        entropy = shannon_entropy(value)
        if entropy >= min_entropy:
            line_num = content[:match.start()].count("\n") + 1
            value_preview = value[:20] + "..." if len(value) > 20 else value

            # Check it wasn't already found by regex
            already_found = any(
                f["line_number"] == line_num and f["source_file"] == str(filepath)
                for f in findings
            )

            if not already_found:
                findings.append({
                    "type": "high_entropy_string",
                    "detection_method": "entropy",
                    "entropy_score": round(entropy, 2),
                    "value_preview": value_preview,
                    "source_file": str(filepath),
                    "line_number": line_num,
                    "context": lines[line_num - 1].strip()[:200] if line_num <= len(lines) else "",
                    "severity": "Triage Severity: LOW — pending human review",
                })

    return findings


def main():
    parser = argparse.ArgumentParser(description="Scan JavaScript for secrets and API keys")
    parser.add_argument("--input-dir", required=True, help="Directory to scan")
    parser.add_argument("--output", required=True, help="Output JSON file")
    parser.add_argument("--min-entropy", type=float, default=4.5,
                        help="Minimum Shannon entropy for high-entropy detection")
    parser.add_argument("--min-length", type=int, default=16,
                        help="Minimum string length for entropy check")

    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    if not input_dir.exists():
        logger.error(f"Input directory does not exist: {input_dir}")
        sys.exit(1)

    js_files = list(input_dir.rglob("*.js"))
    logger.info(f"Scanning {len(js_files)} JS files for secrets")

    all_findings = []
    for js_file in js_files:
        findings = scan_file(js_file, min_entropy=args.min_entropy,
                            min_length=args.min_length)
        all_findings.extend(findings)

    # Write results
    output = {
        "target_dir": str(input_dir),
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "files_scanned": len(js_files),
        "total_findings": len(all_findings),
        "findings_by_type": {},
        "findings": all_findings,
    }

    # Count by type
    for f in all_findings:
        t = f["type"]
        output["findings_by_type"][t] = output["findings_by_type"].get(t, 0) + 1

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(output, indent=2), encoding="utf-8")

    logger.info(f"Scan complete. {len(all_findings)} findings written to {output_path}")

    # Print summary
    if output["findings_by_type"]:
        logger.info("Findings by type:")
        for t, count in sorted(output["findings_by_type"].items()):
            logger.info(f"  {t}: {count}")


if __name__ == "__main__":
    main()
