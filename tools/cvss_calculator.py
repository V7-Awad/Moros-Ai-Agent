#!/usr/bin/env python3
"""
cvss_calculator.py — Official CVSS v3.1 Base Score & Vector Calculator for Moros AI.

Implements the FIRST Common Vulnerability Scoring System (CVSS) v3.1 specification.
Enables enterprise-grade scoring, vector string generation, and threat metrics.
"""

from __future__ import annotations
import math
from typing import Any, Dict, Tuple


# CVSS v3.1 Metric Constants
AV_SCORES = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}  # Network, Adjacent, Local, Physical
AC_SCORES = {"L": 0.77, "H": 0.44}                         # Low, High
PR_SCORES = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},                 # Scope Unchanged: None, Low, High
    "C": {"N": 0.85, "L": 0.68, "H": 0.50},                 # Scope Changed: None, Low, High
}
UI_SCORES = {"N": 0.85, "R": 0.62}                         # None, Required
CIA_SCORES = {"N": 0.0, "L": 0.22, "H": 0.56}              # None, Low, High


def roundup(val: float) -> float:
    """CVSS v3.1 Roundup function: rounds up to nearest 0.1."""
    int_val = round(val * 100000)
    if int_val % 10000 == 0:
        return int_val / 100000.0
    return (math.floor(int_val / 10000) + 1) / 10.0


def calculate_cvss_31(
    av: str = "N",
    ac: str = "L",
    pr: str = "N",
    ui: str = "N",
    s: str = "U",
    c: str = "H",
    i: str = "H",
    a: str = "N",
) -> Tuple[float, str, str]:
    """
    Calculate CVSS v3.1 base score, severity rating, and vector string.
    Returns (score, severity, vector_string).
    """
    av = av.upper()
    ac = ac.upper()
    pr = pr.upper()
    ui = ui.upper()
    s = s.upper()
    c = c.upper()
    i = i.upper()
    a = a.upper()

    # Impact Sub-Score (ISS)
    iss = 1.0 - ((1.0 - CIA_SCORES.get(c, 0.0)) * (1.0 - CIA_SCORES.get(i, 0.0)) * (1.0 - CIA_SCORES.get(a, 0.0)))

    # Impact calculation based on Scope
    if s == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * pow((iss - 0.02), 15)

    # Exploitability
    pr_score = PR_SCORES.get(s, PR_SCORES["U"]).get(pr, 0.85)
    exploitability = 8.22 * AV_SCORES.get(av, 0.85) * AC_SCORES.get(ac, 0.77) * pr_score * UI_SCORES.get(ui, 0.85)

    # Base Score
    if impact <= 0:
        base_score = 0.0
    elif s == "U":
        base_score = roundup(min(impact + exploitability, 10.0))
    else:
        base_score = roundup(min(1.08 * (impact + exploitability), 10.0))

    base_score = max(0.0, min(10.0, base_score))

    # Qualitative Severity Rating
    if base_score == 0.0:
        severity = "None"
    elif base_score <= 3.9:
        severity = "Low"
    elif base_score <= 6.9:
        severity = "Medium"
    elif base_score <= 8.9:
        severity = "High"
    else:
        severity = "Critical"

    vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"
    return base_score, severity, vector


# Default baseline CVSS mappings per vulnerability type / CWE
DEFAULT_CVSS_MAP: Dict[str, Dict[str, str]] = {
    "sqli": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "H", "i": "H", "a": "H"},      # 9.8 Critical
    "rce": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "H", "i": "H", "a": "H"},       # 9.8 Critical
    "ssti": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "H", "i": "H", "a": "H"},      # 9.8 Critical
    "ssrf": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "C", "c": "H", "i": "N", "a": "N"},      # 8.6 High
    "idor": {"av": "N", "ac": "L", "pr": "L", "ui": "N", "s": "U", "c": "H", "i": "H", "a": "N"},      # 8.1 High
    "auth-bypass": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "H", "i": "H", "a": "N"}, # 9.1 Critical
    "subdomain-takeover": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "C", "c": "H", "i": "H", "a": "N"}, # 9.3 Critical
    "path-traversal": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "H", "i": "N", "a": "N"}, # 7.5 High
    "xss-stored": {"av": "N", "ac": "L", "pr": "L", "ui": "R", "s": "C", "c": "L", "i": "L", "a": "N"}, # 5.4 Medium
    "xss-reflected": {"av": "N", "ac": "L", "pr": "N", "ui": "R", "s": "C", "c": "L", "i": "L", "a": "N"}, # 6.1 Medium
    "xss-dom": {"av": "N", "ac": "L", "pr": "N", "ui": "R", "s": "C", "c": "L", "i": "L", "a": "N"},   # 6.1 Medium
    "xss": {"av": "N", "ac": "L", "pr": "N", "ui": "R", "s": "C", "c": "L", "i": "L", "a": "N"},       # 6.1 Medium
    "cors": {"av": "N", "ac": "L", "pr": "N", "ui": "R", "s": "U", "c": "H", "i": "N", "a": "N"},       # 6.5 Medium
    "crlf": {"av": "N", "ac": "L", "pr": "N", "ui": "R", "s": "U", "c": "L", "i": "L", "a": "N"},       # 5.4 Medium
    "host-header": {"av": "N", "ac": "L", "pr": "N", "ui": "R", "s": "U", "c": "L", "i": "L", "a": "N"}, # 5.4 Medium
    "rate-limit": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "N", "i": "L", "a": "N"},  # 5.3 Medium
    "secret": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "H", "i": "N", "a": "N"},      # 7.5 High
    "default": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "L", "i": "N", "a": "N"},     # 5.3 Medium
}


def score_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Score any finding with full CVSS v3.1 parameters."""
    title = str(finding.get("title", "")).lower()
    skill = str(finding.get("skill", "")).lower()
    cwe = str(finding.get("cwe", "")).lower()

    key = "default"
    for candidate_key in DEFAULT_CVSS_MAP:
        if candidate_key in title or candidate_key in skill or candidate_key in cwe:
            key = candidate_key
            break

    params = DEFAULT_CVSS_MAP.get(key, DEFAULT_CVSS_MAP["default"])
    score, sev, vector = calculate_cvss_31(**params)

    # Honor explicit finding severity if higher than baseline mapping
    sev_raw = str(finding.get("severity", "")).lower()
    if "critical" in sev_raw:
        score = max(score, 9.0)
        sev = "Critical"
    elif "high" in sev_raw:
        score = max(score, 7.5)
        sev = "High"

    return {
        "cvss_version": "3.1",
        "cvss_score": score,
        "cvss_severity": sev,
        "cvss_vector": vector,
    }
