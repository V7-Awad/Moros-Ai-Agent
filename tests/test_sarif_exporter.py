import json
import tempfile
from pathlib import Path
from tools.sarif_exporter import (
    build_sarif_report,
    write_sarif_report,
    SARIF_SCHEMA,
    SARIF_VERSION,
    TOOL_NAME,
    _extract_cwe,
    _stride_legs,
)


def test_extract_cwe_and_stride():
    assert _extract_cwe({"title": "Reflected XSS on /search"}) == "CWE-79"
    assert "T" in _stride_legs("CWE-79")

    assert _extract_cwe({"title": "Server-Side Request Forgery via webhook"}) == "CWE-918"
    assert "T" in _stride_legs("CWE-918")

    assert _extract_cwe({"title": "Exposed API Key in bundle.js"}) == "CWE-798"
    assert "S" in _stride_legs("CWE-798")

    assert _extract_cwe({"title": "Race Condition on password reset"}) == "CWE-362"
    assert "T" in _stride_legs("CWE-362")


def test_build_sarif_report_structure():
    findings = [
        {
            "title": "Reflected Cross-Site Scripting (XSS)",
            "severity": "HIGH",
            "url": "https://example.com/search?q=test",
            "notes": "Parameter 'q' is reflected unescaped.",
            "validation_status": "validated",
            "curl": "curl -s 'https://example.com/search?q=%3Cscript%3E'",
        },
        {
            "title": "Hardcoded AWS Secret Access Key",
            "severity": "CRITICAL",
            "url": "assets/app.js",
            "line": 42,
            "notes": "AWS AKIA key exposed in client bundle.",
            "status": "candidate",
            "validation_status": "unverified",
        }
    ]

    sarif = build_sarif_report(findings, target="example.com", tool_version="2.0.0")

    assert sarif["version"] == SARIF_VERSION
    assert sarif["$schema"] == SARIF_SCHEMA
    assert len(sarif["runs"]) == 1

    run = sarif["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == TOOL_NAME
    assert driver["version"] == "2.0.0"
    assert len(driver["rules"]) >= 2

    # Check rule tags and security-severity
    rule_xss = next(r for r in driver["rules"] if "CWE-79" in r["id"])
    assert "security-severity" in rule_xss["properties"]
    assert float(rule_xss["properties"]["security-severity"]) >= 7.0
    assert any("stride:" in t for t in rule_xss["properties"]["tags"])

    # Check results
    assert len(run["results"]) == 2
    res_xss = run["results"][0]
    assert res_xss["level"] == "error"
    assert "[VALIDATED]" in res_xss["message"]["text"]
    assert "logicalLocations" in res_xss["locations"][0]

    res_secret = run["results"][1]
    assert "[CANDIDATE]" in res_secret["message"]["text"]
    assert res_secret["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "assets/app.js"
    assert res_secret["locations"][0]["physicalLocation"]["region"]["startLine"] == 42


def test_write_sarif_report_atomic():
    findings = [
        {
            "title": "Information Disclosure via Stack Trace",
            "severity": "LOW",
            "url": "https://example.com/api/debug",
            "notes": "Debug endpoint exposes internal traces.",
            "status": "candidate",
            "validation_status": "unverified",
        }
    ]

    with tempfile.TemporaryDirectory() as tmp_dir:
        out_path = Path(tmp_dir) / "output" / "report" / "findings.sarif"
        saved = write_sarif_report(out_path, findings, target="example.com")

        assert saved.exists()
        content = json.loads(saved.read_text(encoding="utf-8"))
        assert content["version"] == "2.1.0"
        assert len(content["runs"][0]["results"]) == 1
