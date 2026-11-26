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


def test_sarif_and_report_i18n_distinguish_all_lifecycle_states():
    from tools.report_i18n import format_report_markdown

    findings = [
        {
            "title": "Machine Confirmed SQLi",
            "severity": "CRITICAL",
            "url": "https://example.com/items?id=1",
            "status": "confirmed",
            "validation_result": {
                "status": "confirmed",
                "evidence_ids": ["ev-101"],
                "proof_artifact": "output/evidence/validation/val-101.json",
                "deterministic": True,
            },
        },
        {
            "title": "Human Validated XSS",
            "severity": "HIGH",
            "url": "https://example.com/search?q=x",
            "validation_record": {
                "verified_by": "human:bob",
                "method": "browser",
                "evidence_ids": ["ev-102"],
                "outcome": "reproduced",
            },
        },
        {
            "title": "Candidate SSRF",
            "severity": "MEDIUM",
            "url": "https://example.com/fetch",
            "status": "candidate",
        },
        {
            "title": "Inconclusive Auth",
            "severity": "MEDIUM",
            "url": "https://example.com/auth",
            "status": "inconclusive",
        },
        {
            "title": "False Positive Alert",
            "severity": "LOW",
            "url": "https://example.com/fp",
            "status": "false_positive",
        },
        {
            "title": "Fixed Redirect",
            "severity": "MEDIUM",
            "url": "https://example.com/redir",
            "status": "fixed",
        },
        {
            "title": "Accepted Risk Header",
            "severity": "INFO",
            "url": "https://example.com/",
            "status": "accepted_risk",
            "validation_record": {"verified_by": "human:ciso", "outcome": "accepted_risk"},
        },
    ]

    sarif = build_sarif_report(findings, target="example.com")
    run = sarif["runs"][0]
    props = run["properties"]
    assert props["confirmedFindings"] == 1
    assert props["validatedFindings"] == 1
    assert props["candidateFindings"] == 1
    assert props["inconclusiveFindings"] == 1
    assert props["falsePositiveFindings"] == 1
    assert props["fixedFindings"] == 1
    assert props["acceptedRiskFindings"] == 1

    res = run["results"]
    assert res[0]["message"]["text"].startswith("[CONFIRMED]")
    assert res[0]["properties"]["moros"]["verification_source"] == "machine"
    assert res[0]["properties"]["moros"]["cvss"]["cvss_score"] >= 9.0
    assert res[1]["message"]["text"].startswith("[VALIDATED]")
    assert res[1]["properties"]["moros"]["verification_source"] == "human"
    assert res[2]["message"]["text"].startswith("[CANDIDATE]")
    assert res[3]["message"]["text"].startswith("[INCONCLUSIVE]")
    assert res[4]["message"]["text"].startswith("[FALSE POSITIVE]")
    assert res[4]["suppressions"][0]["kind"] == "external"
    assert res[5]["message"]["text"].startswith("[FIXED]")
    assert res[5]["baselineState"] == "absent"
    assert res[6]["message"]["text"].startswith("[ACCEPTED RISK]")
    assert res[6]["suppressions"][0]["kind"] == "external"

    en_md = format_report_markdown("example.com", findings, lang="en")
    assert "Confirmed (Machine-Verified)" in en_md
    assert "Validated (Human-Reviewed)" in en_md
    assert "Unverified Candidate" in en_md
    assert "Inconclusive" in en_md
    assert "False Positive" in en_md
    assert "Fixed" in en_md
    assert "Accepted Risk" in en_md

    ar_md = format_report_markdown("example.com", findings, lang="ar", dialect="msa")
    assert "مؤكد آلياً (Confirmed)" in ar_md
    assert "مُتحقق منه بشرياً (Validated)" in ar_md
    assert "تم الإصلاح (Fixed)" in ar_md

