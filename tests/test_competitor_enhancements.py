from pathlib import Path
import pytest

from tools.cvss_calculator import calculate_cvss_31, score_finding
from tools.waf_detector import WafDetector
from tools.tech_profiler import TechProfiler
from tools.fp_filter import compute_signature_hash, FalsePositiveFilter
from tools.attack_graph import AttackGraphBuilder


def test_cvss_calculator():
    # Test standard critical SQLi
    score, sev, vector = calculate_cvss_31("N", "L", "N", "N", "U", "H", "H", "H")
    assert score == 9.8
    assert sev == "Critical"
    assert "CVSS:3.1/AV:N" in vector

    # Test score_finding helper
    f_sqli = {"title": "SQL Injection in /api/users", "skill": "sqli-heuristic", "cwe": "CWE-89"}
    res = score_finding(f_sqli)
    assert res["cvss_score"] >= 8.5
    assert res["cvss_severity"] in ("High", "Critical")

    f_xss = {"title": "Reflected XSS on search", "skill": "xss-reflected", "cwe": "CWE-79"}
    res_xss = score_finding(f_xss)
    assert res_xss["cvss_score"] == 6.1
    assert res_xss["cvss_severity"] == "Medium"


def test_waf_detector():
    detector = WafDetector()

    # Cloudflare detection
    cf_res = detector.inspect_response(
        status_code=403,
        headers={"Server": "cloudflare", "cf-ray": "82a8492048-DXB"},
        body="Attention Required! | Cloudflare"
    )
    assert cf_res["waf_detected"] is True
    assert any(w["waf"] == "Cloudflare" for w in cf_res["detected_wafs"])
    assert cf_res["recommended_delay"] >= 0.5

    # Clean response (no WAF)
    clean_res = detector.inspect_response(
        status_code=200,
        headers={"Server": "Apache/2.4.41"},
        body="Welcome to our simple site"
    )
    assert clean_res["waf_detected"] is False


def test_tech_profiler():
    profiler = TechProfiler()

    # Profile Spring Boot & React app
    res = profiler.profile_target(
        headers={"Server": "nginx", "X-Application-Context": "application:8080"},
        body="<html><body><div id='react-root'></div>whitelabel error page</body></html>",
        cookies="JSESSIONID=123456"
    )
    assert "Spring Boot" in res["technologies"]
    assert "Next.js / React" in res["technologies"]
    assert "ssti-detect" in res["prioritized_skills"]


def test_fp_filter(tmp_path):
    # Test signature hash computation
    h1 = compute_signature_hash(200, "A" * 200)
    h2 = compute_signature_hash(200, "A" * 200)
    assert h1 == h2
    assert len(h1) == 8

    # Test FP filter matching
    fp_db = tmp_path / "FALSE_POSITIVE_DB.md"
    fp_db.write_text(
        "| Pattern | Class | Benign explanation | Confuser | Date | Signature-hash (8) | Hits |\n"
        f"| test | xss | benign | test | 2026-01-01 | {h1} | 0 |\n",
        encoding="utf-8"
    )

    filter_engine = FalsePositiveFilter(db_path=fp_db)
    is_fp, reason = filter_engine.is_known_false_positive(200, "A" * 200)
    assert is_fp is True
    assert "Matched known FP" in reason


def test_attack_graph_builder(tmp_path):
    target_dir = tmp_path / "targets" / "graph-test.local"
    output_dir = target_dir / "output"
    (output_dir / "recon").mkdir(parents=True)
    (output_dir / "findings").mkdir(parents=True)

    (output_dir / "recon" / "subdomains.txt").write_text("api.graph-test.local\nadmin.graph-test.local\n", encoding="utf-8")
    (output_dir / "recon" / "endpoints.txt").write_text("/api/v1/users\n/admin/login\n", encoding="utf-8")
    (output_dir / "findings" / "candidates-idor.json").write_text(
        '{"findings": [{"title": "IDOR in Users", "url": "https://api.graph-test.local/api/v1/users", "severity": "HIGH"}]}',
        encoding="utf-8"
    )

    builder = AttackGraphBuilder("graph-test.local", target_dir)
    graph = builder.build_graph()

    assert graph["total_nodes"] >= 4
    assert graph["total_edges"] >= 3
    assert "graph TD" in graph["mermaid"]
    assert (output_dir / "report" / "attack-graph.json").is_file()
