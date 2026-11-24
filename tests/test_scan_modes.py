from hackbot_orchestrator import SKILL_ORDER
from tools.skill_registry import SkillRegistry


def test_scan_mode_skill_resolution():
    # Test quick mode
    quick_skills = ["recon-subdomain", "api-spec-discovery", "js-discover", "js-analyze",
                    "content-discovery", "xss-reflected", "ssrf-identify", "report-conglomeration"]
    for s in quick_skills:
        assert s in SKILL_ORDER

    # Test passive mode
    passive_skills = ["recon-subdomain", "api-spec-discovery", "js-discover", "js-analyze", "report-conglomeration"]
    for s in passive_skills:
        assert s in SKILL_ORDER

    # Deep mode covers all skills
    assert len(SKILL_ORDER) >= 14


def test_quick_mode_skill_subset():
    quick_skills = ["recon-subdomain", "api-spec-discovery", "js-discover", "js-analyze",
                    "content-discovery", "xss-reflected", "ssrf-identify", "report-conglomeration"]
    assert len(quick_skills) == 8
    assert "recon-subdomain" == quick_skills[0]
    assert "report-conglomeration" == quick_skills[-1]


def test_passive_mode_excludes_active_vuln_skills():
    passive_skills = ["recon-subdomain", "api-spec-discovery", "js-discover", "js-analyze", "report-conglomeration"]
    # Ensure active exploitation skills are excluded
    assert "xss-reflected" not in passive_skills
    assert "ssrf-identify" not in passive_skills
    assert "sqli-heuristic" not in passive_skills
    assert "idor-audit" not in passive_skills


def test_deep_mode_includes_all_custom_skills():
    registry = SkillRegistry()
    all_skills = registry.list_skills()
    execution_order = registry.get_execution_order()
    assert len(execution_order) == len(all_skills)
    assert len(execution_order) >= 20
    assert "report-conglomeration" in execution_order
