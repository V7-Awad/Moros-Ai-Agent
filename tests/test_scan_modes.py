from hackbot_orchestrator import SKILL_ORDER


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
