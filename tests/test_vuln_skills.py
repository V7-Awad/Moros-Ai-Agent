import json
import pytest
from pathlib import Path
from tools.skill_runner import SkillRunner


@pytest.fixture
def test_target_env(tmp_path):
    """Create a minimal target directory structure with test endpoints and JS."""
    target_dir = tmp_path / "targets" / "test.local"
    target_dir.mkdir(parents=True)
    out_dir = target_dir / "output"
    (out_dir / "js" / "beautified").mkdir(parents=True)
    (out_dir / "findings").mkdir(parents=True)
    (out_dir / "logs").mkdir(parents=True)
    (out_dir / "api").mkdir(parents=True)

    # Write scope-of-work so authorized checks pass
    (target_dir / "scope-of-work.md").write_text("# Authorized Scope for test.local\nIn scope: test.local\n", encoding="utf-8")

    # Write sample endpoints
    endpoints = {
        "endpoints": [
            {"url": "https://test.local/search", "method": "GET", "parameters": [{"name": "q"}]},
            {"url": "https://test.local/fetch", "method": "GET", "parameters": [{"name": "url"}]},
            {"url": "https://test.local/api/comment", "method": "POST", "parameters": [{"name": "comment"}, {"name": "author"}]},
            {"url": "https://test.local/contact", "method": "POST", "parameters": [{"name": "feedback"}, {"name": "email"}]},
            {"url": "https://test.local/oauth/token", "method": "POST", "parameters": [{"name": "code"}]},
            {"url": "https://test.local/forgot-password", "method": "POST", "parameters": [{"name": "email"}]},
        ]
    }
    (out_dir / "js" / "endpoints.json").write_text(json.dumps(endpoints), encoding="utf-8")

    # Write sample JS with DOM sink
    sample_js = """
    function displayParam() {
        let params = new URLSearchParams(window.location.search);
        let name = params.get('name');
        document.getElementById('user').innerHTML = name;
    }
    """
    (out_dir / "js" / "beautified" / "app.js").write_text(sample_js, encoding="utf-8")

    return target_dir


def test_vuln_skills_dom_xss(test_target_env):
    runner = SkillRunner("test.local", test_target_env)
    runner.scope_authorized = True
    res = runner.run_vuln_skill("xss-dom")
    assert res["status"] == "COMPLETED"
    assert res["findings_count"] > 0

    cand_file = test_target_env / "output" / "findings" / "xss-dom" / "candidates-xss-dom.json"
    assert cand_file.is_file()
    data = json.loads(cand_file.read_text(encoding="utf-8"))
    assert any("innerHTML" in f.get("sink", "") for f in data["findings"])


def test_vuln_skills_stored_xss(test_target_env):
    runner = SkillRunner("test.local", test_target_env)
    runner.scope_authorized = True
    res = runner.run_vuln_skill("xss-stored")
    assert res["status"] == "CANDIDATES_ONLY"
    assert res["findings_count"] > 0

    cand_file = test_target_env / "output" / "findings" / "xss-stored" / "candidates-xss-stored.json"
    assert cand_file.is_file()
    data = json.loads(cand_file.read_text(encoding="utf-8"))
    assert any("comment" in f.get("parameter", "") for f in data["findings"])


def test_vuln_skills_blind_xss(test_target_env):
    runner = SkillRunner("test.local", test_target_env)
    runner.scope_authorized = True
    res = runner.run_vuln_skill("xss-blind")
    assert res["status"] == "CANDIDATES_ONLY"
    assert res["findings_count"] > 0

    cand_file = test_target_env / "output" / "findings" / "xss-blind" / "candidates-xss-blind.json"
    assert cand_file.is_file()


def test_vuln_skills_ssrf_and_post_exploit(test_target_env):
    runner = SkillRunner("test.local", test_target_env)
    runner.scope_authorized = True
    res_id = runner.run_vuln_skill("ssrf-identify")
    assert res_id["status"] == "CANDIDATES_ONLY"
    assert res_id["findings_count"] > 0

    res_post = runner.run_vuln_skill("ssrf-post-exploit")
    assert res_post["status"] == "COMPLETED"
    assert res_post["findings_count"] > 0

    cand_file = test_target_env / "output" / "findings" / "ssrf-post-exploit" / "candidates-ssrf-post-exploit.json"
    assert cand_file.is_file()
    data = json.loads(cand_file.read_text(encoding="utf-8"))
    assert any("boundary_vectors" in f for f in data["findings"])


def test_vuln_skills_idp_race_condition(test_target_env):
    runner = SkillRunner("test.local", test_target_env)
    runner.scope_authorized = True
    res = runner.run_vuln_skill("idp-race-condition")
    assert res["status"] == "CANDIDATES_ONLY"
    assert res["findings_count"] > 0

    cand_file = test_target_env / "output" / "findings" / "idp-race-condition" / "candidates-idp-race-condition.json"
    assert cand_file.is_file()


def test_vuln_skills_auth_password_reset(test_target_env):
    runner = SkillRunner("test.local", test_target_env)
    runner.scope_authorized = True
    res = runner.run_vuln_skill("auth-password-reset-bruteforce")
    assert res["status"] == "COMPLETED"
    assert res["findings_count"] > 0

    cand_file = test_target_env / "output" / "findings" / "auth-password-reset-bruteforce" / "candidates-auth-password-reset-bruteforce.json"
    assert cand_file.is_file()


def test_all_registered_vuln_skills_are_implemented(test_target_env):
    runner = SkillRunner("test.local", test_target_env)
    all_vuln_skills = [
        "xss-reflected",
        "xss-stored",
        "xss-dom",
        "xss-blind",
        "ssrf-identify",
        "ssrf-post-exploit",
        "idp-race-condition",
        "auth-password-reset-bruteforce",
    ]
    for skill in all_vuln_skills:
        res = runner.run_vuln_skill(skill)
        assert res["status"] != "NOT_IMPLEMENTED", f"Skill {skill} returned NOT_IMPLEMENTED!"
