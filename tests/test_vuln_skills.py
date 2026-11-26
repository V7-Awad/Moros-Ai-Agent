import json
import pytest
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


def test_custom_skill_scope_filter_allows_scoped_http_and_blocks_raw_network(tmp_path, monkeypatch):
    import sys
    import subprocess
    from pathlib import Path
    from unittest.mock import patch

    monkeypatch.setenv("MOROS_HTTP_REQUESTS_REMAINING", "0")
    runner = SkillRunner("test.local", tmp_path)
    runner.scope_authorized = True

    # ScopedHttpClient skills must not be blocked as BLOCKED_SCOPE by unscoped_network_patterns
    for skill_name in ("path-traversal", "http-smuggling", "rate-limit-test"):
        res = runner.run_custom_skill(skill_name)
        assert res["status"] == "COMPLETED", f"{skill_name} was unexpectedly blocked: {res}"

    # Raw unscoped network/process scripts must still be blocked
    import skill_registry
    fake_skill_dir = tmp_path / "fake_skills" / "raw-net-skill"
    fake_skill_dir.mkdir(parents=True)
    monkeypatch.setattr(skill_registry, "SKILLS_DIR", tmp_path / "fake_skills")
    for snippet in (
        "import requests\nrequests.get('https://evil.com')\n",
        "import urllib.request\nurllib.request.urlopen('https://evil.com')\n",
        "import http.client\nhttp.client.HTTPConnection('evil.com')\n",
        "import socket\nsocket.socket()\n",
        "import subprocess\nsubprocess.run(['curl', 'https://evil.com'])\n",
    ):
        (fake_skill_dir / "run.py").write_text(snippet, encoding="utf-8")
        blocked = runner.run_custom_skill("raw-net-skill")
        assert blocked["status"] == "BLOCKED_SCOPE"


def test_skill_scripts_edge_cases_and_fixes(tmp_path, monkeypatch):
    import subprocess
    import sys
    from pathlib import Path

    repo_root = Path(__file__).resolve().parent.parent
    skills_dir = repo_root / "skills"

    def run_skill(name: str, target: str = "test.local", env_extra: dict | None = None):
        t_dir = tmp_path / f"target_{name}"
        out_dir = t_dir / "output"
        (out_dir / "findings").mkdir(parents=True, exist_ok=True)
        env = dict(**__import__("os").environ)
        env["MOROS_HTTP_REQUESTS_REMAINING"] = "0"
        if env_extra:
            env.update(env_extra)
        proc = subprocess.run(
            [
                sys.executable,
                str(skills_dir / name / "run.py"),
                "--target", target,
                "--target-dir", str(t_dir),
                "--output-dir", str(out_dir),
            ],
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
        )
        return proc, out_dir

    # 1. Invalid / non-80/443 target fails gracefully with valid empty JSON even when budget > 0
    for name in ("http-smuggling", "cors-audit", "crlf-injection", "idor-audit", "open-redirect", "subdomain-takeover"):
        proc, out_dir = run_skill(name, target="http://test.local:8080", env_extra={"MOROS_HTTP_REQUESTS_REMAINING": "5"})
        assert proc.returncode == 0, f"{name} failed on port 8080: {proc.stderr}"
        out_json = out_dir / "findings" / f"candidates-{name}.json"
        assert out_json.is_file()
        parsed = json.loads(out_json.read_text(encoding="utf-8"))
        assert parsed["findings"] == []

    # 2. Invalid/empty MOROS_HTTP_REQUESTS_REMAINING falls back cleanly without ValueError
    for bad_val in ("", "not-a-number"):
        proc, out_dir = run_skill("crlf-injection", target="http://test.local:8080", env_extra={"MOROS_HTTP_REQUESTS_REMAINING": bad_val})
        assert proc.returncode == 0, proc.stderr

    # 3. jwt-analysis leading slash fix + JSON endpoint loading
    t_jwt = tmp_path / "target_jwt"
    out_jwt = t_jwt / "output"
    (out_jwt / "api").mkdir(parents=True, exist_ok=True)
    (out_jwt / "api" / "endpoints.json").write_text(
        json.dumps({"endpoints": [{"path": "api/v1/jwt/verify"}]}), encoding="utf-8"
    )
    proc = subprocess.run(
        [sys.executable, str(skills_dir / "jwt-analysis" / "run.py"),
         "--target", "test.local", "--target-dir", str(t_jwt), "--output-dir", str(out_jwt)],
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0
    jwt_data = json.loads((out_jwt / "findings" / "candidates-jwt-analysis.json").read_text(encoding="utf-8"))
    assert jwt_data["findings"][0]["url"] == "https://test.local/api/v1/jwt/verify"

    # 4. Nested loop caps break outer loop too (prototype-pollution=20, open-redirect=5, websocket-audit=10)
    t_caps = tmp_path / "target_caps"
    out_caps = t_caps / "output"
    js_dir = out_caps / "js"
    js_dir.mkdir(parents=True, exist_ok=True)
    for idx in range(15):
        (js_dir / f"app_{idx}.js").write_text(
            "a['__proto__'] = 1;\n"
            "b['__proto__'] = 2;\n"
            "const u = '/go?redirect=1&next=2&url=3';\n"
            "const ws = 'wss://test.local/ws1 wss://test.local/ws2 wss://test.local/ws3';\n",
            encoding="utf-8",
        )
    for skill_name, cap in (("prototype-pollution", 20), ("open-redirect", 5), ("websocket-audit", 10)):
        env = dict(**__import__("os").environ)
        env["MOROS_HTTP_REQUESTS_REMAINING"] = "0"
        proc = subprocess.run(
            [sys.executable, str(skills_dir / skill_name / "run.py"),
             "--target", "test.local", "--target-dir", str(t_caps), "--output-dir", str(out_caps)],
            capture_output=True, text=True, env=env, timeout=30,
        )
        assert proc.returncode == 0, proc.stderr
        data = json.loads((out_caps / "findings" / f"candidates-{skill_name}.json").read_text(encoding="utf-8"))
        assert len(data["findings"]) == cap, f"{skill_name} exceeded cap {cap}: {len(data['findings'])}"

    # 5. open-redirect _inject_redirect_dest helper injects test_dest into matching param
    import importlib.util
    spec = importlib.util.spec_from_file_location("open_redirect_run", skills_dir / "open-redirect" / "run.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    injected = mod._inject_redirect_dest(
        "https://test.local/login?next=/home&tab=1",
        ["redirect", "next"],
        "https://moros-redirect-test.example",
    )
    assert "next=https%3A%2F%2Fmoros-redirect-test.example" in injected
    assert "tab=1" in injected
