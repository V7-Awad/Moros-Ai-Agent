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
    monkeypatch.setenv("MOROS_HTTP_REQUESTS_REMAINING", "0")
    runner = SkillRunner("test.local", tmp_path)
    runner.scope_authorized = True

    # ScopedHttpClient skills must not be blocked as BLOCKED_SCOPE by unscoped_network_patterns
    for skill_name in ("path-traversal", "http-smuggling", "rate-limit-test", "graphql-audit", "xxe-detect", "idor-audit"):
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


class _SkillFakeResponse:
    def __init__(self, status: int, url: str, body: bytes, headers: dict | None = None):
        self.status = status
        self._url = url
        self._body = body
        self.headers = headers or {"Content-Type": "application/json"}

    def geturl(self) -> str:
        return self._url

    def read(self, n: int = -1) -> bytes:
        return self._body if n < 0 else self._body[:n]

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def _run_skill_in_process(monkeypatch, skill_name: str, target: str, target_dir, handler):
    import importlib.util
    import sys
    import urllib.request
    from pathlib import Path

    repo_root = Path(__file__).resolve().parent.parent
    script_path = repo_root / "skills" / skill_name / "run.py"
    out_dir = target_dir / "output"
    (out_dir / "findings").mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(urllib.request.OpenerDirector, "open", lambda self, req, timeout=15.0: handler(req))
    monkeypatch.setattr(
        sys,
        "argv",
        [str(script_path), "--target", target, "--target-dir", str(target_dir), "--output-dir", str(out_dir)],
    )
    spec = importlib.util.spec_from_file_location(f"skill_{skill_name.replace('-', '_')}", script_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.main()
    return json.loads((out_dir / "findings" / f"candidates-{skill_name}.json").read_text(encoding="utf-8"))


def test_idor_audit_reduces_false_positives_and_uses_differential_comparison(tmp_path, monkeypatch):
    from tools.checkpoint_manager import CheckpointManager

    t_dir = tmp_path / "idor_target"
    out_dir = t_dir / "output"
    (out_dir / "api").mkdir(parents=True)
    (t_dir / "scope-of-work.md").write_text("In scope: test.local\n", encoding="utf-8")

    # 1. Static identical JSON and HTML 200 responses must NOT trigger false positives
    (out_dir / "api" / "endpoints.json").write_text(
        json.dumps({
            "endpoints": [
                {"url": "https://test.local/api/items/1", "method": "GET"},
                {"url": "https://test.local/api/profiles/1", "method": "GET"},
            ]
        }),
        encoding="utf-8",
    )
    monkeypatch.setenv("MOROS_HTTP_REQUESTS_REMAINING", "15")
    monkeypatch.delenv("MOROS_ALLOW_GATED_POST", raising=False)

    def _fp_handler(req):
        if "/items/" in req.full_url:
            return _SkillFakeResponse(200, req.full_url, b'{"catalog":"public","currency":"USD"}')
        return _SkillFakeResponse(200, req.full_url, b"<html><body>{not-json}</body></html>", {"Content-Type": "text/html"})

    res_fp = _run_skill_in_process(monkeypatch, "idor-audit", "test.local", t_dir, _fp_handler)
    assert res_fp["findings"] == []

    # 2. Differential comparison across two IDs with sensitive fields flags HIGH + evidence
    (out_dir / "api" / "endpoints.json").write_text(
        json.dumps({
            "endpoints": [
                {"url": "https://test.local/api/users/1", "method": "GET"},
                {"url": "https://test.local/api/orders/lookup", "method": "POST", "parameters": [{"name": "order_id"}]},
            ]
        }),
        encoding="utf-8",
    )

    def _diff_handler(req):
        if req.get_method() == "GET" and "/users/1" in req.full_url:
            return _SkillFakeResponse(200, req.full_url, b'{"id":1,"email":"alice@test.local"}')
        if req.get_method() == "GET" and "/users/2" in req.full_url:
            return _SkillFakeResponse(200, req.full_url, b'{"id":2,"email":"bob@test.local"}')
        return _SkillFakeResponse(404, req.full_url, b'{"error":"not found"}')

    res_diff = _run_skill_in_process(monkeypatch, "idor-audit", "test.local", t_dir, _diff_handler)
    assert len(res_diff["findings"]) == 1
    assert res_diff["findings"][0]["severity"] == "HIGH"
    assert "Differential ID comparison" in res_diff["findings"][0]["evidence"]

    # 3. HITL-gated POST comparison: unapproved -> 0 POSTs + WAITING_APPROVAL; approved -> runs POST comparison
    monkeypatch.setenv("MOROS_ALLOW_GATED_POST", "1")
    seen_methods = []

    def _post_handler(req):
        seen_methods.append((req.get_method(), req.full_url))
        if req.get_method() == "POST":
            payload = json.loads(req.data.decode("utf-8"))
            if payload.get("order_id") == 1:
                return _SkillFakeResponse(200, req.full_url, b'{"order_id":1,"account":"acct-1"}')
            return _SkillFakeResponse(200, req.full_url, b'{"order_id":2,"account":"acct-2"}')
        return _SkillFakeResponse(404, req.full_url, b'{"error":"not found"}')

    _run_skill_in_process(monkeypatch, "idor-audit", "test.local", t_dir, _post_handler)
    assert all(m == "GET" for m, _ in seen_methods)

    cm = CheckpointManager("test.local", t_dir)
    cps = cm.list_checkpoints()
    assert any(cp["target_url"] == "https://test.local/api/orders/lookup" and cp["status"] == "WAITING_APPROVAL" for cp in cps)
    for cp in cps:
        if cp["target_url"] == "https://test.local/api/orders/lookup":
            cm.decide(cp["id"], "approve", decider="operator")

    seen_methods.clear()
    res_post = _run_skill_in_process(monkeypatch, "idor-audit", "test.local", t_dir, _post_handler)
    assert any(m == "POST" for m, _ in seen_methods)
    assert any("POST IDOR" in f["title"] for f in res_post["findings"])


def test_graphql_audit_avoids_html_fp_and_supports_gated_post(tmp_path, monkeypatch):
    from tools.checkpoint_manager import CheckpointManager

    t_dir = tmp_path / "gql_target"
    t_dir.mkdir(parents=True)
    (t_dir / "scope-of-work.md").write_text("In scope: test.local\n", encoding="utf-8")
    monkeypatch.setenv("MOROS_HTTP_REQUESTS_REMAINING", "15")
    monkeypatch.delenv("MOROS_ALLOW_GATED_POST", raising=False)

    # HTML reflection of __schema and types must NOT be flagged
    def _html_handler(req):
        return _SkillFakeResponse(
            200,
            req.full_url,
            b"<html><body>Search results for __schema types</body></html>",
            {"Content-Type": "text/html"},
        )

    res_html = _run_skill_in_process(monkeypatch, "graphql-audit", "test.local", t_dir, _html_handler)
    assert res_html["findings"] == []

    # With MOROS_ALLOW_GATED_POST=1 and approved checkpoint, POST introspection succeeds
    monkeypatch.setenv("MOROS_ALLOW_GATED_POST", "1")
    cm = CheckpointManager("test.local", t_dir)
    cp = cm.create_checkpoint("GraphQL POST Introspection", "https://test.local/graphql", method="POST")
    cm.decide(cp["id"], "approve", decider="operator")

    post_bodies = []

    def _gql_post_handler(req):
        if req.get_method() == "POST" and req.full_url == "https://test.local/graphql":
            post_bodies.append(json.loads(req.data.decode("utf-8")))
            return _SkillFakeResponse(
                200,
                req.full_url,
                b'{"data":{"__schema":{"types":[{"name":"Query"},{"name":"User"}]}}}',
            )
        return _SkillFakeResponse(405, req.full_url, b'{"error":"GET not allowed"}')

    res_post = _run_skill_in_process(monkeypatch, "graphql-audit", "test.local", t_dir, _gql_post_handler)
    assert len(post_bodies) == 1
    assert "__schema" in post_bodies[0]["query"]
    assert any("GraphQL Schema Introspection Enabled" in f["title"] for f in res_post["findings"])


def test_rate_limit_test_respects_headers_and_gated_post(tmp_path, monkeypatch):
    from tools.checkpoint_manager import CheckpointManager

    t_dir = tmp_path / "rl_target"
    t_dir.mkdir(parents=True)
    (t_dir / "scope-of-work.md").write_text("In scope: test.local\n", encoding="utf-8")
    monkeypatch.setenv("MOROS_HTTP_REQUESTS_REMAINING", "15")
    monkeypatch.delenv("MOROS_ALLOW_GATED_POST", raising=False)

    # Rate-limit headers present -> no false positive
    def _rl_present_handler(req):
        return _SkillFakeResponse(
            200,
            req.full_url,
            b'{"ok":true}',
            {"Content-Type": "application/json", "X-RateLimit-Remaining": "4"},
        )

    res_ok = _run_skill_in_process(monkeypatch, "rate-limit-test", "test.local", t_dir, _rl_present_handler)
    assert res_ok["findings"] == []

    # Approved HITL POST burst without 429/headers -> flags MEDIUM finding
    monkeypatch.setenv("MOROS_ALLOW_GATED_POST", "1")
    cm = CheckpointManager("test.local", t_dir)
    cp = cm.create_checkpoint("Rate Limit POST Burst", "https://test.local/login", method="POST")
    cm.decide(cp["id"], "approve", decider="operator")

    post_count = 0

    def _rl_missing_post_handler(req):
        nonlocal post_count
        if req.get_method() == "POST":
            post_count += 1
            return _SkillFakeResponse(401, req.full_url, b'{"error":"invalid credentials"}')
        return _SkillFakeResponse(404, req.full_url, b'{"error":"not found"}')

    res_post = _run_skill_in_process(monkeypatch, "rate-limit-test", "test.local", t_dir, _rl_missing_post_handler)
    assert post_count == 5
    assert len(res_post["findings"]) == 1
    assert res_post["findings"][0]["severity"] == "MEDIUM"


def test_xxe_detect_safe_by_default_and_gated_post(tmp_path, monkeypatch):
    from tools.checkpoint_manager import CheckpointManager

    t_dir = tmp_path / "xxe_target"
    out_dir = t_dir / "output"
    (out_dir / "api").mkdir(parents=True)
    (t_dir / "scope-of-work.md").write_text("In scope: test.local\n", encoding="utf-8")
    (out_dir / "api" / "endpoints.json").write_text(
        json.dumps({
            "endpoints": [
                {"url": "https://test.local/static/xml-docs.js"},
                {"url": "https://test.local/api/xml-import"},
            ]
        }),
        encoding="utf-8",
    )
    monkeypatch.setenv("MOROS_HTTP_REQUESTS_REMAINING", "10")
    monkeypatch.setenv("MOROS_ALLOW_GATED_POST", "1")

    methods_seen = []

    def _xxe_handler(req):
        methods_seen.append((req.get_method(), req.full_url))
        if req.get_method() == "POST":
            return _SkillFakeResponse(200, req.full_url, b"<result>moros_entity_resolved</result>", {"Content-Type": "application/xml"})
        return _SkillFakeResponse(405, req.full_url, b"Method Not Allowed", {"Content-Type": "text/plain"})

    # Unapproved -> safe GET only, records LOW candidate and WAITING_APPROVAL checkpoint
    res_unapproved = _run_skill_in_process(monkeypatch, "xxe-detect", "test.local", t_dir, _xxe_handler)
    assert all(m == "GET" for m, _ in methods_seen)
    assert all("xml-docs.js" not in u for _, u in methods_seen)
    assert len(res_unapproved["findings"]) == 1
    assert res_unapproved["findings"][0]["severity"] == "LOW"

    cm = CheckpointManager("test.local", t_dir)
    for cp in cm.list_checkpoints():
        if cp["target_url"] == "https://test.local/api/xml-import":
            cm.decide(cp["id"], "approve", decider="operator")

    # Approved -> sends benign inline entity POST probe and detects resolution
    methods_seen.clear()
    res_approved = _run_skill_in_process(monkeypatch, "xxe-detect", "test.local", t_dir, _xxe_handler)
    assert any(m == "POST" for m, _ in methods_seen)
    assert len(res_approved["findings"]) == 1
    assert res_approved["findings"][0]["severity"] == "HIGH"
