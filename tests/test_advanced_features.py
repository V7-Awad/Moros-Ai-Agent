import json
import urllib.request
from pathlib import Path
from unittest.mock import patch

from tools.scope_validator import ScopeValidator
from tools.poc_generator import PoCGenerator
from tools.alert_dispatcher import AlertDispatcher
from tools.scoped_http import ScopedHttpClient, _SafeRedirectHandler
from tools.finding_review import review_candidates
from tools.finding_dedupe import deduplicate_findings
from tools.agent_runtime import AgentContext, build_default_agent_tools


def test_scope_validator_in_and_out_of_scope():
    validator = ScopeValidator(
        target="example.com",
        in_scope=["*.example.com", "example.com"],
        out_of_scope=["blog.example.com", "status.example.com", "*.zendesk.com"]
    )

    # Allowed in-scope
    ok1, reason1 = validator.is_allowed("api.example.com")
    assert ok1 is True
    ok2, reason2 = validator.is_allowed("example.com")
    assert ok2 is True

    # Blocked out-of-scope
    blocked1, r_b1 = validator.is_allowed("blog.example.com")
    assert blocked1 is False
    assert "OUT-OF-SCOPE" in r_b1

    blocked2, r_b2 = validator.is_allowed("support.zendesk.com")
    assert blocked2 is False
    assert "OUT-OF-SCOPE" in r_b2

    # Blocked foreign domain
    blocked3, r_b3 = validator.is_allowed("malicious.com")
    assert blocked3 is False


def test_scope_policy_enforces_same_host_budget_delay_and_no_auth(tmp_path, monkeypatch):
    target_dir = tmp_path / "target"
    target_dir.mkdir()
    (target_dir / "scope-of-work.md").write_text(
        "Target: https://lastpass.com\n"
        "Test profile: maximum 150 target requests; minimum 0.3 seconds between requests; "
        "same-host GET/HEAD only; no authentication, state-changing actions, exploit payloads, "
        "or cross-host navigation.\n",
        encoding="utf-8",
    )
    (target_dir / "scope.json").write_text(json.dumps({"in_scope": ["lastpass.com", "www.lastpass.com"]}), encoding="utf-8")
    monkeypatch.setenv("MOROS_AUTH_HEADER", "Authorization: Bearer must-not-send")
    monkeypatch.setenv("MOROS_AUTH_COOKIE", "session=must-not-send")
    validator = ScopeValidator("lastpass.com", target_dir=target_dir)
    client = ScopedHttpClient(
        "lastpass.com", max_requests=500, delay_seconds=0.0,
        auth_headers={"X-Auth": "must-not-send"}, cookies="cookie=must-not-send",
        scope_validator=validator,
    )

    assert validator.policy["allow_active_vulnerability_checks"] is False
    assert validator.policy["allow_cross_host_sources"] is False
    assert client.max_requests == 150
    assert client.delay_seconds == 0.3
    assert client.auth_headers == {}
    assert client.cookies == ""
    assert client.get("/", headers={"Authorization": "Bearer bypass"})["status"] == "blocked_scope"
    assert client.request_count == 0
    assert client.stop_requested is True
    assert validator.is_allowed("lastpass.com")[0] is True
    assert validator.is_allowed("www.lastpass.com")[0] is False


def test_finding_review_never_promotes_static_candidates(tmp_path):
    source = tmp_path / "source.js"
    source.write_text("location.href = value", encoding="utf-8")
    import hashlib
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    findings = [{
        "title": "Potential DOM XSS sink",
        "type": "DOM XSS",
        "source_artifact": str(source),
        "evidence": [{"source_artifact": str(source), "source_sha256": digest}],
        "validation_status": "unverified",
    }]

    result = review_candidates("example.com", tmp_path, findings, active_checks_allowed=False)

    assert result["network_requests"] == 0
    assert result["validated_findings"] == 0
    assert result["scope_blocks_reproduction"] is True
    assert result["findings"][0]["evidence_review"]["sha256_matches"] is True
    assert result["findings"][0]["skeptical_review"]["disposition"] == "not_proven"


def test_blocked_redirect_does_not_mark_findings_as_out_of_scope(tmp_path):
    output_logs = tmp_path / "output" / "logs"
    output_logs.mkdir(parents=True)
    (output_logs / "scope-audit-latest.json").write_text(json.dumps({
        "deviation_detected": False,
        "stopped_by_policy": True,
        "out_of_scope_hosts": {},
        "policy_violations": [{
            "kind": "blocked_redirect",
            "from": "lastpass.com",
            "to": "www.lastpass.com",
            "status_code": 302,
        }],
    }), encoding="utf-8")

    result = review_candidates("lastpass.com", tmp_path, [{"title": "Candidate", "type": "XSS"}], active_checks_allowed=False)

    assert result["scope_execution_audit"]["deviation_detected"] is False
    assert result["scope_execution_audit"]["stopped_by_policy"] is True
    assert result["scope_execution_audit"]["out_of_host_request_counts"] == {}


def test_agent_http_tool_reuses_scope_limited_client(tmp_path):
    target_dir = tmp_path / "lastpass.com"
    target_dir.mkdir()
    (target_dir / "scope-of-work.md").write_text(
        "Target: https://lastpass.com\nTest profile: same-host GET/HEAD only; no authentication, "
        "state-changing actions, exploit payloads, or cross-host navigation.\n",
        encoding="utf-8",
    )
    validator = ScopeValidator("lastpass.com", target_dir=target_dir)
    client = ScopedHttpClient("lastpass.com", scope_validator=validator)
    context = AgentContext("lastpass.com", target_dir, "specialist", "run-1")
    registry = build_default_agent_tools(context, allow_subagents=True, http_client=client)

    result = registry.get("http_get").func("https://www.lastpass.com/")

    assert result["status"] == "blocked"
    assert client.request_count == 0
    assert client.stop_requested is True


def test_shared_finding_deduplication_retains_all_occurrences():
    raw = [
        {"title": "Potential DOM XSS Sink 'innerHTML' in bundle.js", "type": "DOM XSS",
         "url": "https://example.com/bundle.js#L10", "line": 10, "source_file": "bundle.js",
         "snippet": "node.innerHTML = value", "evidence_ids": ["ev-1"]},
        {"title": "Potential DOM XSS Sink 'innerHTML' in bundle.js", "type": "DOM XSS",
         "url": "https://example.com/bundle.js#L10", "line": 10, "source_file": "bundle.js",
         "snippet": "node.innerHTML = value", "evidence_ids": ["ev-2"]},
        {"title": "Potential DOM XSS Sink 'eval' in bundle.js", "type": "DOM XSS",
         "url": "https://example.com/bundle.js#L30", "line": 30, "source_file": "bundle.js"},
    ]

    grouped = deduplicate_findings(raw)

    assert len(grouped) == 2
    inner_html = next(item for item in grouped if "innerHTML" in item["title"])
    assert inner_html["raw_record_count"] == 2
    assert inner_html["evidence_ids"] == ["ev-1", "ev-2"]


def test_poc_generator(tmp_path):
    gen = PoCGenerator("target.com", tmp_path)
    finding = {
        "title": "DOM XSS in Search Input",
        "url": "https://target.com/search?q=test",
        "severity": "HIGH",
        "cwe": "CWE-79",
        "evidence": "location.href reflection",
        "notes": "Parameter q reflects in innerHTML"
    }

    pocs = gen.generate_poc(finding, custom_headers={"X-Test": "123"})
    assert "poc_sh" in pocs
    assert "poc_py" in pocs

    sh_file = Path(pocs["poc_sh_abs"])
    py_file = Path(pocs["poc_py_abs"])

    assert sh_file.is_file()
    assert py_file.is_file()

    sh_text = sh_file.read_text(encoding="utf-8")
    assert "curl" in sh_text
    assert "https://target.com/search?q=test" in sh_text
    assert "X-Test: 123" in sh_text

    py_text = py_file.read_text(encoding="utf-8")
    assert "reproduce()" in py_text
    assert "https://target.com/search?q=test" in py_text


def test_scoped_http_client_authenticated_headers():
    client = ScopedHttpClient(
        target="example.com",
        auth_headers={"Authorization": "Bearer test-jwt-token"},
        cookies="session=abc123xyz"
    )

    assert client.auth_headers["Authorization"] == "Bearer test-jwt-token"
    assert client.cookies == "session=abc123xyz"
    assert hasattr(client, "get")
    assert hasattr(client, "head")


def test_scoped_http_redirects_must_stay_on_exact_configured_host():
    handler = _SafeRedirectHandler("lastpass.com")
    blocked = []
    handler_with_audit = _SafeRedirectHandler("lastpass.com", blocked.append)
    request = urllib.request.Request("https://lastpass.com/", method="HEAD")

    same_host = handler.redirect_request(request, None, 302, "Found", {}, "https://lastpass.com/login")
    sibling_host = handler.redirect_request(request, None, 302, "Found", {}, "https://www.lastpass.com/")

    assert same_host is not None
    assert same_host.full_url == "https://lastpass.com/login"
    assert sibling_host is None
    handler_with_audit.redirect_request(request, None, 302, "Found", {}, "https://www.lastpass.com/")
    assert blocked == [{"from": "lastpass.com", "to": "www.lastpass.com", "status_code": 302}]


def test_scoped_http_stops_after_blocked_host_without_sending_request():
    client = ScopedHttpClient(
        "example.com",
        scope_validator=ScopeValidator("example.com", in_scope=["example.com"]),
    )
    result = client.request("https://outside.example.net/")

    assert result["status"] == "blocked"
    assert client.stop_requested is True
    assert client.request_count == 0
    assert client.request("/")["status"] == "blocked_scope"


def test_scope_validator_reads_env_vars(monkeypatch):
    monkeypatch.setenv("MOROS_IN_SCOPE", "api.test.com,*.cdn.test.com")
    monkeypatch.setenv("MOROS_OUT_OF_SCOPE", "blog.test.com")
    sv = ScopeValidator("test.com")
    assert "api.test.com" in sv.in_scope
    assert "blog.test.com" in sv.out_of_scope
    allowed, _ = sv.is_allowed("api.test.com")
    assert allowed
    allowed, _ = sv.is_allowed("blog.test.com")
    assert not allowed


def test_alert_dispatcher_safe_handling():
    with patch.dict("os.environ", {}, clear=True):
        dispatcher = AlertDispatcher()
        assert dispatcher.is_configured() is False
        # Should not crash when not configured
        dispatcher.send_alert("Test Alert", "Test Message", "HIGH")


def test_alert_dispatcher_telegram_and_slack():
    env = {
        "TELEGRAM_BOT_TOKEN": "mock-token",
        "TELEGRAM_CHAT_ID": "12345",
        "SLACK_WEBHOOK_URL": "https://hooks.slack.com/services/mock",
    }
    with patch.dict("os.environ", env, clear=True):
        dispatcher = AlertDispatcher()
        assert dispatcher.is_configured() is True
        with patch("urllib.request.urlopen") as mock_open:
            dispatcher.send_alert(
                "SQLi Vulnerability",
                "Discovered parameter injection on /api/items",
                "HIGH",
                fields={"Target": "target.com", "Param": "id"}
            )
            assert mock_open.call_count == 2


class _FakeHttpResponse:
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


def test_scoped_http_blocks_state_changing_methods_by_default():
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        client = ScopedHttpClient("example.com")
        res = client.post("/api/items", json_body={"name": "test"}) if method == "POST" else client.request("/api/items", method=method, json_body={"name": "test"})
        assert res["status"] == "blocked_scope"
        assert client.stop_requested is True
        assert client.request_count == 0
        assert any(v["kind"] == "blocked_method" and v["method"] == method for v in client.policy_violations)


def test_scoped_http_requires_explicit_approval_callback_for_state_changing(tmp_path):
    # 1. Missing approval_callback -> default deny
    client_no_cb = ScopedHttpClient("example.com", allow_state_changing=True)
    res_no_cb = client_no_cb.post("/api/items", json_body={"id": 1})
    assert res_no_cb["status"] == "blocked_scope"
    assert client_no_cb.request_count == 0
    assert any(v["kind"] == "unapproved_state_changing" for v in client_no_cb.policy_violations)

    # 2. Callback returning False -> denied
    client_denied = ScopedHttpClient(
        "example.com",
        allow_state_changing=True,
        approval_callback=lambda m, u, b: False,
    )
    res_denied = client_denied.post("/api/items", json_body={"id": 1})
    assert res_denied["status"] == "blocked_scope"
    assert client_denied.request_count == 0
    assert any(v["kind"] == "hitl_rejected" for v in client_denied.policy_violations)

    # 3. Callback raising exception -> fail closed
    def _boom(m, u, b):
        raise RuntimeError("callback error")

    client_err = ScopedHttpClient("example.com", allow_state_changing=True, approval_callback=_boom)
    assert client_err.post("/api/items", data="x=1")["status"] == "blocked_scope"
    assert client_err.request_count == 0

    # 4. Scope policy forbidding state-changing actions overrides allow_state_changing=True
    (tmp_path / "scope-of-work.md").write_text(
        "Target: https://example.com\nTest profile: no state-changing actions.\n",
        encoding="utf-8",
    )
    sv = ScopeValidator("example.com", target_dir=tmp_path)
    client_policy = ScopedHttpClient(
        "example.com",
        scope_validator=sv,
        allow_state_changing=True,
        approval_callback=lambda m, u, b: True,
    )
    assert client_policy.post("/api/items", json_body={"id": 1})["status"] == "blocked_scope"
    assert client_policy.request_count == 0


def test_scoped_http_approved_post_sends_json_and_redacts_logs():
    seen_approvals = []
    captured_requests = []

    def _approve(method: str, url: str, preview: str) -> bool:
        seen_approvals.append((method, url, preview))
        return True

    def _fake_open(req, timeout=15.0):
        captured_requests.append(req)
        return _FakeHttpResponse(200, req.full_url, b'{"data":{"__typename":"Query"}}')

    client = ScopedHttpClient(
        "example.com",
        delay_seconds=0.0,
        auth_headers={"Authorization": "Bearer super-secret-jwt", "X-Api-Key": "secret-api-key"},
        cookies="session=super-secret-cookie",
        allow_state_changing=True,
        approval_callback=_approve,
    )

    # Out-of-scope POST must be blocked before invoking approval_callback
    blocked_oos = client.post("https://evil.com/graphql", json_body={"query": "{}"})
    assert blocked_oos["status"] == "blocked"
    assert seen_approvals == []

    # Fresh approved client for valid in-scope JSON POST
    client2 = ScopedHttpClient(
        "example.com",
        delay_seconds=0.0,
        auth_headers={"Authorization": "Bearer super-secret-jwt", "X-Api-Key": "secret-api-key"},
        cookies="session=super-secret-cookie",
        allow_state_changing=True,
        approval_callback=_approve,
    )
    with patch.object(client2._opener, "open", side_effect=_fake_open):
        resp = client2.post(
            "/api/graphql",
            json_body={"query": "{ __typename }"},
            headers={"Accept": "application/json"},
        )

    assert resp["status"] == "response"
    assert resp["status_code"] == 200
    assert client2.request_count == 1
    assert len(seen_approvals) == 1
    assert seen_approvals[0][0] == "POST"
    assert seen_approvals[0][1] == "https://example.com/api/graphql"
    assert '"query"' in seen_approvals[0][2]

    sent_req = captured_requests[0]
    assert sent_req.get_method() == "POST"
    assert json.loads(sent_req.data.decode("utf-8")) == {"query": "{ __typename }"}
    assert sent_req.get_header("Content-type") == "application/json"

    assert len(client2.request_logs) == 1
    log_entry = client2.request_logs[0]
    assert log_entry["method"] == "POST"
    assert log_entry["has_body"] is True
    assert log_entry["headers"]["Authorization"] == "[REDACTED]"
    assert log_entry["headers"]["X-Api-Key"] == "[REDACTED]"
    assert log_entry["headers"]["Cookie"] == "[REDACTED]"
    assert log_entry["headers"]["Accept"] == "application/json"
