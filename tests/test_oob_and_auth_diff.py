#!/usr/bin/env python3
"""Comprehensive pytest unit tests for tools/oob_server.py and tools/auth_diff.py."""

import json
import threading
import time
import urllib.error
import urllib.request

import pytest

from tools.auth_diff import (
    AuthDiffChecker,
    SessionContext,
    compute_response_similarity,
    normalize_response_body,
)
from tools.oob_server import OOBServer, OOBToken
from tools.scope_validator import ScopeValidator
from tools.scoped_http import ScopedHttpClient


def _http_call(url: str, method: str = "GET", headers=None, data: bytes = None):
    req = urllib.request.Request(url, data=data, headers=dict(headers or {}), method=method)
    with urllib.request.urlopen(req, timeout=5.0) as resp:
        return resp.status, dict(resp.headers), resp.read().decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# OOBServer & OOBToken tests (always use ephemeral port 0)
# ---------------------------------------------------------------------------


def test_oob_server_lifecycle_ephemeral_port():
    server = OOBServer(host="127.0.0.1", port=0)
    assert not server.is_running

    bound_port = server.start()
    assert bound_port > 0
    assert server.port == bound_port
    assert server.is_running
    assert server.base_url == f"http://127.0.0.1:{bound_port}"

    # Idempotent start()
    assert server.start() == bound_port

    server.stop()
    assert not server.is_running
    # Idempotent stop()
    server.stop()


def test_oob_token_registration_and_correlation_methods():
    with OOBServer(host="127.0.0.1", port=0, callback_domain="oob.test.local") as server:
        t_xss = server.register_token("xss-blind", "example.com", "https://example.com/feedback", metadata={"param": "msg"})
        t_ssrf = server.register_token("ssrf-identify", "example.com", "https://example.com/fetch")
        t_xxe = server.register_token("xxe-detect", "example.com", "https://example.com/xml")

        assert isinstance(t_xss, OOBToken)
        assert t_xss.token != t_ssrf.token != t_xxe.token
        assert t_xss.callback_url == f"{server.base_url}/oob/{t_xss.token}"
        assert t_xss.dns_canary == f"{t_xss.token}.oob.test.local"
        assert len(server.list_tokens()) == 3
        assert len(server.list_tokens(skill="xss-blind")) == 1

        # 1. Path correlation with .js suffix (blind XSS <script src=...>)
        status, headers, body = _http_call(f"{t_xss.callback_url}.js")
        assert status == 200
        assert "javascript" in headers.get("Content-Type", "").lower()
        assert "moros oob" in body

        # 2. Query parameter + POST body correlation (blind SSRF)
        status, _, _ = _http_call(
            f"{server.base_url}/collect?token={t_ssrf.token}&via=ssrf",
            method="POST",
            headers={"Content-Type": "application/json"},
            data=b'{"internal":"metadata"}',
        )
        assert status == 200

        # 3. Host-header canary + .dtd suffix (blind XXE)
        status, headers, _ = _http_call(
            f"{server.base_url}/entity.dtd",
            headers={"Host": f"{t_xxe.token}.oob.test.local"},
        )
        assert status == 200
        assert "xml" in headers.get("Content-Type", "").lower()

        xss_hits = server.poll_callbacks(t_xss)
        assert len(xss_hits) == 1
        assert xss_hits[0]["protocol"] == "http"
        assert xss_hits[0]["method"] == "GET"

        ssrf_hits = server.poll_callbacks(t_ssrf.token)
        assert len(ssrf_hits) == 1
        assert ssrf_hits[0]["method"] == "POST"
        assert ssrf_hits[0]["body"] == '{"internal":"metadata"}'
        assert ssrf_hits[0]["query_params"]["via"] == ["ssrf"]

        xxe_hits = server.poll_callbacks(t_xxe.token)
        assert len(xxe_hits) == 1
        assert xxe_hits[0]["host"] == f"{t_xxe.token}.oob.test.local"

        # Non-destructive poll vs consume=True
        assert len(server.poll_callbacks(t_xss.token, consume=False)) == 1
        assert len(server.poll_callbacks(t_xss.token, consume=True)) == 1
        assert server.poll_callbacks(t_xss.token) == []


def test_oob_dns_canary_and_wait_for_callback(tmp_path):
    state_file = tmp_path / "oob-state.json"
    with OOBServer(host="127.0.0.1", port=0, persistence_path=state_file) as server:
        tok = server.register_token("ssrf-identify", "example.com", "https://example.com/proxy")
        templates = server.build_canary_templates(tok)
        assert tok.callback_url in templates["xss-blind"]
        assert tok.dns_canary in templates["ssrf-dns"]
        assert tok.callback_url in templates["xxe-detect"]

        # Trigger DNS hit asynchronously while wait_for_callback blocks
        def _delayed_dns():
            time.sleep(0.08)
            _http_call(
                f"{server.base_url}/_dns",
                method="POST",
                headers={"Content-Type": "application/json"},
                data=json.dumps({"qname": tok.dns_canary, "qtype": "A", "source_ip": "10.0.0.5"}).encode("utf-8"),
            )

        t = threading.Thread(target=_delayed_dns, daemon=True)
        t.start()
        events = server.wait_for_callback(tok.token, timeout=2.0)
        t.join(timeout=2.0)

        assert len(events) == 1
        assert events[0]["protocol"] == "dns"
        assert events[0]["query_name"] == tok.dns_canary
        assert events[0]["remote_addr"] == "10.0.0.5"

        # Unmatched hit tracking
        _http_call(f"{server.base_url}/unknown-path")
        assert len(server.unmatched_callbacks()) == 1

        summaries = server.summarize_findings()
        assert len(summaries) == 1
        assert summaries[0]["confirmed"] is True
        assert summaries[0]["protocols"] == ["dns"]

    # Persistence reload check
    reloaded = OOBServer(host="127.0.0.1", port=0, persistence_path=state_file)
    assert reloaded.get_token(tok.token) is not None
    assert len(reloaded.poll_callbacks(tok.token)) == 1

    # Timeout returns empty list for untriggered token
    tok2 = reloaded.register_token("xxe-detect", "example.com", "https://example.com/soap")
    assert reloaded.wait_for_callback(tok2.token, timeout=0.05) == []


# ---------------------------------------------------------------------------
# AuthDiffChecker tests (with ScopedHttpClient & ScopeValidator)
# ---------------------------------------------------------------------------


class _FakeSessionClient:
    """In-memory transport stub matching ScopedHttpClient.get() response schema."""

    def __init__(self, handler, scope_validator: ScopeValidator, max_requests: int = 50):
        self.handler = handler
        self.scope_validator = scope_validator
        self.max_requests = max_requests
        self.request_count = 0
        self.stop_requested = False
        self.auth_headers = {}
        self.cookies = ""

    def get(self, url_or_path: str, headers=None, params=None):
        allowed, reason = self.scope_validator.is_allowed(url_or_path)
        if not allowed:
            self.stop_requested = True
            return {"status": "blocked", "reason": reason}
        if self.request_count >= self.max_requests:
            return {"status": "budget_exhausted", "reason": "Budget exhausted"}
        self.request_count += 1
        return self.handler(url_or_path, headers=headers, params=params)


def _json_resp(code: int, payload: dict, url: str = "https://app.example.com/api/orders/101"):
    body = json.dumps(payload)
    return {
        "status": "response",
        "status_code": code,
        "url": url,
        "headers": {"content-type": "application/json"},
        "body": body,
        "body_bytes": len(body.encode("utf-8")),
        "body_sha256": f"sha-{hash(body)}",
    }


def test_response_normalization_and_similarity():
    a = '{"id": 101, "owner": "alice", "timestamp": "2026-11-26T10:00:00Z", "request_id": "req-1"}'
    b = '{"request_id": "req-99", "owner": "alice", "id": 101, "timestamp": "2026-11-26T10:05:12Z"}'
    assert normalize_response_body(a, "application/json") == normalize_response_body(b, "application/json")
    assert compute_response_similarity(a, b, "application/json", "application/json") == 1.0

    err = '{"error": "forbidden"}'
    assert compute_response_similarity(a, err, "application/json", "application/json") < 0.5


def test_auth_diff_detects_bola_idor_and_respects_volatile_fields():
    validator = ScopeValidator("app.example.com")

    def handler_a(url, headers=None, params=None):
        return _json_resp(200, {"order_id": 101, "owner": "alice", "total": 99.5, "request_id": "aaa"}, url=url)

    def handler_b(url, headers=None, params=None):
        return _json_resp(200, {"order_id": 101, "owner": "alice", "total": 99.5, "request_id": "bbb"}, url=url)

    def handler_u(url, headers=None, params=None):
        return _json_resp(401, {"error": "Authentication required"}, url=url)

    checker = AuthDiffChecker(
        target="https://app.example.com",
        scope_validator=validator,
        user_a=SessionContext(name="user_a", role="owner", auth_headers={"Authorization": "Bearer A"}, owned_ids=["101", "alice"], client=_FakeSessionClient(handler_a, validator)),
        user_b=SessionContext(name="user_b", role="peer", auth_headers={"Authorization": "Bearer B"}, client=_FakeSessionClient(handler_b, validator)),
        unauthenticated=SessionContext(name="unauthenticated", role="unauthenticated", client=_FakeSessionClient(handler_u, validator)),
    )

    res = checker.check_endpoint("/api/orders/101")
    assert res["vulnerable"] is True
    assert res["finding_type"] == "bola_idor"
    assert res["cwe"] == "CWE-639"
    assert res["severity"] == "HIGH"
    assert res["similarity_user_a_vs_b"] == 1.0


def test_auth_diff_detects_owned_id_leakage_even_with_different_wrapper():
    validator = ScopeValidator("app.example.com")

    checker = AuthDiffChecker(
        target="https://app.example.com",
        scope_validator=validator,
        user_a=SessionContext(
            name="user_a",
            role="owner",
            auth_headers={"Authorization": "Bearer A"},
            owned_ids=["acct-778899"],
            client=_FakeSessionClient(
                lambda u, **kw: _json_resp(200, {"account": "acct-778899", "balance": 5000}, url=u),
                validator,
            ),
        ),
        user_b=SessionContext(
            name="user_b",
            role="peer",
            auth_headers={"Authorization": "Bearer B"},
            client=_FakeSessionClient(
                lambda u, **kw: _json_resp(200, {"viewer": "bob", "shared_notice": "Ref acct-778899", "extra": "x" * 200}, url=u),
                validator,
            ),
        ),
        unauthenticated=SessionContext(
            name="unauthenticated",
            role="unauthenticated",
            client=_FakeSessionClient(lambda u, **kw: _json_resp(403, {"error": "Forbidden"}, url=u), validator),
        ),
    )

    res = checker.check_endpoint("/api/accounts/acct-778899")
    assert res["vulnerable"] is True
    assert res["finding_type"] == "bola_idor"
    assert "acct-778899" in res["evidence"]["leaked_owner_ids"]


def test_auth_diff_detects_broken_access_control_and_ignores_login_shell():
    validator = ScopeValidator("app.example.com")

    # Case A: Unauthenticated gets exact same private JSON -> broken_access_control
    checker_open = AuthDiffChecker(
        target="https://app.example.com",
        scope_validator=validator,
        user_a=SessionContext(
            name="user_a",
            role="owner",
            auth_headers={"Authorization": "Bearer A"},
            client=_FakeSessionClient(lambda u, **kw: _json_resp(200, {"invoice": 42, "ssn_last4": "1234"}, url=u), validator),
        ),
        user_b=SessionContext(
            name="user_b",
            role="peer",
            auth_headers={"Authorization": "Bearer B"},
            client=_FakeSessionClient(lambda u, **kw: _json_resp(200, {"invoice": 42, "ssn_last4": "1234"}, url=u), validator),
        ),
        unauthenticated=SessionContext(
            name="unauthenticated",
            role="unauthenticated",
            client=_FakeSessionClient(lambda u, **kw: _json_resp(200, {"invoice": 42, "ssn_last4": "1234"}, url=u), validator),
        ),
    )
    res_open = checker_open.check_endpoint("/api/invoices/42")
    assert res_open["vulnerable"] is True
    assert res_open["finding_type"] == "broken_access_control"
    assert res_open["cwe"] == "CWE-862"

    # Case B: Unauthenticated gets 200 HTML login page while User A gets JSON -> NOT vulnerable
    checker_login = AuthDiffChecker(
        target="https://app.example.com",
        scope_validator=validator,
        user_a=SessionContext(
            name="user_a",
            role="owner",
            auth_headers={"Authorization": "Bearer A"},
            client=_FakeSessionClient(lambda u, **kw: _json_resp(200, {"invoice": 42, "amount": 50}, url=u), validator),
        ),
        user_b=SessionContext(
            name="user_b",
            role="peer",
            auth_headers={"Authorization": "Bearer B"},
            client=_FakeSessionClient(lambda u, **kw: _json_resp(403, {"error": "Forbidden"}, url=u), validator),
        ),
        unauthenticated=SessionContext(
            name="unauthenticated",
            role="unauthenticated",
            client=_FakeSessionClient(
                lambda u, **kw: {
                    "status": "response",
                    "status_code": 200,
                    "url": "https://app.example.com/login",
                    "headers": {"content-type": "text/html"},
                    "body": '<form><input type="password" name="password">Log in</form>',
                    "body_bytes": 58,
                    "body_sha256": "login-html",
                },
                validator,
            ),
        ),
    )
    res_login = checker_login.check_endpoint("/api/invoices/42")
    assert res_login["vulnerable"] is False
    assert res_login["finding_type"] == "access_controlled"


def test_auth_diff_avoids_false_positive_on_tenant_isolated_profile():
    validator = ScopeValidator("app.example.com")

    checker = AuthDiffChecker(
        target="https://app.example.com",
        scope_validator=validator,
        user_a=SessionContext(
            name="user_a",
            role="owner",
            auth_headers={"Authorization": "Bearer A"},
            owned_ids=["user-alice"],
            client=_FakeSessionClient(
                lambda u, **kw: _json_resp(200, {"id": "user-alice", "email": "alice@example.com", "bio": "Alice security engineer"}, url=u),
                validator,
            ),
        ),
        user_b=SessionContext(
            name="user_b",
            role="peer",
            auth_headers={"Authorization": "Bearer B"},
            owned_ids=["user-bob"],
            client=_FakeSessionClient(
                lambda u, **kw: _json_resp(200, {"id": "user-bob", "email": "bob@example.org", "bio": "Bob backend developer"}, url=u),
                validator,
            ),
        ),
        unauthenticated=SessionContext(
            name="unauthenticated",
            role="unauthenticated",
            client=_FakeSessionClient(lambda u, **kw: _json_resp(401, {"error": "Unauthorized"}, url=u), validator),
        ),
    )

    res = checker.check_endpoint("/api/me")
    assert res["vulnerable"] is False
    assert res["finding_type"] == "tenant_isolated"


def test_auth_diff_multi_role_and_symmetric_id_enumeration():
    validator = ScopeValidator("app.example.com")

    def handler_a(url, headers=None, params=None):
        if "/101" in url:
            return _json_resp(200, {"id": 101, "owner": "alice", "secret": "alpha"}, url=url)
        return _json_resp(403, {"error": "Forbidden"}, url=url)

    def handler_b(url, headers=None, params=None):
        if "/102" in url:
            return _json_resp(200, {"id": 102, "owner": "bob", "secret": "beta"}, url=url)
        # B can read 101 -> asymmetric BOLA!
        return _json_resp(200, {"id": 101, "owner": "alice", "secret": "alpha"}, url=url)

    def handler_readonly(url, headers=None, params=None):
        return _json_resp(200, {"id": 101, "owner": "alice", "secret": "alpha"}, url=url)

    checker = AuthDiffChecker(
        target="https://app.example.com",
        scope_validator=validator,
        user_a=SessionContext(name="user_a", role="owner", auth_headers={"Authorization": "Bearer A"}, client=_FakeSessionClient(handler_a, validator)),
        user_b=SessionContext(name="user_b", role="peer", auth_headers={"Authorization": "Bearer B"}, client=_FakeSessionClient(handler_b, validator)),
        unauthenticated=SessionContext(name="unauthenticated", role="unauthenticated", client=_FakeSessionClient(lambda u, **kw: _json_resp(401, {"error": "Unauthorized"}, url=u), validator)),
    )

    enum_res = checker.compare_id_enumeration("/api/orders/{id}", "101", "102")
    assert enum_res["vulnerable"] is True
    assert enum_res["user_a_resource"]["vulnerable"] is True
    assert enum_res["user_a_resource"]["finding_type"] == "bola_idor"
    assert enum_res["user_b_resource"]["vulnerable"] is False

    # Multi-role privilege escalation check (extra session matching owner when user_b is denied)
    multi_checker = AuthDiffChecker(
        target="https://app.example.com",
        scope_validator=validator,
        user_a=SessionContext(name="user_a", role="admin", auth_headers={"Authorization": "Bearer Admin"}, client=_FakeSessionClient(handler_readonly, validator)),
        user_b=SessionContext(name="user_b", role="peer", auth_headers={"Authorization": "Bearer B"}, client=_FakeSessionClient(lambda u, **kw: _json_resp(403, {"error": "Denied"}, url=u), validator)),
        unauthenticated=SessionContext(name="unauthenticated", role="unauthenticated", client=_FakeSessionClient(lambda u, **kw: _json_resp(401, {"error": "Unauthorized"}, url=u), validator)),
        extra_sessions=[
            SessionContext(name="readonly_role", role="readonly", auth_headers={"Authorization": "Bearer RO"}, client=_FakeSessionClient(handler_readonly, validator)),
        ],
    )
    multi_res = multi_checker.check_endpoint("/api/admin/audit-logs")
    assert multi_res["vulnerable"] is True
    assert multi_res["finding_type"] == "privilege_escalation"
    assert multi_res["cwe"] == "CWE-269"


def test_auth_diff_enforces_scope_validator_and_scoped_http_client(tmp_path, monkeypatch):
    # 1. Verify env auth credentials never leak into unauthenticated ScopedHttpClient
    monkeypatch.setenv("MOROS_AUTH_HEADER", "Authorization: Bearer secret-env-token")
    monkeypatch.setenv("MOROS_AUTH_COOKIE", "session=env-cookie")

    validator = ScopeValidator("app.example.com", out_of_scope=["admin.app.example.com", "evil.com"])
    checker = AuthDiffChecker(
        target="https://app.example.com",
        scope_validator=validator,
        user_a=SessionContext(name="user_a", role="owner", auth_headers={"Authorization": "Bearer A"}),
        user_b=SessionContext(name="user_b", role="peer", auth_headers={"Authorization": "Bearer B"}),
    )

    assert isinstance(checker.clients["user_a"], ScopedHttpClient)
    assert isinstance(checker.clients["unauthenticated"], ScopedHttpClient)
    assert checker.clients["unauthenticated"].auth_headers == {}
    assert checker.clients["unauthenticated"].cookies == ""

    # 2. Out-of-scope host is blocked before any network call
    blocked_res = checker.check_endpoint("https://evil.com/api/users/1")
    assert blocked_res["vulnerable"] is False
    assert blocked_res["finding_type"] == "scope_blocked"
    assert blocked_res["status"] == "blocked_scope"

    sub_blocked = checker.check_endpoint("https://admin.app.example.com/api/users/1")
    assert sub_blocked["finding_type"] == "scope_blocked"

    # 3. Scope policy "No authentication" blocks authenticated diffing cleanly
    target_dir = tmp_path / "target"
    target_dir.mkdir()
    (target_dir / "scope-of-work.md").write_text(
        "# Scope\nSame-host GET/HEAD only. No authentication allowed.\n## In Scope\n- `app.example.com`\n",
        encoding="utf-8",
    )
    strict_validator = ScopeValidator("app.example.com", target_dir=target_dir)
    strict_checker = AuthDiffChecker(
        target="https://app.example.com",
        scope_validator=strict_validator,
        user_a=SessionContext(name="user_a", role="owner", auth_headers={"Authorization": "Bearer A"}),
        user_b=SessionContext(name="user_b", role="peer", cookies="sid=B"),
    )
    assert strict_checker.clients["user_a"].auth_headers == {}
    assert strict_checker.clients["user_b"].cookies == ""
    policy_res = strict_checker.check_endpoint("/api/profile")
    assert policy_res["vulnerable"] is False
    assert policy_res["finding_type"] == "scope_blocked"
    assert policy_res["status"] == "blocked_scope"


def test_auth_diff_batch_endpoints_and_budget_stop():
    validator = ScopeValidator("app.example.com")
    client_a = _FakeSessionClient(lambda u, **kw: _json_resp(200, {"id": 1}, url=u), validator, max_requests=2)
    client_b = _FakeSessionClient(lambda u, **kw: _json_resp(200, {"id": 1}, url=u), validator, max_requests=2)
    client_u = _FakeSessionClient(lambda u, **kw: _json_resp(401, {"error": "Unauthorized"}, url=u), validator, max_requests=2)

    checker = AuthDiffChecker(
        target="https://app.example.com",
        scope_validator=validator,
        user_a=SessionContext(name="user_a", role="owner", auth_headers={"Authorization": "Bearer A"}, client=client_a),
        user_b=SessionContext(name="user_b", role="peer", auth_headers={"Authorization": "Bearer B"}, client=client_b),
        unauthenticated=SessionContext(name="unauthenticated", role="unauthenticated", client=client_u),
    )

    summary = checker.check_endpoints(["/api/1", "/api/2", "/api/3", "/api/4"])
    assert summary["total_checked"] == 3
    assert summary["vulnerable_count"] == 2
    assert summary["results"][-1]["finding_type"] == "budget_exhausted"


def test_oob_server_log_dir_alias_and_list_callbacks(tmp_path):
    log_dir = tmp_path / "logs"
    with OOBServer(host="127.0.0.1", port=0, log_dir=log_dir) as server:
        assert server.persistence_path == log_dir / "oob-state.json"
        tok = server.register_token("ssrf-identify", "example.com", "https://example.com/proxy")
        status, _, _ = _http_call(tok.callback_url)
        assert status == 200

        all_hits = server.list_callbacks()
        assert len(all_hits) == 1
        assert all_hits[0]["token"] == tok.token

        tok_hits = server.list_callbacks(tok.token)
        assert len(tok_hits) == 1
        assert (log_dir / "oob-state.json").is_file()

