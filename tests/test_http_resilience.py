#!/usr/bin/env python3
"""Offline unit tests for ScopedHttpClient resilience features (proxy, retry/backoff, cookie jar)."""

import http.client
import json
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

import pytest

from tools.scope_validator import ScopeValidator
from tools.scoped_http import ScopedHttpClient


class _EphemeralHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _start_server(handler_cls):
    server = _EphemeralHTTPServer(("127.0.0.1", 0), handler_cls)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


def _forward_port_80(monkeypatch, target_port: int):
    orig_init = http.client.HTTPConnection.__init__

    def _patched_init(conn_self, host, conn_port=None, *args, **kwargs):
        if conn_port is None and "port" in kwargs:
            conn_port = kwargs.pop("port")
        if host == "127.0.0.1" and conn_port in (None, 80):
            conn_port = target_port
        return orig_init(conn_self, host, conn_port, *args, **kwargs)

    monkeypatch.setattr(http.client.HTTPConnection, "__init__", _patched_init)


# ---------------------------------------------------------------------------
# Proxy validation, credential redaction, and routing tests
# ---------------------------------------------------------------------------


def test_proxy_validation_and_normalization(monkeypatch):
    monkeypatch.delenv("MOROS_PROXY", raising=False)

    default_client = ScopedHttpClient("example.com")
    assert default_client.proxy is None

    bare = ScopedHttpClient("example.com", proxy="127.0.0.1:8080")
    assert bare.proxy == "http://127.0.0.1:8080"
    assert any(isinstance(h, urllib.request.ProxyHandler) for h in bare._opener.handlers)

    https_p = ScopedHttpClient("example.com", proxy="https://proxy.internal:8443")
    assert https_p.proxy == "https://proxy.internal:8443"

    socks_p = ScopedHttpClient("example.com", proxy="socks5://127.0.0.1:1080")
    assert socks_p.proxy == "socks5://127.0.0.1:1080"

    ipv6_p = ScopedHttpClient("example.com", proxy="[::1]:8888")
    assert ipv6_p.proxy == "http://[::1]:8888"

    # Environment variable MOROS_PROXY fallback and explicit override
    monkeypatch.setenv("MOROS_PROXY", "127.0.0.1:3128")
    env_client = ScopedHttpClient("example.com")
    assert env_client.proxy == "http://127.0.0.1:3128"

    disabled_client = ScopedHttpClient("example.com", proxy="")
    assert disabled_client.proxy is None

    # Credential redaction in self.proxy and in validation errors
    cred_client = ScopedHttpClient("example.com", proxy="http://alice:s3cr3t_pw@127.0.0.1:8080")
    assert cred_client.proxy == "http://[REDACTED]@127.0.0.1:8080"
    assert "alice" not in cred_client.proxy
    assert "s3cr3t_pw" not in cred_client.proxy

    with pytest.raises(ValueError) as exc_info:
        ScopedHttpClient("example.com", proxy="http://alice:s3cr3t_pw@127.0.0.1:99999")
    assert "alice" not in str(exc_info.value)
    assert "s3cr3t_pw" not in str(exc_info.value)

    for bad_proxy in (
        "file:///etc/passwd",
        "file:/etc/passwd",
        "ftp://127.0.0.1:21",
        "javascript:alert(1)",
        "http://",
        "just-a-hostname",
        "http://127.0.0.1:0",
        "http://127.0.0.1:99999",
        "http://127.0.0.1:8080/unexpected-path",
        "http://127.0.0.1:8080 bad",
    ):
        with pytest.raises(ValueError):
            ScopedHttpClient("example.com", proxy=bad_proxy)


def test_http_proxy_routing_redacts_credentials_and_preserves_scope():
    proxied_requests = []

    class MockProxyHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def do_GET(self):
            proxied_requests.append({
                "method": self.command,
                "path": self.path,
                "host": self.headers.get("Host"),
                "proxy_auth": self.headers.get("Proxy-Authorization"),
            })
            if self.path.endswith("/bounce-evil"):
                self.send_response(302)
                self.send_header("Location", "https://evil.example/exfil")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

            payload = json.dumps({"proxied": True, "url": self.path}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    proxy_srv, proxy_port = _start_server(MockProxyHandler)
    try:
        client = ScopedHttpClient(
            "http://example.com",
            delay_seconds=0.0,
            max_retries=0,
            proxy=f"http://proxyuser:proxypass99@127.0.0.1:{proxy_port}",
        )
        resp = client.get("/api/ping")
        assert resp["status"] == "response"
        assert resp["status_code"] == 200
        assert json.loads(resp["body"])["proxied"] is True
        assert len(proxied_requests) == 1
        assert proxied_requests[0]["path"] == "http://example.com/api/ping"
        assert proxied_requests[0]["proxy_auth"].startswith("Basic ")

        # Verify proxy credentials never appear in client.proxy or request_logs
        assert client.proxy == f"http://[REDACTED]@127.0.0.1:{proxy_port}"
        serialized_logs = json.dumps(client.request_logs)
        assert "proxyuser" not in serialized_logs
        assert "proxypass99" not in serialized_logs
        assert client.request_logs[0]["proxy"] == client.proxy
        assert client.request_logs[0]["headers"].get("Proxy-authorization") == "[REDACTED]"

        # Out-of-scope target host must still be blocked before hitting proxy
        blocked = client.get("https://evil.example/steal")
        assert blocked["status"] == "blocked"
        assert len(proxied_requests) == 1

        # Cross-host redirect returned via proxy must still be blocked by _SafeRedirectHandler
        client2 = ScopedHttpClient(
            "http://example.com",
            delay_seconds=0.0,
            max_retries=0,
            proxy=f"http://127.0.0.1:{proxy_port}",
        )
        redir_resp = client2.get("/bounce-evil")
        assert redir_resp["status_code"] == 302
        assert client2.stop_requested is True
        assert any(v["kind"] == "blocked_redirect" and v["to"] == "evil.example" for v in client2.policy_violations)
        assert all("evil.example" not in r["path"] for r in proxied_requests)

        # Loopback targets also route through explicit proxy on Windows/macOS/Linux
        loopback_client = ScopedHttpClient(
            "http://127.0.0.1",
            delay_seconds=0.0,
            max_retries=0,
            proxy=f"127.0.0.1:{proxy_port}",
        )
        lb_resp = loopback_client.get("/local-check")
        assert lb_resp["status"] == "response"
        assert lb_resp["status_code"] == 200
        assert proxied_requests[-1]["path"] == "http://127.0.0.1/local-check"
    finally:
        proxy_srv.shutdown()
        proxy_srv.server_close()


def test_proxy_network_error_redacts_credentials():
    # Find an unbound ephemeral port by binding and closing a socket
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        closed_port = s.getsockname()[1]

    client = ScopedHttpClient(
        "http://example.com",
        delay_seconds=0.0,
        max_retries=0,
        proxy=f"http://alice:verysecretpass@127.0.0.1:{closed_port}",
    )
    res = client.get("/test")
    assert res["status"] == "network_error"
    assert "alice" not in res["error"]
    assert "verysecretpass" not in res["error"]
    serialized_logs = json.dumps(client.request_logs)
    assert "alice" not in serialized_logs
    assert "verysecretpass" not in serialized_logs


# ---------------------------------------------------------------------------
# Transient retry & backoff tests
# ---------------------------------------------------------------------------


def test_transient_retry_503_and_429_retry_after_and_budget(monkeypatch):
    counters = {"flaky_get": 0, "rl_get": 0, "flaky_head": 0, "not_found": 0, "post": 0, "always_503": 0}

    class RetryHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def do_HEAD(self):
            counters["flaky_head"] += 1
            if counters["flaky_head"] < 2:
                self.send_response(502)
                self.end_headers()
                return
            self.send_response(200)
            self.end_headers()

        def do_GET(self):
            if self.path == "/flaky":
                counters["flaky_get"] += 1
                if counters["flaky_get"] <= 2:
                    self._send_text(503, "Service Unavailable")
                    return
                self._send_text(200, "recovered-503")
                return

            if self.path == "/rate-limited":
                counters["rl_get"] += 1
                if counters["rl_get"] == 1:
                    self.send_response(429)
                    self.send_header("Retry-After", "0.12")
                    self.send_header("Content-Length", "12")
                    self.end_headers()
                    self.wfile.write(b"slow down...")
                    return
                self._send_text(200, "recovered-429")
                return

            if self.path == "/rate-limited-huge":
                self.send_response(429)
                self.send_header("Retry-After", "9999")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

            if self.path == "/missing":
                counters["not_found"] += 1
                self._send_text(404, "not found")
                return

            if self.path == "/always-503":
                counters["always_503"] += 1
                self._send_text(503, "down")
                return

            self._send_text(500, "server error")

        def do_POST(self):
            counters["post"] += 1
            self._send_text(503, "unavailable")

        def do_PUT(self):
            counters["post"] += 1
            self._send_text(429, "rate limited")

        def do_PATCH(self):
            counters["post"] += 1
            self._send_text(503, "unavailable")

        def do_DELETE(self):
            counters["post"] += 1
            self._send_text(504, "gateway timeout")

        def _send_text(self, status: int, text: str):
            body = text.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv, port = _start_server(RetryHandler)
    _forward_port_80(monkeypatch, port)
    try:
        # 1. GET 503 -> 503 -> 200 succeeds on 3rd attempt
        client = ScopedHttpClient(
            "http://127.0.0.1",
            delay_seconds=0.0,
            max_retries=2,
            retry_backoff_seconds=0.02,
            max_retry_wait=0.2,
        )
        res = client.get("/flaky")
        assert res["status"] == "response"
        assert res["status_code"] == 200
        assert res["body"] == "recovered-503"
        assert res["retries"] == 2
        assert counters["flaky_get"] == 3
        assert client.request_count == 3
        assert len(client.request_logs) == 3

        # 2. HEAD 502 -> 200 succeeds on retry
        head_res = client.head("/flaky-head")
        assert head_res["status_code"] == 200
        assert head_res["retries"] == 1
        assert counters["flaky_head"] == 2

        # 3. GET 429 respects numeric Retry-After header
        t0 = time.monotonic()
        rl_res = client.get("/rate-limited")
        elapsed = time.monotonic() - t0
        assert rl_res["status_code"] == 200
        assert rl_res["body"] == "recovered-429"
        assert rl_res["retries"] == 1
        assert elapsed >= 0.09

        # 4. Huge Retry-After is capped at max_retry_wait
        capped_client = ScopedHttpClient(
            "http://127.0.0.1",
            delay_seconds=0.0,
            max_retries=1,
            retry_backoff_seconds=0.01,
            max_retry_wait=0.08,
        )
        t1 = time.monotonic()
        capped_res = capped_client.get("/rate-limited-huge")
        capped_elapsed = time.monotonic() - t1
        assert capped_res["status_code"] == 429
        assert capped_elapsed < 1.0

        # 5. Non-transient 404 is never retried
        nf_res = client.get("/missing")
        assert nf_res["status_code"] == 404
        assert nf_res["retries"] == 0
        assert counters["not_found"] == 1

        # 6. Budget cap stops retries cleanly without exceeding max_requests
        budget_client = ScopedHttpClient(
            "http://127.0.0.1",
            max_requests=2,
            delay_seconds=0.0,
            max_retries=5,
            retry_backoff_seconds=0.01,
        )
        b_res = budget_client.get("/always-503")
        assert b_res["status"] == "response"
        assert b_res["status_code"] == 503
        assert budget_client.request_count == 2
        assert counters["always_503"] == 2

        # 7. State-changing methods (POST/PUT/PATCH/DELETE) NEVER retry even on 503/429/504
        for idx, state_method in enumerate(("POST", "PUT", "PATCH", "DELETE"), start=1):
            sc_client = ScopedHttpClient(
                "http://127.0.0.1",
                delay_seconds=0.0,
                max_retries=3,
                retry_backoff_seconds=0.01,
                allow_state_changing=True,
                approval_callback=lambda m, u, b: True,
            )
            sc_res = (
                sc_client.post("/submit", json_body={"x": 1})
                if state_method == "POST"
                else sc_client.request("/submit", method=state_method, json_body={"x": 1})
            )
            assert sc_res["status"] == "response"
            assert sc_res["status_code"] in (429, 503, 504)
            assert sc_res["retries"] == 0
            assert sc_client.request_count == 1
            assert counters["post"] == idx

        # 8. max_retries=0 and MOROS_HTTP_RETRIES env var
        no_retry = ScopedHttpClient("http://127.0.0.1", delay_seconds=0.0, max_retries=0)
        nr_res = no_retry.get("/always-503")
        assert nr_res["status_code"] == 503
        assert no_retry.request_count == 1

        monkeypatch.setenv("MOROS_HTTP_RETRIES", "1")
        env_retry = ScopedHttpClient("http://127.0.0.1", delay_seconds=0.0, retry_backoff_seconds=0.01)
        assert env_retry.max_retries == 1
        env_res = env_retry.get("/always-503")
        assert env_res["status_code"] == 503
        assert env_retry.request_count == 2
    finally:
        srv.shutdown()
        srv.server_close()


def test_transient_timeout_retries_and_succeeds(monkeypatch):
    calls = {"n": 0}

    class FakeResp:
        status = 200
        headers = {"Content-Type": "text/plain"}

        def geturl(self):
            return "https://example.com/slow"

        def read(self, n=-1):
            return b"ok-after-timeout"

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    client = ScopedHttpClient(
        "https://example.com",
        delay_seconds=0.0,
        max_retries=2,
        retry_backoff_seconds=0.01,
    )

    def _flaky_open(req, timeout=15.0):
        calls["n"] += 1
        if calls["n"] == 1:
            raise TimeoutError("timed out")
        return FakeResp()

    monkeypatch.setattr(client._opener, "open", _flaky_open)
    res = client.get("/slow")
    assert res["status"] == "response"
    assert res["status_code"] == 200
    assert res["body"] == "ok-after-timeout"
    assert res["retries"] == 1
    assert client.request_count == 2


# ---------------------------------------------------------------------------
# Cookie jar persistence & log redaction tests
# ---------------------------------------------------------------------------


def test_cookie_jar_persists_session_and_redacts_logs(tmp_path, monkeypatch):
    seen_cookies = []

    class CookieHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def do_GET(self):
            cookie_hdr = self.headers.get("Cookie", "")
            seen_cookies.append((self.path, cookie_hdr))
            if self.path == "/login":
                body = b'{"logged_in":true}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie", "moros_sid=secret_session_value_42; Path=/; HttpOnly")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            if self.path == "/whoami":
                authed = "moros_sid=secret_session_value_42" in cookie_hdr
                body = json.dumps({"authenticated": authed}).encode("utf-8")
                self.send_response(200 if authed else 401)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            self.send_response(404)
            self.end_headers()

    srv, port = _start_server(CookieHandler)
    _forward_port_80(monkeypatch, port)
    try:
        # 1. Default enable_cookie_jar=False preserves existing stateless behavior
        stateless = ScopedHttpClient("http://127.0.0.1", delay_seconds=0.0, max_retries=0)
        assert stateless.cookie_jar is None
        assert stateless.get("/login")["status_code"] == 200
        who_stateless = stateless.get("/whoami")
        assert who_stateless["status_code"] == 401
        assert seen_cookies[-1] == ("/whoami", "")

        # 2. enable_cookie_jar=True persists Set-Cookie -> Cookie across requests
        seen_cookies.clear()
        jar_client = ScopedHttpClient(
            "http://127.0.0.1",
            delay_seconds=0.0,
            max_retries=0,
            enable_cookie_jar=True,
        )
        r1 = jar_client.get("/login")
        assert r1["status_code"] == 200
        assert "moros_sid=secret_session_value_42" in r1["headers"].get("set-cookie", "")

        r2 = jar_client.get("/whoami")
        assert r2["status_code"] == 200
        assert json.loads(r2["body"])["authenticated"] is True
        assert seen_cookies == [("/login", ""), ("/whoami", "moros_sid=secret_session_value_42")]

        # Verify request_logs redact both Set-Cookie and Cookie without leaking the secret value
        serialized_logs = json.dumps(jar_client.request_logs)
        assert "secret_session_value_42" not in serialized_logs
        assert jar_client.request_logs[0]["response_headers"]["set-cookie"] == "[REDACTED]"
        assert jar_client.request_logs[1]["headers"]["Cookie"] == "[REDACTED]"

        # 3. MOROS_COOKIE_JAR=1 enables jar when enable_cookie_jar is omitted
        monkeypatch.setenv("MOROS_COOKIE_JAR", "1")
        env_jar = ScopedHttpClient("http://127.0.0.1", delay_seconds=0.0, max_retries=0)
        assert env_jar.enable_cookie_jar is True
        assert env_jar.cookie_jar is not None

        # 4. Scope policy "no authentication" disables cookie jar even if MOROS_COOKIE_JAR=1
        (tmp_path / "scope-of-work.md").write_text(
            "Target: http://127.0.0.1\nTest profile: same-host GET/HEAD only; no authentication.\n",
            encoding="utf-8",
        )
        sv = ScopeValidator("127.0.0.1", target_dir=tmp_path)
        blocked_auth_client = ScopedHttpClient(
            "http://127.0.0.1",
            delay_seconds=0.0,
            scope_validator=sv,
            enable_cookie_jar=True,
        )
        assert blocked_auth_client.enable_cookie_jar is False
        assert blocked_auth_client.cookie_jar is None
    finally:
        srv.shutdown()
        srv.server_close()
