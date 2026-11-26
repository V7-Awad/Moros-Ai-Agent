import datetime as dt
import io
import json
import ssl
import subprocess
import sys
import threading
import types
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from dashboard import server


def _http_handler(method="GET", path="/", body=None, headers=None, client_ip="127.0.0.1", srv=None):
    handler = server.DashboardHandler.__new__(server.DashboardHandler)
    raw_headers = {"Host": "127.0.0.1:8080"}
    if headers:
        raw_headers.update(headers)
    body_bytes = b"" if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode("utf-8"))
    if body is not None and "Content-Length" not in raw_headers:
        raw_headers["Content-Length"] = str(len(body_bytes))
    handler.command = method
    handler.path = path
    handler.headers = raw_headers
    handler.client_address = (client_ip, 54321)
    handler.server = srv
    handler.rfile = io.BytesIO(body_bytes)
    handler.wfile = io.BytesIO()
    handler._status_code = None
    handler._resp_headers = []

    def send_response(code, message=None):
        handler._status_code = code

    def send_header(k, v):
        handler._resp_headers.append((k, v))

    def end_headers():
        pass

    handler.send_response = send_response
    handler.send_header = send_header
    handler.end_headers = end_headers
    return handler


def _response_json(handler):
    return json.loads(handler.wfile.getvalue().decode("utf-8"))


def _generate_self_signed_cert(cert_path: Path, key_path: Path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import ipaddress

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


class TestCsrfOriginProtection:
    def test_cross_origin_post_rejected_with_403_and_allowed_same_host_or_headerless(self, tmp_path, monkeypatch):
        import setup as moros_setup

        targets_dir = tmp_path / "targets"
        targets_dir.mkdir()
        monkeypatch.delenv("MOROS_DASHBOARD_TOKEN", raising=False)
        monkeypatch.setattr(moros_setup, "PROJECT_ROOT", tmp_path)
        monkeypatch.setattr(server, "TARGETS_DIR", targets_dir)
        srv = types.SimpleNamespace(allow_remote=False, rate_limit_rpm=600)

        # 1. Cross-origin POST rejected with 403 {"error": "Cross-origin request blocked"}
        h_evil = _http_handler(
            "POST",
            "/api/targets/create",
            body={"domain": "evil-target.example"},
            headers={"Host": "127.0.0.1:8080", "Origin": "https://evil.example"},
            srv=srv,
        )
        h_evil.do_POST()
        assert h_evil._status_code == 403
        assert _response_json(h_evil)["error"] == "Cross-origin request blocked"
        assert not (targets_dir / "evil-target.example").exists()

        # 2. Same-host different-port Origin rejected with 403
        h_wrong_port = _http_handler(
            "POST",
            "/api/targets/create",
            body={"domain": "port-target.example"},
            headers={"Host": "127.0.0.1:8080", "Origin": "http://127.0.0.1:9999"},
            srv=srv,
        )
        h_wrong_port.do_POST()
        assert h_wrong_port._status_code == 403
        assert _response_json(h_wrong_port)["error"] == "Cross-origin request blocked"

        # 3. Origin: null rejected with 403
        h_null = _http_handler(
            "POST",
            "/api/targets/create",
            body={"domain": "null-target.example"},
            headers={"Host": "127.0.0.1:8080", "Origin": "null"},
            srv=srv,
        )
        h_null.do_POST()
        assert h_null._status_code == 403
        assert _response_json(h_null)["error"] == "Cross-origin request blocked"

        # 4. Mismatched Referer when Origin absent rejected with 403
        h_ref_evil = _http_handler(
            "POST",
            "/api/targets/create",
            body={"domain": "ref-target.example"},
            headers={"Host": "127.0.0.1:8080", "Referer": "https://evil.example/csrf.html"},
            srv=srv,
        )
        h_ref_evil.do_POST()
        assert h_ref_evil._status_code == 403
        assert _response_json(h_ref_evil)["error"] == "Cross-origin request blocked"

        # 5. PUT and DELETE cross-origin requests also rejected with 403
        for method_name in ("do_PUT", "do_DELETE"):
            h_mut = _http_handler(
                method_name.removeprefix("do_"),
                "/api/targets",
                headers={"Host": "127.0.0.1:8080", "Origin": "https://evil.example"},
                srv=srv,
            )
            getattr(h_mut, method_name)()
            assert h_mut._status_code == 403
            assert _response_json(h_mut)["error"] == "Cross-origin request blocked"

        # 6. Same-host Origin passes
        h_same = _http_handler(
            "POST",
            "/api/targets/create",
            body={"domain": "same-origin.example"},
            headers={"Host": "127.0.0.1:8080", "Origin": "http://127.0.0.1:8080"},
            srv=srv,
        )
        h_same.do_POST()
        assert h_same._status_code == 200
        assert (targets_dir / "same-origin.example").is_dir()

        # 7. Loopback-equivalent Origin (localhost vs 127.0.0.1 on same port) passes
        h_loopback = _http_handler(
            "POST",
            "/api/targets/create",
            body={"domain": "loopback-equiv.example"},
            headers={"Host": "127.0.0.1:8080", "Origin": "http://localhost:8080"},
            srv=srv,
        )
        h_loopback.do_POST()
        assert h_loopback._status_code == 200
        assert (targets_dir / "loopback-equiv.example").is_dir()

        # 8. Matching Referer without Origin passes
        h_ref_ok = _http_handler(
            "POST",
            "/api/targets/create",
            body={"domain": "ref-ok.example"},
            headers={"Host": "127.0.0.1:8080", "Referer": "http://localhost:8080/dashboard"},
            srv=srv,
        )
        h_ref_ok.do_POST()
        assert h_ref_ok._status_code == 200
        assert (targets_dir / "ref-ok.example").is_dir()

        # 9. Headerless API request (no Origin, no Referer) passes through to token auth
        monkeypatch.setenv("MOROS_DASHBOARD_TOKEN", "secret-token-123")
        h_no_hdr_unauth = _http_handler(
            "POST",
            "/api/targets/create",
            body={"domain": "cli-unauth.example"},
            headers={"Host": "127.0.0.1:8080"},
            srv=srv,
        )
        h_no_hdr_unauth.do_POST()
        assert h_no_hdr_unauth._status_code == 401

        h_no_hdr_auth = _http_handler(
            "POST",
            "/api/targets/create",
            body={"domain": "cli-auth.example"},
            headers={"Host": "127.0.0.1:8080", "Authorization": "Bearer secret-token-123"},
            srv=srv,
        )
        h_no_hdr_auth.do_POST()
        assert h_no_hdr_auth._status_code == 200
        assert (targets_dir / "cli-auth.example").is_dir()

    def test_remote_bind_rejects_loopback_origin_when_host_is_remote(self, tmp_path, monkeypatch):
        import setup as moros_setup

        targets_dir = tmp_path / "targets"
        targets_dir.mkdir()
        monkeypatch.setattr(moros_setup, "PROJECT_ROOT", tmp_path)
        monkeypatch.setattr(server, "TARGETS_DIR", targets_dir)
        srv = types.SimpleNamespace(allow_remote=True, dashboard_token="tok-remote", rate_limit_rpm=600)

        h_bad = _http_handler(
            "POST",
            "/api/targets/create",
            body={"domain": "remote-bad.example"},
            headers={
                "Host": "moros.corp.internal:8443",
                "Origin": "http://127.0.0.1:8443",
                "Authorization": "Bearer tok-remote",
            },
            srv=srv,
        )
        h_bad.do_POST()
        assert h_bad._status_code == 403
        assert _response_json(h_bad)["error"] == "Cross-origin request blocked"

        h_ok = _http_handler(
            "POST",
            "/api/targets/create",
            body={"domain": "remote-ok.example"},
            headers={
                "Host": "moros.corp.internal:8443",
                "Origin": "https://moros.corp.internal:8443",
                "Authorization": "Bearer tok-remote",
            },
            srv=srv,
        )
        h_ok.do_POST()
        assert h_ok._status_code == 200
        assert (targets_dir / "remote-ok.example").is_dir()


class TestApiRateLimiting:
    def test_sliding_window_limiter_unit_window_expiry(self):
        limiter = server.SlidingWindowRateLimiter(window_seconds=60.0)
        assert limiter.allow("10.0.0.1", limit=2, now=100.0) == (True, 0)
        assert limiter.allow("10.0.0.1", limit=2, now=110.0) == (True, 0)
        allowed, retry_after = limiter.allow("10.0.0.1", limit=2, now=120.0)
        assert allowed is False
        assert retry_after == 40
        # Other IP unaffected
        assert limiter.allow("10.0.0.2", limit=2, now=120.0) == (True, 0)
        # Oldest timestamp expires at 160.0 -> allowed again at 160.1
        assert limiter.allow("10.0.0.1", limit=2, now=160.1) == (True, 0)

    def test_live_http_server_returns_429_with_retry_after_when_limit_exceeded(self, tmp_path, monkeypatch):
        static_dir = tmp_path / "static"
        static_dir.mkdir()
        (static_dir / "index.html").write_text("<h1>Moros</h1>", encoding="utf-8")
        targets_dir = tmp_path / "targets"
        targets_dir.mkdir()
        monkeypatch.setattr(server, "STATIC_DIR", static_dir)
        monkeypatch.setattr(server, "TARGETS_DIR", targets_dir)
        monkeypatch.delenv("MOROS_DASHBOARD_TOKEN", raising=False)

        httpd = server.ThreadedHTTPServer(("127.0.0.1", 0), server.DashboardHandler)
        httpd.rate_limit_rpm = 3
        port = httpd.server_address[1]
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            for _ in range(3):
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/targets", timeout=5) as resp:
                    assert resp.status == 200

            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/api/targets", timeout=5)
            err = exc_info.value
            assert err.code == 429
            retry_after = err.headers.get("Retry-After")
            assert retry_after is not None and int(retry_after) >= 1
            payload = json.loads(err.read().decode("utf-8"))
            assert "rate limit" in payload["error"].lower()

            # Static HTML remains unthrottled by /api/ rate limiter
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5) as static_resp:
                assert static_resp.status == 200
                assert b"Moros" in static_resp.read()
        finally:
            httpd.shutdown()
            httpd.server_close()

    def test_env_rate_limit_applies_to_post_and_different_clients_are_isolated(self, tmp_path, monkeypatch):
        import setup as moros_setup

        targets_dir = tmp_path / "targets"
        targets_dir.mkdir()
        monkeypatch.setattr(moros_setup, "PROJECT_ROOT", tmp_path)
        monkeypatch.setattr(server, "TARGETS_DIR", targets_dir)
        monkeypatch.delenv("MOROS_DASHBOARD_TOKEN", raising=False)
        monkeypatch.setenv("MOROS_DASHBOARD_RATE_LIMIT", "2")
        srv = types.SimpleNamespace(allow_remote=False)

        for idx in range(2):
            h = _http_handler("POST", "/api/targets/create", body={"domain": f"t{idx}.example"}, client_ip="10.1.1.1", srv=srv)
            h.do_POST()
            assert h._status_code == 200

        h_limited = _http_handler("POST", "/api/targets/create", body={"domain": "t2.example"}, client_ip="10.1.1.1", srv=srv)
        h_limited.do_POST()
        assert h_limited._status_code == 429
        hdrs = {k.lower(): v for k, v in h_limited._resp_headers}
        assert int(hdrs["retry-after"]) >= 1

        # Different client IP still allowed
        h_other = _http_handler("GET", "/api/targets", client_ip="10.1.1.2", srv=srv)
        h_other.do_GET()
        assert h_other._status_code == 200


class TestDashboardTlsSupport:
    def test_mismatched_or_missing_tls_args_raise_errors(self, tmp_path, monkeypatch):
        cert = tmp_path / "cert.pem"
        key = tmp_path / "key.pem"
        cert.write_text("dummy", encoding="utf-8")
        key.write_text("dummy", encoding="utf-8")
        monkeypatch.delenv("MOROS_DASHBOARD_SSL_CERT", raising=False)
        monkeypatch.delenv("MOROS_DASHBOARD_SSL_KEY", raising=False)

        with pytest.raises(ValueError, match="must be provided together"):
            server.run_dashboard(host="127.0.0.1", port=0, open_browser=False, ssl_cert=str(cert))

        with pytest.raises(ValueError, match="must be provided together"):
            server.run_dashboard(host="127.0.0.1", port=0, open_browser=False, ssl_key=str(key))

        monkeypatch.setenv("MOROS_DASHBOARD_SSL_CERT", str(cert))
        with pytest.raises(ValueError, match="must be provided together"):
            server.run_dashboard(host="127.0.0.1", port=0, open_browser=False)
        monkeypatch.delenv("MOROS_DASHBOARD_SSL_CERT", raising=False)

        with pytest.raises(FileNotFoundError, match="certificate"):
            server.run_dashboard(
                host="127.0.0.1",
                port=0,
                open_browser=False,
                ssl_cert=str(tmp_path / "missing-cert.pem"),
                ssl_key=str(key),
            )

        with pytest.raises(FileNotFoundError, match="private key"):
            server.run_dashboard(
                host="127.0.0.1",
                port=0,
                open_browser=False,
                ssl_cert=str(cert),
                ssl_key=str(tmp_path / "missing-key.pem"),
            )

    def test_run_dashboard_tls_ssl_context_wrapping_mocked(self, tmp_path, monkeypatch, capsys):
        cert = tmp_path / "server.crt"
        key = tmp_path / "server.key"
        cert.write_text("CERT", encoding="utf-8")
        key.write_text("KEY", encoding="utf-8")

        captured = {}
        orig_server_cls = server.ThreadedHTTPServer

        class FakeServer(orig_server_cls):
            def serve_forever(self, poll_interval=0.5):
                captured["httpd"] = self
                return

        mock_ctx = MagicMock()
        mock_wrapped_sock = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_wrapped_sock
        ctx_calls = []

        def fake_ssl_context(protocol):
            ctx_calls.append(protocol)
            return mock_ctx

        monkeypatch.setattr(server, "ThreadedHTTPServer", FakeServer)
        monkeypatch.setattr(server.ssl, "SSLContext", fake_ssl_context)

        server.run_dashboard(
            host="127.0.0.1",
            port=0,
            open_browser=False,
            ssl_cert=str(cert),
            ssl_key=str(key),
        )

        out = capsys.readouterr().out
        assert "https://127.0.0.1:" in out
        assert ctx_calls == [ssl.PROTOCOL_TLS_SERVER]
        mock_ctx.load_cert_chain.assert_called_once_with(certfile=str(cert), keyfile=str(key))
        mock_ctx.wrap_socket.assert_called_once()
        _, wrap_kwargs = mock_ctx.wrap_socket.call_args
        assert wrap_kwargs.get("server_side") is True
        assert captured["httpd"].is_tls is True

    def test_run_dashboard_real_https_handshake_with_self_signed_cert(self, tmp_path, monkeypatch):
        cert = tmp_path / "self.crt"
        key = tmp_path / "self.key"
        _generate_self_signed_cert(cert, key)
        targets_dir = tmp_path / "targets"
        targets_dir.mkdir()
        monkeypatch.setattr(server, "TARGETS_DIR", targets_dir)
        monkeypatch.setenv("MOROS_DASHBOARD_SSL_CERT", str(cert))
        monkeypatch.setenv("MOROS_DASHBOARD_SSL_KEY", str(key))
        monkeypatch.delenv("MOROS_DASHBOARD_TOKEN", raising=False)

        ready = threading.Event()
        holder = {}
        orig_server_cls = server.ThreadedHTTPServer

        class SignallingServer(orig_server_cls):
            def serve_forever(self, poll_interval=0.5):
                holder["httpd"] = self
                ready.set()
                return super().serve_forever(poll_interval=poll_interval)

        monkeypatch.setattr(server, "ThreadedHTTPServer", SignallingServer)

        srv_thread = threading.Thread(
            target=server.run_dashboard,
            kwargs={"host": "127.0.0.1", "port": 0, "open_browser": False},
            daemon=True,
        )
        srv_thread.start()
        assert ready.wait(timeout=5)
        httpd = holder["httpd"]
        port = httpd.server_address[1]
        try:
            client_ctx = ssl.create_default_context(cafile=str(cert))
            with urllib.request.urlopen(f"https://127.0.0.1:{port}/api/targets", context=client_ctx, timeout=5) as resp:
                assert resp.status == 200
                assert json.loads(resp.read().decode("utf-8")) == []

            with urllib.request.urlopen(f"https://127.0.0.1:{port}/.well-known/agent.json", context=client_ctx, timeout=5) as card_resp:
                assert card_resp.status == 200
                card = json.loads(card_resp.read().decode("utf-8"))
                assert card["url"].startswith("https://")
        finally:
            httpd.shutdown()
            srv_thread.join(timeout=5)

    def test_cli_help_exposes_ssl_and_rate_limit_flags(self):
        proc = subprocess.run(
            [sys.executable, str(Path(__file__).resolve().parent.parent / "dashboard" / "server.py"), "--help"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert proc.returncode == 0
        assert "--ssl-cert" in proc.stdout
        assert "--ssl-key" in proc.stdout
        assert "--rate-limit" in proc.stdout
