import http.client
import importlib.util
import json
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import ThreadingMixIn

from dashboard import server as dashboard_server
from tools.llm_client import LLMClient
from tools.scope_validator import ScopeValidator
from tools.scoped_http import ScopedHttpClient
from tools.skill_runner import SkillRunner


class _EphemeralHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _make_mock_vuln_handler(recorded_requests: list):
    class MockVulnAppHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def _record(self):
            recorded_requests.append((self.command, self.path))

        def do_HEAD(self):
            self._record()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()

        def do_GET(self):
            self._record()
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path
            params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

            if path == "/":
                body = (
                    "<!doctype html><html><head><title>Mock Target</title></head>"
                    "<body><h1>Mock Vulnerable App</h1>"
                    "<a href='/search?q=hello'>Search</a>"
                    "<a href='/redirect?next=/home'>Redirect</a>"
                    "<script src='/app.js'></script>"
                    "</body></html>"
                ).encode("utf-8")
                self._send(200, "text/html; charset=utf-8", body)
                return

            if path == "/robots.txt":
                body = b"User-agent: *\nDisallow: /admin\nAllow: /graphql\nAllow: /search\n"
                self._send(200, "text/plain; charset=utf-8", body)
                return

            if path == "/app.js":
                js = (
                    "const ReactApp = React.createElement('div', null, 'MockApp');\n"
                    "async function runSearch(q) { return fetch('/search?q=test'); }\n"
                    "async function goNext() { return fetch('/redirect?next=/dashboard'); }\n"
                    "async function runGql() { return fetch('/graphql'); }\n"
                    "async function createUser() { return axios.post('/api/v1/users', { name: 'alice' }); }\n"
                    "function renderUnsafe() {\n"
                    "  document.getElementById('out').innerHTML = location.search;\n"
                    "}\n"
                    "//# sourceMappingURL=/app.js.map\n"
                ).encode("utf-8")
                self._send(200, "application/javascript; charset=utf-8", js)
                return

            if path == "/app.js.map":
                smap = json.dumps({
                    "version": 3,
                    "sources": ["src/app.tsx"],
                    "names": [],
                    "mappings": "",
                    "sourcesContent": ["export const GRAPHQL_ENDPOINT = '/graphql';"],
                }).encode("utf-8")
                self._send(200, "application/json; charset=utf-8", smap)
                return

            if path == "/search":
                q = params.get("q", [""])[0]
                # Deliberately unescaped reflection for reflected XSS candidate detection
                html = f"<html><body><h1>Search Results</h1><div id='results'>{q}</div></body></html>".encode("utf-8")
                self._send(200, "text/html; charset=utf-8", html)
                return

            if path == "/redirect":
                next_url = params.get("next", ["/"])[0]
                self.send_response(302)
                self.send_header("Location", next_url)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

            if path == "/graphql":
                payload = json.dumps({"data": {"__schema": {"types": [{"name": "Query"}]}}}).encode("utf-8")
                self._send(200, "application/json; charset=utf-8", payload)
                return

            self._send(404, "text/plain; charset=utf-8", b"Not Found")

        def do_POST(self):
            self._record()
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path == "/graphql":
                payload = json.dumps({"data": {"__schema": {"types": [{"name": "Query"}]}}}).encode("utf-8")
                self._send(200, "application/json; charset=utf-8", payload)
                return
            self._send(404, "text/plain; charset=utf-8", b"Not Found")

        def _send(self, status: int, content_type: str, body: bytes):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return MockVulnAppHandler


def _load_open_redirect_main():
    script_path = Path(__file__).resolve().parent.parent / "skills" / "open-redirect" / "run.py"
    spec = importlib.util.spec_from_file_location("open_redirect_skill", script_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module.main


def test_e2e_local_mock_target_pipeline_and_dashboard_collectors(tmp_path, monkeypatch):
    recorded_requests = []
    httpd = _EphemeralHTTPServer(("127.0.0.1", 0), _make_mock_vuln_handler(recorded_requests))
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()

    # Keep ScopedHttpClient unmodified (port 80/443 policy) while routing local test
    # connections for 127.0.0.1:80 to our ephemeral in-process ThreadingHTTPServer port.
    orig_http_init = http.client.HTTPConnection.__init__

    def _port_forwarded_init(conn_self, host, conn_port=None, *args, **kwargs):
        if conn_port is None and "port" in kwargs:
            conn_port = kwargs.pop("port")
        if host == "127.0.0.1" and conn_port in (None, 80):
            conn_port = port
        return orig_http_init(conn_self, host, conn_port, *args, **kwargs)

    monkeypatch.setattr(http.client.HTTPConnection, "__init__", _port_forwarded_init)

    try:
        target_name = "127.0.0.1"
        target_dir = tmp_path / target_name
        target_dir.mkdir(parents=True)
        (target_dir / "scope-of-work.md").write_text(
            "# Authorized Scope\n"
            "No cross-host requests.\n\n"
            "## In Scope\n"
            "- `127.0.0.1`\n\n"
            "## Out of Scope\n"
            "- `evil.example`\n"
            "- `*.blocked.local`\n",
            encoding="utf-8",
        )

        # 1. Verify ScopeValidator & ScopedHttpClient port/scope enforcement
        validator = ScopeValidator(target_name, target_dir=target_dir)
        assert validator.is_allowed("http://127.0.0.1/search?q=test")[0] is True
        assert validator.is_allowed("https://evil.example/steal")[0] is False
        assert validator.is_allowed("https://api.blocked.local/v1")[0] is False

        # ScopedHttpClient still rejects custom non-80/443 ports by default
        try:
            ScopedHttpClient(f"http://127.0.0.1:{port}")
            assert False, "Expected ValueError for non-80/443 port"
        except ValueError as exc:
            assert "Custom target ports" in str(exc)

        # Separate client confirms out-of-scope host blocking
        scope_probe_client = ScopedHttpClient("http://127.0.0.1", delay_seconds=0.0, scope_validator=validator)
        blocked_res = scope_probe_client.get("http://evil.example/steal")
        assert blocked_res["status"] == "blocked"
        assert any(v.get("kind") == "blocked_host" for v in scope_probe_client.policy_violations)

        # 2. Run SkillRunner pipeline against the real local ThreadingHTTPServer
        monkeypatch.setenv("MOROS_LLM_PROVIDER", "none")
        runner = SkillRunner(
            "http://127.0.0.1",
            target_dir,
            llm_client=LLMClient(provider="none"),
            max_http_requests=100,
            request_delay=0.0,
        )
        runner.target = target_name
        runner.scope_authorized = True
        runner.http.scope_validator.policy["same_host_only"] = True
        runner.http.scope_validator.policy["allow_cross_host_sources"] = False

        # Fetch JS & HTML from real server + confirm source map & auxiliary endpoints
        js_disc = runner.run_js_discover()
        assert js_disc["status"] == "SUCCESS"
        assert js_disc["files_collected"] >= 1

        smap_resp = runner.http.get("/app.js.map")
        assert smap_resp["status"] == "response" and smap_resp["status_code"] == 200
        assert "GRAPHQL_ENDPOINT" in smap_resp["body"]

        cd_res = runner.run_content_discovery()
        assert cd_res["status"] == "COMPLETED"
        discovered_paths = {row["path"]: row["status_code"] for row in json.loads(
            (target_dir / "output" / "content-discovery" / "discovered-paths.json").read_text(encoding="utf-8")
        )["paths_checked"]}
        assert discovered_paths.get("/robots.txt") == 200
        assert discovered_paths.get("/graphql") == 200
        assert discovered_paths.get("/search") == 200

        # JS analysis extracts API routes, DOM sinks, and framework fingerprint
        js_ana = runner.run_js_analyze()
        assert js_ana["status"] == "SUCCESS"
        endpoints_data = json.loads((target_dir / "output" / "js" / "endpoints.json").read_text(encoding="utf-8"))
        ep_urls = [ep.get("url", "") for ep in endpoints_data.get("endpoints", [])]
        assert any("/search" in u for u in ep_urls)
        assert any("/redirect" in u for u in ep_urls)
        assert any("/graphql" in u for u in ep_urls)

        # Reflected XSS skill sends real probe to /search?q=... and observes reflection
        xss_res = runner.run_vuln_skill("xss-reflected")
        assert xss_res["status"] == "COMPLETED"
        assert xss_res["findings_count"] >= 1
        xss_findings = json.loads(
            (target_dir / "output" / "findings" / "xss-reflected" / "candidates-xss-reflected.json").read_text(encoding="utf-8")
        )["findings"]
        assert any(f.get("type") == "Reflected XSS" and "/search" in f.get("url", "") for f in xss_findings)

        # Open redirect skill sends real probe to /redirect?next=... and catches 302 Location
        open_redirect_main = _load_open_redirect_main()
        monkeypatch.setenv("MOROS_HTTP_REQUESTS_REMAINING", "5")
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "open-redirect/run.py",
                "--target", "http://127.0.0.1",
                "--target-dir", str(target_dir),
                "--output-dir", str(target_dir / "output"),
            ],
        )
        open_redirect_main()
        redirect_findings_file = target_dir / "output" / "findings" / "candidates-open-redirect.json"
        assert redirect_findings_file.is_file()
        redirect_findings = json.loads(redirect_findings_file.read_text(encoding="utf-8"))["findings"]
        assert any("Unvalidated Open Redirect" in f.get("title", "") for f in redirect_findings)

        # Report conglomeration generates markdown, JSON, review, and SARIF 2.1.0
        report_res = runner.run_report_conglomeration()
        assert report_res["status"] == "SUCCESS"
        assert report_res["findings_count"] >= 3
        sarif_path = Path(report_res["sarif_path"])
        assert sarif_path.is_file()
        sarif_doc = json.loads(sarif_path.read_text(encoding="utf-8"))
        assert sarif_doc["version"] == "2.1.0"
        assert len(sarif_doc["runs"][0]["results"]) >= 3

        # Confirm real HTTP requests hit the local server endpoints
        hit_paths = {p.split("?", 1)[0] for _, p in recorded_requests}
        assert {"/", "/app.js", "/app.js.map", "/robots.txt", "/graphql", "/search", "/redirect"}.issubset(hit_paths)

        # 3. Verify DashboardHandler API collectors against generated artifacts
        monkeypatch.setattr(dashboard_server, "TARGETS_DIR", tmp_path)
        handler = dashboard_server.DashboardHandler.__new__(dashboard_server.DashboardHandler)

        targets_list = handler.get_targets_list()
        assert any(t["name"] == target_name and t["findings_total"] >= 3 for t in targets_list)

        summary = handler.get_target_summary(target_name)
        assert summary["has_scope"] is True
        assert summary["total_findings"] >= 3
        assert summary["total_endpoints"] >= 3
        assert summary["total_js_files"] >= 1

        dash_findings = handler.get_target_findings(target_name)
        titles = [f.get("title", "") for f in dash_findings]
        assert any("Reflected input observed" in t for t in titles)
        assert any("Unvalidated Open Redirect" in t for t in titles)

        dash_endpoints = handler.get_target_endpoints(target_name)
        assert dash_endpoints["total_endpoints"] >= 3

        dash_report = handler.get_target_report(target_name)
        assert "Penetration Testing Assessment Report" in dash_report["markdown"]
        assert "Report snapshot is out of date" not in dash_report["markdown"]

        dash_sarif = handler.get_target_sarif(target_name)
        assert dash_sarif["version"] == "2.1.0"
        assert len(dash_sarif["runs"][0]["results"]) >= 3
    finally:
        httpd.shutdown()
        httpd.server_close()
