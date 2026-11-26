import io
import json
import os
import subprocess
import types
from unittest.mock import MagicMock

from dashboard import server


def _handler():
    return server.DashboardHandler.__new__(server.DashboardHandler)


def _http_handler(method="GET", path="/", body=None, headers=None):
    handler = _handler()
    raw_headers = {"Host": "127.0.0.1:8080"}
    if headers:
        raw_headers.update(headers)
    body_bytes = b"" if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode("utf-8"))
    if body is not None and "Content-Length" not in raw_headers:
        raw_headers["Content-Length"] = str(len(body_bytes))
    handler.command = method
    handler.path = path
    handler.headers = raw_headers
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


def test_gadget_duplicates_are_collapsed_and_local_paths_are_hidden(tmp_path, monkeypatch):
    target = tmp_path / "lastpass.com" / "output"
    (target / "js").mkdir(parents=True)
    source_path = r"D:\Moros Ai\targets\lastpass.com\output\js\raw\external\app.js"
    (target / "js" / "gadgets.json").write_text(json.dumps({
        "gadgets": [
            {"type": "innerHTML assignment", "source_file": "app.js"},
            {"type": "innerHTML assignment", "source_file": "app.js"},
        ]
    }), encoding="utf-8")
    (target / "js" / "endpoints.json").write_text(json.dumps({
        "endpoints": [{"url": "/api/items", "method": "GET", "source_file": source_path}]
    }), encoding="utf-8")
    monkeypatch.setattr(server, "TARGETS_DIR", tmp_path)
    handler = _handler()

    findings = handler.get_target_findings("lastpass.com")
    endpoints = handler.get_target_endpoints("lastpass.com")

    assert len(findings) == 1
    assert findings[0]["raw_record_count"] == 2
    assert endpoints["endpoints"][0]["source_file"] == "js/raw/external/app.js"
    assert "D:\\Moros Ai" not in endpoints["endpoints"][0]["source_file"]


def test_report_warns_when_saved_snapshot_disagrees_with_current_findings(tmp_path, monkeypatch):
    target = tmp_path / "example.com" / "output"
    findings_dir = target / "findings" / "xss"
    report_dir = target / "report"
    findings_dir.mkdir(parents=True)
    report_dir.mkdir(parents=True)
    (findings_dir / "candidates-xss.json").write_text(json.dumps({
        "findings": [{"title": "Candidate XSS", "severity": "Triage Severity: LOW"}]
    }), encoding="utf-8")
    (report_dir / "hackbot-report-example.com-20261123.md").write_text(
        "# Assessment report\n\nThe saved snapshot contains three items.\n", encoding="utf-8"
    )
    (report_dir / "hackbot-report-example.com-20261123.json").write_text(json.dumps({
        "summary": {"triage_items": 3}, "findings": [{}, {}, {}]
    }), encoding="utf-8")
    monkeypatch.setattr(server, "TARGETS_DIR", tmp_path)

    report = _handler().get_target_report("example.com")

    assert "Report snapshot is out of date" in report["markdown"]
    assert "3 triage items" in report["markdown"]
    assert "current dashboard data contains 1" in report["markdown"]


def test_fresh_report_is_canonical_for_dashboard_findings(tmp_path, monkeypatch):
    target_dir = tmp_path / "example.com"
    output = target_dir / "output"
    finding_file = output / "findings" / "xss" / "candidates-xss.json"
    finding_file.parent.mkdir(parents=True)
    finding_file.write_text(json.dumps({"findings": [
        {"title": "Candidate XSS", "type": "XSS", "url": "https://example.com/a"},
        {"title": "Candidate XSS", "type": "XSS", "url": "https://example.com/a"},
    ]}), encoding="utf-8")
    report_dir = output / "report"
    report_dir.mkdir()
    manifest = {"output/findings/xss/candidates-xss.json": finding_file.stat().st_mtime}
    (report_dir / "hackbot-report-example.com-20261124.json").write_text(json.dumps({
        "source_artifact_mtimes": manifest,
        "findings": [{"title": "Candidate XSS", "type": "XSS", "url": "https://example.com/a", "raw_record_count": 2}],
    }), encoding="utf-8")
    monkeypatch.setattr(server, "TARGETS_DIR", tmp_path)

    findings = _handler().get_target_findings("example.com")

    assert len(findings) == 1
    assert findings[0]["raw_record_count"] == 2


def test_overlapping_dom_evidence_and_duplicate_secret_locations_group_into_unique_findings(tmp_path, monkeypatch):
    output = tmp_path / "example.com" / "output"
    (output / "findings" / "xss-dom").mkdir(parents=True)
    (output / "js").mkdir(parents=True)
    candidate = {
        "title": "Potential DOM XSS Sink 'innerHTML' in a.js",
        "type": "DOM XSS",
        "sink": "innerHTML",
        "line": 17,
        "snippet": "node.innerHTML = value",
        "url": "https://example.com/a.js#L17",
        "severity": "Triage Severity: UNASSESSED",
    }
    alias = {**candidate, "title": "Potential DOM XSS Sink 'innerHTML' in alias.js", "url": "https://example.com/alias.js#L17"}
    (output / "findings" / "xss-dom" / "candidates-xss-dom.json").write_text(json.dumps({
        "findings": [candidate, alias]
    }), encoding="utf-8")
    (output / "js" / "gadgets.json").write_text(json.dumps({"gadgets": [
        {"type": "innerHTML assignment", "source_file": "a.js"},
        {"type": "innerHTML assignment", "source_file": "a.js"},
        {"type": "innerHTML assignment", "source_file": "alias.js"},
    ]}), encoding="utf-8")
    (output / "js" / "secrets-findings.json").write_text(json.dumps({"findings": [
        {"type": "test_key", "value_fingerprint": "fingerprint-1", "value_preview": "abcd…wxyz", "source_file": "a.js"},
        {"type": "test_key", "value_fingerprint": "fingerprint-1", "value_preview": "abcd…wxyz", "source_file": "alias.js"},
    ]}), encoding="utf-8")
    monkeypatch.setattr(server, "TARGETS_DIR", tmp_path)

    findings = _handler().get_target_findings("example.com")

    assert len(findings) == 2
    assert sum(item["raw_record_count"] for item in findings) == 7
    dom_finding = next(item for item in findings if item["category"] == "xss-dom")
    secret_finding = next(item for item in findings if item["category"] == "secrets")
    assert dom_finding["raw_record_count"] == 5
    assert len(dom_finding["occurrences"]) == 2
    assert secret_finding["raw_record_count"] == 2
    assert len(secret_finding["occurrences"]) == 2


def test_skill_status_uses_latest_run_and_does_not_promote_old_logs_to_current_completion(tmp_path, monkeypatch):
    target = tmp_path / "example.com"
    runs = target / "output" / "runs" / "run-latest"
    logs = target / "output" / "logs"
    (runs).mkdir(parents=True)
    (logs / "review").mkdir(parents=True)
    (logs / "xss-dom").mkdir()
    (logs / "xss-dom" / "old.log").write_text("historical", encoding="utf-8")
    review_file = logs / "review" / "recon-subdomain-review-1.json"
    review_file.write_text(json.dumps({"overall_status": "PASS"}), encoding="utf-8")
    os.utime(review_file, (1, 1))
    (runs / "events.jsonl").write_text(json.dumps({
        "event": "SKILL_COMPLETED", "details": {"skill": "recon-subdomain"}
    }) + "\n", encoding="utf-8")

    class FakeRunManager:
        def __init__(self, _target):
            pass

        def get_latest_or_active_run(self):
            return {
                "run_id": "run-latest",
                "started_at": "2026-11-24T12:00:00+02:00",
                "skills_requested": ["recon-subdomain"],
                "skills_completed": [],
                "skills_failed": [],
            }

    class FakeSkillRegistry:
        def list_skills(self):
            return [{"id": "recon-subdomain"}, {"id": "xss-dom"}]

    monkeypatch.setattr(server, "TARGETS_DIR", tmp_path)
    monkeypatch.setattr(server, "RunManager", FakeRunManager)
    monkeypatch.setattr(server, "SkillRegistry", FakeSkillRegistry)

    statuses = {item["skill"]: item for item in _handler().get_target_skills_status("example.com")}

    assert statuses["recon-subdomain"]["state"] == "completed"
    assert statuses["recon-subdomain"]["review_status"] == "historical"
    assert statuses["xss-dom"]["state"] == "not_run"
    assert statuses["xss-dom"]["review_status"] == "not_run"
    assert statuses["xss-dom"]["logs_count"] == 1


def test_learning_graph_uses_export_graph_and_sanitizes_500(tmp_path, monkeypatch):
    import sys

    closed = {"count": 0}

    class FakeDB:
        def close(self):
            closed["count"] += 1

    class FakeEngine:
        def __init__(self):
            self.db = FakeDB()

        def export_graph(self):
            return {"nodes": [{"id": "n1"}], "edges": []}

        def distill(self):
            raise RuntimeError("secret-db-internal-detail")

    fake_mod = types.ModuleType("learning_engine.engine")
    fake_mod.LearningEngine = FakeEngine
    monkeypatch.setitem(sys.modules, "learning_engine.engine", fake_mod)

    handler = _http_handler("GET", "/api/learning/graph")
    handler.do_GET()
    assert handler._status_code == 200
    assert _response_json(handler) == {"nodes": [{"id": "n1"}], "edges": []}
    assert closed["count"] == 1

    err_handler = _http_handler("GET", "/api/learning/stats")
    err_handler.do_GET()
    assert err_handler._status_code == 500
    err_payload = _response_json(err_handler)
    assert "secret-db-internal-detail" not in json.dumps(err_payload)
    assert closed["count"] == 2


def test_do_post_rejects_malformed_and_non_dict_json():
    bad_json = _http_handler("POST", "/api/targets/create", body=b"{not valid json")
    bad_json.do_POST()
    assert bad_json._status_code == 400

    list_json = _http_handler("POST", "/api/targets/create", body=b'["a", "b"]')
    list_json.do_POST()
    assert list_json._status_code == 400

    null_json = _http_handler("POST", "/api/targets/create", body=b"null")
    null_json.do_POST()
    assert null_json._status_code == 400


def test_local_browser_request_ipv6_and_origin():
    for host in ("[::1]", "[::1]:8080", "127.0.0.1:8080", "localhost"):
        h = _http_handler("GET", "/", headers={"Host": host})
        assert h._is_local_browser_request() is True

    h_remote = _http_handler("GET", "/", headers={"Host": "evil.com"})
    assert h_remote._is_local_browser_request() is False

    h_bad_origin = _http_handler("GET", "/", headers={"Host": "[::1]", "Origin": "https://evil.com"})
    assert h_bad_origin._is_local_browser_request() is False


def test_static_and_logs_path_containment(tmp_path, monkeypatch):
    static_dir = tmp_path / "static"
    static_dir.mkdir()
    (static_dir / "index.html").write_text("<h1>ok</h1>", encoding="utf-8")
    sibling_dir = tmp_path / "static_secret"
    sibling_dir.mkdir()
    (sibling_dir / "leak.txt").write_text("SECRET", encoding="utf-8")

    monkeypatch.setattr(server, "STATIC_DIR", static_dir)
    h = _http_handler("GET", "/../static_secret/leak.txt")
    h.do_GET()
    assert h._status_code == 403
    assert b"SECRET" not in h.wfile.getvalue()

    logs_dir = tmp_path / "example.com" / "output" / "logs"
    logs_dir.mkdir(parents=True)
    (logs_dir / "run.log").write_text("line1", encoding="utf-8")
    (tmp_path / "example.com" / "output" / "outside.log").write_text("NOPE", encoding="utf-8")
    monkeypatch.setattr(server, "TARGETS_DIR", tmp_path)

    assert _handler().get_target_logs("example.com", "../outside.log")["content"] == ""
    assert _handler().get_target_logs("example.com", ".")["content"] == ""
    assert _handler().get_target_logs("example.com", "run.log")["content"] == "line1"


def test_defensive_reads_summary_report_endpoints_and_findings(tmp_path, monkeypatch):
    output = tmp_path / "example.com" / "output"
    (output / "recon").mkdir(parents=True)
    (output / "report").mkdir(parents=True)
    (output / "js").mkdir(parents=True)
    (output / "findings" / "xss").mkdir(parents=True)

    (output / "recon" / "subdomains-all.txt").write_bytes(b"a.example.com\n\xff\xfe\nb.example.com\n")
    (output / "report" / "hackbot-report-example.com-20261125.md").write_bytes(b"# Report \xff\xfe\n")
    (output / "js" / "endpoints.json").write_text(json.dumps({
        "endpoints": ["not-a-dict", {"url": "/api/v1", "source_file": "app.js"}]
    }), encoding="utf-8")
    (output / "findings" / "xss" / "candidates-xss.json").write_text(json.dumps({
        "findings": [{"title": "None Severity Finding", "url": "https://example.com/x", "severity": None}]
    }), encoding="utf-8")
    (output / "js" / "secrets-findings.json").write_text(json.dumps({
        "findings": [{"type": "api_key", "severity": None, "source_file": "app.js", "line_number": 3}]
    }), encoding="utf-8")
    (output / "js" / "gadgets.json").write_text(json.dumps({
        "gadgets": [{"type": "eval", "source_file": "app.js"}]
    }), encoding="utf-8")

    monkeypatch.setattr(server, "TARGETS_DIR", tmp_path)
    handler = _handler()

    summary = handler.get_target_summary("example.com")
    assert summary["total_subdomains"] == 3

    report = handler.get_target_report("example.com")
    assert "# Report \ufffd\ufffd" in report["markdown"]

    endpoints = handler.get_target_endpoints("example.com")
    assert endpoints["total_endpoints"] == 1
    assert endpoints["endpoints"][0]["url"] == "/api/v1"

    findings = handler.get_target_findings("example.com")
    assert len(findings) == 3
    secret_f = next(f for f in findings if f["category"] == "secrets")
    gadget_f = next(f for f in findings if f["category"] == "dom-xss")
    assert secret_f["validation_status"] == "unverified"
    assert secret_f["confidence"] == "not-scored"
    assert gadget_f["validation_status"] == "unverified"
    assert gadget_f["confidence"] == "not-scored"


def test_notification_config_newline_rejection_slack_and_discord_clear(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "PROJECT_ROOT", tmp_path)
    monkeypatch.delenv("DISCORD_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    handler = _handler()

    # Reject newline injection in Discord/Slack/Telegram
    res_nl = handler.save_notification_config({
        "discord_webhook_url": "https://discord.com/api/webhooks/123/abc\nOPENAI_API_KEY=evil"
    })
    assert res_nl["status"] == "error"
    assert not (tmp_path / ".env").exists()

    res_slack_nl = handler.save_notification_config({
        "slack_webhook_url": "https://hooks.slack.com/services/T1/B2/C3\r\nEVIL=1"
    })
    assert res_slack_nl["status"] == "error"

    res_slack_bad = handler.save_notification_config({
        "slack_webhook_url": "https://evil.example.com/services/T1/B2/C3"
    })
    assert res_slack_bad["status"] == "error"

    # Save valid Discord + Slack
    res_ok = handler.save_notification_config({
        "discord_webhook_url": "https://discord.com/api/webhooks/123456/abcdef_123",
        "slack_webhook_url": "https://hooks.slack.com/services/T111/B222/secret333",
    })
    assert res_ok["status"] == "success"
    assert os.environ.get("DISCORD_WEBHOOK_URL") == "https://discord.com/api/webhooks/123456/abcdef_123"
    assert os.environ.get("SLACK_WEBHOOK_URL") == "https://hooks.slack.com/services/T111/B222/secret333"

    # Clear Discord explicitly with ""
    res_clear = handler.save_notification_config({"discord_webhook_url": ""})
    assert res_clear["status"] == "success"
    assert "DISCORD_WEBHOOK_URL" not in os.environ
    env_text = (tmp_path / ".env").read_text(encoding="utf-8")
    assert "DISCORD_WEBHOOK_URL=" not in env_text
    assert "SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T111/B222/secret333" in env_text


def test_llm_config_rejects_newlines_and_non_http_base_url(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "PROJECT_ROOT", tmp_path)
    handler = _handler()

    res_nl = handler.save_llm_config({
        "provider": "openai",
        "model": "gpt-4o-mini",
        "api_key": "sk-abc\nEVIL=1",
    })
    assert res_nl["status"] == "error"
    assert not (tmp_path / ".env").exists()

    res_bad_url = handler.save_llm_config({
        "provider": "custom",
        "model": "local",
        "api_key": "sk-test-1234",
        "base_url": "file:///etc/passwd",
    })
    assert res_bad_url["status"] == "error"

    res_test_bad_url = handler.test_llm_config({
        "provider": "custom",
        "model": "local",
        "api_key": "sk-test-1234",
        "base_url": "ftp://example.com/v1",
    })
    assert res_test_bad_url["status"] == "error"


def test_scan_job_atomic_starting_stopped_preservation_and_sse_cors(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "TARGETS_DIR", tmp_path)
    (tmp_path / "example.com").mkdir()
    handler = _handler()

    with server.active_scans_lock:
        server.active_scans.clear()
        server.active_scans["example.com"] = {"status": "starting", "logs": []}

    dup = handler.start_scan_job("example.com", "all", "default")
    assert dup["status"] == "error"

    # Stopping while process exits non-zero must preserve "stopped" status
    with server.active_scans_lock:
        server.active_scans.clear()

    fake_proc = MagicMock()
    fake_proc.stdout = io.StringIO("line1\n")
    fake_proc.returncode = -15

    def wait_and_stop():
        handler.stop_scan_job("example.com")
        return -15

    fake_proc.wait.side_effect = wait_and_stop

    monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: fake_proc)
    res = handler.start_scan_job("example.com", "all", "default")
    assert res["status"] == "success"
    with server.active_scans_lock:
        t = server.active_scans["example.com"]["thread"]
    t.join(timeout=5)
    assert handler.get_scan_status("example.com")["status"] == "stopped"

    # SSE stream must not emit Access-Control-Allow-Origin: *
    class FakeRM:
        def __init__(self, _path):
            pass

        def list_runs(self):
            return [{"run_id": "r1", "status": "completed"}]

        def get_event_stream(self, _run_id):
            return []

    monkeypatch.setattr(server, "RunManager", FakeRM)
    sse_h = _http_handler("GET", "/api/scan/stream?target=example.com")
    sse_h.handle_sse_stream("example.com")
    assert ("Access-Control-Allow-Origin", "*") not in sse_h._resp_headers


def test_dashboard_auth_optional_on_loopback_and_enforced_when_token_set(tmp_path, monkeypatch):
    static_dir = tmp_path / "static"
    static_dir.mkdir()
    (static_dir / "index.html").write_text("<h1>Moros UI</h1>", encoding="utf-8")
    targets_dir = tmp_path / "targets"
    targets_dir.mkdir()
    monkeypatch.setattr(server, "STATIC_DIR", static_dir)
    monkeypatch.setattr(server, "TARGETS_DIR", targets_dir)

    # 1. Loopback remains frictionless when MOROS_DASHBOARD_TOKEN is unset
    monkeypatch.delenv("MOROS_DASHBOARD_TOKEN", raising=False)
    h_open = _http_handler("GET", "/api/targets")
    h_open.do_GET()
    assert h_open._status_code == 200
    assert _response_json(h_open) == []

    # 2. When MOROS_DASHBOARD_TOKEN is set, /api/* requires Bearer or X-Moros-Token
    secret = "moros-test-secret-token-987654"
    monkeypatch.setenv("MOROS_DASHBOARD_TOKEN", secret)

    h_missing = _http_handler("GET", "/api/targets")
    h_missing.do_GET()
    assert h_missing._status_code == 401
    assert secret not in h_missing.wfile.getvalue().decode("utf-8")

    h_bad = _http_handler("GET", "/api/targets", headers={"Authorization": "Bearer wrong-token"})
    h_bad.do_GET()
    assert h_bad._status_code == 401
    assert secret not in h_bad.wfile.getvalue().decode("utf-8")

    h_post_missing = _http_handler("POST", "/api/targets/create", body={"domain": "example.com"})
    h_post_missing.do_POST()
    assert h_post_missing._status_code == 401

    # Static UI remains accessible on GET / so browser can prompt for token
    h_static = _http_handler("GET", "/")
    h_static.do_GET()
    assert h_static._status_code == 200
    assert b"Moros UI" in h_static.wfile.getvalue()

    # Valid Bearer token succeeds
    h_bearer = _http_handler("GET", "/api/targets", headers={"Authorization": f"Bearer {secret}"})
    h_bearer.do_GET()
    assert h_bearer._status_code == 200

    # Valid X-Moros-Token succeeds (including case-insensitive header name)
    h_xheader = _http_handler("GET", "/api/targets", headers={"x-moros-token": secret})
    h_xheader.do_GET()
    assert h_xheader._status_code == 200


def test_non_loopback_bind_auto_generates_runtime_token_and_logs_warning(tmp_path, monkeypatch, caplog):
    import logging
    import threading
    import urllib.error
    import urllib.request

    monkeypatch.delenv("MOROS_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(server, "TARGETS_DIR", tmp_path)

    captured_httpd = {}
    orig_server_cls = server.ThreadedHTTPServer

    class FakeServer(orig_server_cls):
        def serve_forever(self, poll_interval=0.5):
            captured_httpd["httpd"] = self
            return

    monkeypatch.setattr(server, "ThreadedHTTPServer", FakeServer)

    with caplog.at_level(logging.WARNING):
        server.run_dashboard(host="0.0.0.0", port=0, open_browser=False)

    assert any("non-loopback host '0.0.0.0'" in rec.message for rec in caplog.records)
    httpd = captured_httpd["httpd"]
    assert httpd.allow_remote is True
    runtime_token = httpd.dashboard_token
    assert isinstance(runtime_token, str) and len(runtime_token) >= 24

    # Spin up real ephemeral ThreadedHTTPServer with remote-bind attributes to test live HTTP auth
    real_httpd = orig_server_cls(("127.0.0.1", 0), server.DashboardHandler)
    real_httpd.dashboard_token = runtime_token
    real_httpd.allow_remote = True
    port = real_httpd.server_address[1]
    t = threading.Thread(target=real_httpd.serve_forever, daemon=True)
    t.start()
    try:
        # Unauthenticated /api/targets -> 401 and token never leaked in response
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/api/targets", timeout=5)
            assert False, "Expected HTTP 401"
        except urllib.error.HTTPError as err:
            assert err.code == 401
            body = err.read().decode("utf-8")
            assert runtime_token not in body

        # Authenticated with X-Moros-Token -> 200
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/targets",
            headers={"X-Moros-Token": runtime_token},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            assert resp.status == 200
            assert json.loads(resp.read().decode("utf-8")) == []

        # Remote Host header allowed when allow_remote=True, still requires token
        h_remote = _http_handler("GET", "/api/targets", headers={"Host": "192.168.1.50:8080", "Authorization": f"Bearer {runtime_token}"})
        h_remote.server = real_httpd
        h_remote.do_GET()
        assert h_remote._status_code == 200

        # Mismatched Origin header still rejected with 403
        h_csrf = _http_handler("GET", "/api/targets", headers={"Host": "192.168.1.50:8080", "Origin": "https://evil.com", "Authorization": f"Bearer {runtime_token}"})
        h_csrf.server = real_httpd
        h_csrf.do_GET()
        assert h_csrf._status_code == 403
    finally:
        real_httpd.shutdown()
        real_httpd.server_close()


def test_dashboard_html_contains_session_storage_token_prompt():
    from pathlib import Path

    html = (Path(__file__).resolve().parent.parent / "dashboard" / "static" / "index.html").read_text(encoding="utf-8")
    assert "sessionStorage" in html
    assert "authTokenModal" in html
    assert "Authorization" in html

