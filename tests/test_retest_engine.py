#!/usr/bin/env python3
"""Comprehensive offline tests for Phase 4 Retesting Engine (tools/retest_engine.py)."""

from __future__ import annotations

import copy
import hashlib
import html
import http.client
import json
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Any, Dict, List, Optional

import pytest

from tools.auth_diff import AuthDiffChecker, SessionContext
from tools.checkpoint_manager import CheckpointManager
from tools.exploit_validator import ExploitValidator
from tools.oob_server import OOBServer
from tools.retest_engine import (
    FIXED_LIMITATION_NOTE,
    VALID_RETEST_OUTCOMES,
    BeforeAfterComparator,
    RegressionAnalyzer,
    RetestEngine,
    RetestPlan,
    RetestPlanner,
    RetestResult,
    RetestRunner,
    update_finding_lifecycle,
)
from tools.scope_validator import ScopeValidator
from tools.scoped_http import ScopedHttpClient


class _EphemeralHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _make_retest_handler(
    recorded_requests: List[Dict[str, Any]],
    oob_port_holder: Dict[str, int],
    mode_state: Dict[str, str],
):
    class _Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _send(
            self,
            status: int,
            body: str,
            content_type: str = "text/html; charset=utf-8",
            extra_headers: Optional[Dict[str, str]] = None,
        ) -> None:
            raw = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Connection", "close")
            if extra_headers:
                for k, v in extra_headers.items():
                    self.send_header(k, v)
            self.end_headers()
            self.close_connection = True
            if self.command.upper() != "HEAD":
                self.wfile.write(raw)

        def _handle(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            length = int(self.headers.get("Content-Length", "0") or "0")
            req_body = self.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else ""

            recorded_requests.append({
                "method": self.command.upper(),
                "path": self.path,
                "headers": {k.lower(): v for k, v in self.headers.items()},
                "body": req_body,
            })

            # Home route for same-host redirect baseline
            if path == "/":
                self._send(200, "<html><body>Home</body></html>", "text/html")
                return

            # Dynamic route /app/xss controlled by mode_state["xss"]
            if path == "/app/xss":
                q = qs.get("q", [""])[0]
                mode = mode_state.get("xss", "vuln")
                if mode == "vuln":
                    self._send(200, f"<html><body>Results: {q}</body></html>", "text/html")
                    return
                if mode == "incomplete":
                    # Only strips <script>, leaving <moros-probe> unescaped
                    sanitized = q.replace("<script>", "").replace("</script>", "")
                    self._send(200, f"<html><body>Results: {sanitized}</body></html>", "text/html")
                    return
                if mode == "fixed":
                    self._send(200, f"<html><body>Results: {html.escape(q, quote=True)}</body></html>", "text/html")
                    return
                if mode == "missing":
                    self._send(404, "Not Found", "text/plain")
                    return

            # Dynamic route /app/sqli controlled by mode_state["sqli"]
            if path == "/app/sqli":
                item_id = qs.get("id", ["1"])[0]
                mode = mode_state.get("sqli", "vuln")
                if mode in ("vuln", "incomplete") and "'" in item_id:
                    self._send(
                        500,
                        json.dumps({"error": "SQLITE_ERROR: near \"'\": syntax error (you have an error in your SQL syntax)"}),
                        "application/json",
                    )
                    return
                if mode == "broken_500":
                    self._send(
                        500,
                        "Traceback (most recent call last):\n  File \"app.py\", line 42\nInternal Server Error",
                        "text/plain",
                    )
                    return
                if mode == "fixed":
                    self._send(200, json.dumps({"id": item_id, "parameterized": True}), "application/json")
                    return
                self._send(200, json.dumps({"id": item_id, "name": "Widget"}), "application/json")
                return

            # Dynamic route /app/redirect controlled by mode_state["redirect"]
            if path == "/app/redirect":
                dest = qs.get("next", ["/"])[0]
                if mode_state.get("redirect", "vuln") == "fixed":
                    if dest.startswith("/") and not dest.startswith("//"):
                        self._send(302, "", "text/plain", extra_headers={"Location": dest})
                    else:
                        self._send(400, json.dumps({"error": "Untrusted redirect target"}), "application/json")
                    return
                self._send(302, "", "text/plain", extra_headers={"Location": dest})
                return

            # Dynamic route /app/cors controlled by mode_state["cors"]
            if path == "/app/cors":
                if mode_state.get("cors", "vuln") == "fixed":
                    self._send(
                        200,
                        json.dumps({"ok": True}),
                        "application/json",
                        extra_headers={"Access-Control-Allow-Origin": "https://trusted.example"},
                    )
                    return
                origin = self.headers.get("Origin", "")
                hdrs = {}
                if origin:
                    hdrs["Access-Control-Allow-Origin"] = origin
                    hdrs["Access-Control-Allow-Credentials"] = "true"
                self._send(200, json.dumps({"ok": True}), "application/json", extra_headers=hdrs)
                return

            # Dynamic route /app/file controlled by mode_state["traversal"]
            if path == "/app/file":
                page = qs.get("page", [""])[0]
                if mode_state.get("traversal", "vuln") == "fixed":
                    self._send(400, "Invalid path", "text/plain")
                    return
                if "../" in page or "..\\" in page or "etc/passwd" in page.lower():
                    self._send(200, "root:x:0:0:root:/root:/bin/bash\n", "text/plain")
                    return
                self._send(200, "Index page", "text/plain")
                return

            # Dynamic route /app/ssti controlled by mode_state["ssti"]
            if path == "/app/ssti":
                name = qs.get("name", [""])[0]
                if mode_state.get("ssti", "vuln") == "vuln" and "{{7*7}}" in name:
                    self._send(200, "Hello 49!", "text/html")
                    return
                self._send(200, f"Hello {html.escape(name)}", "text/html")
                return

            # Dynamic route /app/crlf controlled by mode_state["crlf"]
            if path == "/app/crlf":
                val = qs.get("lang", [""])[0]
                if mode_state.get("crlf", "vuln") == "vuln" and ("\r\n" in val or "\n" in val):
                    injected = val.split("Set-Cookie:", 1)[-1].strip() if "Set-Cookie:" in val else "moros_crlf=1"
                    self._send(200, "OK", "text/plain", extra_headers={"Set-Cookie": injected})
                    return
                self._send(200, "OK", "text/plain")
                return

            # Dynamic route /app/ssrf controlled by mode_state["ssrf"]
            if path == "/app/ssrf":
                if mode_state.get("ssrf", "vuln") == "fixed":
                    self._send(403, json.dumps({"error": "Blocked outbound URL"}), "application/json")
                    return
                target_url = qs.get("url", [""])[0]
                if target_url.startswith(f"http://127.0.0.1:{oob_port_holder.get('port', -1)}/"):
                    with urllib.request.urlopen(target_url, timeout=2.0) as r:
                        _ = r.read()
                self._send(200, json.dumps({"fetched": True}), "application/json")
                return

            # Dynamic route /app/secrets for secret redaction verification
            if path == "/app/secrets":
                q = qs.get("q", [""])[0]
                body = (
                    f"<html><body>"
                    f"APIKey=sk-1234567890abcdefghijklmnop "
                    f"Authorization: Bearer super_secret_bearer_token_999 "
                    f"Results: {html.escape(q)}"
                    f"</body></html>"
                )
                self._send(
                    200,
                    body,
                    "text/html",
                    extra_headers={"Set-Cookie": "sid=top_secret_session_cookie; HttpOnly"},
                )
                return

            # Related routes for RegressionAnalyzer
            if path == "/api/health":
                if mode_state.get("health", "ok") == "500":
                    self._send(500, "Internal Server Error", "text/plain")
                    return
                self._send(200, json.dumps({"status": "healthy"}), "application/json")
                return

            if path == "/api/profile":
                if mode_state.get("profile", "ok") == "500":
                    self._send(
                        500,
                        "Traceback (most recent call last):\nTypeError: unsupported operand",
                        "text/plain",
                    )
                    return
                if mode_state.get("profile", "ok") == "degraded":
                    self._send(200, json.dumps({"profile": "empty"}), "application/json")
                    return
                self._send(200, json.dumps({"profile": "ACTIVE_USER"}), "application/json")
                return

            if path == "/api/legacy-search":
                q = qs.get("q", [""])[0]
                if mode_state.get("legacy_search", "safe") == "reintroduced_xss":
                    self._send(200, f"<html><body>Legacy: {q}</body></html>", "text/html")
                    return
                self._send(200, f"<html><body>Legacy: {html.escape(q)}</body></html>", "text/html")
                return

            # Generic replay endpoint
            if path == "/app/generic":
                if mode_state.get("generic", "vuln") == "vuln":
                    self._send(200, json.dumps({"vuln": True, "marker": "LEAK_ACTIVE"}), "application/json")
                    return
                if mode_state.get("generic", "vuln") == "fixed":
                    self._send(403, json.dumps({"error": "Forbidden"}), "application/json")
                    return
                if mode_state.get("generic", "vuln") == "missing":
                    self._send(404, "Not found", "text/plain")
                    return

            # Gated state-changing POST endpoint
            if path == "/gated/action" and self.command.upper() in ("POST", "PUT", "DELETE"):
                if mode_state.get("gated", "vuln") == "vuln":
                    self._send(200, json.dumps({"applied": True, "indicator": "GATED_STATE_CONFIRMED"}), "application/json")
                    return
                self._send(403, json.dumps({"error": "Forbidden"}), "application/json")
                return

            # Slow endpoint for timeout testing
            if path == "/slow":
                time.sleep(1.5)
                self._send(200, "too late", "text/plain")
                return

            self._send(404, "Not found", "text/plain")

        def do_GET(self) -> None:
            self._handle()

        def do_HEAD(self) -> None:
            self._handle()

        def do_POST(self) -> None:
            self._handle()

        def do_PUT(self) -> None:
            self._handle()

        def do_DELETE(self) -> None:
            self._handle()

    return _Handler


@pytest.fixture()
def local_server(monkeypatch):
    recorded: List[Dict[str, Any]] = []
    oob_port_holder: Dict[str, int] = {"port": -1}
    mode_state: Dict[str, str] = {}
    httpd = _EphemeralHTTPServer(("127.0.0.1", 0), _make_retest_handler(recorded, oob_port_holder, mode_state))
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()

    orig_http_init = http.client.HTTPConnection.__init__

    def _forward_127_80(conn_self, host, conn_port=None, *args, **kwargs):
        if conn_port is None and "port" in kwargs:
            conn_port = kwargs.pop("port")
        if host == "127.0.0.1" and conn_port in (None, 80):
            conn_port = port
        return orig_http_init(conn_self, host, conn_port, *args, **kwargs)

    monkeypatch.setattr(http.client.HTTPConnection, "__init__", _forward_127_80)
    try:
        yield {
            "base_url": "http://127.0.0.1",
            "port": port,
            "recorded": recorded,
            "oob_port_holder": oob_port_holder,
            "mode_state": mode_state,
        }
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=2.0)


def _setup_target_dir(tmp_path: Path, extra_scope: str = "") -> Path:
    target_dir = tmp_path / "127.0.0.1"
    target_dir.mkdir(parents=True, exist_ok=True)
    (target_dir / "scope-of-work.md").write_text(
        "# Scope\n"
        "## In Scope\n"
        "- `127.0.0.1`\n\n"
        "## Out of Scope\n"
        "- `evil.example`\n"
        "- `*.blocked.local`\n"
        + extra_scope,
        encoding="utf-8",
    )
    return target_dir


def _make_mini_auth_checker(validator: ScopeValidator, *, user_b_code: int, user_b_payload: dict) -> AuthDiffChecker:
    class _MiniAuthClient:
        def __init__(self, code: int, payload: dict):
            self.code = code
            self.payload = payload
            self.scope_validator = validator
            self.stop_requested = False
            self.auth_headers = {}
            self.cookies = ""

        def get(self, url_or_path, headers=None, params=None):
            body = json.dumps(self.payload)
            return {
                "status": "response",
                "status_code": self.code,
                "url": url_or_path,
                "headers": {"content-type": "application/json"},
                "body": body,
                "body_bytes": len(body),
                "body_sha256": hashlib.sha256(body.encode()).hexdigest(),
            }

    return AuthDiffChecker(
        target="http://127.0.0.1",
        scope_validator=validator,
        user_a=SessionContext(
            name="user_a",
            role="owner",
            auth_headers={"Authorization": "Bearer A"},
            owned_ids=["42"],
            client=_MiniAuthClient(200, {"id": 42, "email": "alice@test"}),
        ),
        user_b=SessionContext(
            name="user_b",
            role="peer",
            auth_headers={"Authorization": "Bearer B"},
            client=_MiniAuthClient(user_b_code, user_b_payload),
        ),
        unauthenticated=SessionContext(
            name="unauthenticated",
            role="unauthenticated",
            client=_MiniAuthClient(401, {"error": "Unauthorized"}),
        ),
    )


# ---------------------------------------------------------------------------
# 1. Successful fix (`fixed`) across all core strategies + limitation note
# ---------------------------------------------------------------------------


def test_successful_fix_across_strategies_and_limitation_note(tmp_path, local_server):
    target_dir = _setup_target_dir(tmp_path)
    validator = ScopeValidator("127.0.0.1", target_dir=target_dir)

    with OOBServer(host="127.0.0.1", port=0) as oob:
        local_server["oob_port_holder"]["port"] = oob.port
        vuln_auth = _make_mini_auth_checker(validator, user_b_code=200, user_b_payload={"id": 42, "email": "alice@test"})

        ev = ExploitValidator(
            target="http://127.0.0.1",
            target_dir=target_dir,
            scope_validator=validator,
            oob_server=oob,
            auth_diff_checker=vuln_auth,
            delay_seconds=0.0,
            oob_wait_seconds=0.5,
        )

        findings = [
            {"title": "Reflected XSS", "skill": "xss-reflected", "url": "http://127.0.0.1/app/xss?q=test", "parameter": "q"},
            {"title": "SQL Injection", "skill": "sqli-heuristic", "url": "http://127.0.0.1/app/sqli?id=1", "parameter": "id"},
            {"title": "Open Redirect", "skill": "open-redirect", "url": "http://127.0.0.1/app/redirect?next=/", "parameter": "next"},
            {"title": "CORS Misconfiguration", "skill": "cors-audit", "url": "http://127.0.0.1/app/cors"},
            {"title": "Path Traversal", "skill": "path-traversal", "url": "http://127.0.0.1/app/file?page=home", "parameter": "page"},
            {"title": "SSRF", "skill": "ssrf-identify", "url": "http://127.0.0.1/app/ssrf?url=https://127.0.0.1/", "parameter": "url"},
            {"title": "IDOR", "skill": "idor-audit", "url": "http://127.0.0.1/api/orders/42"},
            {"title": "SSTI", "skill": "ssti-detect", "url": "http://127.0.0.1/app/ssti?name=alice", "parameter": "name"},
            {"title": "CRLF Injection", "skill": "crlf-injection", "url": "http://127.0.0.1/app/crlf?lang=en", "parameter": "lang"},
        ]

        val_results = ev.validate_findings(findings)
        assert all(r.status == "confirmed" for r in val_results)

        # Deploy remediation on all endpoints
        local_server["mode_state"].update({
            "xss": "fixed",
            "sqli": "fixed",
            "redirect": "fixed",
            "cors": "fixed",
            "traversal": "fixed",
            "ssrf": "fixed",
            "ssti": "fixed",
            "crlf": "fixed",
        })
        fixed_auth = _make_mini_auth_checker(validator, user_b_code=403, user_b_payload={"error": "Forbidden"})

        engine = RetestEngine(
            target="http://127.0.0.1",
            target_dir=target_dir,
            scope_validator=validator,
            oob_server=oob,
            auth_diff_checker=fixed_auth,
            delay_seconds=0.0,
            oob_wait_seconds=0.2,
        )

        retest_results = engine.retest_findings(
            findings,
            remediation_id="rem-2026-001",
            code_version="commit-abcdef12",
            environment={"env": "staging"},
            regression_routes=["/api/health", "/api/profile"],
        )

        assert len(retest_results) == 9
        for finding, res in zip(findings, retest_results):
            assert res.outcome == "fixed", f"{res.strategy} got {res.outcome}: {res.limitations}"
            assert res.outcome in VALID_RETEST_OUTCOMES
            assert FIXED_LIMITATION_NOTE in res.limitations
            assert res.remediation_id == "rem-2026-001"
            assert res.code_version == "commit-abcdef12"
            assert res.retest_artifact.startswith("output/evidence/retests/")
            assert (target_dir / res.retest_artifact).is_file()
            assert engine.verify_retest_integrity(res.retest_id)["valid"] is True
            assert res.regression_report["regression_detected"] is False
            assert finding["status"] == "fixed"
            assert finding["validation_status"] == "fixed"
            # Serialization round-trip
            reloaded = RetestResult.from_dict(res.to_dict())
            assert reloaded.outcome == "fixed"
            assert reloaded.retest_id == res.retest_id


# ---------------------------------------------------------------------------
# 2. Incomplete fix (`still_vulnerable`)
# ---------------------------------------------------------------------------


def test_incomplete_fix_stays_still_vulnerable_and_preserves_lifecycle(tmp_path, local_server):
    target_dir = _setup_target_dir(tmp_path)
    ev = ExploitValidator(target="http://127.0.0.1", target_dir=target_dir, delay_seconds=0.0)

    xss_finding = {
        "title": "Reflected XSS in /app/xss",
        "skill": "xss-reflected",
        "url": "http://127.0.0.1/app/xss?q=test",
        "parameter": "q",
    }
    val_res = ev.validate_finding(xss_finding)
    assert val_res.status == "confirmed"

    # Incomplete patch only strips <script>, still reflects <moros-probe>
    local_server["mode_state"]["xss"] = "incomplete"

    engine = RetestEngine(target="http://127.0.0.1", target_dir=target_dir, delay_seconds=0.0)
    res = engine.retest_finding(
        xss_finding,
        remediation_id="rem-incomplete",
        code_version="v1.0.1",
        mutate_finding=False,
    )

    assert res.outcome == "still_vulnerable"
    assert res.confidence >= 0.85
    assert res.before_after["suggested_outcome"] == "still_vulnerable"
    assert res.before_after["after"]["reflection_marker"] is True

    # Lifecycle update keeps confirmed for confirmed findings and validating for validating findings
    updated_confirmed = update_finding_lifecycle(xss_finding, res)
    assert updated_confirmed["status"] == "confirmed"
    assert updated_confirmed["validation_status"] == "confirmed"
    assert len(updated_confirmed["retest_history"]) == 1
    assert updated_confirmed["retest_history"][0]["outcome"] == "still_vulnerable"

    validating_finding = copy.deepcopy(xss_finding)
    validating_finding["status"] = "validating"
    updated_validating = update_finding_lifecycle(validating_finding, res)
    assert updated_validating["status"] == "validating"
    assert updated_validating["validation_status"] == "validating"


# ---------------------------------------------------------------------------
# 3. Regression introduced by patch (`regression_detected`)
# ---------------------------------------------------------------------------


def test_regression_detected_on_5xx_breakage_and_reintroduced_vuln(tmp_path, local_server):
    target_dir = _setup_target_dir(tmp_path)
    ev = ExploitValidator(target="http://127.0.0.1", target_dir=target_dir, delay_seconds=0.0)

    # 3A: Patch fixes XSS on /app/xss, but breaks /api/profile with HTTP 500 + Traceback
    xss_finding = {"title": "XSS", "skill": "xss-reflected", "url": "http://127.0.0.1/app/xss?q=test", "parameter": "q"}
    assert ev.validate_finding(xss_finding).status == "confirmed"

    local_server["mode_state"]["xss"] = "fixed"
    local_server["mode_state"]["profile"] = "500"

    engine = RetestEngine(target="http://127.0.0.1", target_dir=target_dir, delay_seconds=0.0)
    res_related_500 = engine.retest_finding(
        xss_finding,
        remediation_id="rem-reg-1",
        regression_routes=["/api/health", "/api/profile"],
        expected_routes={"/api/health": {"expected_status": 200, "expected_indicator": "healthy"}},
    )
    assert res_related_500.outcome == "regression_detected"
    assert res_related_500.regression_report["regression_detected"] is True
    assert any(r["kind"] == "http_5xx" and "/api/profile" in r["route"] for r in res_related_500.regression_report["regressions"])
    assert xss_finding["status"] == "confirmed"  # NEVER marked fixed on regression

    # 3B: Patch causes target endpoint itself (/app/sqli) to return HTTP 500 on clean baseline
    local_server["mode_state"]["profile"] = "ok"
    local_server["mode_state"]["sqli"] = "vuln"
    sqli_finding = {"title": "SQLi", "skill": "sqli-heuristic", "url": "http://127.0.0.1/app/sqli?id=1", "parameter": "id"}
    assert ev.validate_finding(sqli_finding).status == "confirmed"

    local_server["mode_state"]["sqli"] = "broken_500"
    res_target_500 = engine.retest_finding(sqli_finding, remediation_id="rem-reg-2")
    assert res_target_500.outcome == "regression_detected"
    assert res_target_500.regression_report["regression_detected"] is True
    assert sqli_finding["status"] == "confirmed"

    # 3C: Patch fixes /app/xss and /api/profile is 200, but assertion fails (degraded) or reintroduced vuln on related route
    local_server["mode_state"]["profile"] = "degraded"
    res_breakage = engine.retest_finding(
        xss_finding,
        remediation_id="rem-reg-3",
        expected_routes={"/api/profile": {"expected_status": 200, "expected_indicator": "ACTIVE_USER"}},
    )
    assert res_breakage.outcome == "regression_detected"
    assert any(r["kind"] == "functionality_breakage" for r in res_breakage.regression_report["regressions"])

    local_server["mode_state"]["profile"] = "ok"
    local_server["mode_state"]["legacy_search"] = "reintroduced_xss"
    res_reintro = engine.retest_finding(
        xss_finding,
        remediation_id="rem-reg-4",
        regression_routes=["/api/legacy-search?q=test"],
        check_reintroduced_vulns=True,
    )
    assert res_reintro.outcome == "regression_detected"
    assert any(r["kind"] == "reintroduced_vulnerability" for r in res_reintro.regression_report["regressions"])


# ---------------------------------------------------------------------------
# 4. Environment / endpoint mismatch (`inconclusive`)
# ---------------------------------------------------------------------------


def test_environment_and_endpoint_mismatch_returns_inconclusive(tmp_path, local_server):
    target_dir = _setup_target_dir(tmp_path)
    ev = ExploitValidator(target="http://127.0.0.1", target_dir=target_dir, delay_seconds=0.0)

    # Confirm original XSS + generic finding
    xss_finding = {"title": "XSS", "skill": "xss-reflected", "url": "http://127.0.0.1/app/xss?q=test", "parameter": "q"}
    assert ev.validate_finding(xss_finding).status == "confirmed"

    generic_finding = {
        "title": "Sensitive endpoint leak",
        "url": "http://127.0.0.1/app/generic",
        "expected_status": 200,
        "expected_indicator": "LEAK_ACTIVE",
    }
    assert ev.validate_finding(generic_finding).status == "confirmed"

    engine = RetestEngine(target="http://127.0.0.1", target_dir=target_dir, delay_seconds=0.0)

    # 4A: Endpoint returns 404 on retest (route missing in target environment -> inconclusive, NOT fixed)
    local_server["mode_state"]["xss"] = "missing"
    res_404_xss = engine.retest_finding(copy.deepcopy(xss_finding), mutate_finding=False)
    assert res_404_xss.outcome == "inconclusive"
    assert res_404_xss.before_after["environment_mismatch"] is True

    local_server["mode_state"]["generic"] = "missing"
    res_404_generic = engine.retest_finding(copy.deepcopy(generic_finding), mutate_finding=False)
    assert res_404_generic.outcome == "inconclusive"
    assert res_404_generic.before_after["environment_mismatch"] is True

    # 4B: Endpoint path changed compared to original proof bundle
    local_server["mode_state"]["xss"] = "fixed"
    moved_finding = copy.deepcopy(xss_finding)
    moved_finding["url"] = "http://127.0.0.1/different-path/xss?q=test"
    res_path_mismatch = engine.retest_finding(moved_finding, mutate_finding=False)
    assert res_path_mismatch.outcome == "inconclusive"
    assert any("path mismatch" in r.lower() for r in res_path_mismatch.before_after["mismatch_reasons"])

    # 4C: Service metadata mismatch between original proof environment and retest environment
    xss_with_env = copy.deepcopy(xss_finding)
    xss_with_env["validation_result"]["environment"] = {"service": "orders-api", "env": "staging"}
    res_svc_mismatch = engine.retest_finding(
        xss_with_env,
        environment={"service": "billing-api", "env": "staging"},
        mutate_finding=False,
    )
    assert res_svc_mismatch.outcome == "inconclusive"
    assert any("service" in r.lower() for r in res_svc_mismatch.before_after["mismatch_reasons"])

    # 4D: Unverified candidate finding (never confirmed) does NOT inflate to 'fixed'
    unverified_candidate = {
        "title": "Unverified XSS lead",
        "skill": "xss-reflected",
        "url": "http://127.0.0.1/app/xss?q=test",
        "parameter": "q",
        "status": "candidate",
    }
    res_unverified = engine.retest_finding(unverified_candidate)
    assert res_unverified.outcome == "inconclusive"
    assert unverified_candidate["status"] == "inconclusive"

    # 4E: Timeout / network error on slow endpoint -> inconclusive
    slow_finding = {
        "title": "Slow endpoint",
        "url": "http://127.0.0.1/slow",
        "expected_indicator": "anything",
        "status": "confirmed",
        "validation_result": {"status": "confirmed", "validation_run_id": "val-slow", "evidence_ids": ["ev-slow"]},
    }
    timeout_client = ScopedHttpClient("http://127.0.0.1", max_requests=5, delay_seconds=0.0, timeout_seconds=1.0, max_retries=0)
    engine_to = RetestEngine(target="http://127.0.0.1", target_dir=target_dir, http_client=timeout_client, delay_seconds=0.0)
    res_timeout = engine_to.retest_finding(slow_finding, mutate_finding=False)
    assert res_timeout.outcome == "inconclusive"


# ---------------------------------------------------------------------------
# 5. Retest blocked by scope policy & HITL gates (`blocked_scope`)
# ---------------------------------------------------------------------------


def test_retest_blocked_by_scope_policy_and_hitl_gates(tmp_path, local_server, monkeypatch):
    target_dir = _setup_target_dir(tmp_path)
    cm = CheckpointManager("127.0.0.1", target_dir)
    engine = RetestEngine(
        target="http://127.0.0.1",
        target_dir=target_dir,
        checkpoint_manager=cm,
        delay_seconds=0.0,
    )

    before_count = len(local_server["recorded"])

    # 5A: Explicit out-of-scope domain, wildcard out-of-scope, and third-party host
    for bad_url in (
        "https://evil.example/search?q=1",
        "https://api.blocked.local/item?id=1",
        "https://unrelated-third-party.org/api",
    ):
        f = {"title": "Out of scope", "skill": "xss-reflected", "url": bad_url, "parameter": "q"}
        res = engine.retest_finding(f, mutate_finding=False)
        assert res.outcome == "blocked_scope"
        assert res.requests_used == 0
        assert any("scope" in lim.lower() for lim in res.limitations)
        assert (target_dir / res.retest_artifact).is_file()

    assert len(local_server["recorded"]) == before_count

    # 5B: Gated state-changing POST requires MOROS_ALLOW_GATED_POST=1 + CheckpointManager APPROVED
    gated_finding = {
        "title": "Gated POST issue",
        "url": "http://127.0.0.1/gated/action",
        "method": "POST",
        "json_body": {"probe": "safe"},
        "expected_status": 200,
        "expected_indicator": "GATED_STATE_CONFIRMED",
        "status": "confirmed",
        "validation_result": {"status": "confirmed", "validation_run_id": "val-post", "evidence_ids": ["ev-post"]},
    }

    monkeypatch.delenv("MOROS_ALLOW_GATED_POST", raising=False)
    monkeypatch.delenv("MOROS_HITL_BLOCKING", raising=False)
    res_no_env = engine.retest_finding(copy.deepcopy(gated_finding), mutate_finding=False)
    assert res_no_env.outcome == "blocked_scope"
    assert res_no_env.requests_used == 0

    # Enable env var, checkpoint created in WAITING_APPROVAL -> blocked_scope until human approves
    monkeypatch.setenv("MOROS_ALLOW_GATED_POST", "1")
    res_waiting = engine.retest_finding(copy.deepcopy(gated_finding), mutate_finding=False)
    assert res_waiting.outcome == "blocked_scope"
    assert res_waiting.requests_used == 0
    cps = cm.list_checkpoints()
    assert len(cps) == 1
    assert cps[0]["status"] == "WAITING_APPROVAL"

    # Reject -> still blocked_scope
    cm.decide(cps[0]["id"], "reject", notes="Deny retest POST")
    res_rejected = engine.retest_finding(copy.deepcopy(gated_finding), mutate_finding=False)
    assert res_rejected.outcome == "blocked_scope"
    assert res_rejected.requests_used == 0

    # Approve -> executes POST and detects still_vulnerable, then patch -> fixed
    cm.decide(cps[0]["id"], "approve", notes="Approve retest POST")
    res_approved_vuln = engine.retest_finding(copy.deepcopy(gated_finding), mutate_finding=False)
    assert res_approved_vuln.outcome == "still_vulnerable"
    assert res_approved_vuln.requests_used >= 1

    local_server["mode_state"]["gated"] = "fixed"
    res_approved_fixed = engine.retest_finding(copy.deepcopy(gated_finding), mutate_finding=False)
    assert res_approved_fixed.outcome == "fixed"


# ---------------------------------------------------------------------------
# 6. Historical evidence preservation, tamper detection & secret redaction
# ---------------------------------------------------------------------------


def test_historical_evidence_preservation_tamper_detection_and_redaction(tmp_path, local_server):
    target_dir = _setup_target_dir(tmp_path)
    ev = ExploitValidator(target="http://127.0.0.1", target_dir=target_dir, delay_seconds=0.0)

    finding = {
        "title": "Reflected XSS in /app/xss",
        "skill": "xss-reflected",
        "url": "http://127.0.0.1/app/xss?q=test",
        "parameter": "q",
        "evidence_ids": ["ev-legacy-seed-001"],
        "retest_history": [{"retest_id": "ret-prior-000", "outcome": "still_vulnerable"}],
    }
    orig_val = ev.validate_finding(finding)
    assert orig_val.status == "confirmed"
    orig_proof_path = finding["proof_artifact"]
    orig_val_snapshot = copy.deepcopy(finding["validation_result"])
    orig_ev_ids_snapshot = list(finding["evidence_ids"])
    assert "ev-legacy-seed-001" in orig_ev_ids_snapshot
    assert len(orig_ev_ids_snapshot) >= 2

    # First retest: incomplete fix -> still_vulnerable
    local_server["mode_state"]["xss"] = "incomplete"
    engine = RetestEngine(target="http://127.0.0.1", target_dir=target_dir, delay_seconds=0.0)
    res1 = engine.retest_finding(finding, remediation_id="rem-1", code_version="v1.1")
    assert res1.outcome == "still_vulnerable"

    # Second retest: complete fix -> fixed
    local_server["mode_state"]["xss"] = "fixed"
    res2 = engine.retest_finding(finding, remediation_id="rem-2", code_version="v1.2")
    assert res2.outcome == "fixed"

    # Historical evidence_ids, proof_artifact, validation_result MUST NEVER be deleted or overwritten
    assert finding["status"] == "fixed"
    assert finding["proof_artifact"] == orig_proof_path
    assert finding["validation_result"] == orig_val_snapshot
    for eid in orig_ev_ids_snapshot:
        assert eid in finding["evidence_ids"]
    assert res1.retest_evidence_id in finding["evidence_ids"]
    assert res2.retest_evidence_id in finding["evidence_ids"]

    history = finding["retest_history"]
    assert [h["retest_id"] for h in history] == ["ret-prior-000", res1.retest_id, res2.retest_id]
    assert [h["outcome"] for h in history] == ["still_vulnerable", "still_vulnerable", "fixed"]

    # Original proof integrity & new retest artifact integrity both pass SHA-256 ledger checks
    assert ev.proof_recorder.verify_proof_integrity(orig_val.validation_run_id)["valid"] is True
    assert engine.verify_retest_integrity(res1.retest_id)["valid"] is True
    assert engine.verify_retest_integrity(res2.retest_id)["valid"] is True

    # Tampering with persisted retest JSON is detected
    retest_file = target_dir / res2.retest_artifact
    retest_file.write_text(retest_file.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    tamper_check = engine.verify_retest_integrity(res2.retest_id)
    assert tamper_check["valid"] is False
    assert "mismatch" in tamper_check["reason"].lower()

    # Secret redaction in persisted retest artifacts
    validator = ScopeValidator("127.0.0.1", target_dir=target_dir)
    authed_client = ScopedHttpClient(
        target="http://127.0.0.1",
        max_requests=10,
        delay_seconds=0.0,
        scope_validator=validator,
        auth_headers={
            "Authorization": "Bearer super_secret_client_jwt_12345",
            "X-API-Key": "sk-clientsecretkey1234567890abcdef",
        },
        cookies="session=client_cookie_secret_987",
    )
    sec_engine = RetestEngine(
        target="http://127.0.0.1",
        target_dir=target_dir,
        scope_validator=validator,
        http_client=authed_client,
        delay_seconds=0.0,
    )
    sec_finding = {
        "title": "Secrets endpoint",
        "skill": "xss-reflected",
        "url": "http://127.0.0.1/app/secrets?q=test&api_key=url_secret_key_555",
        "parameter": "q",
        "status": "confirmed",
        "validation_result": {"status": "confirmed", "validation_run_id": "val-sec", "evidence_ids": ["ev-sec"]},
    }
    sec_res = sec_engine.retest_finding(sec_finding)
    retest_text = (target_dir / sec_res.retest_artifact).read_text(encoding="utf-8")
    ledger_text = (target_dir / "output" / "evidence" / "ledger.jsonl").read_text(encoding="utf-8")

    for secret in (
        "super_secret_client_jwt_12345",
        "sk-clientsecretkey1234567890abcdef",
        "client_cookie_secret_987",
        "url_secret_key_555",
        "sk-1234567890abcdefghijklmnop",
        "super_secret_bearer_token_999",
        "top_secret_session_cookie",
    ):
        assert secret not in retest_text, f"Secret leaked in retest JSON: {secret}"
        assert secret not in ledger_text, f"Secret leaked in ledger: {secret}"
