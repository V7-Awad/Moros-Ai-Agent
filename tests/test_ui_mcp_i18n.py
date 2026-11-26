#!/usr/bin/env python3
"""Tests for MCP SSE/config loading, bilingual Arabic/English reporting, and dashboard observability UI."""

import io
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))

from mcp_client import HttpTransport, MCPClient, MCPError, StdioTransport  # noqa: E402
from report_i18n import format_report_markdown, localize_severity_label  # noqa: E402


class TestHttpTransportSSE:
    def test_parse_sse_events_single_and_multiline(self):
        raw = (
            ": keepalive\r\n"
            "event: message\r\n"
            'data: {"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progress": 50}}\r\n\r\n'
            "event: message\r\n"
            'data: {"jsonrpc": "2.0", "id": 1,\r\n'
            'data: "result": {"tools": [{"name": "nuclei_scan"}]}}\r\n\r\n'
            "data: [DONE]\r\n\r\n"
        )
        events = HttpTransport.parse_sse_events(raw)
        assert len(events) == 2
        assert events[0]["method"] == "notifications/progress"
        assert events[1]["id"] == 1
        assert events[1]["result"]["tools"][0]["name"] == "nuclei_scan"

    def test_parse_sse_response_matches_request_id(self):
        raw = (
            'data: {"jsonrpc": "2.0", "id": 99, "result": {"wrong": true}}\n\n'
            'data: {"jsonrpc": "2.0", "id": 2, "result": {"ok": true}}\n\n'
        )
        msg = HttpTransport.parse_sse_response(raw, req_id=2)
        assert msg["id"] == 2
        assert msg["result"] == {"ok": True}

    def test_parse_sse_response_empty_raises(self):
        with pytest.raises(MCPError, match="No JSON-RPC response"):
            HttpTransport.parse_sse_response(": ping\n\ndata: [DONE]\n\n", req_id=1)

    def test_send_request_sse_buffered_response(self):
        transport = HttpTransport("http://localhost:8085/mcp", headers={"Authorization": "Bearer tok"})
        sse_body = (
            b"event: message\n"
            b'data: {"jsonrpc": "2.0", "method": "notifications/progress"}\n\n'
            b"event: message\n"
            b'data: {"jsonrpc": "2.0", "id": 1, "result": {"serverInfo": {"name": "burp-mcp"}}}\n\n'
        )
        mock_resp = MagicMock()
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.__exit__.return_value = False
        mock_resp.headers = {
            "Content-Type": "text/event-stream; charset=utf-8",
            "Mcp-Session-Id": "sess-42",
        }
        mock_resp.read.return_value = sse_body

        with patch("urllib.request.urlopen", return_value=mock_resp) as mock_open:
            result = transport.send_request("initialize", {"capabilities": {}})

        assert result == {"serverInfo": {"name": "burp-mcp"}}
        assert transport._session_id == "sess-42"
        sent_req = mock_open.call_args[0][0]
        assert "text/event-stream" in sent_req.get_header("Accept")

    def test_send_request_sse_streaming_readline(self):
        transport = HttpTransport("http://localhost:8085/mcp")
        stream = io.BytesIO(
            b"event: message\r\n"
            b'data: {"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "scan"}]}}\r\n'
            b"\r\n"
            b": trailing keepalive\r\n"
        )
        mock_resp = MagicMock()
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.__exit__.return_value = False
        mock_resp.headers = {"Content-Type": "text/event-stream"}
        mock_resp.readline = stream.readline

        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = transport.send_request("tools/list")

        assert result == {"tools": [{"name": "scan"}]}

    def test_send_request_sse_error_raises_mcp_error(self):
        transport = HttpTransport("http://localhost:8085/mcp")
        mock_resp = MagicMock()
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.__exit__.return_value = False
        mock_resp.headers = {"Content-Type": "text/event-stream"}
        mock_resp.read.return_value = (
            b'data: {"jsonrpc": "2.0", "id": 1, "error": {"code": -32601, "message": "Method not found"}}\n\n'
        )

        with patch("urllib.request.urlopen", return_value=mock_resp):
            with pytest.raises(MCPError, match="Method not found"):
                transport.send_request("bad/method")

    def test_send_request_json_still_works(self):
        transport = HttpTransport("http://localhost:8085/mcp")
        mock_resp = MagicMock()
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.__exit__.return_value = False
        mock_resp.headers = {"Content-Type": "application/json"}
        mock_resp.read.return_value = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}).encode("utf-8")

        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = transport.send_request("ping")

        assert result == {"ok": True}


class TestMCPConfigLoading:
    def test_load_from_mcp_servers_schema(self, tmp_path):
        config_file = tmp_path / "mcp-servers.json"
        config_file.write_text(
            json.dumps({
                "mcpServers": {
                    "burp": {
                        "command": "python",
                        "args": ["-m", "burp_mcp"],
                        "env": {"BURP_TOKEN": "abc"},
                        "toolAllowlist": ["get_proxy_history"],
                    },
                    "nuclei": {
                        "url": "http://127.0.0.1:9090/sse",
                        "transport": "sse",
                        "headers": {"X-Api-Key": "secret"},
                        "tool_allowlist": ["nuclei_scan"],
                        "timeout": 45,
                    },
                    "disabled-srv": {
                        "url": "http://127.0.0.1:9999/mcp",
                        "disabled": True,
                    },
                }
            }),
            encoding="utf-8",
        )

        clients = MCPClient.load_from_config(config_file)
        assert len(clients) == 2

        burp, nuclei = clients
        assert burp.server_name == "burp"
        assert isinstance(burp._transport, StdioTransport)
        assert burp._transport._command == ["python", "-m", "burp_mcp"]
        assert burp._transport._env["BURP_TOKEN"] == "abc"
        assert burp._allowlist == {"get_proxy_history"}

        assert nuclei.server_name == "nuclei"
        assert isinstance(nuclei._transport, HttpTransport)
        assert nuclei._transport._base_url == "http://127.0.0.1:9090/sse"
        assert nuclei._transport._headers == {"X-Api-Key": "secret"}
        assert nuclei._transport._timeout == 45
        assert nuclei._allowlist == {"nuclei_scan"}

    def test_load_from_servers_list_schema(self, tmp_path):
        config_file = tmp_path / "mcp-servers.json"
        config_file.write_text(
            json.dumps({
                "servers": [
                    {"name": "local-tool", "command": "node server.js", "allowlist": []},
                    {"name": "skipped", "url": "http://localhost:8000", "enabled": False},
                ]
            }),
            encoding="utf-8",
        )
        clients = MCPClient.load_from_config(config_file)
        assert len(clients) == 1
        assert clients[0].server_name == "local-tool"
        assert clients[0]._transport._command == ["node", "server.js"]
        assert clients[0]._allowlist == set()

    def test_load_from_missing_or_invalid_config_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            MCPClient.load_from_config(tmp_path / "missing.json")

        bad_file = tmp_path / "bad.json"
        bad_file.write_text("{not valid json", encoding="utf-8")
        with pytest.raises(ValueError, match="Invalid MCP config JSON"):
            MCPClient.load_from_config(bad_file)


class TestReportI18n:
    def test_localize_severity_label_languages_and_dialects(self):
        assert localize_severity_label("CRITICAL", lang="en") == "Critical"
        assert localize_severity_label("HIGH", lang="ar", dialect="msa") == "عالي"
        assert localize_severity_label("CRITICAL", lang="ar", dialect="egyptian") == "حرج جداً"
        assert localize_severity_label("LOW", lang="ar", dialect="egyptian") == "بسيط"
        assert localize_severity_label(
            "Triage Severity: HIGH — pending human review",
            lang="ar",
            dialect="msa",
            bilingual=True,
        ) == "عالي (High)"

    def test_format_report_markdown_arabic_msa_bilingual(self):
        findings = [
            {
                "title": "Reflected XSS in Search",
                "severity_level": "HIGH",
                "endpoint": "https://example.com/search",
                "parameter": "q",
                "cwe": "CWE-79",
                "validation_status": "validated",
                "evidence_ids": ["ev-1234"],
                "curl_command": "curl -s 'https://example.com/search?q=test'",
                "details": "Reflected without HTML encoding.",
                "remediation": "Encode output contextually.",
            },
            {
                "title": "Potential IDOR on Profile",
                "severity_level": "MEDIUM",
                "endpoint": "https://example.com/api/profile/42",
                "validation_status": "unverified",
            },
        ]
        md = format_report_markdown("example.com", findings, lang="ar", dialect="msa")

        assert '<div dir="rtl">' in md
        assert "تقرير اختبار الاختراق الأمني (Penetration Test Report)" in md
        assert "الملخص التنفيذي (Executive Summary)" in md
        assert "مستوى الخطورة (Severity)" in md
        assert "العدد (Count)" in md
        assert "النقطة الطرفية (Endpoint)" in md
        assert "التوصيات العلاجية (Remediation)" in md
        assert "خطة المعالجة والتوصيات العامة (Remediation Recommendations)" in md
        assert "عالي (High)" in md
        assert "متوسط (Medium)" in md
        assert "Encode output contextually." in md

    def test_format_report_markdown_egyptian_and_english_empty(self):
        eg_md = format_report_markdown("app.example.com", [], lang="ar", dialect="egyptian")
        assert "التقرير ده بيوضح" in eg_md
        assert "مفيش أي ثغرات" in eg_md
        assert "توصيات الإصلاح العامة (Remediation Recommendations)" in eg_md

        en_md = format_report_markdown("app.example.com", [], lang="en")
        assert "# Penetration Test Report — app.example.com" in en_md
        assert "## Executive Summary" in en_md
        assert "## Remediation Recommendations" in en_md


class TestDashboardObservabilityUI:
    def test_dashboard_html_wires_observability_and_security_endpoints(self):
        html_path = REPO_ROOT / "dashboard" / "static" / "index.html"
        html = html_path.read_text(encoding="utf-8")

        # Required API endpoint hooks
        assert "/costs`" in html
        assert "/traces`" in html
        assert "/memory`" in html
        assert "/api/security/posture" in html

        # Navigation buttons and tab panels
        for tab_name in ("costs", "traces", "memory", "posture"):
            assert f'id="tabBtn-{tab_name}"' in html
            assert f'id="tab-{tab_name}"' in html
            assert f"'{tab_name}'" in html

        # Key data containers
        for container_id in (
            "costsSkillTableBody",
            "costsEntriesTableBody",
            "tracesTimelineContainer",
            "memoryFactsTableBody",
            "memoryTechniquesTableBody",
            "memoryEventsList",
            "securityPostureTableBody",
            "postureCoveragePill",
        ):
            assert f'id="{container_id}"' in html
