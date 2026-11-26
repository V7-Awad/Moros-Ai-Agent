#!/usr/bin/env python3
"""Tests for mcp_client.py — MCP Client."""

import sys
import pytest
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))
from mcp_client import (
    MCPClient, MCPTool, MCPError,
    StdioTransport, HttpTransport,
    MCP_JSONRPC_VERSION, MCP_PROTOCOL_VERSION,
)


class TestMCPTool:
    def test_tool_creation(self):
        t = MCPTool(name="scan", description="Run a scan", server_name="test-server")
        assert t.name == "scan"
        assert t.server_name == "test-server"

    def test_tool_to_dict(self):
        t = MCPTool(name="lookup", description="DNS lookup",
                    input_schema={"type": "object", "properties": {"domain": {"type": "string"}},
                                  "required": ["domain"]})
        d = t.to_dict()
        assert d["name"] == "lookup"
        assert "domain" in str(d["input_schema"])

    def test_validate_args_success(self):
        t = MCPTool(name="test", input_schema={
            "type": "object",
            "required": ["url"],
            "properties": {"url": {"type": "string"}},
        })
        ok, reason = t.validate_args({"url": "https://example.com"})
        assert ok
        assert reason == ""

    def test_validate_args_missing_required(self):
        t = MCPTool(name="test", input_schema={
            "type": "object",
            "required": ["url", "method"],
            "properties": {},
        })
        ok, reason = t.validate_args({"url": "https://example.com"})
        assert not ok
        assert "method" in reason


class TestMCPError:
    def test_error_attributes(self):
        e = MCPError(code=-32600, message="Invalid request")
        assert e.code == -32600
        assert "Invalid request" in str(e)

    def test_error_with_data(self):
        e = MCPError(code=-1, message="fail", data={"detail": "timeout"})
        assert e.data == {"detail": "timeout"}


class TestMCPClient:
    def test_client_requires_command_for_stdio(self):
        with pytest.raises(ValueError, match="command"):
            MCPClient(transport="stdio")

    def test_client_requires_url_for_http(self):
        with pytest.raises(ValueError, match="url"):
            MCPClient(transport="http")

    def test_unsupported_transport(self):
        with pytest.raises(ValueError, match="Unsupported"):
            MCPClient(transport="grpc")

    def test_client_creation_stdio(self):
        client = MCPClient(
            server_name="test",
            transport="stdio",
            command=["echo", "test"],
        )
        assert client.server_name == "test"

    def test_client_creation_http(self):
        client = MCPClient(
            server_name="http-test",
            transport="http",
            url="http://localhost:8080",
        )
        assert client.server_name == "http-test"

    def test_allowlist_filtering(self):
        client = MCPClient(
            transport="stdio",
            command=["echo"],
            tool_allowlist=["scan", "lookup"],
        )
        assert client._allowlist == {"scan", "lookup"}

    def test_empty_allowlist_blocks_all_tools(self):
        client = MCPClient(
            transport="stdio",
            command=["echo"],
            tool_allowlist=[],
        )
        client._transport.send_request = MagicMock(return_value={
            "tools": [{"name": "scan", "description": "Scan"}]
        })
        assert client.discover_tools() == []

    def test_http_rejects_unsafe_url_scheme(self):
        with pytest.raises(ValueError, match="Unsupported or invalid HTTP MCP URL"):
            MCPClient(transport="http", url="file:///etc/passwd")

    def test_list_tools_empty(self):
        client = MCPClient(transport="stdio", command=["echo"])
        assert client.list_tools() == []

    def test_call_tool_unknown(self):
        client = MCPClient(transport="stdio", command=["echo"])
        with pytest.raises(MCPError, match="not found"):
            client.call_tool("nonexistent", {})


class TestStdioTransport:
    def test_creation(self):
        t = StdioTransport(["echo", "test"])
        assert t._command == ["echo", "test"]
        assert t._process is None

    def test_send_without_start_raises(self):
        t = StdioTransport(["echo"])
        with pytest.raises(MCPError, match="not running"):
            t.send_request("test/method")


class TestHttpTransport:
    def test_creation(self):
        t = HttpTransport("http://localhost:3000")
        assert t._base_url == "http://localhost:3000"

    def test_stop_is_noop(self):
        t = HttpTransport("http://localhost:3000")
        t.stop()  # Should not raise
