#!/usr/bin/env python3
"""
mcp_client.py — Model Context Protocol (MCP) Client for Moros.

Connects to external MCP tool servers (e.g., Burp Suite MCP, Nuclei MCP,
custom security tool servers) and exposes their tools as callable functions
within the Moros agent loop.

Supports:
- stdio transport (subprocess pipe)
- SSE / HTTP transport (network)
- Tool discovery via `tools/list`
- Tool invocation via `tools/call`
- Schema-based argument validation
- Allowlist-based tool filtering (no arbitrary execution)

Reference: https://spec.modelcontextprotocol.io/
"""

import json
import logging
import os
import subprocess
import threading
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("mcp-client")

# Protocol constants
MCP_JSONRPC_VERSION = "2.0"
MCP_PROTOCOL_VERSION = "2024-11-05"


class MCPError(Exception):
    """MCP protocol or transport error."""
    def __init__(self, code: int = -1, message: str = "", data: Any = None):
        self.code = code
        self.message = message
        self.data = data
        super().__init__(f"MCP Error {code}: {message}")


class MCPTool:
    """Represents a single tool discovered from an MCP server."""
    __slots__ = ("name", "description", "input_schema", "server_name")

    def __init__(self, name: str, description: str = "",
                 input_schema: Dict[str, Any] = None, server_name: str = ""):
        self.name = name
        self.description = description
        self.input_schema = input_schema or {}
        self.server_name = server_name

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
            "server_name": self.server_name,
        }

    def validate_args(self, args: Dict[str, Any]) -> Tuple[bool, str]:
        """Basic validation against required properties in the schema."""
        if not isinstance(args, dict):
            return False, "Arguments must be a dict"
        required = self.input_schema.get("required", [])
        for field in required:
            if field not in args:
                return False, f"Missing required argument: {field}"
        return True, ""


class StdioTransport:
    """
    MCP transport over subprocess stdin/stdout (JSON-RPC line protocol).
    """

    def __init__(self, command: List[str], env: Dict[str, str] = None, cwd: str = None):
        self._command = command
        self._env = {**os.environ, **(env or {})}
        self._cwd = cwd
        self._process: Optional[subprocess.Popen] = None
        self._request_id = 0
        self._lock = threading.Lock()

    def start(self):
        """Launch the MCP server subprocess."""
        try:
            self._process = subprocess.Popen(
                self._command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=self._env,
                cwd=self._cwd,
                bufsize=0,
            )
            logger.info("MCP stdio transport started: %s (pid=%d)", self._command, self._process.pid)
        except (FileNotFoundError, OSError) as exc:
            raise MCPError(-1, f"Failed to start MCP server '{self._command[0]}': {exc}")

    def send_request(self, method: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """Send a JSON-RPC request and read the response."""
        if not self._process or self._process.poll() is not None:
            raise MCPError(-1, "MCP server process is not running")

        with self._lock:
            self._request_id += 1
            req_id = self._request_id

            request: Dict[str, Any] = {
                "jsonrpc": MCP_JSONRPC_VERSION,
                "id": req_id,
                "method": method,
            }
            if params is not None:
                request["params"] = params

            payload = json.dumps(request, ensure_ascii=False) + "\n"

            try:
                self._process.stdin.write(payload.encode("utf-8"))
                self._process.stdin.flush()
            except (BrokenPipeError, OSError) as exc:
                raise MCPError(-1, f"Failed to write to MCP server: {exc}")

            # Read response line
            try:
                line = self._process.stdout.readline()
                if not line:
                    raise MCPError(-1, "MCP server closed stdout unexpectedly")
                response = json.loads(line.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise MCPError(-1, f"Invalid response from MCP server: {exc}")

        if "error" in response:
            err = response["error"]
            raise MCPError(err.get("code", -1), err.get("message", "Unknown error"), err.get("data"))

        return response.get("result", {})

    def send_notification(self, method: str, params: Dict[str, Any] = None):
        """Send a JSON-RPC notification (no id, no response expected)."""
        if not self._process or self._process.poll() is not None:
            return
        notification: Dict[str, Any] = {
            "jsonrpc": MCP_JSONRPC_VERSION,
            "method": method,
        }
        if params is not None:
            notification["params"] = params
        payload = json.dumps(notification, ensure_ascii=False) + "\n"
        with self._lock:
            try:
                self._process.stdin.write(payload.encode("utf-8"))
                self._process.stdin.flush()
            except (BrokenPipeError, OSError) as exc:
                logger.debug("Failed to send MCP notification %s: %s", method, exc)

    def stop(self):
        if self._process:
            if self._process.poll() is None:
                try:
                    if self._process.stdin:
                        self._process.stdin.close()
                    self._process.wait(timeout=5)
                except Exception:
                    self._process.kill()
                    try:
                        self._process.wait(timeout=5)
                    except Exception:
                        pass
            for pipe in (self._process.stdin, self._process.stdout, self._process.stderr):
                if pipe and not pipe.closed:
                    try:
                        pipe.close()
                    except Exception:
                        pass
            logger.info("MCP stdio transport stopped")
        self._process = None


class HttpTransport:
    """
    MCP transport over HTTP (simple request/response, no streaming).
    """

    def __init__(self, base_url: str, headers: Dict[str, str] = None, timeout: int = 30):
        parsed = urllib.parse.urlparse(base_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError(f"Unsupported or invalid HTTP MCP URL: {base_url}")
        self._base_url = base_url.rstrip("/")
        self._headers = headers or {}
        self._timeout = timeout
        self._request_id = 0
        self._lock = threading.Lock()

    def start(self):
        """Verify connectivity to the MCP HTTP server."""
        try:
            req = urllib.request.Request(
                f"{self._base_url}/",
                method="GET",
                headers=self._headers,
            )
            with urllib.request.urlopen(req, timeout=self._timeout):
                pass
        except Exception as exc:
            logger.warning("MCP HTTP server connectivity check failed: %s", exc)

    def send_request(self, method: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        with self._lock:
            self._request_id += 1
            req_id = self._request_id

        request: Dict[str, Any] = {
            "jsonrpc": MCP_JSONRPC_VERSION,
            "id": req_id,
            "method": method,
        }
        if params is not None:
            request["params"] = params

        payload = json.dumps(request, ensure_ascii=False).encode("utf-8")
        headers = {**self._headers, "Content-Type": "application/json"}

        try:
            req = urllib.request.Request(
                self._base_url,
                data=payload,
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                body = resp.read().decode("utf-8")
                response = json.loads(body)
        except (urllib.error.URLError, json.JSONDecodeError, UnicodeDecodeError, TimeoutError, OSError) as exc:
            raise MCPError(-1, f"HTTP transport error: {exc}")

        if "error" in response:
            err = response["error"]
            raise MCPError(err.get("code", -1), err.get("message", ""), err.get("data"))

        return response.get("result", {})

    def send_notification(self, method: str, params: Dict[str, Any] = None):
        """Send a JSON-RPC notification over HTTP."""
        notification: Dict[str, Any] = {
            "jsonrpc": MCP_JSONRPC_VERSION,
            "method": method,
        }
        if params is not None:
            notification["params"] = params
        payload = json.dumps(notification, ensure_ascii=False).encode("utf-8")
        headers = {**self._headers, "Content-Type": "application/json"}
        try:
            req = urllib.request.Request(
                self._base_url,
                data=payload,
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self._timeout):
                pass
        except Exception as exc:
            logger.debug("HTTP MCP notification %s failed: %s", method, exc)

    def stop(self):
        pass  # stateless


class MCPClient:
    """
    High-level MCP client that manages server connections, discovers tools,
    validates calls, and enforces an allowlist.
    """

    def __init__(self, server_name: str = "default",
                 transport: str = "stdio",
                 command: List[str] = None,
                 url: str = None,
                 env: Dict[str, str] = None,
                 tool_allowlist: List[str] = None):
        self.server_name = server_name
        self._tools: Dict[str, MCPTool] = {}
        self._allowlist = set(tool_allowlist) if tool_allowlist is not None else None

        if transport == "stdio":
            if not command:
                raise ValueError("stdio transport requires a command list")
            self._transport = StdioTransport(command, env=env)
        elif transport == "http":
            if not url:
                raise ValueError("http transport requires a url")
            self._transport = HttpTransport(url)
        else:
            raise ValueError(f"Unsupported transport: {transport}")

    def connect(self):
        """Start transport and perform MCP initialization handshake."""
        self._transport.start()
        # Send initialize
        result = self._transport.send_request("initialize", {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "moros-agent", "version": "2.3.0"},
        })
        logger.info("MCP server initialized: %s", result.get("serverInfo", {}))

        # Send initialized notification (JSON-RPC notification; no response expected)
        try:
            self._transport.send_notification("notifications/initialized")
        except Exception:
            pass

    def discover_tools(self) -> List[MCPTool]:
        """Fetch available tools from the MCP server."""
        result = self._transport.send_request("tools/list")
        tools_data = result.get("tools", [])
        self._tools.clear()

        for t in tools_data:
            name = t.get("name", "")
            if self._allowlist is not None and name not in self._allowlist:
                logger.debug("Skipping tool %s (not in allowlist)", name)
                continue
            tool = MCPTool(
                name=name,
                description=t.get("description", ""),
                input_schema=t.get("inputSchema", {}),
                server_name=self.server_name,
            )
            self._tools[name] = tool

        logger.info("Discovered %d tools from %s", len(self._tools), self.server_name)
        return list(self._tools.values())

    def call_tool(self, tool_name: str, arguments: Dict[str, Any] = None) -> Any:
        """Invoke a tool on the MCP server with validation."""
        tool = self._tools.get(tool_name)
        if not tool:
            raise MCPError(-1, f"Tool '{tool_name}' not found on server '{self.server_name}'")

        args = arguments if arguments is not None else {}
        valid, reason = tool.validate_args(args)
        if not valid:
            raise MCPError(-1, f"Argument validation failed for {tool_name}: {reason}")

        result = self._transport.send_request("tools/call", {
            "name": tool_name,
            "arguments": args,
        })
        return result

    def list_tools(self) -> List[Dict[str, Any]]:
        """Return discovered tools as dicts."""
        return [t.to_dict() for t in self._tools.values()]

    def disconnect(self):
        """Shut down the transport."""
        self._transport.stop()
        self._tools.clear()
        logger.info("Disconnected from MCP server %s", self.server_name)
