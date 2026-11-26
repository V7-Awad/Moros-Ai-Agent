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
import shlex
import subprocess
import threading
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

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
    MCP transport over HTTP (supports JSON and SSE ``text/event-stream`` responses).
    """

    def __init__(self, base_url: str, headers: Dict[str, str] = None, timeout: int = 30):
        parsed = urllib.parse.urlparse(base_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError(f"Unsupported or invalid HTTP MCP URL: {base_url}")
        self._base_url = base_url.rstrip("/")
        self._headers = dict(headers) if headers else {}
        self._timeout = timeout
        self._request_id = 0
        self._session_id: Optional[str] = None
        self._lock = threading.Lock()

    @staticmethod
    def parse_sse_events(raw_text: str) -> List[Dict[str, Any]]:
        """Parse Server-Sent Events (text/event-stream) payloads into JSON-RPC dicts."""
        if not raw_text:
            return []
        normalized = raw_text.replace("\r\n", "\n").replace("\r", "\n")
        messages: List[Dict[str, Any]] = []
        data_lines: List[str] = []

        def _flush():
            if not data_lines:
                return
            payload = "\n".join(data_lines).strip()
            data_lines.clear()
            if not payload or payload == "[DONE]":
                return
            try:
                parsed = json.loads(payload)
            except json.JSONDecodeError:
                return
            if isinstance(parsed, dict):
                messages.append(parsed)

        for line in normalized.split("\n"):
            if line == "":
                _flush()
                continue
            if line.startswith(":"):
                continue
            field, sep, value = line.partition(":")
            if sep and value.startswith(" "):
                value = value[1:]
            if field == "data":
                data_lines.append(value)

        _flush()
        return messages

    @staticmethod
    def _select_jsonrpc_message(messages: List[Dict[str, Any]],
                                req_id: Optional[int] = None) -> Dict[str, Any]:
        """Select the JSON-RPC response matching req_id from parsed SSE events."""
        if req_id is not None:
            for msg in messages:
                if msg.get("id") == req_id and ("result" in msg or "error" in msg):
                    return msg
            for msg in messages:
                if msg.get("id") == req_id:
                    return msg
        for msg in reversed(messages):
            if "result" in msg or "error" in msg:
                return msg
        raise MCPError(-1, "HTTP transport error: No JSON-RPC response found in SSE stream")

    @classmethod
    def parse_sse_response(cls, raw_text: str, req_id: Optional[int] = None) -> Dict[str, Any]:
        """Parse an SSE stream body and return the matching JSON-RPC message."""
        events = cls.parse_sse_events(raw_text)
        return cls._select_jsonrpc_message(events, req_id=req_id)

    def _read_sse_response(self, resp: Any, req_id: Optional[int] = None) -> Dict[str, Any]:
        """Read an SSE response stream incrementally or from a buffered body."""
        readline_fn = getattr(resp, "readline", None)
        if callable(readline_fn):
            first_line = readline_fn()
            if isinstance(first_line, (bytes, bytearray, str)):
                messages: List[Dict[str, Any]] = []
                data_lines: List[str] = []

                def _flush_event() -> Optional[Dict[str, Any]]:
                    if not data_lines:
                        return None
                    payload = "\n".join(data_lines).strip()
                    data_lines.clear()
                    if not payload or payload == "[DONE]":
                        return None
                    try:
                        parsed = json.loads(payload)
                    except json.JSONDecodeError:
                        return None
                    if not isinstance(parsed, dict):
                        return None
                    messages.append(parsed)
                    if req_id is not None and parsed.get("id") == req_id and (
                        "result" in parsed or "error" in parsed
                    ):
                        return parsed
                    return None

                line_obj: Any = first_line
                while True:
                    if isinstance(line_obj, (bytes, bytearray)):
                        line_str = line_obj.decode("utf-8")
                    elif isinstance(line_obj, str):
                        line_str = line_obj
                    else:
                        break
                    if line_str == "":
                        break
                    stripped = line_str.rstrip("\r\n")
                    if stripped == "":
                        matched = _flush_event()
                        if matched is not None:
                            return matched
                    elif not stripped.startswith(":"):
                        field, sep, value = stripped.partition(":")
                        if sep and value.startswith(" "):
                            value = value[1:]
                        if field == "data":
                            data_lines.append(value)
                    line_obj = readline_fn()

                matched = _flush_event()
                if matched is not None:
                    return matched
                return self._select_jsonrpc_message(messages, req_id=req_id)

        raw_bytes = resp.read()
        raw_text = raw_bytes.decode("utf-8") if isinstance(raw_bytes, (bytes, bytearray)) else str(raw_bytes)
        return self.parse_sse_response(raw_text, req_id=req_id)

    def _build_headers(self, include_accept_sse: bool = False) -> Dict[str, str]:
        headers = {**self._headers, "Content-Type": "application/json"}
        if include_accept_sse and not any(k.lower() == "accept" for k in headers):
            headers["Accept"] = "application/json, text/event-stream"
        if self._session_id and not any(k.lower() == "mcp-session-id" for k in headers):
            headers["Mcp-Session-Id"] = self._session_id
        return headers

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
        headers = self._build_headers(include_accept_sse=True)

        try:
            req = urllib.request.Request(
                self._base_url,
                data=payload,
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                resp_headers = getattr(resp, "headers", None)
                content_type = ""
                if resp_headers is not None:
                    session_hdr = resp_headers.get("Mcp-Session-Id") or resp_headers.get("mcp-session-id")
                    if isinstance(session_hdr, str) and session_hdr.strip():
                        self._session_id = session_hdr.strip()
                    raw_ct = resp_headers.get("Content-Type") or resp_headers.get("content-type")
                    if isinstance(raw_ct, str):
                        content_type = raw_ct.lower()

                if "text/event-stream" in content_type:
                    response = self._read_sse_response(resp, req_id=req_id)
                else:
                    raw_body = resp.read()
                    body = raw_body.decode("utf-8") if isinstance(raw_body, (bytes, bytearray)) else str(raw_body)
                    try:
                        response = json.loads(body)
                    except json.JSONDecodeError:
                        if body.lstrip().startswith(("data:", "event:", ":")):
                            response = self.parse_sse_response(body, req_id=req_id)
                        else:
                            raise
        except MCPError:
            raise
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
        headers = self._build_headers(include_accept_sse=True)
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
        self._session_id = None


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
                 tool_allowlist: List[str] = None,
                 headers: Dict[str, str] = None,
                 cwd: str = None,
                 timeout: int = 30):
        self.server_name = server_name
        self._tools: Dict[str, MCPTool] = {}
        self._allowlist = set(tool_allowlist) if tool_allowlist is not None else None

        normalized_transport = (transport or "").strip().lower()
        if normalized_transport == "stdio":
            if not command:
                raise ValueError("stdio transport requires a command list")
            self._transport = StdioTransport(command, env=env, cwd=cwd)
        elif normalized_transport in ("http", "sse"):
            if not url:
                raise ValueError("http transport requires a url")
            self._transport = HttpTransport(url, headers=headers, timeout=timeout)
        else:
            raise ValueError(f"Unsupported transport: {transport}")

    @classmethod
    def load_from_config(cls, config_path: Union[str, Path]) -> List["MCPClient"]:
        """
        Instantiate MCPClient instances from an ``mcp-servers.json`` config file.

        Supports standard ``{"mcpServers": {...}}``, ``{"servers": {...}}``,
        list-based ``{"servers": [...]}``, and flat ``{"name": {...}}`` schemas.
        Disabled entries (``disabled: true`` or ``enabled: false``) are skipped.
        """
        path = Path(config_path)
        raw_text = path.read_text(encoding="utf-8")
        try:
            data = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid MCP config JSON in {path}: {exc}") from exc

        entries: List[Tuple[str, Dict[str, Any]]] = []
        if isinstance(data, dict):
            if "mcpServers" in data:
                servers_obj = data["mcpServers"]
            elif "servers" in data:
                servers_obj = data["servers"]
            else:
                servers_obj = data

            if isinstance(servers_obj, dict):
                for name, cfg in servers_obj.items():
                    if isinstance(cfg, dict):
                        entries.append((str(name), cfg))
                    else:
                        raise ValueError(f"MCP server entry '{name}' must be an object")
            elif isinstance(servers_obj, list):
                for idx, cfg in enumerate(servers_obj, 1):
                    if not isinstance(cfg, dict):
                        raise ValueError(f"MCP server entry #{idx} must be an object")
                    entries.append((str(cfg.get("name") or f"mcp-{idx}"), cfg))
            else:
                raise ValueError("MCP servers collection must be an object or list")
        elif isinstance(data, list):
            for idx, cfg in enumerate(data, 1):
                if not isinstance(cfg, dict):
                    raise ValueError(f"MCP server entry #{idx} must be an object")
                entries.append((str(cfg.get("name") or f"mcp-{idx}"), cfg))
        else:
            raise ValueError("MCP config root must be a JSON object or array")

        clients: List[MCPClient] = []
        for name, cfg in entries:
            if cfg.get("disabled") is True or cfg.get("enabled") is False:
                logger.debug("Skipping disabled MCP server '%s'", name)
                continue

            raw_transport = (cfg.get("transport") or cfg.get("type") or "").strip().lower()
            if not raw_transport:
                if cfg.get("command") is not None:
                    raw_transport = "stdio"
                elif cfg.get("url") is not None:
                    raw_transport = "http"

            command: Optional[List[str]] = None
            url: Optional[str] = cfg.get("url")

            if raw_transport == "stdio":
                raw_cmd = cfg.get("command")
                raw_args = cfg.get("args") or []
                if not isinstance(raw_args, list):
                    raise ValueError(f"MCP server '{name}' args must be a list")
                args_list = [str(a) for a in raw_args]
                if isinstance(raw_cmd, list):
                    command = [str(c) for c in raw_cmd] + args_list
                elif isinstance(raw_cmd, str) and raw_cmd.strip():
                    cmd_str = raw_cmd.strip()
                    if args_list:
                        command = [cmd_str] + args_list
                    elif " " in cmd_str and not Path(cmd_str).exists():
                        command = shlex.split(cmd_str)
                    else:
                        command = [cmd_str]

            allowlist: Optional[List[str]] = None
            for key in ("tool_allowlist", "toolAllowlist", "allowlist"):
                if key in cfg:
                    raw_allow = cfg[key]
                    if raw_allow is not None and not isinstance(raw_allow, list):
                        raise ValueError(f"MCP server '{name}' {key} must be a list")
                    allowlist = [str(t) for t in raw_allow] if raw_allow is not None else None
                    break

            env = cfg.get("env")
            if env is not None and not isinstance(env, dict):
                raise ValueError(f"MCP server '{name}' env must be an object")
            headers = cfg.get("headers")
            if headers is not None and not isinstance(headers, dict):
                raise ValueError(f"MCP server '{name}' headers must be an object")

            clients.append(cls(
                server_name=name,
                transport=raw_transport or "stdio",
                command=command,
                url=url,
                env={str(k): str(v) for k, v in env.items()} if env else None,
                tool_allowlist=allowlist,
                headers={str(k): str(v) for k, v in headers.items()} if headers else None,
                cwd=cfg.get("cwd"),
                timeout=int(cfg.get("timeout", 30)),
            ))

        return clients

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
