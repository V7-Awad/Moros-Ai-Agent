#!/usr/bin/env python3
"""
a2a_server.py — Agent-to-Agent (A2A) Interoperability Protocol for Moros AI (P2-4).

Provides:
- `A2AAgentCard`: `build_agent_card(base_url)` returning `/.well-known/agent.json`
  compliant metadata describing Moros capabilities and registered skills.
- `A2ATaskHandler`: JSON-RPC 2.0 dispatcher implementing `tasks/send`, `tasks/get`,
  and `tasks/cancel` with RBAC scope permissions and ScopeValidator target checks.
"""

import hmac
import json
import logging
import threading
import urllib.parse
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

try:
    from scope_validator import ScopeValidator
    from skill_registry import SkillRegistry
except ImportError:
    from tools.scope_validator import ScopeValidator
    from tools.skill_registry import SkillRegistry

logger = logging.getLogger("a2a-server")

JSONRPC_VERSION = "2.0"
A2A_PROTOCOL_VERSION = "0.2.1"

# Standard JSON-RPC 2.0 and A2A error codes
ERR_PARSE = -32700
ERR_INVALID_REQUEST = -32600
ERR_METHOD_NOT_FOUND = -32601
ERR_INVALID_PARAMS = -32602
ERR_INTERNAL = -32603
ERR_TASK_NOT_FOUND = -32001
ERR_TASK_NOT_CANCELABLE = -32002
ERR_PERMISSION_DENIED = -32003
ERR_SCOPE_VIOLATION = -32004

TERMINAL_TASK_STATES = {"completed", "failed", "canceled"}

METHOD_REQUIRED_PERMISSIONS: Dict[str, Set[str]] = {
    "tasks/send": {"tasks:write", "tasks:send", "scan:execute", "*"},
    "tasks/get": {"tasks:read", "tasks:get", "tasks:write", "*"},
    "tasks/cancel": {"tasks:cancel", "tasks:write", "*"},
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _validate_base_url(base_url: str) -> str:
    raw = (base_url or "").strip()
    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc or not parsed.hostname:
        raise ValueError(f"Invalid A2A base_url (must be http/https): {base_url!r}")
    return raw.rstrip("/")


class _DualBindMethod:
    """Allow `build_agent_card` to be called on either A2AAgentCard class or instance."""

    def __init__(self, func: Callable[..., Dict[str, Any]]):
        self._func = func

    def __get__(self, instance: Any, owner: Any = None) -> Callable[..., Dict[str, Any]]:
        target = instance if instance is not None else owner()
        return self._func.__get__(target, owner)


class A2AAgentCard:
    """Builds `/.well-known/agent.json` A2A Agent Card metadata for Moros AI."""

    def __init__(
        self,
        skill_registry: Optional[SkillRegistry] = None,
        name: str = "Moros AI",
        description: str = "Autonomous offensive web security assessment and verification agent.",
        version: str = "1.0.0",
        auth_schemes: Optional[List[str]] = None,
    ):
        self.skill_registry = skill_registry or SkillRegistry()
        self.name = name
        self.description = description
        self.version = version
        self.auth_schemes = auth_schemes or ["Bearer"]

    @_DualBindMethod
    def build_agent_card(
        self,
        base_url: str,
        skills_filter: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Return a `/.well-known/agent.json` compliant A2A Agent Card dict."""
        normalized_url = _validate_base_url(base_url)
        registered_skills = self.skill_registry.list_skills()
        allowed_set = set(skills_filter) if skills_filter is not None else None

        a2a_skills: List[Dict[str, Any]] = []
        for s in registered_skills:
            sid = s.get("id", "")
            if not sid:
                continue
            if allowed_set is not None and sid not in allowed_set:
                continue
            category = s.get("category", "Security Assessment")
            a2a_skills.append({
                "id": sid,
                "name": s.get("title", sid),
                "description": s.get("description", ""),
                "tags": [category.lower().replace(" ", "-"), "security", "moros"],
                "examples": [f"Run {sid} against authorized target example.com"],
                "inputModes": ["text/plain", "application/json"],
                "outputModes": ["application/json", "text/markdown"],
            })

        return {
            "name": self.name,
            "description": self.description,
            "url": normalized_url,
            "version": self.version,
            "protocolVersion": A2A_PROTOCOL_VERSION,
            "provider": {
                "organization": "Moros AI",
                "url": normalized_url,
            },
            "documentationUrl": f"{normalized_url}/docs",
            "capabilities": {
                "streaming": False,
                "pushNotifications": False,
                "stateTransitionHistory": True,
            },
            "authentication": {
                "schemes": list(self.auth_schemes),
            },
            "defaultInputModes": ["text/plain", "application/json"],
            "defaultOutputModes": ["application/json", "text/markdown"],
            "skills": a2a_skills,
        }


def build_agent_card(base_url: str, skill_registry: Optional[SkillRegistry] = None) -> Dict[str, Any]:
    """Convenience function returning Moros A2A `/.well-known/agent.json` metadata."""
    return A2AAgentCard(skill_registry=skill_registry).build_agent_card(base_url)


class A2ATaskHandler:
    """
    JSON-RPC 2.0 dispatcher for A2A tasks (`tasks/send`, `tasks/get`, `tasks/cancel`)
    with scoped RBAC permissions, target scope validation, and skill allowlists.
    """

    def __init__(
        self,
        scope_validator: Optional[ScopeValidator] = None,
        api_tokens: Optional[Dict[str, List[str]]] = None,
        require_auth: bool = False,
        allowed_skills: Optional[List[str]] = None,
        task_executor: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        storage_path: Optional[Path] = None,
    ):
        self.scope_validator = scope_validator
        self._api_tokens = {
            tok: list(perms) for tok, perms in (api_tokens or {}).items()
        }
        self.require_auth = bool(require_auth or bool(self._api_tokens))
        self.allowed_skills = set(allowed_skills) if allowed_skills is not None else None
        self.task_executor = task_executor
        self.storage_path = Path(storage_path).resolve() if storage_path else None
        self._tasks: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

        if self.storage_path and self.storage_path.is_file():
            self._load_tasks()

    def _load_tasks(self) -> None:
        try:
            data = json.loads(self.storage_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                self._tasks = data
        except (OSError, json.JSONDecodeError):
            self._tasks = {}

    def _persist_tasks(self) -> None:
        if not self.storage_path:
            return
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.storage_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self._tasks, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self.storage_path)

    @staticmethod
    def _error_response(req_id: Any, code: int, message: str, data: Any = None) -> Dict[str, Any]:
        err: Dict[str, Any] = {"code": code, "message": message}
        if data is not None:
            err["data"] = data
        return {"jsonrpc": JSONRPC_VERSION, "id": req_id, "error": err}

    @staticmethod
    def _ok_response(req_id: Any, result: Any) -> Dict[str, Any]:
        return {"jsonrpc": JSONRPC_VERSION, "id": req_id, "result": result}

    def _resolve_auth_context(
        self,
        auth_context: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Optional[Dict[str, Any]]:
        if auth_context is not None:
            return auth_context

        if headers:
            auth_header = ""
            for k, v in headers.items():
                if k.lower() == "authorization":
                    auth_header = v.strip()
                    break
            if auth_header.lower().startswith("bearer "):
                token = auth_header[7:].strip()
                for configured_token, perms in self._api_tokens.items():
                    if hmac.compare_digest(token, configured_token):
                        return {
                            "principal": f"token:{configured_token[:6]}",
                            "permissions": list(perms),
                        }
                return {"principal": "anonymous", "permissions": [], "_invalid_token": True}

        if self.require_auth:
            return {"principal": "anonymous", "permissions": [], "_missing_auth": True}
        return None

    def _authorize_method(
        self,
        method: str,
        resolved_auth: Optional[Dict[str, Any]],
    ) -> Optional[str]:
        if resolved_auth is None:
            return None
        if resolved_auth.get("_invalid_token"):
            return "Invalid bearer token"
        if resolved_auth.get("_missing_auth"):
            return "Authentication required"

        granted = set(resolved_auth.get("permissions") or [])
        required = METHOD_REQUIRED_PERMISSIONS.get(method, set())
        if not (granted & required):
            return f"Missing required permission for '{method}' (requires one of {sorted(required)})"
        return None

    @staticmethod
    def _extract_task_target_and_skills(params: Dict[str, Any]) -> Dict[str, Any]:
        metadata = params.get("metadata") if isinstance(params.get("metadata"), dict) else {}
        target = metadata.get("target")
        skills = metadata.get("skills")

        message = params.get("message") if isinstance(params.get("message"), dict) else {}
        for part in message.get("parts", []) if isinstance(message.get("parts"), list) else []:
            if isinstance(part, dict) and part.get("type") == "data" and isinstance(part.get("data"), dict):
                data = part["data"]
                if not target and data.get("target"):
                    target = data.get("target")
                if not skills and data.get("skills"):
                    skills = data.get("skills")

        if isinstance(skills, str):
            skills = [s.strip() for s in skills.split(",") if s.strip()]
        elif not isinstance(skills, list):
            skills = []

        return {"target": target, "skills": skills}

    def _validate_task_scope(
        self,
        target: Optional[str],
        skills: List[str],
        resolved_auth: Optional[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        # Check target against auth_context allowed_targets and ScopeValidator
        if resolved_auth:
            allowed_targets = resolved_auth.get("allowed_targets")
            if allowed_targets is not None:
                if not target or str(target).lower() not in {t.lower() for t in allowed_targets}:
                    return {
                        "code": ERR_SCOPE_VIOLATION,
                        "message": f"Target '{target}' is not in caller's allowed_targets",
                    }

            caller_skills = resolved_auth.get("allowed_skills")
            if caller_skills is not None:
                disallowed = [s for s in skills if s not in set(caller_skills)]
                if disallowed:
                    return {
                        "code": ERR_PERMISSION_DENIED,
                        "message": f"Skills not permitted for caller: {disallowed}",
                    }

        if self.allowed_skills is not None and skills:
            disallowed = [s for s in skills if s not in self.allowed_skills]
            if disallowed:
                return {
                    "code": ERR_PERMISSION_DENIED,
                    "message": f"Skills not permitted by A2A handler policy: {disallowed}",
                }

        if self.scope_validator is not None:
            if not target or not isinstance(target, str) or not target.strip():
                return {
                    "code": ERR_SCOPE_VIOLATION,
                    "message": "Target is required when ScopeValidator is active",
                }
            allowed, reason = self.scope_validator.is_allowed(target.strip())
            if not allowed:
                return {
                    "code": ERR_SCOPE_VIOLATION,
                    "message": f"Target scope violation: {reason}",
                }

        return None

    def handle_json(
        self,
        raw_body: str,
        auth_context: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Parse a raw JSON string and dispatch the JSON-RPC 2.0 request."""
        try:
            payload = json.loads(raw_body)
        except json.JSONDecodeError as exc:
            return self._error_response(None, ERR_PARSE, f"Parse error: {exc}")
        return self.handle_request(payload, auth_context=auth_context, headers=headers)

    def handle_request(
        self,
        request: Dict[str, Any],
        auth_context: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Dispatch a parsed JSON-RPC 2.0 request dict."""
        if not isinstance(request, dict):
            return self._error_response(None, ERR_INVALID_REQUEST, "Request must be a JSON object")

        req_id = request.get("id")
        if request.get("jsonrpc") != JSONRPC_VERSION or not isinstance(request.get("method"), str):
            return self._error_response(req_id, ERR_INVALID_REQUEST, "Invalid JSON-RPC 2.0 request")

        method = request["method"]
        params = request.get("params")
        if params is None:
            params = {}
        if not isinstance(params, dict):
            return self._error_response(req_id, ERR_INVALID_PARAMS, "Params must be an object")

        if method not in METHOD_REQUIRED_PERMISSIONS:
            return self._error_response(req_id, ERR_METHOD_NOT_FOUND, f"Method not found: {method}")

        resolved_auth = self._resolve_auth_context(auth_context=auth_context, headers=headers)
        auth_err = self._authorize_method(method, resolved_auth)
        if auth_err:
            return self._error_response(req_id, ERR_PERMISSION_DENIED, auth_err)

        if method == "tasks/send":
            return self._handle_tasks_send(req_id, params, resolved_auth)
        if method == "tasks/get":
            return self._handle_tasks_get(req_id, params, resolved_auth)
        if method == "tasks/cancel":
            return self._handle_tasks_cancel(req_id, params, resolved_auth)
        return self._error_response(req_id, ERR_METHOD_NOT_FOUND, f"Method not found: {method}")

    def _handle_tasks_send(
        self,
        req_id: Any,
        params: Dict[str, Any],
        resolved_auth: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        message = params.get("message")
        if not isinstance(message, dict) or not isinstance(message.get("parts"), list) or not message["parts"]:
            return self._error_response(
                req_id,
                ERR_INVALID_PARAMS,
                "tasks/send requires params.message with non-empty parts list",
            )

        extracted = self._extract_task_target_and_skills(params)
        scope_err = self._validate_task_scope(
            extracted["target"],
            extracted["skills"],
            resolved_auth,
        )
        if scope_err:
            return self._error_response(req_id, scope_err["code"], scope_err["message"])

        task_id = str(params.get("id") or f"task-{uuid.uuid4().hex[:12]}")
        session_id = str(params.get("sessionId") or f"sess-{uuid.uuid4().hex[:10]}")
        principal = (resolved_auth or {}).get("principal", "default")
        now_iso = _now_iso()

        with self._lock:
            existing = self._tasks.get(task_id)
            if existing:
                if existing.get("owner") != principal and principal != "default":
                    return self._error_response(req_id, ERR_PERMISSION_DENIED, "Task owned by another principal")
                if existing["status"]["state"] in TERMINAL_TASK_STATES:
                    return self._error_response(
                        req_id,
                        ERR_TASK_NOT_CANCELABLE,
                        f"Cannot send message to task in terminal state '{existing['status']['state']}'",
                    )
                existing["history"].append(message)
                existing["status"] = {"state": "working", "timestamp": now_iso}
                task = existing
            else:
                task = {
                    "id": task_id,
                    "sessionId": session_id,
                    "owner": principal,
                    "status": {"state": "submitted", "timestamp": now_iso},
                    "history": [message],
                    "artifacts": [],
                    "metadata": {
                        **(params.get("metadata") if isinstance(params.get("metadata"), dict) else {}),
                        "target": extracted["target"],
                        "skills": extracted["skills"],
                    },
                }
                self._tasks[task_id] = task

            if self.task_executor is not None:
                try:
                    exec_out = self.task_executor(dict(task))
                    if isinstance(exec_out, dict):
                        new_state = exec_out.get("state", "completed")
                        task["status"] = {
                            "state": new_state,
                            "timestamp": _now_iso(),
                            **({"message": exec_out["message"]} if "message" in exec_out else {}),
                        }
                        if isinstance(exec_out.get("artifacts"), list):
                            task["artifacts"].extend(exec_out["artifacts"])
                except Exception as exc:
                    task["status"] = {
                        "state": "failed",
                        "timestamp": _now_iso(),
                        "message": {"role": "agent", "parts": [{"type": "text", "text": str(exc)}]},
                    }

            self._persist_tasks()
            result = self._public_task(task)

        return self._ok_response(req_id, result)

    def _handle_tasks_get(
        self,
        req_id: Any,
        params: Dict[str, Any],
        resolved_auth: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        task_id = params.get("id")
        if not task_id or not isinstance(task_id, str):
            return self._error_response(req_id, ERR_INVALID_PARAMS, "tasks/get requires string params.id")

        history_length = params.get("historyLength")
        if history_length is not None and (not isinstance(history_length, int) or history_length < 0):
            return self._error_response(req_id, ERR_INVALID_PARAMS, "historyLength must be a non-negative integer")

        principal = (resolved_auth or {}).get("principal", "default")
        with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                return self._error_response(req_id, ERR_TASK_NOT_FOUND, f"Task not found: {task_id}")
            if resolved_auth is not None and "*" not in (resolved_auth.get("permissions") or []):
                if task.get("owner") not in (principal, "default"):
                    return self._error_response(req_id, ERR_PERMISSION_DENIED, "Task owned by another principal")
            result = self._public_task(task, history_length=history_length)

        return self._ok_response(req_id, result)

    def _handle_tasks_cancel(
        self,
        req_id: Any,
        params: Dict[str, Any],
        resolved_auth: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        task_id = params.get("id")
        if not task_id or not isinstance(task_id, str):
            return self._error_response(req_id, ERR_INVALID_PARAMS, "tasks/cancel requires string params.id")

        principal = (resolved_auth or {}).get("principal", "default")
        with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                return self._error_response(req_id, ERR_TASK_NOT_FOUND, f"Task not found: {task_id}")
            if resolved_auth is not None and "*" not in (resolved_auth.get("permissions") or []):
                if task.get("owner") not in (principal, "default"):
                    return self._error_response(req_id, ERR_PERMISSION_DENIED, "Task owned by another principal")
            if task["status"]["state"] in TERMINAL_TASK_STATES:
                return self._error_response(
                    req_id,
                    ERR_TASK_NOT_CANCELABLE,
                    f"Task '{task_id}' is already in terminal state '{task['status']['state']}'",
                )
            task["status"] = {"state": "canceled", "timestamp": _now_iso()}
            self._persist_tasks()
            result = self._public_task(task)

        return self._ok_response(req_id, result)

    @staticmethod
    def _public_task(task: Dict[str, Any], history_length: Optional[int] = None) -> Dict[str, Any]:
        history = list(task.get("history", []))
        if history_length is not None:
            history = history[-history_length:] if history_length > 0 else []
        return {
            "id": task["id"],
            "sessionId": task["sessionId"],
            "status": dict(task["status"]),
            "history": history,
            "artifacts": list(task.get("artifacts", [])),
            "metadata": dict(task.get("metadata", {})),
        }


def make_a2a_http_handler(
    agent_card: A2AAgentCard,
    task_handler: A2ATaskHandler,
    base_url: str,
):
    """Create a BaseHTTPRequestHandler subclass serving `/.well-known/agent.json` and JSON-RPC POST."""

    class _A2ARequestHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def _send_json(self, data: Dict[str, Any], status: int = 200) -> None:
            body = json.dumps(data, indent=2).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if urllib.parse.urlparse(self.path).path == "/.well-known/agent.json":
                self._send_json(agent_card.build_agent_card(base_url))
                return
            self._send_json({"error": "Not Found"}, status=404)

        def do_POST(self):
            try:
                length = int(self.headers.get("Content-Length", 0))
            except (TypeError, ValueError):
                self._send_json(A2ATaskHandler._error_response(None, ERR_INVALID_REQUEST, "Invalid Content-Length"), 400)
                return
            if length < 0 or length > 1_000_000:
                self._send_json(A2ATaskHandler._error_response(None, ERR_INVALID_REQUEST, "Payload too large"), 413)
                return
            raw = self.rfile.read(length).decode("utf-8", errors="replace")
            headers = {k: v for k, v in self.headers.items()}
            resp = task_handler.handle_json(raw, headers=headers)
            self._send_json(resp, status=200)

    return _A2ARequestHandler
