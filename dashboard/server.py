#!/usr/bin/env python3
"""
Moros AI Agent — Web Dashboard Server
Native Moros AI operations center and real-time security telemetry viewer.

Provides a local web server and REST API for:
- Managing assessment targets & scope compliance
- Monitoring multi-agent skill coordination in real-time
- Inspecting security findings, PoC curl commands, and evidence
- Handling human-in-the-loop (HITL) checkpoint approvals
- Streaming live tool logs & terminal output
- Viewing and exporting conglomerated penetration testing reports
"""

import hmac
import json
import logging
import math
import mimetypes
import os
import re
import secrets
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict, deque
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Any, Dict, Optional, Tuple

PROJECT_ROOT = Path(__file__).parent.parent.resolve()
STATIC_DIR = Path(__file__).parent / "static"
TARGETS_DIR = PROJECT_ROOT / "targets"
SKILLS_DIR = PROJECT_ROOT / "skills"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools.conversation_store import ConversationStore, safe_agent_name
from tools.llm_client import LLMClient, redact_secrets
from tools.checkpoint_manager import CheckpointManager
from tools.run_manager import RunManager
from tools.skill_registry import SkillRegistry
from tools.finding_dedupe import deduplicate_findings, finding_identity

logger = logging.getLogger(__name__)

# In-memory scan manager
active_scans = {}  # target -> {thread, status, logs, start_time, pid}
active_scans_lock = threading.Lock()

# In-memory runtime state for LLM connectivity
llm_runtime_state = {
    "configured": False,
    "tested": False,
    "model_responding": False,
    "status": "offline",  # "offline", "configured", "tested", "connected", "error"
    "last_tested": None,
    "last_error": None,
    "active_model": None,
}
llm_runtime_lock = threading.Lock()


def _has_newline(value) -> bool:
    """Return True if a value contains CR, LF, or NUL bytes that could inject lines."""
    if value is None:
        return False
    text = str(value)
    return "\r" in text or "\n" in text or "\x00" in text


def _is_loopback_host(host: str) -> bool:
    """Return True if the bind host resolves to a loopback interface."""
    cleaned = (host or "").strip().lower().strip("[]")
    return cleaned in {"127.0.0.1", "localhost", "::1"}


def _close_learning_engine(engine) -> None:
    """Close LearningEngine SQLite connection if opened."""
    if engine is None:
        return
    close_fn = getattr(engine, "close", None)
    if callable(close_fn):
        close_fn()
    elif getattr(engine, "db", None) is not None:
        engine.db.close()


def is_valid_http_url(value) -> bool:
    """Validate an http:// or https:// base URL without newlines."""
    if not isinstance(value, str) or _has_newline(value):
        return False
    try:
        parsed = urllib.parse.urlsplit(value.strip())
        return parsed.scheme.lower() in {"http", "https"} and bool(parsed.netloc) and bool(parsed.hostname)
    except (TypeError, ValueError):
        return False


def is_valid_discord_webhook_url(value):
    if not isinstance(value, str) or _has_newline(value):
        return False
    try:
        parsed = urllib.parse.urlsplit(value)
        return (
            parsed.scheme == "https"
            and parsed.hostname in {"discord.com", "discordapp.com"}
            and parsed.port in (None, 443)
            and not parsed.username
            and not parsed.password
            and not parsed.query
            and not parsed.fragment
            and re.fullmatch(r"/api/webhooks/\d+/[A-Za-z0-9._-]+", parsed.path) is not None
        )
    except (TypeError, ValueError):
        return False


def is_valid_slack_webhook_url(value):
    if not isinstance(value, str) or _has_newline(value):
        return False
    try:
        parsed = urllib.parse.urlsplit(value)
        return (
            parsed.scheme == "https"
            and parsed.hostname == "hooks.slack.com"
            and parsed.port in (None, 443)
            and not parsed.username
            and not parsed.password
            and not parsed.query
            and not parsed.fragment
            and re.fullmatch(r"/(?:services|workflows|triggers)/[A-Za-z0-9._/-]+", parsed.path) is not None
        )
    except (TypeError, ValueError):
        return False


def _safe_source_reference(value, target_name):
    """Return an artifact path without exposing the operator's local workspace path."""
    raw = str(value or "").strip().replace("\\", "/")
    if not raw:
        return ""
    marker = f"/targets/{target_name}/output/"
    offset = raw.casefold().find(marker.casefold())
    if offset >= 0:
        return raw[offset + len(marker):]
    if re.match(r"^[A-Za-z]:/", raw) or raw.startswith("/"):
        return Path(raw).name
    return raw.removeprefix("./").lstrip("/")


def send_discord_scan_summary(target, status):
    webhook_url = os.environ.get("DISCORD_WEBHOOK_URL", "").strip()
    if not webhook_url or not is_valid_discord_webhook_url(webhook_url):
        return "not configured"

    report_dir = TARGETS_DIR / target / "output" / "report"
    report_data = {}
    if report_dir.is_dir():
        report_files = sorted(report_dir.glob("hackbot-report-*.json"), key=lambda path: path.stat().st_mtime, reverse=True)
        if report_files:
            try:
                report_data = json.loads(report_files[0].read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                report_data = {}

    summary = report_data.get("summary", {}) if isinstance(report_data, dict) else {}
    findings = report_data.get("findings", []) if isinstance(report_data, dict) else []
    if not isinstance(findings, list):
        findings = []

    lines = [
        "**Moros AI scan finished**",
        f"Target: `{target}`",
        f"Status: `{status}`",
        f"Triage items: {summary.get('triage_items', len(findings))}",
        f"Validated: {summary.get('validated_findings', 0)} · Pending review: {summary.get('unverified_candidates', len(findings))}",
    ]
    if findings:
        lines.append("Top results (titles and severity only):")
        for finding in findings[:8]:
            if not isinstance(finding, dict):
                continue
            title = re.sub(r"[\r\n`*_~|<>]", " ", str(finding.get("title", finding.get("type", "Finding"))))
            severity = re.sub(r"[\r\n`*_~|<>]", " ", str(finding.get("severity", "Unassessed")))
            validation = str(finding.get("validation_status", "unverified"))
            lines.append(f"• {severity[:48]} — {title[:120]} ({validation[:32]})")

    content = "\n".join(lines)
    if len(content) > 1900:
        content = content[:1890] + "..."
    payload = json.dumps({"content": content, "allowed_mentions": {"parse": []}}).encode("utf-8")
    request = urllib.request.Request(
        webhook_url,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "Moros-AI-Scan-Notifier"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            response.read(1)
        return "sent"
    except urllib.error.HTTPError as exc:
        return f"HTTP {exc.code}"
    except Exception:
        return "unavailable"


DEFAULT_RATE_LIMIT_RPM = 600
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


class SlidingWindowRateLimiter:
    """Thread-safe per-client sliding-window rate limiter."""

    def __init__(self, window_seconds: float = 60.0):
        self.window_seconds = max(1.0, float(window_seconds))
        self._buckets: Dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, client_key: str, limit: int, now: Optional[float] = None) -> Tuple[bool, int]:
        """Return (allowed, retry_after_seconds) for a client within the sliding window."""
        if limit <= 0:
            return True, 0
        current = time.monotonic() if now is None else float(now)
        cutoff = current - self.window_seconds
        key = str(client_key or "local")

        with self._lock:
            bucket = self._buckets[key]
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()

            if len(bucket) >= limit:
                oldest = bucket[0]
                retry_after = max(1, int(math.ceil((oldest + self.window_seconds) - current)))
                return False, retry_after

            bucket.append(current)

            if len(self._buckets) > 1024:
                stale_keys = [
                    k for k, q in self._buckets.items()
                    if k != key and (not q or q[-1] <= cutoff)
                ]
                for k in stale_keys:
                    del self._buckets[k]

            return True, 0

    def reset(self) -> None:
        """Clear all recorded request timestamps."""
        with self._lock:
            self._buckets.clear()


_FALLBACK_RATE_LIMITER = SlidingWindowRateLimiter()
_SERVER_LIMITER_LOCK = threading.Lock()


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, *args, rate_limit_rpm: Optional[int] = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.rate_limit_rpm = rate_limit_rpm
        self.is_tls = False
        self._rate_limiter = SlidingWindowRateLimiter()


class DashboardHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Mute standard noisy HTTP logging, keep terminal clean
        pass

    def send_json(self, data, status=200, headers: Optional[Dict[str, str]] = None):
        body = json.dumps(data, indent=2, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        if headers:
            for k, v in headers.items():
                self.send_header(str(k), str(v))
        self.end_headers()
        self.wfile.write(body)

    def send_error_json(self, message, status=400, headers: Optional[Dict[str, str]] = None):
        self.send_json({"error": message, "status": "error"}, status=status, headers=headers)

    def do_OPTIONS(self):
        self.send_error_json("Cross-origin requests are not supported", status=405)

    def _get_header(self, name: str) -> str:
        """Case-insensitive header lookup supporting both HTTPMessage and dict mocks."""
        headers = getattr(self, "headers", None)
        if not headers:
            return ""
        val = headers.get(name)
        if val is not None:
            return str(val).strip()
        target = name.lower()
        for k, v in headers.items():
            if str(k).lower() == target:
                return str(v).strip()
        return ""

    def _get_rate_limiter(self) -> SlidingWindowRateLimiter:
        server_obj = getattr(self, "server", None)
        if server_obj is None:
            return _FALLBACK_RATE_LIMITER
        limiter = getattr(server_obj, "_rate_limiter", None)
        if limiter is None:
            with _SERVER_LIMITER_LOCK:
                limiter = getattr(server_obj, "_rate_limiter", None)
                if limiter is None:
                    limiter = SlidingWindowRateLimiter()
                    try:
                        setattr(server_obj, "_rate_limiter", limiter)
                    except Exception:
                        return _FALLBACK_RATE_LIMITER
        return limiter

    def _get_rate_limit_rpm(self) -> int:
        server_obj = getattr(self, "server", None)
        if server_obj is not None:
            srv_limit = getattr(server_obj, "rate_limit_rpm", None)
            if srv_limit is not None:
                try:
                    return int(srv_limit)
                except (TypeError, ValueError):
                    pass
        env_limit = os.environ.get("MOROS_DASHBOARD_RATE_LIMIT", "").strip()
        if env_limit:
            try:
                return int(env_limit)
            except ValueError:
                logger.warning("Invalid MOROS_DASHBOARD_RATE_LIMIT=%r; using default %d", env_limit, DEFAULT_RATE_LIMIT_RPM)
        return DEFAULT_RATE_LIMIT_RPM

    def _get_client_ip(self) -> str:
        client_addr = getattr(self, "client_address", None)
        if isinstance(client_addr, (tuple, list)) and client_addr:
            return str(client_addr[0])
        return "local"

    def _enforce_rate_limit(self) -> bool:
        """Enforce per-client sliding-window rate limit on /api/ routes."""
        limit = self._get_rate_limit_rpm()
        if limit <= 0:
            return True
        limiter = self._get_rate_limiter()
        allowed, retry_after = limiter.allow(self._get_client_ip(), limit)
        if not allowed:
            self.send_error_json(
                "Rate limit exceeded: too many requests",
                status=429,
                headers={"Retry-After": str(retry_after)},
            )
            return False
        return True

    def _is_tls_request(self) -> bool:
        server_obj = getattr(self, "server", None)
        if server_obj is not None and getattr(server_obj, "is_tls", False):
            return True
        conn = getattr(self, "connection", None)
        return isinstance(conn, ssl.SSLSocket)

    def _get_required_token(self) -> str:
        """Return configured dashboard auth token (server runtime token or MOROS_DASHBOARD_TOKEN)."""
        server_obj = getattr(self, "server", None)
        server_token = getattr(server_obj, "dashboard_token", None) if server_obj is not None else None
        if server_token:
            return str(server_token).strip()
        return os.environ.get("MOROS_DASHBOARD_TOKEN", "").strip()

    def _extract_request_token(self) -> str:
        """Extract token from X-Moros-Token or Authorization: Bearer headers."""
        moros_token = self._get_header("X-Moros-Token")
        if moros_token:
            return moros_token
        auth_header = self._get_header("Authorization")
        if auth_header.lower().startswith("bearer "):
            return auth_header[7:].strip()
        return ""

    def _is_api_authorized(self) -> bool:
        """Validate token for /api/* routes when authentication is enabled."""
        required = self._get_required_token()
        if not required:
            return True
        provided = self._extract_request_token()
        if not provided:
            return False
        return hmac.compare_digest(provided.encode("utf-8"), required.encode("utf-8"))

    @staticmethod
    def _parse_authority(raw_host: str) -> Optional[Tuple[str, Optional[int]]]:
        """Parse an HTTP Host header into (lowercase_hostname, port_or_None)."""
        if not raw_host or any(ch in raw_host for ch in ("/", "\\", "@", "?", "#")):
            return None
        try:
            parsed_host = urllib.parse.urlsplit(f"//{raw_host}")
            host = (parsed_host.hostname or "").lower()
            port = parsed_host.port
        except ValueError:
            return None
        if not host:
            return None
        return host, port

    @staticmethod
    def _parse_origin_url(raw_url: str) -> Optional[Tuple[str, str, int]]:
        """Parse an Origin or Referer URL into (scheme, lowercase_hostname, effective_port)."""
        cleaned = (raw_url or "").strip()
        if not cleaned or cleaned.lower() == "null":
            return None
        try:
            parsed = urllib.parse.urlsplit(cleaned)
        except ValueError:
            return None
        scheme = (parsed.scheme or "").lower()
        if scheme not in {"http", "https"}:
            return None
        host = (parsed.hostname or "").lower()
        if not host:
            return None
        try:
            explicit_port = parsed.port
        except ValueError:
            return None
        effective_port = explicit_port if explicit_port is not None else (443 if scheme == "https" else 80)
        return scheme, host, effective_port

    def _origin_matches_host(self, raw_origin_url: str, raw_host: str) -> bool:
        """Verify that Origin/Referer hostname+port matches Host (or loopback equivalent on same port)."""
        host_parts = self._parse_authority(raw_host)
        origin_parts = self._parse_origin_url(raw_origin_url)
        if host_parts is None or origin_parts is None:
            return False
        host_name, host_port = host_parts
        origin_scheme, origin_host, origin_port = origin_parts

        if host_port is not None:
            if origin_port != host_port:
                return False
        else:
            default_port = 443 if origin_scheme == "https" else 80
            if origin_port != default_port:
                return False

        if origin_host == host_name:
            return True
        if host_name in _LOOPBACK_HOSTS and origin_host in _LOOPBACK_HOSTS:
            return True
        return False

    def _is_csrf_origin_valid(self) -> bool:
        """Validate Origin (or Referer if Origin absent) when present on state-changing requests."""
        origin = self._get_header("Origin")
        referer = self._get_header("Referer") if not origin else ""
        candidate = origin or referer
        if not candidate:
            return True
        raw_host = self._get_header("Host")
        return self._origin_matches_host(candidate, raw_host)

    def _is_local_browser_request(self):
        raw_host = self._get_header("Host")
        host_parts = self._parse_authority(raw_host)
        if host_parts is None:
            return False
        host, _ = host_parts
        if host not in _LOOPBACK_HOSTS:
            return False
        origin = self._get_header("Origin")
        if origin and not self._origin_matches_host(origin, raw_host):
            return False
        return True

    def _is_request_host_allowed(self) -> bool:
        """Allow loopback browser requests, or matching-origin requests when bound remotely with auth."""
        server_obj = getattr(self, "server", None)
        allow_remote = bool(getattr(server_obj, "allow_remote", False)) if server_obj is not None else False
        if not allow_remote:
            return self._is_local_browser_request()
        raw_host = self._get_header("Host")
        if self._parse_authority(raw_host) is None:
            return False
        origin = self._get_header("Origin")
        if origin and not self._origin_matches_host(origin, raw_host):
            return False
        return True

    def do_GET(self):
        if not self._is_request_host_allowed():
            origin = self._get_header("Origin")
            if origin and not self._origin_matches_host(origin, self._get_header("Host")):
                self.send_error_json("Cross-origin request blocked", status=403)
            else:
                self.send_error_json("Dashboard is restricted to local browser requests", status=403)
            return
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # A2A AgentCard endpoint
        if path == "/.well-known/agent.json":
            try:
                from tools.a2a_server import build_agent_card
                host = self._get_header("Host") or "127.0.0.1:8080"
                scheme = "https" if self._is_tls_request() else "http"
                self.send_json(build_agent_card(f"{scheme}://{host}"))
            except Exception as exc:
                self.send_json({"error": str(exc)}, status=500)
            return

        # REST API Endpoints
        if path.startswith("/api/"):
            if not self._enforce_rate_limit():
                return
            if not self._is_api_authorized():
                self.send_error_json("Unauthorized: valid dashboard token required", status=401)
                return
            self.handle_api_get(path, query)
            return

        # Static file serving
        self.handle_static_get(path)

    def _prepare_state_changing_request(self) -> Optional[str]:
        """Run CSRF origin, host, rate-limit, and token auth checks for POST/PUT/DELETE."""
        if not self._is_csrf_origin_valid():
            self.send_error_json("Cross-origin request blocked", status=403)
            return None
        if not self._is_request_host_allowed():
            self.send_error_json("Dashboard is restricted to local browser requests", status=403)
            return None
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path.startswith("/api/"):
            if not self._enforce_rate_limit():
                return None
            if not self._is_api_authorized():
                self.send_error_json("Unauthorized: valid dashboard token required", status=401)
                return None
        return path

    def do_POST(self):
        path = self._prepare_state_changing_request()
        if path is None:
            return

        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except (TypeError, ValueError):
            self.send_error_json("Invalid Content-Length", status=400)
            return
        if content_length < 0 or content_length > 1_000_000:
            self.send_error_json("Request body is too large", status=413)
            return
        body_bytes = self.rfile.read(content_length) if content_length > 0 else b"{}"

        try:
            body_json = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
        except (UnicodeDecodeError, json.JSONDecodeError):
            self.send_error_json("Invalid JSON request body", status=400)
            return

        if not isinstance(body_json, dict):
            self.send_error_json("JSON request body must be an object", status=400)
            return

        if path.startswith("/api/"):
            self.handle_api_post(path, body_json)
            return

        self.send_error_json("Not Found", status=404)

    def do_PUT(self):
        if self._prepare_state_changing_request() is None:
            return
        self.send_error_json("Method not allowed", status=405)

    def do_DELETE(self):
        if self._prepare_state_changing_request() is None:
            return
        self.send_error_json("Method not allowed", status=405)

    def handle_static_get(self, path):
        static_root = STATIC_DIR.resolve()
        if path in ["", "/", "/index.html"]:
            file_path = static_root / "index.html"
        else:
            rel = path.lstrip("/")
            file_path = (static_root / rel).resolve()
            if not file_path.is_relative_to(static_root):
                self.send_error_json("Forbidden", status=403)
                return

        if not file_path.exists() or not file_path.is_file():
            # Fallback to index.html for SPA client-side routing
            file_path = static_root / "index.html"

        mime, _ = mimetypes.guess_type(str(file_path))
        mime = mime or "application/octet-stream"

        try:
            data = file_path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except Exception:
            logger.exception("Error reading static file %s", file_path)
            self.send_error_json("Error reading static file", status=500)

    # ==================== API HANDLERS ====================

    def handle_api_get(self, path, query):
        # 1. System info / prereq
        if path == "/api/system":
            self.send_json(self.get_system_info())
            return

        # 2. List all targets
        if path == "/api/targets":
            self.send_json(self.get_targets_list())
            return

        # 3. Available skills list
        if path == "/api/skills":
            self.send_json(self.get_skills_meta())
            return

        # 4. Target specific endpoints: /api/targets/{target}/...
        target_match = re.match(r"^/api/targets/([^/]+)/?(.*)$", path)
        if target_match:
            target_name = urllib.parse.unquote(target_match.group(1))
            sub = target_match.group(2)

            try:
                from setup import validate_target_name
                validate_target_name(target_name)
            except ValueError:
                self.send_error_json("Invalid target name", status=400)
                return

            target_path = TARGETS_DIR / target_name
            if not target_path.exists():
                self.send_error_json(f"Target '{target_name}' not found", status=404)
                return

            if sub in ["", "summary"]:
                self.send_json(self.get_target_summary(target_name))
                return
            elif sub == "skills":
                self.send_json(self.get_target_skills_status(target_name))
                return
            elif sub == "findings":
                self.send_json(self.get_target_findings(target_name))
                return
            elif sub == "endpoints":
                self.send_json(self.get_target_endpoints(target_name))
                return
            elif sub == "tech":
                self.send_json(self.get_target_tech_fingerprint(target_name))
                return
            elif sub == "logs":
                self.send_json(self.get_target_logs(target_name, query.get("file", [None])[0]))
                return
            elif sub == "checkpoints":
                self.send_json(self.get_target_checkpoints(target_name))
                return
            elif sub == "runs":
                rm = RunManager(target_path)
                self.send_json({"target": target_name, "runs": rm.list_runs()})
                return
            elif sub.startswith("runs/"):
                rest = sub[5:]
                rm = RunManager(target_path)
                if "/agents" in rest:
                    run_id = rest.split("/agents")[0].strip("/")
                    self.send_json({"run_id": run_id, "agents": rm.list_agent_sessions(run_id)})
                    return
                run_id = rest
                run_data = rm.get_run(run_id)
                if not run_data:
                    self.send_error_json("Run not found", status=404)
                    return
                self.send_json(run_data)
                return
            elif sub == "conversations":
                agent = query.get("agent", ["coordinator"])[0]
                try:
                    limit = int(query.get("limit", [200])[0])
                except (TypeError, ValueError):
                    limit = 200
                store = ConversationStore(target_path)
                messages = store.read(agent, limit)
                messages = self._dashboard_conversation_messages(messages)
                agent_safe = safe_agent_name(agent)
                if not messages:
                    welcome_text = self.get_agent_greeting(target_name, agent_safe)
                    messages = [{
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "agent": agent_safe,
                        "role": "assistant",
                        "content": welcome_text,
                        "source": "greeting"
                    }]
                self.send_json({
                    "target": target_name,
                    "agent": agent_safe,
                    "agents": store.list_agents(),
                    "roster": self.get_subagent_roster(target_name),
                    "messages": messages,
                })
                return
            elif sub == "report":
                self.send_json(self.get_target_report(target_name))
                return
            elif sub == "sarif":
                self.send_json(self.get_target_sarif(target_name))
                return
            elif sub == "costs":
                self.send_json(self.get_target_costs(target_name))
                return
            elif sub == "traces":
                self.send_json(self.get_target_traces(target_name))
                return
            elif sub == "memory":
                self.send_json(self.get_target_memory(target_name))
                return
            elif sub == "schedules":
                try:
                    from tools.scheduler import ScanScheduler
                    sched = ScanScheduler(target=target_name, target_dir=target_path)
                    self.send_json({"target": target_name, "schedules": sched.list_schedules()})
                except Exception as exc:
                    self.send_json({"error": str(exc)}, status=500)
                return
            elif sub == "skill-proposals":
                try:
                    from tools.skill_learner import SkillLearner
                    learner = SkillLearner(target_dir=target_path)
                    self.send_json({"target": target_name, "proposals": learner.list_proposals()})
                except Exception as exc:
                    self.send_json({"error": str(exc)}, status=500)
                return

        # 5. Scan status
        if path == "/api/scan/status":
            target = query.get("target", [None])[0]
            self.send_json(self.get_scan_status(target))
            return

        # 5b. Scan progress SSE stream
        if path == "/api/scan/stream":
            target = query.get("target", [None])[0]
            self.handle_sse_stream(target)
            return

        # 6. Active runs across targets
        if path == "/api/runs/active":
            active_runs = []
            if TARGETS_DIR.exists():
                for td in TARGETS_DIR.iterdir():
                    if td.is_dir():
                        rm = RunManager(td)
                        for r in rm.list_runs():
                            if r.get("status") == "running":
                                active_runs.append(r)
            self.send_json({"active_runs": active_runs})
            return

        # 7. Current LLM configuration
        if path == "/api/config/llm":
            self.send_json(self.get_llm_config())
            return
        if path == "/api/config/notifications":
            self.send_json(self.get_notification_config())
            return

        # 7b. Agentic security posture (OWASP Agentic Top 10 coverage)
        if path == "/api/security/posture":
            try:
                from tools.agent_security import get_security_posture
                self.send_json(get_security_posture())
            except Exception as e:
                self.send_json({"error": str(e)}, status=500)
            return

        # 8. Learning Engine Endpoints
        if path == "/api/learning/stats":
            engine = None
            try:
                from learning_engine.engine import LearningEngine
                engine = LearningEngine()
                self.send_json(engine.distill())
            except Exception:
                logger.exception("Failed to load learning stats")
                self.send_json({"error": "Failed to load learning stats"}, status=500)
            finally:
                _close_learning_engine(engine)
            return

        if path == "/api/learning/recall":
            try:
                limit = int(query.get("limit", [10])[0])
            except (TypeError, ValueError):
                self.send_error_json("Invalid limit parameter", status=400)
                return
            engine = None
            try:
                q = query.get("q", [""])[0]
                from learning_engine.engine import LearningEngine
                engine = LearningEngine()
                self.send_json({"results": engine.recall(q, limit=limit)})
            except Exception:
                logger.exception("Failed to recall learning entries")
                self.send_json({"error": "Failed to recall learning entries"}, status=500)
            finally:
                _close_learning_engine(engine)
            return

        if path == "/api/learning/graph":
            engine = None
            try:
                from learning_engine.engine import LearningEngine
                engine = LearningEngine()
                self.send_json(engine.export_graph())
            except Exception:
                logger.exception("Failed to export learning graph")
                self.send_json({"error": "Failed to export learning graph"}, status=500)
            finally:
                _close_learning_engine(engine)
            return

        self.send_error_json("Unknown API endpoint", status=404)

    def handle_api_post(self, path, body):
        # A2A JSON-RPC Task Handler
        if path == "/api/a2a":
            try:
                from tools.a2a_server import A2ATaskHandler
                from tools.scope_validator import ScopeValidator

                params = body.get("params") if isinstance(body, dict) and isinstance(body.get("params"), dict) else {}
                extracted = A2ATaskHandler._extract_task_target_and_skills(params)
                target_name = extracted.get("target")
                scope_validator = None
                if isinstance(target_name, str) and target_name.strip():
                    clean_target = target_name.strip()
                    t_dir = TARGETS_DIR / clean_target
                    scope_validator = ScopeValidator(
                        clean_target,
                        target_dir=t_dir if t_dir.is_dir() else None,
                    )

                handler = A2ATaskHandler(
                    scope_validator=scope_validator,
                    storage_path=TARGETS_DIR / ".a2a_tasks.json",
                )
                req_headers = {}
                auth_header = self._get_header("Authorization")
                if auth_header:
                    req_headers["Authorization"] = auth_header
                x_token = self._get_header("X-Moros-Token")
                if x_token:
                    req_headers["X-Moros-Token"] = x_token
                resp = handler.handle_request(body, headers=req_headers)
                self.send_json(resp)
            except Exception as exc:
                self.send_json({"error": str(exc)}, status=500)
            return

        # Learning Engine Endpoints
        if path == "/api/learning/finding":
            engine = None
            try:
                from learning_engine.engine import LearningEngine
                engine = LearningEngine()
                res = engine.record_finding(
                    target=body.get("target", "unknown"),
                    vuln_class=body.get("vuln_class", "general"),
                    title=body.get("title", ""),
                    severity=body.get("severity", "medium"),
                    confidence=float(body.get("confidence", 0.5)),
                    evidence=body.get("evidence"),
                    signals=body.get("signals"),
                    source=body.get("source", "dashboard"),
                )
                self.send_json(res)
            except (TypeError, ValueError):
                self.send_error_json("Invalid learning finding payload", status=400)
            except Exception:
                logger.exception("Failed to record learning finding")
                self.send_json({"error": "Failed to record learning finding"}, status=500)
            finally:
                _close_learning_engine(engine)
            return

        if path == "/api/learning/triage":
            engine = None
            try:
                from learning_engine.engine import LearningEngine
                engine = LearningEngine()
                res = engine.record_triage(
                    finding_id=body.get("finding_id", ""),
                    verdict=body.get("verdict", "unverified"),
                    reason=body.get("reason"),
                    reviewer=body.get("reviewer", "dashboard"),
                )
                self.send_json(res)
            except Exception:
                logger.exception("Failed to record learning triage")
                self.send_json({"error": "Failed to record learning triage"}, status=500)
            finally:
                _close_learning_engine(engine)
            return

        if path == "/api/learning/score":
            try:
                from learning_engine.scoring.engine import score
                res = score(body.get("signals", {}))
                self.send_json(res)
            except Exception:
                logger.exception("Failed to score learning signals")
                self.send_json({"error": "Failed to score learning signals"}, status=500)
            return

        # 1. Create target
        if path == "/api/targets/create":
            domain = str(body.get("domain", "")).strip()
            if not domain:
                self.send_error_json("Domain name is required")
                return

            # Invoke setup script to create target folder
            from setup import init_target
            try:
                from setup import validate_target_name
                validate_target_name(domain)
                init_target(domain)
                self.send_json({"status": "success", "message": f"Target {domain} created", "target": domain})
            except ValueError as e:
                self.send_error_json(str(e), status=400)
            except Exception as e:
                self.send_error_json(f"Failed to create target: {e}")
            return

        # 2. Start Scan
        if path == "/api/scan/start":
            target = str(body.get("target", "")).strip()
            skills = body.get("skills", "all")
            models = body.get("models", "default")
            dry_run = body.get("dry_run", False)
            scan_mode = body.get("scan_mode", "quick")

            if not target:
                self.send_error_json("Target is required")
                return

            try:
                from setup import validate_target_name
                validate_target_name(target)
            except ValueError:
                self.send_error_json("Invalid target name", status=400)
                return

            try:
                max_sub = int(body.get("max_subagents", 10))
                res = self.start_scan_job(target, skills, models, dry_run, scan_mode=scan_mode, max_subagents=max_sub)
                self.send_json(res)
            except Exception as exc:
                logger.exception("Failed to enqueue dashboard scan for %s", target)
                self.send_json({"status": "error", "message": f"Could not start scan ({type(exc).__name__})."}, status=500)
            return

        # 3. Stop Scan
        if path == "/api/scan/stop":
            target = str(body.get("target", "")).strip()
            try:
                from setup import validate_target_name
                validate_target_name(target)
            except ValueError:
                self.send_error_json("Invalid target name", status=400)
                return
            res = self.stop_scan_job(target)
            self.send_json(res)
            return

        # 4. Checkpoint approval/rejection
        if path == "/api/checkpoints/action":
            target = str(body.get("target", "")).strip()
            try:
                from setup import validate_target_name
                validate_target_name(target)
            except ValueError:
                self.send_error_json("Invalid target name", status=400)
                return
            checkpoint_id = body.get("checkpoint_id", "")
            action = body.get("action", "")  # "approve" or "reject"
            notes = body.get("notes", "")

            res = self.handle_checkpoint_decision(target, checkpoint_id, action, notes)
            self.send_json(res)
            return

        # 5. Coordinator / sub-agent conversation message
        if path == "/api/conversations/chat":
            target = str(body.get("target", "")).strip()
            agent = safe_agent_name(body.get("agent", "coordinator"))
            message = str(body.get("message", "")).strip()
            if not target or not message:
                self.send_error_json("Target and message are required")
                return
            try:
                from setup import validate_target_name
                validate_target_name(target)
            except ValueError:
                self.send_error_json("Invalid target name", status=400)
                return
            target_path = TARGETS_DIR / target
            if not target_path.is_dir():
                self.send_error_json(f"Target '{target}' not found", status=404)
                return
            if len(message) > 60000:
                self.send_error_json("Message is too long (max 60000 characters)")
                return

            res = self.execute_subagent_chat(target, agent, message)
            self.send_json(res)
            return

        # 6. Save LLM Configuration directly from Dashboard
        if path == "/api/config/llm":
            res = self.save_llm_config(body)
            self.send_json(res, status=200 if res.get("status") == "success" else 400)
            return

        # 7. Test LLM Connection from Dashboard
        if path == "/api/config/llm/test":
            res = self.test_llm_config(body)
            self.send_json(res, status=200 if res.get("status") == "success" else 400)
            return

        if path == "/api/config/notifications":
            res = self.save_notification_config(body)
            self.send_json(res, status=200 if res.get("status") == "success" else 400)
            return

        # 8. Custom Skills Engine: Create Custom Skill
        if path == "/api/skills/create":
            skill_id = str(body.get("id", "")).strip()
            title = str(body.get("title", "")).strip()
            description = str(body.get("description", "")).strip()
            category = str(body.get("category", "Custom Security")).strip()
            checklist = body.get("checklist", [])
            methodology = str(body.get("methodology", "")).strip()
            if not skill_id or not title:
                self.send_error_json("Skill ID and Title are required", status=400)
                return
            try:
                registry = SkillRegistry()
                created = registry.create_custom_skill(
                    skill_id=skill_id,
                    title=title,
                    description=description,
                    category=category,
                    checklist=checklist,
                    methodology=methodology
                )
                self.send_json({"status": "success", "message": f"Custom skill '{skill_id}' registered successfully", "skill": created})
            except Exception as e:
                self.send_error_json(str(e), status=400)
            return

        # 9. Custom Skills Engine: Delete Custom Skill
        if path == "/api/skills/delete":
            skill_id = str(body.get("id", "")).strip()
            if not skill_id:
                self.send_error_json("Skill ID is required", status=400)
                return
            try:
                registry = SkillRegistry()
                success = registry.delete_custom_skill(skill_id)
                if success:
                    self.send_json({"status": "success", "message": f"Skill '{skill_id}' deleted successfully"})
                else:
                    self.send_error_json(f"Skill '{skill_id}' not found", status=404)
            except Exception as e:
                self.send_error_json(str(e), status=400)
            return

        self.send_error_json("Unknown API endpoint", status=404)

    def get_llm_config(self):
        client = LLMClient(provider="auto")
        key = client.api_key or ""
        configured = client.is_available()

        with llm_runtime_lock:
            runtime_snapshot = dict(llm_runtime_state)

        if not configured:
            conn_state = "offline"
            responding = False
        elif runtime_snapshot.get("model_responding"):
            conn_state = "connected"
            responding = True
        elif runtime_snapshot.get("status") == "error":
            conn_state = "error"
            responding = False
        elif runtime_snapshot.get("tested"):
            conn_state = "tested"
            responding = False
        else:
            conn_state = "configured"
            responding = False

        return {
            "provider": client.provider,
            "model": runtime_snapshot.get("active_model") or client.model,
            "base_url": client.base_url or "",
            "is_available": configured,
            "has_api_key": bool(key),
            "connection_state": conn_state,
            "model_responding": responding,
            "last_error": redact_secrets(runtime_snapshot.get("last_error")),
            "last_tested": runtime_snapshot.get("last_tested"),
        }

    def get_notification_config(self):
        return {
            "has_discord_webhook": bool(os.environ.get("DISCORD_WEBHOOK_URL", "").strip()),
            "has_telegram": bool(os.environ.get("TELEGRAM_BOT_TOKEN", "").strip() and os.environ.get("TELEGRAM_CHAT_ID", "").strip()),
            "has_slack_webhook": bool(os.environ.get("SLACK_WEBHOOK_URL", "").strip()),
        }

    def save_notification_config(self, body):
        env_file = PROJECT_ROOT / ".env"
        try:
            lines = env_file.read_text(encoding="utf-8", errors="replace").splitlines() if env_file.is_file() else []
        except OSError:
            logger.exception("Failed to read .env while saving notification settings")
            return {"status": "error", "message": "Could not read notification settings locally."}
        saved = []

        if "discord_webhook_url" in body:
            raw_webhook = body.get("discord_webhook_url")
            if _has_newline(raw_webhook):
                return {"status": "error", "message": "Discord webhook URL must not contain newlines."}
            webhook_url = str(raw_webhook or "").strip()
            lines = [line for line in lines if not line.strip().startswith("DISCORD_WEBHOOK_URL=")]
            if webhook_url:
                if not is_valid_discord_webhook_url(webhook_url):
                    return {"status": "error", "message": "Enter a valid HTTPS Discord webhook URL."}
                lines.append(f"DISCORD_WEBHOOK_URL={webhook_url}")
                os.environ["DISCORD_WEBHOOK_URL"] = webhook_url
                saved.append("Discord")
            else:
                os.environ.pop("DISCORD_WEBHOOK_URL", None)
                saved.append("Discord (cleared)")

        if "telegram_bot_token" in body and "telegram_chat_id" in body:
            raw_token = body.get("telegram_bot_token")
            raw_chat = body.get("telegram_chat_id")
            if _has_newline(raw_token) or _has_newline(raw_chat):
                return {"status": "error", "message": "Telegram settings must not contain newlines."}
            tg_token = str(raw_token or "").strip()
            tg_chat = str(raw_chat or "").strip()
            if tg_token and tg_chat:
                lines = [line for line in lines if not line.strip().startswith(("TELEGRAM_BOT_TOKEN=", "TELEGRAM_CHAT_ID="))]
                lines.append(f"TELEGRAM_BOT_TOKEN={tg_token}")
                lines.append(f"TELEGRAM_CHAT_ID={tg_chat}")
                os.environ["TELEGRAM_BOT_TOKEN"] = tg_token
                os.environ["TELEGRAM_CHAT_ID"] = tg_chat
                saved.append("Telegram")
            elif not tg_token and not tg_chat:
                lines = [line for line in lines if not line.strip().startswith(("TELEGRAM_BOT_TOKEN=", "TELEGRAM_CHAT_ID="))]
                os.environ.pop("TELEGRAM_BOT_TOKEN", None)
                os.environ.pop("TELEGRAM_CHAT_ID", None)
                saved.append("Telegram (cleared)")

        if "slack_webhook_url" in body:
            raw_slack = body.get("slack_webhook_url")
            if _has_newline(raw_slack):
                return {"status": "error", "message": "Slack webhook URL must not contain newlines."}
            slack_url = str(raw_slack or "").strip()
            lines = [line for line in lines if not line.strip().startswith("SLACK_WEBHOOK_URL=")]
            if slack_url:
                if not is_valid_slack_webhook_url(slack_url):
                    return {"status": "error", "message": "Enter a valid HTTPS Slack webhook URL."}
                lines.append(f"SLACK_WEBHOOK_URL={slack_url}")
                os.environ["SLACK_WEBHOOK_URL"] = slack_url
                saved.append("Slack")
            else:
                os.environ.pop("SLACK_WEBHOOK_URL", None)
                saved.append("Slack (cleared)")

        try:
            content = ("\n".join(lines).rstrip() + "\n") if lines else ""
            env_file.write_text(content, encoding="utf-8")
        except OSError:
            logger.exception("Failed to save notification settings")
            return {"status": "error", "message": "Could not save notification settings locally."}

        return {"status": "success", "message": f"Configured alerts: {', '.join(saved) if saved else 'Saved.'}"}

    def save_llm_config(self, body):
        raw_provider = body.get("provider", "openai")
        raw_model = body.get("model", "")
        raw_api_key = body.get("api_key", "")
        raw_base_url = body.get("base_url", "")
        for field_name, raw_val in (
            ("provider", raw_provider),
            ("model", raw_model),
            ("api_key", raw_api_key),
            ("base_url", raw_base_url),
        ):
            if _has_newline(raw_val):
                return {"status": "error", "message": f"Invalid {field_name}: newline characters are not allowed."}

        provider = str(raw_provider or "openai").strip().lower()
        model = str(raw_model or "").strip()
        api_key = str(raw_api_key or "").strip()
        base_url = str(raw_base_url or "").strip()

        if base_url and not is_valid_http_url(base_url):
            return {"status": "error", "message": "Invalid base_url: must be an http:// or https:// URL."}

        env_file = PROJECT_ROOT / ".env"
        env_lines = []
        if env_file.is_file():
            try:
                env_lines = env_file.read_text(encoding="utf-8", errors="replace").splitlines()
            except Exception:
                pass

        env_dict = {}
        for line in env_lines:
            line_str = line.strip()
            if line_str and not line_str.startswith("#") and "=" in line_str:
                k, v = line_str.split("=", 1)
                clean_k = k.strip()
                clean_v = v.strip().strip('"').strip("'")
                if clean_k and not _has_newline(clean_k) and not _has_newline(clean_v):
                    env_dict[clean_k] = clean_v

        # Map according to provider
        env_dict["MOROS_LLM_PROVIDER"] = provider
        if provider == "deepseek":
            if api_key:
                env_dict["DEEPSEEK_API_KEY"] = api_key
            env_dict["DEEPSEEK_MODEL"] = model or "deepseek-chat"
        elif provider == "groq":
            if api_key:
                env_dict["GROQ_API_KEY"] = api_key
            env_dict["GROQ_MODEL"] = model or "llama-3.3-70b-versatile"
        elif provider == "anthropic":
            if api_key:
                env_dict["ANTHROPIC_API_KEY"] = api_key
            env_dict["ANTHROPIC_MODEL"] = model or "claude-3-5-sonnet-20241022"
        elif provider == "gemini":
            if api_key:
                env_dict["GEMINI_API_KEY"] = api_key
            env_dict["GEMINI_MODEL"] = model or "gemini-3.8-flash"
        elif provider == "openrouter":
            if api_key:
                env_dict["OPENROUTER_API_KEY"] = api_key
            env_dict["OPENROUTER_MODEL"] = model or "meta-llama/llama-3.1-8b-instruct"
        elif provider in ["xai", "grok"]:
            if api_key:
                env_dict["XAI_API_KEY"] = api_key
            env_dict["XAI_MODEL"] = model or "grok-2-latest"
        elif provider == "mistral":
            if api_key:
                env_dict["MISTRAL_API_KEY"] = api_key
            env_dict["MISTRAL_MODEL"] = model or "mistral-large-latest"
        elif provider == "together":
            if api_key:
                env_dict["TOGETHER_API_KEY"] = api_key
            env_dict["TOGETHER_MODEL"] = model or "meta-llama/Llama-3.3-70B-Instruct-Turbo"
        elif provider == "cerebras":
            if api_key:
                env_dict["CEREBRAS_API_KEY"] = api_key
            env_dict["CEREBRAS_MODEL"] = model or "llama3.3-70b"
        elif provider == "sambanova":
            if api_key:
                env_dict["SAMBANOVA_API_KEY"] = api_key
            env_dict["SAMBANOVA_MODEL"] = model or "Meta-Llama-3.3-70B-Instruct"
        elif provider == "fireworks":
            if api_key:
                env_dict["FIREWORKS_API_KEY"] = api_key
            env_dict["FIREWORKS_MODEL"] = model or "accounts/fireworks/models/llama-v3p3-70b-instruct"
        elif provider == "perplexity":
            if api_key:
                env_dict["PERPLEXITY_API_KEY"] = api_key
            env_dict["PERPLEXITY_MODEL"] = model or "sonar-pro"
        elif provider == "cohere":
            if api_key:
                env_dict["COHERE_API_KEY"] = api_key
            env_dict["COHERE_MODEL"] = model or "command-r-plus"
        elif provider == "ollama":
            env_dict["OLLAMA_BASE_URL"] = base_url or "http://localhost:11434"
            env_dict["OLLAMA_MODEL"] = model or "llama3"
        elif provider == "custom" or base_url:
            if base_url:
                env_dict["OPENAI_BASE_URL"] = base_url
            if api_key:
                env_dict["OPENAI_API_KEY"] = api_key
            env_dict["OPENAI_MODEL"] = model or "default"
        else:  # standard openai or any other provider
            if api_key:
                env_dict["OPENAI_API_KEY"] = api_key
            env_dict["OPENAI_MODEL"] = model or "gpt-4o-mini"
            if base_url:
                env_dict["OPENAI_BASE_URL"] = base_url

        # Apply to live os.environ
        for k, v in env_dict.items():
            os.environ[k] = v

        # Write back to .env
        out_content = "# Moros AI Environment Configuration (Saved from Dashboard)\n"
        for k, v in env_dict.items():
            out_content += f"{k}={v}\n"
        try:
            env_file.write_text(out_content, encoding="utf-8")
        except OSError:
            logger.exception("Failed to write LLM configuration to .env")
            return {"status": "error", "message": "Could not save LLM configuration locally."}

        # Reset runtime state to reflect newly configured credentials
        has_key = bool(api_key or (provider == "ollama"))
        with llm_runtime_lock:
            llm_runtime_state["configured"] = has_key
            llm_runtime_state["model_responding"] = False
            llm_runtime_state["tested"] = False
            llm_runtime_state["status"] = "configured" if has_key else "offline"
            llm_runtime_state["last_error"] = None
            llm_runtime_state["active_model"] = model

        return {
            "status": "success",
            "message": "LLM configuration saved to .env and activated successfully",
            "config": self.get_llm_config()
        }

    def test_llm_config(self, body):
        raw_base_url = body.get("base_url", "")
        if _has_newline(raw_base_url):
            return {
                "status": "error",
                "message": "Invalid base_url: newline characters are not allowed.",
                "connection_state": "error",
                "model_responding": False,
            }
        provider = str(body.get("provider", "")).strip().lower() or None
        model = str(body.get("model", "")).strip() or None
        api_key = str(body.get("api_key", "")).strip() or None
        base_url = str(raw_base_url or "").strip() or None

        if base_url and not is_valid_http_url(base_url):
            return {
                "status": "error",
                "message": "Invalid base_url: must be an http:// or https:// URL.",
                "connection_state": "error",
                "model_responding": False,
            }

        try:
            client = LLMClient(provider=provider or "auto", model=model, api_key=api_key, base_url=base_url)
            if not client.is_available():
                with llm_runtime_lock:
                    llm_runtime_state["status"] = "offline"
                    llm_runtime_state["model_responding"] = False
                    llm_runtime_state["last_error"] = "LLM credentials missing or incomplete"
                return {
                    "status": "error",
                    "message": "LLM credentials missing or incomplete",
                    "connection_state": "offline",
                    "model_responding": False,
                }
            resp = client.complete("Ping. Respond with 'PONG' only.", max_tokens=256, timeout=12)
            tested_at = datetime.now(timezone.utc).isoformat()
            if resp:
                clean_resp = redact_secrets(resp.strip())
                with llm_runtime_lock:
                    llm_runtime_state["last_tested"] = tested_at
                    llm_runtime_state["status"] = "connected"
                    llm_runtime_state["model_responding"] = True
                    llm_runtime_state["tested"] = True
                    llm_runtime_state["last_error"] = None
                    llm_runtime_state["active_model"] = client.model
                return {
                    "status": "success",
                    "message": f"Connected to {client.provider}/{client.model}! Response: {clean_resp}",
                    "connection_state": "connected",
                    "model_responding": True,
                    "model": client.model,
                    "provider": client.provider,
                }
            else:
                detail = redact_secrets(client.last_error or f"{client.provider} returned an empty response")
                with llm_runtime_lock:
                    llm_runtime_state["last_tested"] = tested_at
                    llm_runtime_state["status"] = "error"
                    llm_runtime_state["model_responding"] = False
                    llm_runtime_state["tested"] = True
                    llm_runtime_state["last_error"] = detail
                return {
                    "status": "error",
                    "message": f"Connection failed: {detail}",
                    "connection_state": "error",
                    "model_responding": False,
                }
        except Exception as e:
            err_msg = redact_secrets(str(e))
            with llm_runtime_lock:
                llm_runtime_state["status"] = "error"
                llm_runtime_state["model_responding"] = False
                llm_runtime_state["tested"] = True
                llm_runtime_state["last_error"] = err_msg
            return {
                "status": "error",
                "message": f"Connection test failed: {err_msg}",
                "connection_state": "error",
                "model_responding": False,
            }

    # ==================== DATA COLLECTORS ====================

    def get_system_info(self):
        playwright_ok = False
        try:
            import playwright
            playwright_ok = True
        except ImportError:
            pass

        with active_scans_lock:
            active_scans_count = len(active_scans)

        return {
            "name": "Moros AI Agent Dashboard",
            "version": "1.0.0",
            "python_version": sys.version,
            "playwright_installed": playwright_ok,
            "active_scans_count": active_scans_count,
            "targets_count": len(list(TARGETS_DIR.glob("*"))) if TARGETS_DIR.exists() else 0,
            "all_skills_count": len(SkillRegistry().list_skills()),
        }

    def get_targets_list(self):
        targets = []
        if not TARGETS_DIR.exists():
            return targets

        with active_scans_lock:
            scanning_targets = {
                name for name, info in active_scans.items()
                if info.get("status") in {"starting", "running"}
            }

        for d in TARGETS_DIR.iterdir():
            if d.is_dir():
                scope_files = list(d.glob("scope-of-work.*"))
                has_scope = len(scope_files) > 0

                findings = self.get_target_findings(d.name)
                sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "UNASSESSED": 0}
                for f in findings:
                    sev = f.get("severity_level", "INFO")
                    sev_counts[sev] = sev_counts.get(sev, 0) + 1

                is_scanning = d.name in scanning_targets

                targets.append({
                    "name": d.name,
                    "has_scope": has_scope,
                    "scope_file": scope_files[0].name if has_scope else None,
                    "findings_total": len(findings),
                    "raw_findings_total": sum(int(f.get("raw_record_count", 1)) for f in findings),
                    "severities": sev_counts,
                    "is_scanning": is_scanning,
                    "created_at": datetime.fromtimestamp(d.stat().st_ctime, tz=timezone.utc).isoformat(),
                })

        return sorted(targets, key=lambda x: x["name"])

    def get_skills_meta(self):
        skills = SkillRegistry().list_skills()
        for s in skills:
            s["name"] = s.get("title", s["id"])
            s["has_definition"] = True
        return skills

    def get_target_summary(self, target_name):
        target_dir = TARGETS_DIR / target_name
        output_dir = target_dir / "output"

        scope_files = list(target_dir.glob("scope-of-work.*"))
        has_scope = len(scope_files) > 0

        findings = self.get_target_findings(target_name)
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "UNASSESSED": 0}
        for f in findings:
            sev = f.get("severity_level", "INFO")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        # Read tech fingerprint if present
        tech_file = output_dir / "js" / "tech-fingerprint.json"
        tech_data = {}
        if tech_file.exists():
            try:
                tech_data = json.loads(tech_file.read_text(encoding="utf-8", errors="replace"))
            except Exception:
                pass

        # Read endpoints count from JavaScript and OpenAPI inventories.
        endpoints_count = self.get_target_endpoints(target_name).get("total_endpoints", 0)

        # Read JS files count
        raw_js_dir = output_dir / "js" / "raw"
        js_count = len(list(raw_js_dir.rglob("*.js"))) if raw_js_dir.exists() else 0

        # Subdomains count
        subdomains_file = output_dir / "recon" / "subdomains-all.txt"
        subdomain_count = 0
        if subdomains_file.is_file():
            try:
                subdomain_count = len([
                    line for line in subdomains_file.read_text(encoding="utf-8", errors="replace").splitlines()
                    if line.strip()
                ])
            except OSError:
                subdomain_count = 0

        with active_scans_lock:
            is_scanning = active_scans.get(target_name, {}).get("status") in {"starting", "running"}

        return {
            "target": target_name,
            "has_scope": has_scope,
            "scope_file": scope_files[0].name if has_scope else None,
            "total_findings": len(findings),
            "raw_findings_count": sum(int(f.get("raw_record_count", 1)) for f in findings),
            "severities": sev_counts,
            "total_endpoints": endpoints_count,
            "total_js_files": js_count,
            "total_subdomains": subdomain_count,
            "tech_fingerprint": tech_data,
            "is_scanning": is_scanning,
        }

    @staticmethod
    def _dashboard_conversation_messages(messages):
        """Hide AgentRunner's internal transcript copies from dashboard history."""
        final_answers = {
            str(item.get("content", ""))
            for item in messages
            if item.get("role") == "assistant"
            and item.get("source") in ("llm", "deterministic_fallback")
        }
        visible = []
        for item in messages:
            role = item.get("role")
            content = str(item.get("content", ""))

            # System prompts are runtime context, not chat messages.
            if role == "system":
                continue

            # AgentRunner records the same operator prompt with a run_id after
            # the dashboard has already recorded it with source="dashboard".
            if (
                role == "user"
                and item.get("run_id")
                and visible
                and visible[-1].get("role") == "user"
                and visible[-1].get("source") == "dashboard"
                and visible[-1].get("content") == content
            ):
                continue

            # A successful ReAct turn stores its raw text and the dashboard
            # stores the extracted final answer. Show only the final answer.
            if role == "assistant" and item.get("step") and content in final_answers:
                continue

            visible.append(item)
        return visible

    def get_agent_greeting(self, target_name, agent):
        greetings = {
            "coordinator": (
                f"🛡️ **Moros Master Coordinator — Active**\n\n"
                f"Target workspace: `{target_name}` | Status: `READY`\n\n"
                "I orchestrate multi-agent operations, attack trees, and skill dispatch. "
                "You can command me to run assessments, verify candidate findings, or coordinate sub-agents."
            ),
            "recon-agent": (
                f"🌐 **Reconnaissance Specialist Agent — Active**\n\n"
                f"Target workspace: `{target_name}` | Status: `READY`\n\n"
                "Specialized in subdomain enumeration, DNS resolution, alive checks, and Wayback scraping.\n\n"
                "**Directives supported:**\n"
                "- `Scan subdomains` / `Run recon`\n"
                "- `Check alive hosts`\n"
                "- `Scrape Wayback URLs`\n"
                "- `Summarize mapped attack surface`"
            ),
            "js-analyzer": (
                f"⚡ **JavaScript & API Hunter Agent — Active**\n\n"
                f"Target workspace: `{target_name}` | Status: `READY`\n\n"
                "Specialized in headless browser crawling, source map recovery, AST route extraction, and credential pattern detection.\n\n"
                "**Directives supported:**\n"
                "- `Analyze JavaScript files`\n"
                "- `Extract API endpoints`\n"
                "- `Scan for exposed secrets and tokens`\n"
                "- `Audit client-side source maps`"
            ),
            "xss-specialist": (
                f"🎯 **XSS & Client-Side Specialist Agent — Active**\n\n"
                f"Target workspace: `{target_name}` | Status: `READY`\n\n"
                "Specialized in DOM, Reflected, Stored, and Blind XSS payload injection with context-escape analysis.\n\n"
                "**Directives supported:**\n"
                "- `Test reflected parameters`\n"
                "- `Trace DOM sinks and sources`\n"
                "- `Generate context-tailored XSS payloads`"
            ),
            "ssrf-specialist": (
                f"☁️ **SSRF & Cloud Metadata Hunter Agent — Active**\n\n"
                f"Target workspace: `{target_name}` | Status: `READY`\n\n"
                "Specialized in SSRF identification, out-of-band canary interaction, and AWS/GCP/Azure instance metadata pivots.\n\n"
                "**Directives supported:**\n"
                "- `Audit SSRF vectors`\n"
                "- `Probe cloud metadata endpoints`\n"
                "- `Inspect webhook and callback parameters`"
            ),
            "auth-race-specialist": (
                f"🔑 **Auth & Race Condition Agent — Active**\n\n"
                f"Target workspace: `{target_name}` | Status: `READY`\n\n"
                "Specialized in IdP multi-threaded race conditions, token collisions, and password reset rate-limit auditing.\n\n"
                "**Directives supported:**\n"
                "- `Audit multi-threaded race conditions`\n"
                "- `Test rate limit bypass vectors`\n"
                "- `Evaluate OAuth/SAML state handling`"
            ),
            "review-verifier": (
                f"🔍 **Review-Skill Verifier Gate — Active**\n\n"
                f"Target workspace: `{target_name}` | Status: `READY`\n\n"
                "Specialized in strict evidence enforcement, independent cURL reproduction replay, and false-positive elimination.\n\n"
                "**Directives supported:**\n"
                "- `Verify candidate findings`\n"
                "- `Replay reproduction cURLs`\n"
                "- `Enforce verification proof standards`"
            ),
            "report-specialist": (
                f"📄 **Reporting & Synthesis Agent — Active**\n\n"
                f"Target workspace: `{target_name}` | Status: `READY`\n\n"
                "Specialized in OASIS SARIF 2.1.0 deliverable compilation, CVSS v3.1 scoring, and executive markdown synthesis.\n\n"
                "**Directives supported:**\n"
                "- `Generate SARIF 2.1.0 report`\n"
                "- `Compile executive assessment report`\n"
                "- `Export findings for GitHub Code Scanning`"
            ),
        }
        return greetings.get(agent, (
            f"🛡️ **Moros Specialist Agent — {agent}**\n\n"
            f"Target workspace: `{target_name}` | Status: `READY`\n\n"
            "Ready to execute operational directives for authorized assessment scope."
        ))

    def get_subagent_roster(self, target_name):
        target_path = TARGETS_DIR / target_name
        store = ConversationStore(target_path)
        with active_scans_lock:
            scan_state = active_scans.get(target_name, {}).get("status", "idle")
        with llm_runtime_lock:
            llm_responding = bool(llm_runtime_state.get("model_responding"))
            llm_status = llm_runtime_state.get("status")
        llm_available = LLMClient(provider="auto").is_available()
        run_manager = RunManager(target_path)
        latest_run = run_manager.get_latest_or_active_run()
        sessions = run_manager.list_agent_sessions(latest_run["run_id"]) if latest_run else []
        skill_states = {}
        for session in sessions:
            skill_states[session.get("skill", "")] = session.get("status", "")

        def _coordinator_status():
            if scan_state in {"starting", "running"}:
                return "RUNNING"
            if scan_state in {"stopping", "stopped", "failed", "blocked_scope"}:
                return scan_state.upper()
            if not llm_available:
                return "LLM OFFLINE"
            if llm_responding:
                return "ONLINE (Active)"
            if llm_status == "error":
                return "LLM ERROR"
            return "CONFIGURED (Ready)"

        def _specialist_status(*skill_ids):
            states = [skill_states.get(skill, "") for skill in skill_ids if skill_states.get(skill)]
            if any(state in {"running", "RUNNING"} for state in states):
                return "RUNNING"
            if states:
                latest = states[-1].lower()
                if latest in {"blocked_scope", "blocked"}:
                    return "BLOCKED BY SCOPE"
                if latest in {"success", "completed", "no_spec"}:
                    return "COMPLETED"
                if latest in {"failed", "error"}:
                    return "FAILED"
            if scan_state in {"starting", "running"}:
                return "QUEUED"
            if scan_state in {"stopping", "stopped", "failed", "blocked_scope"}:
                return scan_state.upper()
            return "STANDBY (On-Demand)"

        roster = [
            {
                "id": "coordinator",
                "name": "Coordinator Master",
                "role": "Attack tree orchestration, plan dispatch & multi-agent planner",
                "tier": "Coordinator (Primary Interactive Session)",
                "status": _coordinator_status(),
                "icon": "shield-alert",
                "messages_count": len(store.read("coordinator", 200)),
            },
            {
                "id": "recon-agent",
                "name": "Reconnaissance Specialist",
                "role": "Scope-aware hostname inventory and authorized reachability checks",
                "tier": "Skill: recon-subdomain",
                "status": _specialist_status("recon-subdomain"),
                "icon": "globe",
                "messages_count": len(store.read("recon-agent", 200)),
            },
            {
                "id": "js-analyzer",
                "name": "JavaScript & API Hunter",
                "role": "Same-host JavaScript collection, endpoint inventory and static sink analysis",
                "tier": "Skills: api-spec-discovery, js-discover, js-analyze",
                "status": _specialist_status("api-spec-discovery", "js-discover", "js-analyze"),
                "icon": "code",
                "messages_count": len(store.read("js-analyzer", 200)),
            },
            {
                "id": "xss-specialist",
                "name": "XSS & Client-Side Specialist",
                "role": "XSS candidate analysis; active verification is gated by scope policy",
                "tier": "Skills: xss-reflected, xss-stored, xss-dom, xss-blind",
                "status": _specialist_status("xss-reflected", "xss-stored", "xss-dom", "xss-blind"),
                "icon": "zap",
                "messages_count": len(store.read("xss-specialist", 200)),
            },
            {
                "id": "ssrf-specialist",
                "name": "SSRF & Cloud Metadata Hunter",
                "role": "SSRF candidate analysis; callbacks and active checks require explicit scope",
                "tier": "Skills: ssrf-identify, ssrf-post-exploit",
                "status": _specialist_status("ssrf-identify", "ssrf-post-exploit"),
                "icon": "cloud-lightning",
                "messages_count": len(store.read("ssrf-specialist", 200)),
            },
            {
                "id": "auth-race-specialist",
                "name": "Auth & Race Condition Agent",
                "role": "Authentication and race-condition checks when authorized by scope",
                "tier": "Skills: idp-race-condition, auth-password-reset-bruteforce",
                "status": _specialist_status("idp-race-condition", "auth-password-reset-bruteforce"),
                "icon": "key",
                "messages_count": len(store.read("auth-race-specialist", 200)),
            },
            {
                "id": "evidence-integrity-review",
                "name": "Evidence Integrity Reviewer",
                "role": "Checks evidence files and hashes; does not claim exploitability validation",
                "tier": "Deterministic saved-artifact review",
                "status": _specialist_status("evidence-integrity-review"),
                "icon": "check-circle",
                "messages_count": len(store.read("evidence-integrity-review", 200)),
            },
            {
                "id": "skeptical-false-positive-review",
                "name": "Skeptical Finding Reviewer",
                "role": "Records missing proof and plausible false-positive explanations for each candidate",
                "tier": "Deterministic adversarial triage",
                "status": _specialist_status("skeptical-false-positive-review"),
                "icon": "shield-alert",
                "messages_count": len(store.read("skeptical-false-positive-review", 200)),
            },
            {
                "id": "report-specialist",
                "name": "Reporting & Synthesis Agent",
                "role": "Deduplicated assessment report and SARIF export with explicit candidate status",
                "tier": "Skill: report-conglomeration",
                "status": _specialist_status("report-conglomeration"),
                "icon": "file-text",
                "messages_count": len(store.read("report-specialist", 200)),
            },
        ]
        return roster

    def get_target_sarif(self, target_name):
        target_path = TARGETS_DIR / target_name
        sarif_file = target_path / "output" / "report" / "findings.sarif"
        if sarif_file.exists():
            try:
                return json.loads(sarif_file.read_text(encoding="utf-8"))
            except Exception:
                pass
        from tools.sarif_exporter import build_sarif_report
        findings = self.get_target_findings(target_name)
        return build_sarif_report(findings, target=target_name)

    def get_target_costs(self, target_name):
        target_path = TARGETS_DIR / target_name
        receipt_file = target_path / "output" / "costs" / "receipt.json"
        if receipt_file.is_file():
            try:
                return json.loads(receipt_file.read_text(encoding="utf-8"))
            except Exception:
                pass
        log_file = target_path / "output" / "costs" / "cost-log.jsonl"
        entries = []
        total_cost = 0.0
        in_tok = 0
        out_tok = 0
        if log_file.is_file():
            for line in log_file.read_text(encoding="utf-8", errors="replace").splitlines():
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                    entries.append(row)
                    total_cost += float(row.get("cost_usd", 0.0))
                    in_tok += int(row.get("input_tokens", 0))
                    out_tok += int(row.get("output_tokens", 0))
                except Exception:
                    continue
        return {
            "target": target_name,
            "summary": {
                "total_cost_usd": round(total_cost, 6),
                "total_input_tokens": in_tok,
                "total_output_tokens": out_tok,
                "total_llm_calls": len(entries),
            },
            "entries": entries,
        }

    def get_target_traces(self, target_name):
        target_path = TARGETS_DIR / target_name
        traces_dir = target_path / "output" / "traces"
        traces = []
        if traces_dir.is_dir():
            files = sorted(traces_dir.glob("trace*.json"), key=lambda p: p.stat().st_mtime, reverse=True)[:10]
            for f in files:
                try:
                    traces.append({
                        "file": f.name,
                        "spans": json.loads(f.read_text(encoding="utf-8")),
                    })
                except Exception:
                    continue
        return {"target": target_name, "traces": traces}

    def get_target_memory(self, target_name):
        target_path = TARGETS_DIR / target_name
        try:
            from tools.memory_manager import MemoryManager
            mm = MemoryManager(target_path)
            return {
                "target": target_name,
                "stats": mm.get_stats(),
                "facts": mm.recall_facts(limit=50),
                "techniques": mm.recall_techniques(limit=30),
                "recent_events": mm.recall_events(limit=30),
            }
        except Exception as exc:
            return {"target": target_name, "error": str(exc)}

    def execute_subagent_chat(self, target: str, agent: str, message: str) -> Dict[str, Any]:
        target_path = TARGETS_DIR / target
        store = ConversationStore(target_path)
        clean_user_message = redact_secrets(message)
        store.append(agent, "user", clean_user_message, source="dashboard")

        # Track session in RunManager
        rm = RunManager(target_path)
        latest_run = rm.get_latest_or_active_run()
        if not latest_run:
            latest_run = rm.create_run(target=target, skills=[agent], dry_run=False, models="interactive")
        run_id = latest_run["run_id"]
        rm.register_agent_session(run_id, agent_id=agent, skill=agent, status="running")
        rm.log_event(run_id, "agent_chat_directive", {"agent": agent, "directive": clean_user_message[:200]})

        # Check for tools execution
        from tools.agent_runtime import AgentContext, AgentRunner, ToolRegistry
        from tools.skill_runner import SkillRunner
        from tools.sarif_exporter import write_sarif_report
        from tools.scope_validator import ScopeValidator

        runner = SkillRunner(target=target, target_dir=target_path)
        scope_validator = ScopeValidator(target, target_dir=target_path)
        is_scope_valid, scope_reason = scope_validator.is_allowed(target)
        runner.scope_authorized = bool(is_scope_valid)
        runner.http.scope_validator = scope_validator

        registry = ToolRegistry()

        def _tool_recon(active: bool = False):
            if active and not runner.scope_authorized:
                return "Active recon blocked: target authorization scope note required."
            res = runner.run_recon_subdomain(active_validation=active)
            return f"Recon completed: {res.get('subdomains_found', 0)} subdomains, {res.get('alive_hosts', 0)} alive hosts."

        def _tool_js_analyze():
            if not runner.scope_authorized:
                return "JavaScript crawl blocked: target authorization scope note required."
            res = runner.run_js_analyze()
            return f"JavaScript analysis completed: {res.get('secrets_found', 0)} secrets, {res.get('endpoints_found', 0)} endpoints."

        def _tool_review():
            res = runner.run_review_skill("all")
            return f"Review gate executed: {res.get('overall_status', 'SUCCESS')}"

        def _tool_sarif():
            findings = self.get_target_findings(target)
            out_file = target_path / "output" / "report" / "findings.sarif"
            write_sarif_report(out_file, findings, target=target)
            return f"SARIF 2.1.0 written to {out_file} ({len(findings)} findings)"

        def _tool_list_endpoints():
            ep_file = target_path / "output" / "recon" / "endpoints.txt"
            if not ep_file.exists():
                ep_file = target_path / "output" / "content" / "discovered-endpoints.txt"
            if ep_file.exists():
                lines = [line.strip() for line in ep_file.read_text(encoding="utf-8").splitlines() if line.strip()]
                return lines[:30]
            return []

        def _tool_list_findings():
            return self.get_target_findings(target)[:20]

        registry.register("run_subdomain_recon", _tool_recon, "Execute subdomain discovery & alive host enumeration", {"active": "bool"})
        registry.register("run_js_analysis", _tool_js_analyze, "Execute headless JavaScript crawling, AST parsing & secret extraction")
        registry.register("run_review_verification", _tool_review, "Execute independent verification gate and false positive pruning")
        registry.register("generate_sarif_report", _tool_sarif, "Generate GitHub Code Scanning compliant SARIF 2.1.0 deliverable")
        registry.register("list_endpoints", _tool_list_endpoints, "Retrieve discovered HTTP endpoints for the target")
        registry.register("list_findings", _tool_list_findings, "Retrieve security findings and candidate triage items")

        client = LLMClient(provider="auto")
        source = None
        answer = None
        llm_error_msg = None

        if client.is_available():
            context = AgentContext(
                target=target,
                target_dir=target_path,
                skill=agent,
                run_id=run_id,
            )
            system_prompt = (
                f"You are the Moros AI specialist agent '{agent}' assessing target '{target}'. "
                "You have direct execution access to target workspace tools and artifacts. "
                "Stay strictly within authorization scope. When directed to run actions, invoke the appropriate tool. "
                "For direct questions, ping checks, or conversational queries, answer concisely and directly."
            )
            try:
                agent_runner = AgentRunner(llm_client=client)
                # The dashboard handler owns the operator/final-answer transcript.
                # Avoid writing AgentRunner's internal prompt and raw model turns to
                # the same conversation file, where they would appear as duplicates.
                result = agent_runner.run(context, registry, system_prompt, message, persist_conversation=False)
                if result.status == "completed" and result.summary:
                    answer = redact_secrets(result.summary)
                    source = "llm"
                    with llm_runtime_lock:
                        llm_runtime_state["model_responding"] = True
                        llm_runtime_state["status"] = "connected"
                        llm_runtime_state["active_model"] = client.model
                        llm_runtime_state["last_error"] = None
                else:
                    llm_error_msg = redact_secrets(result.summary or client.last_error or f"Model returned status '{result.status}'")
                    with llm_runtime_lock:
                        llm_runtime_state["model_responding"] = False
                        llm_runtime_state["status"] = "error"
                        llm_runtime_state["last_error"] = llm_error_msg
            except Exception as e:
                llm_error_msg = redact_secrets(str(e))
                logger.warning(f"AgentRunner execution failed: {llm_error_msg}")
                with llm_runtime_lock:
                    llm_runtime_state["model_responding"] = False
                    llm_runtime_state["status"] = "error"
                    llm_runtime_state["last_error"] = llm_error_msg
        else:
            llm_error_msg = "No LLM provider configured (missing API credentials)"
            with llm_runtime_lock:
                llm_runtime_state["status"] = "offline"
                llm_runtime_state["model_responding"] = False

        if answer and source == "llm":
            # Successful model response
            store.append(agent, "assistant", answer, provider=client.provider, model=client.model, source="llm")
            rm.update_agent_session(run_id, agent_id=agent, status="completed", summary=answer[:200])
            return {
                "status": "success",
                "agent": agent,
                "provider": client.provider,
                "model": client.model,
                "message": answer,
                "source": "llm",
                "fallback_used": False,
            }

        # Deterministic Fallback Path (LLM failed or unavailable)
        # Explicitly labeled fallback — NEVER present as a Gemini or successful agent response
        fallback_source = "deterministic_fallback"
        fallback_provider = "deterministic-fallback"
        fallback_model = "deterministic-fallback"

        msg_lower = message.lower()
        if any(k in msg_lower for k in ["recon", "subdomain", "enumerate", "alive hosts"]):
            res = runner.run_recon_subdomain(active_validation=False)
            sub_count = res.get("subdomains_found", 0)
            alive_count = res.get("alive_hosts", 0)
            sub_file = target_path / "output" / "recon" / "subdomains.txt"
            sample_subs = []
            if sub_file.exists():
                sample_subs = [s.strip() for s in sub_file.read_text(encoding="utf-8").splitlines() if s.strip()][:8]
            sub_list = "\n".join(f"- `{s}`" for s in sample_subs) if sample_subs else "- None recorded yet"
            fallback_body = (
                f"🌐 **[RECON-AGENT] Subdomain Enumeration Directive Executed**\n\n"
                f"Target: `{target}` | Status: `COMPLETED (Deterministic Fallback)`\n\n"
                f"### Key Metrics\n"
                f"- **Total Subdomains Discovered:** `{sub_count}`\n"
                f"- **Alive Web Endpoints:** `{alive_count}`\n"
                f"- **Workspace Output:** `targets/{target}/output/recon/`\n\n"
                f"### Discovered Subdomain Sample\n{sub_list}\n\n"
                f"**Next Action:** Run `run_js_analyze` or test active endpoints for parameter reflection."
            )
        elif any(k in msg_lower for k in ["js", "javascript", "secret", "token", "source map", "sourcemap", "ast"]):
            res = runner.run_js_analyze()
            sec_count = res.get("secrets_found", 0)
            ep_count = res.get("endpoints_found", 0)
            sec_file = target_path / "output" / "js" / "secrets-findings.json"
            sec_items = []
            if sec_file.exists():
                try:
                    s_data = json.loads(sec_file.read_text(encoding="utf-8"))
                    sec_items = s_data.get("findings", [])[:5]
                except Exception:
                    pass
            sec_summary = "\n".join(f"- `{s.get('type')}` in `{s.get('source_file')}` ({s.get('severity')})" for s in sec_items) if sec_items else "- No exposed API keys or tokens identified."
            fallback_body = (
                f"⚡ **[JS-ANALYZER] JavaScript & Secret Extraction Executed**\n\n"
                f"Target: `{target}` | Status: `COMPLETED (Deterministic Fallback)`\n\n"
                f"### Key Metrics\n"
                f"- **Secrets / Credentials Flagged:** `{sec_count}`\n"
                f"- **Endpoints Extracted via AST:** `{ep_count}`\n"
                f"- **Workspace Output:** `targets/{target}/output/js/`\n\n"
                f"### Extracted Secrets\n{sec_summary}\n\n"
                f"**Next Action:** Validate detected secret patterns against live endpoints or test candidate routes."
            )
        elif any(k in msg_lower for k in ["sarif", "github", "code scanning", "export", "report"]):
            res = runner.run_report_conglomeration()
            findings_count = res.get("findings_count", 0)
            sarif_path = res.get("sarif_path") or f"targets/{target}/output/report/findings.sarif"
            report_path = res.get("report_path") or f"targets/{target}/output/report/"
            fallback_body = (
                f"📄 **[REPORT-SPECIALIST] Enterprise Deliverables Compiled**\n\n"
                f"Target: `{target}` | Status: `COMPLETED (Deterministic Fallback)`\n\n"
                f"### Export Artifacts\n"
                f"- **OASIS SARIF 2.1.0:** `{sarif_path}` (Directly uploadable via `github/codeql-action/upload-sarif`)\n"
                f"- **Executive Deliverable:** `{report_path}`\n"
                f"- **Total Triage Items Processed:** `{findings_count}`\n\n"
                f"**CI/CD Integration Hint:**\n"
                f"```bash\n"
                f"# Upload to GitHub Code Scanning Alerts\n"
                f"gh code-scanning upload-sarif --sarif {sarif_path}\n"
                f"```"
            )
        elif any(k in msg_lower for k in ["verify", "verification", "review", "proof", "reproduce", "candidate"]):
            res = runner.run_review_skill("all")
            status_str = res.get("overall_status", "SUCCESS")
            fallback_body = (
                f"🔍 **[REVIEW-VERIFIER] Verification Gate Executed**\n\n"
                f"Target: `{target}` | Status: `{status_str} (Deterministic Fallback)`\n\n"
                f"- Evaluated candidate findings against strict evidence gates.\n"
                f"- Verified reproduction proof standards (independent evidence, cURL validation).\n"
                f"- Findings without reproducible evidence marked as unverified candidates to eliminate false positives."
            )
        elif any(k in msg_lower for k in ["endpoint", "endpoints", "routes", "url", "urls"]):
            eps = _tool_list_endpoints()
            ep_text = "\n".join(f"- `{e}`" for e in eps[:15]) if eps else "- No endpoints discovered yet. Run recon or js-analyze first."
            fallback_body = (
                f"🛡️ **[AGENT: {agent.upper()}] Discovered Endpoints Inventory**\n\n"
                f"Target: `{target}` | Inventory Count: `{len(eps)}`\n\n"
                f"### Target Routes\n{ep_text}\n\n"
                f"Directives available: Ask to test specific endpoints or run vulnerability auditing."
            )
        elif any(k in msg_lower for k in ["finding", "findings", "vuln", "vulnerabilities", "bug", "status"]):
            findings = self.get_target_findings(target)
            validated = sum(1 for f in findings if f.get("validation_status") == "validated")
            candidates = len(findings) - validated
            f_sample = "\n".join(f"- **{f.get('title')}** — `{f.get('severity')}` [{f.get('validation_status')}]" for f in findings[:8]) if findings else "- No findings recorded in workspace."
            fallback_body = (
                f"🛡️ **[AGENT: {agent.upper()}] Workspace Triage Overview**\n\n"
                f"Target: `{target}` | Total Items: `{len(findings)}` ({validated} validated, {candidates} unverified candidates)\n\n"
                f"### Key Findings\n{f_sample}\n\n"
                f"Use `Verify findings` to invoke the verification gate or `Generate SARIF 2.1.0` to compile CI/CD reports."
            )
        elif any(k in msg_lower for k in ["pong", "ping", "connectivity", "hello", "hi"]):
            fallback_body = (
                f"The agent could not generate a model response for your ping/connectivity request because the upstream LLM backend is unavailable.\n\n"
                f"**LLM Error Details:** `{llm_error_msg or 'No response from model'}`\n\n"
                f"Please test model connectivity in Dashboard Settings or check your API key quota."
            )
        else:
            summary_data = self.get_target_summary(target)
            endpoints = summary_data.get("total_endpoints", 0)
            findings = summary_data.get("total_findings", 0)
            fallback_body = (
                f"🛡️ **[AGENT: {agent.upper()}] Deterministic Workspace Briefing**\n\n"
                f"Target: `{target}` | Status: `FALLBACK_READY`\n\n"
                f"Workspace context for `{target}` contains {endpoints} endpoints and {findings} triage items. "
                f"Deterministic tools remain available under authorization scope.\n\n"
                f"**Suggested Directives:**\n"
                f"- `Run subdomain recon` — Enumerate subdomains & alive hosts\n"
                f"- `Analyze JavaScript` — Crawl JS files, extract AST routes & scan for secrets\n"
                f"- `Verify findings` — Execute independent cURL replay & prune false positives\n"
                f"- `Export SARIF 2.1.0` — Build GitHub Code Scanning deliverable"
            )

        err_detail = llm_error_msg or "Model execution failed or timed out"
        fallback_banner = (
            f"⚠️ **[LLM UNAVAILABLE — DETERMINISTIC FALLBACK]**\n"
            f"*Model '{client.provider}/{client.model}' failed: {err_detail}*\n\n"
            f"---\n\n"
        )
        full_fallback_message = fallback_banner + fallback_body

        store.append(agent, "assistant", full_fallback_message, provider=fallback_provider, model=fallback_model, source=fallback_source)
        rm.update_agent_session(run_id, agent_id=agent, status="fallback_completed", summary=full_fallback_message[:200])

        return {
            "status": "fallback",
            "agent": agent,
            "provider": fallback_provider,
            "model": fallback_model,
            "message": full_fallback_message,
            "source": fallback_source,
            "fallback_used": True,
            "llm_error": llm_error_msg,
        }

    def get_target_skills_status(self, target_name):
        target_dir = TARGETS_DIR / target_name
        output_dir = target_dir / "output"
        logs_dir = output_dir / "logs"

        latest_status = {}
        latest_run = None
        requested_skills = set()
        completed_skills = set()
        failed_skills = set()
        run_started_at = None
        try:
            latest_run = RunManager(target_dir).get_latest_or_active_run()
            if latest_run:
                requested_skills = set(latest_run.get("skills_requested", []))
                completed_skills = set(latest_run.get("skills_completed", []))
                failed_skills = set(latest_run.get("skills_failed", []))
                started = latest_run.get("started_at")
                if started:
                    run_started_at = datetime.fromisoformat(str(started).replace("Z", "+00:00"))
                events_path = output_dir / "runs" / latest_run["run_id"] / "events.jsonl"
                if events_path.is_file():
                    for line in events_path.read_text(encoding="utf-8").splitlines():
                        try:
                            event = json.loads(line)
                            details = event.get("details", {})
                            skill = details.get("skill")
                            kind = event.get("event", "")
                            if skill and kind.startswith("SKILL_"):
                                latest_status[skill] = kind.removeprefix("SKILL_").lower()
                        except (json.JSONDecodeError, AttributeError):
                            continue
        except (OSError, KeyError, TypeError):
            pass

        statuses = []
        registry = SkillRegistry()
        all_skills = registry.list_skills()
        for s_obj in all_skills:
            s = s_obj["id"]
            skill_log_dir = logs_dir / s
            log_files = [f.name for f in skill_log_dir.glob("*.log")] if skill_log_dir.exists() else []
            run_state = latest_status.get(s)
            if s not in requested_skills:
                state = "not_run"
                review_status = "not_run"
            elif run_state in {"running", "failed", "blocked", "blocked_scope"}:
                state = run_state
                review_status = "not_recorded"
            elif run_state == "candidates_only":
                state = "candidates_only"
                review_status = "not_recorded"
            elif run_state == "not_implemented":
                state = "not_implemented"
                review_status = "not_recorded"
            elif run_state in {"completed", "success"}:
                state = "completed"
                review_status = "not_recorded"
            elif s in failed_skills:
                state = "failed"
                review_status = "not_recorded"
            elif s in completed_skills:
                state = "completed"
                review_status = "not_recorded"
            else:
                state = "no_result"
                review_status = "not_recorded"

            # Only treat a review file as current when it postdates this run's start.
            review_log = logs_dir / "review" / f"{s}-review-1.json"
            if s in requested_skills and review_log.exists():
                try:
                    review_time = datetime.fromtimestamp(review_log.stat().st_mtime, tz=timezone.utc)
                    comparable_start = run_started_at.astimezone(timezone.utc) if run_started_at else None
                    if comparable_start and review_time < comparable_start:
                        review_status = "historical"
                    else:
                        rev_data = json.loads(review_log.read_text(encoding="utf-8"))
                        review_status = rev_data.get("overall_status", "PASS")
                        if review_status == "FAIL":
                            state = "failed"
                except Exception:
                    review_status = "not_recorded"

            statuses.append({
                "skill": s,
                "name": s_obj.get("title", s),
                "title": s_obj.get("title", s),
                "category": s_obj.get("category", "General"),
                "description": s_obj.get("description", ""),
                "is_custom": s_obj.get("is_custom", False),
                "state": state,
                "review_status": review_status,
                "logs_count": len(log_files),
                "log_files": log_files,
                "latest_run_id": latest_run.get("run_id") if latest_run else None,
                "requested_in_latest_run": s in requested_skills,
            })

        return statuses

    def get_target_findings(self, target_name):
        target_dir = TARGETS_DIR / target_name
        output_dir = target_dir / "output"

        # A current report is the canonical grouped inventory. When source
        # artifacts have changed since that report, fall through and rebuild the
        # live view so stale reports cannot hide new evidence.
        report_files = sorted(
            (output_dir / "report").glob("hackbot-report-*.json"),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        if report_files:
            latest_report = report_files[0]
            source_roots = [output_dir / "findings"]
            source_files = [
                output_dir / "js" / "secrets-findings.json",
                output_dir / "js" / "gadgets.json",
                output_dir / "content-discovery" / "interesting-findings.json",
            ]
            if source_roots[0].exists():
                source_files.extend(source_roots[0].rglob("*.json"))
            current_manifest = {
                str(path.relative_to(target_dir)).replace("\\", "/"): path.stat().st_mtime
                for path in source_files if path.is_file()
            }
            try:
                report_data = json.loads(latest_report.read_text(encoding="utf-8"))
                source_manifest = report_data.get("source_artifact_mtimes") if isinstance(report_data, dict) else None
                if isinstance(source_manifest, dict) and source_manifest == current_manifest:
                    report_findings = report_data.get("findings", []) if isinstance(report_data, dict) else []
                    if isinstance(report_findings, list):
                        normalized = []
                        for index, raw in enumerate(report_findings, 1):
                            if not isinstance(raw, dict):
                                continue
                            finding = dict(raw)
                            finding.setdefault("id", f"report-{index}")
                            finding.setdefault("endpoint", finding.get("url", ""))
                            finding.setdefault("category", finding.get("type", "candidate"))
                            severity = str(finding.get("severity") or "UNASSESSED").upper()
                            finding.setdefault("severity_level", next((level for level in
                                ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") if level in severity), "UNASSESSED"))
                            finding.setdefault("validation_status", "unverified")
                            finding.setdefault("status", "candidate")
                            normalized.append(finding)
                        return normalized
            except (OSError, json.JSONDecodeError):
                pass

        findings = []
        grouped = {}
        dom_lookup = {}

        def sink_name(item):
            value = str(item.get("sink", "")).strip()
            if not value:
                match = re.search(r"Potential DOM XSS Sink ['\"]([^'\"]+)", str(item.get("title", "")))
                value = match.group(1) if match else ""
            value = value.casefold().replace(" assignment", "").replace(" redirect", "")
            return value

        def add_occurrence(finding, source, line=None):
            occurrence = {"source_file": source, "line": line}
            occurrences = finding.setdefault("occurrences", [])
            if occurrence not in occurrences:
                occurrences.append(occurrence)
            finding["raw_record_count"] = finding.get("raw_record_count", 1) + 1

        def source_basename(source):
            return Path(str(source or "").replace("\\", "/")).name.casefold()

        # 1. From findings/* directory
        findings_dir = output_dir / "findings"
        if findings_dir.exists():
            for fpath in findings_dir.rglob("*.json"):
                if fpath.name.startswith(("confirmed-", "candidates-")) or fpath.name.endswith("-results.json"):
                    try:
                        content = json.loads(fpath.read_text(encoding="utf-8"))
                        items = content if isinstance(content, list) else content.get("findings", [content])
                        for item in items:
                            if isinstance(item, dict) and ("type" in item or "title" in item or "url" in item):
                                raw_title = str(item.get("title", item.get("type", fpath.stem)))
                                url = str(item.get("url", item.get("endpoint", "")))
                                is_dom_candidate = "Potential DOM XSS Sink" in raw_title
                                sink = sink_name(item) if is_dom_candidate else ""
                                parsed_url = urllib.parse.urlsplit(url)
                                line_match = re.search(r"#L(\d+)", url)
                                line = item.get("line") or (int(line_match.group(1)) if line_match else None)
                                if is_dom_candidate:
                                    source_reference = Path(parsed_url.path).name
                                    identity = finding_identity({
                                        **item, "type": "DOM XSS", "sink": sink,
                                        "source_file": source_reference, "url": url,
                                    })
                                else:
                                    source_reference = _safe_source_reference(item.get("source_file") or str(fpath.relative_to(output_dir)), target_name)
                                    identity = finding_identity({
                                        **item, "title": raw_title, "category": item.get("type", fpath.parent.name),
                                        "source_file": source_reference, "url": url,
                                    })

                                raw_sev = item.get("severity") or "Triage Severity: UNASSESSED — pending evidence and human review"
                                sev_upper = str(raw_sev or "info").upper()
                                sev_lvl = "UNASSESSED" if "UNASSESSED" in sev_upper else "MEDIUM"
                                if "CRITICAL" in sev_upper:
                                    sev_lvl = "CRITICAL"
                                elif "HIGH" in sev_upper:
                                    sev_lvl = "HIGH"
                                elif "LOW" in sev_upper:
                                    sev_lvl = "LOW"
                                elif "INFO" in sev_upper:
                                    sev_lvl = "INFO"

                                validation = item.get("validation_record") or {}
                                human_validation = (
                                    isinstance(validation, dict)
                                    and str(validation.get("verified_by", "")).startswith("human:")
                                    and bool(validation.get("method"))
                                    and bool(validation.get("evidence_ids"))
                                    and validation.get("outcome") == "reproduced"
                                )
                                existing = grouped.get(identity)
                                if existing:
                                    add_occurrence(existing, source_reference, line)
                                    if is_dom_candidate:
                                        dom_lookup[(source_basename(source_reference), sink)] = existing
                                    continue

                                finding = {
                                    "id": f"{fpath.stem}-{len(findings)+1}",
                                    "title": raw_title,
                                    "category": fpath.parent.name,
                                    "severity": raw_sev,
                                    "severity_level": sev_lvl,
                                    "endpoint": url,
                                    "parameter": item.get("parameter", item.get("param", "")),
                                    "payload": item.get("payload", ""),
                                    "curl_command": item.get("curl", ""),
                                    "source_file": source_reference,
                                    "line": line,
                                    "occurrences": [{"source_file": source_reference, "line": line}],
                                    "raw_record_count": 1,
                                    "details": item.get("notes", item.get("context", "")),
                                    "status": "validated" if human_validation else "candidate",
                                    "validation_status": "validated" if human_validation else "unverified",
                                    "confidence": item.get("confidence", "not-scored"),
                                    "evidence_ids": item.get("evidence_ids", []),
                                    "poc_sh": item.get("poc_sh", ""),
                                    "poc_py": item.get("poc_py", ""),
                                }
                                grouped[identity] = finding
                                findings.append(finding)
                                if is_dom_candidate:
                                    dom_lookup[(source_basename(source_reference), sink)] = finding
                    except Exception:
                        pass

        # 2. From secrets-findings.json
        secrets_file = output_dir / "js" / "secrets-findings.json"
        if secrets_file.exists():
            try:
                s_data = json.loads(secrets_file.read_text(encoding="utf-8"))
                for s in s_data.get("findings", []):
                    source_file = _safe_source_reference(s.get("source_file", ""), target_name)
                    fingerprint = str(s.get("value_fingerprint", "")).strip()
                    identity = ("secret", str(s.get("type", "")).casefold(), fingerprint) if fingerprint else (
                        "secret", str(s.get("type", "")).casefold(), source_file, s.get("line_number")
                    )
                    existing = grouped.get(identity)
                    if existing:
                        add_occurrence(existing, source_file, s.get("line_number"))
                        continue
                    raw_sev = s.get("severity") or "Triage Severity: MEDIUM — pending human review"
                    sev_upper = str(raw_sev or "info").upper()
                    sev_lvl = "MEDIUM"
                    if "HIGH" in sev_upper:
                        sev_lvl = "HIGH"
                    elif "CRITICAL" in sev_upper:
                        sev_lvl = "CRITICAL"
                    elif "LOW" in sev_upper:
                        sev_lvl = "LOW"
                    elif "INFO" in sev_upper:
                        sev_lvl = "INFO"
                    elif "UNASSESSED" in sev_upper:
                        sev_lvl = "UNASSESSED"

                    finding = {
                        "id": f"secret-{len(findings)+1}",
                        "title": f"Hardcoded Secret: {s.get('type')}",
                        "category": "secrets",
                        "severity": raw_sev,
                        "severity_level": sev_lvl,
                        # A local artifact path is provenance, never a target URL.
                        "endpoint": s.get("url", ""),
                        "parameter": s.get("pattern_name", ""),
                        "payload": s.get("value_preview", ""),
                        "curl_command": "",
                        "source_file": source_file,
                        "line": s.get("line_number"),
                        "occurrences": [{"source_file": source_file, "line": s.get("line_number")}],
                        "raw_record_count": 1,
                        "details": s.get("context", ""),
                        "status": "pending_review",
                        "validation_status": "unverified",
                        "confidence": s.get("confidence", "not-scored"),
                    }
                    grouped[identity] = finding
                    findings.append(finding)
            except Exception:
                pass

        # 3. From gadgets.json (DOM XSS sinks)
        gadgets_file = output_dir / "js" / "gadgets.json"
        if gadgets_file.exists():
            try:
                g_data = json.loads(gadgets_file.read_text(encoding="utf-8"))
                gadget_groups = {}
                for g in g_data.get("gadgets", []):
                    source_file = _safe_source_reference(g.get("source_file", ""), target_name)
                    sink = sink_name({"sink": g.get("type", "")})
                    identity = (source_file.casefold(), sink, str(g.get("line_number", "")).strip())
                    if identity not in gadget_groups:
                        gadget_groups[identity] = {"count": 0, "sample": g, "source_file": source_file}
                    gadget_groups[identity]["count"] += 1

                for (source_key, sink, _line), group in gadget_groups.items():
                    raw_count = group["count"]
                    candidate = dom_lookup.get((source_key, sink))
                    if candidate:
                        candidate["raw_record_count"] += raw_count
                        continue
                    g = group["sample"]
                    source_file = group["source_file"]
                    finding = {
                        "id": f"gadget-{len(findings)+1}",
                        "title": f"Dangerous Sink: {sink}",
                        "category": "dom-xss",
                        "severity": "Triage Severity: MEDIUM — pending human review",
                        "severity_level": "MEDIUM",
                        "endpoint": g.get("source_file", ""),
                        "parameter": g.get("controllable_source", ""),
                        "payload": "",
                        "curl_command": "",
                        "source_file": source_file,
                        "line": None,
                        "occurrences": [{"source_file": source_file, "line": None}],
                        "raw_record_count": raw_count,
                        "details": "Potential DOM sink identified in client-side JavaScript; no controllable input-to-sink path has been demonstrated.",
                        "status": "pending_review",
                        "validation_status": "unverified",
                        "confidence": "not-scored",
                    }
                    grouped[("gadget", source_key, sink)] = finding
                    findings.append(finding)
            except Exception:
                pass

        return deduplicate_findings(findings)

    def get_target_endpoints(self, target_name):
        ep_file = TARGETS_DIR / target_name / "output" / "js" / "endpoints.json"
        api_file = TARGETS_DIR / target_name / "output" / "api" / "endpoints.json"
        legacy_api_file = TARGETS_DIR / target_name / "output" / "api" / "openapi-endpoints.json"
        inventory = {"endpoints": [], "total_endpoints": 0}
        endpoints = []
        if ep_file.exists():
            try:
                loaded = json.loads(ep_file.read_text(encoding="utf-8", errors="replace"))
                if isinstance(loaded, dict):
                    inventory = loaded
                    raw_endpoints = loaded.get("endpoints", [])
                elif isinstance(loaded, list):
                    raw_endpoints = loaded
                else:
                    raw_endpoints = []
                if isinstance(raw_endpoints, list):
                    for endpoint in raw_endpoints:
                        if not isinstance(endpoint, dict):
                            continue
                        ep = dict(endpoint)
                        ep.setdefault("source", "javascript")
                        ep["source_file"] = _safe_source_reference(ep.get("source_file"), target_name)
                        endpoints.append(ep)
            except Exception as e:
                logger.warning("Failed to load JS endpoints for %s: %s", target_name, e)
                return {"error": "Failed to load JavaScript endpoints", "endpoints": []}
        if api_file.exists() or legacy_api_file.exists():
            try:
                source_file = api_file if api_file.exists() else legacy_api_file
                api_inventory = json.loads(source_file.read_text(encoding="utf-8", errors="replace"))
                raw_api_endpoints = (
                    api_inventory.get("endpoints", [])
                    if isinstance(api_inventory, dict)
                    else (api_inventory if isinstance(api_inventory, list) else [])
                )
                if isinstance(raw_api_endpoints, list):
                    for endpoint in raw_api_endpoints:
                        if not isinstance(endpoint, dict):
                            continue
                        ep = dict(endpoint)
                        ep["source"] = "openapi"
                        ep["source_file"] = _safe_source_reference(ep.get("source_file"), target_name)
                        ep["url"] = str(ep.get("base_url", "") or "").rstrip("/") + str(ep.get("path", "") or "")
                        endpoints.append(ep)
            except Exception as e:
                logger.warning("Failed to load API endpoints for %s: %s", target_name, e)
                return {"error": "Failed to load API endpoints", "endpoints": endpoints}
        inventory["endpoints"] = endpoints
        inventory["total_endpoints"] = len(endpoints)
        return inventory

    def get_target_tech_fingerprint(self, target_name):
        tech_file = TARGETS_DIR / target_name / "output" / "js" / "tech-fingerprint.json"
        if tech_file.exists():
            try:
                return json.loads(tech_file.read_text(encoding="utf-8", errors="replace"))
            except Exception as e:
                logger.warning("Failed to load tech fingerprint for %s: %s", target_name, e)
                return {"error": "Failed to load technology fingerprint"}
        return {}

    def get_target_logs(self, target_name, specific_file=None):
        logs_dir = (TARGETS_DIR / target_name / "output" / "logs").resolve()
        if not logs_dir.is_dir():
            return {"logs": [], "content": ""}

        all_logs = []
        for p in logs_dir.rglob("*.log"):
            if p.is_file():
                all_logs.append({
                    "path": str(p.relative_to(logs_dir)).replace("\\", "/"),
                    "size": p.stat().st_size,
                    "modified": datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc).isoformat(),
                })

        content = ""
        if specific_file:
            safe_p = (logs_dir / specific_file).resolve()
            if safe_p.is_relative_to(logs_dir) and safe_p.is_file():
                try:
                    content = safe_p.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    content = ""

        return {"logs": sorted(all_logs, key=lambda x: x["path"]), "content": content}

    def get_target_checkpoints(self, target_name):
        target_dir = TARGETS_DIR / target_name
        cp_mgr = CheckpointManager(target_name, target_dir)
        return cp_mgr.list_checkpoints()

    def handle_checkpoint_decision(self, target_name, checkpoint_id, action, notes):
        target_dir = TARGETS_DIR / target_name
        cp_mgr = CheckpointManager(target_name, target_dir)
        decided = cp_mgr.decide(checkpoint_id, action, notes, decider="dashboard_operator")
        return {
            "status": "success",
            "message": f"Checkpoint {checkpoint_id} marked as {decided.get('status')}",
            "checkpoint": decided
        }

    def get_target_report(self, target_name):
        report_dir = TARGETS_DIR / target_name / "output" / "report"
        if not report_dir.exists():
            return {"markdown": "# No Report Generated Yet", "json": {}}

        md_files = sorted(report_dir.glob("*.md"), key=lambda path: path.stat().st_mtime, reverse=True)
        json_files = sorted(report_dir.glob("hackbot-report-*.json"), key=lambda path: path.stat().st_mtime, reverse=True)

        md_file = md_files[0] if md_files else None
        md_content = "# No report markdown found"
        if md_file:
            try:
                md_content = md_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                md_content = "# Unable to read report markdown"
        json_content = {}
        matching_json = next((path for path in json_files if md_file and path.stem == md_file.stem), None)
        json_file = matching_json or (json_files[0] if json_files else None)
        if json_file:
            try:
                json_content = json.loads(json_file.read_text(encoding="utf-8", errors="replace"))
            except Exception:
                pass

        report_summary = json_content.get("summary", {}) if isinstance(json_content, dict) else {}
        report_findings = json_content.get("findings", []) if isinstance(json_content, dict) else []
        report_count = report_summary.get("triage_items") if isinstance(report_summary, dict) else None
        if report_count is None and isinstance(report_findings, list):
            report_count = len(report_findings)
        current_count = len(self.get_target_findings(target_name))
        if isinstance(report_count, int) and report_count != current_count:
            warning = (
                f"> **Report snapshot is out of date:** it contains {report_count} triage items, "
                f"while the current dashboard data contains {current_count}. Regenerate the report before sharing it.\n\n"
            )
            md_content = warning + md_content

        return {"markdown": md_content, "json": json_content, "files": [f.name for f in md_files + sorted(report_dir.glob("*.json"), key=lambda path: path.stat().st_mtime, reverse=True)]}

    # ==================== SCAN MANAGEMENT ====================

    def start_scan_job(self, target, skills, models, dry_run=False, scan_mode="quick", max_subagents=10):
        log_buffer = []
        with active_scans_lock:
            existing = active_scans.get(target)
            if existing and existing.get("status") in {"starting", "running"}:
                return {"status": "error", "message": f"A scan is already running for {target}"}
            active_scans[target] = {
                "thread": None,
                "status": "starting",
                "logs": log_buffer,
                "target": target,
            }

        target_dir = TARGETS_DIR / target
        initialized = not target_dir.is_dir()
        if initialized:
            try:
                from setup import init_target
                init_target(target)
            except Exception as exc:
                with active_scans_lock:
                    active_scans.pop(target, None)
                return {"status": "error", "message": f"Could not initialize target workspace: {exc}"}

        def _append_log(entry_text: str) -> None:
            with active_scans_lock:
                log_buffer.append(entry_text)
                if len(log_buffer) > 2000:
                    del log_buffer[:-2000]

        def run_worker():
            with active_scans_lock:
                scan_entry = active_scans.get(target)
                if not scan_entry or scan_entry.get("status") == "stopped":
                    return
                scan_entry["status"] = "running"
                scan_entry["start_time"] = datetime.now(timezone.utc).isoformat()

            cmd = [
                sys.executable,
                str(PROJECT_ROOT / "run.py"),
                "--target", target,
                "--skills", skills,
                "--models", models,
                "--scan-mode", scan_mode,
                "--https-only",
                "--max-http-requests", "40",
                "--request-delay", "0.4",
                "--max-subagents", str(max_subagents),
            ]
            if dry_run:
                cmd.append("--dry-run")

            _append_log(f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] Executing: {' '.join(cmd)}\n")

            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    bufsize=1,
                    cwd=str(PROJECT_ROOT),
                )
                stop_requested = False
                with active_scans_lock:
                    scan_entry = active_scans.get(target)
                    if scan_entry is not None:
                        scan_entry["process"] = proc
                        stop_requested = scan_entry.get("status") == "stopped"
                if stop_requested:
                    proc.terminate()

                for line in iter(proc.stdout.readline, ""):
                    _append_log(line)

                proc.stdout.close()
                proc.wait()

                with active_scans_lock:
                    scan_entry = active_scans.get(target)
                    current_status = scan_entry.get("status") if scan_entry else None
                    if current_status == "stopped":
                        final_status = "stopped"
                    elif proc.returncode == 0:
                        final_status = "completed"
                    elif proc.returncode == 3:
                        final_status = "blocked_scope"
                    else:
                        final_status = "failed"
                    if scan_entry is not None:
                        scan_entry["status"] = final_status
                _append_log(f"\n[Finished with exit code {proc.returncode}]\n")
                notification = send_discord_scan_summary(target, final_status)
                if notification != "not configured":
                    _append_log(f"[Discord] Scan summary notification: {notification}.\n")
            except Exception as e:
                with active_scans_lock:
                    scan_entry = active_scans.get(target)
                    if scan_entry is not None and scan_entry.get("status") != "stopped":
                        scan_entry["status"] = "error"
                _append_log(f"\n[Execution error: {e}]\n")

        thread = threading.Thread(target=run_worker, daemon=True)
        with active_scans_lock:
            if target in active_scans:
                active_scans[target]["thread"] = thread
        thread.start()

        message = f"Scan started for {target}"
        if initialized:
            message += ". A workspace was created; without a matching readable scope-of-work note, only passive recon can run."
        return {"status": "success", "message": message, "target": target, "initialized_target": initialized}

    def stop_scan_job(self, target):
        proc = None
        with active_scans_lock:
            scan_info = active_scans.get(target)
            if not scan_info:
                return {"status": "error", "message": f"No active scan found for {target}"}
            proc = scan_info.get("process")
            if not proc and scan_info.get("status") not in {"starting", "running"}:
                return {"status": "error", "message": f"No active scan found for {target}"}
            scan_info["status"] = "stopped"

        if proc:
            try:
                proc.terminate()
            except Exception:
                logger.exception("Failed to terminate scan process for %s", target)
                return {"status": "error", "message": f"Failed to stop scan for {target}"}
        return {"status": "success", "message": f"Scan for {target} stopped"}

    def get_scan_status(self, target):
        if not target:
            return {"status": "idle", "logs": []}

        with active_scans_lock:
            scan_info = active_scans.get(target)
            if not scan_info:
                return {"status": "idle", "logs": []}
            status = scan_info.get("status", "idle")
            start_time = scan_info.get("start_time")
            logs_copy = list(scan_info.get("logs", []))

        return {
            "status": status,
            "target": target,
            "start_time": start_time,
            "logs": "".join(logs_copy),
        }

    def handle_sse_stream(self, target):
        """Server-Sent Events endpoint streaming scan progress."""
        if not target:
            self.send_error_json("Target parameter is required", status=400)
            return

        try:
            from setup import validate_target_name
            validate_target_name(target)
        except ValueError:
            self.send_error_json("Invalid target name", status=400)
            return

        target_path = TARGETS_DIR / target
        if not target_path.exists():
            self.send_error_json(f"Target '{target}' not found", status=404)
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache, no-transform")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

        rm = RunManager(target_path)
        last_event_count = 0
        iterations = 0
        max_iterations = 60

        try:
            while iterations < max_iterations:
                scan_status = self.get_scan_status(target)
                runs = rm.list_runs()
                latest_run = runs[0] if runs else None
                run_id = latest_run.get("run_id") if latest_run else None

                events = []
                if run_id:
                    events = rm.get_event_stream(run_id)

                payload = {
                    "scan_status": scan_status,
                    "latest_run": latest_run,
                    "new_events": events[last_event_count:] if len(events) > last_event_count else [],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                last_event_count = len(events)

                data = f"data: {json.dumps(payload)}\n\n"
                self.wfile.write(data.encode("utf-8"))
                self.wfile.flush()

                with active_scans_lock:
                    scan_info = active_scans.get(target)
                    scan_state = scan_info.get("status") if scan_info else None
                if not scan_state or scan_state in ("completed", "failed", "stopped"):
                    if latest_run and latest_run.get("status") in ("completed", "failed"):
                        break

                time.sleep(1.0)
                iterations += 1
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as exc:
            logger.debug("SSE stream terminated: %s", exc)


def _resolve_tls_paths(
    ssl_cert: Optional[str] = None,
    ssl_key: Optional[str] = None,
) -> Optional[Tuple[Path, Path]]:
    """Validate optional TLS certificate and private key paths from args or env vars."""
    raw_cert = ssl_cert if ssl_cert is not None else os.environ.get("MOROS_DASHBOARD_SSL_CERT", "")
    raw_key = ssl_key if ssl_key is not None else os.environ.get("MOROS_DASHBOARD_SSL_KEY", "")
    cert_val = str(raw_cert).strip()
    key_val = str(raw_key).strip()

    if not cert_val and not key_val:
        return None
    if bool(cert_val) != bool(key_val):
        raise ValueError(
            "Both ssl_cert (MOROS_DASHBOARD_SSL_CERT) and ssl_key (MOROS_DASHBOARD_SSL_KEY) "
            "must be provided together to enable HTTPS/TLS."
        )

    cert_file = Path(cert_val)
    key_file = Path(key_val)
    if not cert_file.is_file():
        raise FileNotFoundError(f"SSL certificate file not found: {cert_file}")
    if not key_file.is_file():
        raise FileNotFoundError(f"SSL private key file not found: {key_file}")
    return cert_file, key_file


def run_dashboard(
    host="127.0.0.1",
    port=8080,
    open_browser=True,
    default_target=None,
    ssl_cert: Optional[str] = None,
    ssl_key: Optional[str] = None,
    rate_limit_rpm: Optional[int] = None,
):
    """Run the Moros AI Agent dashboard server."""
    tls_paths = _resolve_tls_paths(ssl_cert=ssl_cert, ssl_key=ssl_key)

    is_loopback = _is_loopback_host(host)
    env_token = os.environ.get("MOROS_DASHBOARD_TOKEN", "").strip()
    runtime_token = env_token
    generated_ephemeral = False
    if not is_loopback and not runtime_token:
        runtime_token = secrets.token_urlsafe(32)
        generated_ephemeral = True
        logger.warning(
            "Dashboard bound to non-loopback host '%s' without MOROS_DASHBOARD_TOKEN; "
            "auto-generated a runtime authentication token.",
            host,
        )

    server_address = (host, port)
    httpd = ThreadedHTTPServer(server_address, DashboardHandler)
    use_tls = tls_paths is not None
    try:
        httpd.dashboard_token = runtime_token or None
        httpd.allow_remote = not is_loopback
        if rate_limit_rpm is not None:
            httpd.rate_limit_rpm = int(rate_limit_rpm)

        if tls_paths is not None:
            cert_file, key_file = tls_paths
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            if hasattr(ssl, "TLSVersion"):
                ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ssl_ctx.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
            httpd.socket = ssl_ctx.wrap_socket(httpd.socket, server_side=True)
            httpd.is_tls = True
    except Exception:
        httpd.server_close()
        raise

    display_host = "127.0.0.1" if host in {"0.0.0.0", "::"} else host
    scheme = "https" if use_tls else "http"
    bound_port = httpd.server_address[1] if port == 0 else port
    url = f"{scheme}://{display_host}:{bound_port}"
    if default_target:
        url += f"?target={default_target}"

    print("=" * 60)
    print("🛡️  MOROS AI AGENT — WEB DASHBOARD")
    print(f"📡 Dashboard running at: {url}")
    print(f"📂 Project Root: {PROJECT_ROOT}")
    print("⌨️  Press Ctrl+C to stop the dashboard server")
    print("=" * 60)
    if use_tls:
        print("[*] HTTPS/TLS encryption enabled.")
    if generated_ephemeral:
        print(f"[!] Non-loopback bind ({host}) without MOROS_DASHBOARD_TOKEN. Runtime token: {runtime_token}")
    elif runtime_token:
        print("[*] Dashboard API authentication enabled via MOROS_DASHBOARD_TOKEN.")

    if open_browser:
        import webbrowser
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 Dashboard server stopped.")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Moros AI Agent — Web Dashboard Server")
    parser.add_argument("--host", default="127.0.0.1", help="Host address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="Port (default: 8080)")
    parser.add_argument("--target", default=None, help="Default target domain to open")
    parser.add_argument("--no-open", action="store_true", help="Do not open browser automatically")
    parser.add_argument("--ssl-cert", default=None, help="Path to TLS/SSL certificate PEM file (or MOROS_DASHBOARD_SSL_CERT)")
    parser.add_argument("--ssl-key", default=None, help="Path to TLS/SSL private key PEM file (or MOROS_DASHBOARD_SSL_KEY)")
    parser.add_argument("--rate-limit", type=int, default=None, help="Per-client API rate limit in requests/minute (default: 600, or MOROS_DASHBOARD_RATE_LIMIT)")

    args = parser.parse_args()
    run_dashboard(
        host=args.host,
        port=args.port,
        open_browser=not args.no_open,
        default_target=args.target,
        ssl_cert=args.ssl_cert,
        ssl_key=args.ssl_key,
        rate_limit_rpm=args.rate_limit,
    )

