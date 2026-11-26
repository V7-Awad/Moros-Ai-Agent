#!/usr/bin/env python3
"""
oob_server.py — Out-of-Band (OOB) Callback Server & Token Correlation Manager.

Provides a lightweight, thread-safe HTTP loopback callback listener and DNS/HTTP
canary correlation manager for verifying blind vulnerabilities:
- Blind XSS (xss-blind)
- Blind SSRF (ssrf-identify)
- Blind XXE (xxe-detect)
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import threading
import time
from typing import Any, Dict, List, Optional, Union
import urllib.parse


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class OOBToken:
    """Correlation token linking an injected canary to a target endpoint and skill."""

    token: str
    skill: str
    target: str
    url: str
    callback_url: str
    dns_canary: str
    created_at: float = field(default_factory=time.time)
    created_at_iso: str = field(default_factory=_utc_iso)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "token": self.token,
            "skill": self.skill,
            "target": self.target,
            "url": self.url,
            "callback_url": self.callback_url,
            "dns_canary": self.dns_canary,
            "created_at": self.created_at,
            "created_at_iso": self.created_at_iso,
            "metadata": dict(self.metadata),
        }


class _QuietThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class OOBServer:
    """Loopback HTTP OOB callback listener and token correlation manager."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 0,
        callback_domain: str = "oob.local",
        persistence_path: Optional[Union[str, Path]] = None,
        max_body_bytes: int = 65536,
        log_dir: Optional[Union[str, Path]] = None,
    ):
        self.host = str(host or "127.0.0.1")
        self._requested_port = int(port)
        self.port = int(port)
        self.callback_domain = (callback_domain or "oob.local").strip().lower().rstrip(".")
        resolved_persistence: Optional[Path] = Path(persistence_path) if persistence_path else None
        if resolved_persistence is None and log_dir is not None:
            log_path = Path(log_dir)
            if log_path.suffix.lower() == ".json" and not log_path.is_dir():
                resolved_persistence = log_path
            else:
                resolved_persistence = log_path / "oob-state.json"
        self.log_dir: Optional[Path] = Path(log_dir) if log_dir is not None else (
            resolved_persistence.parent if resolved_persistence else None
        )
        self.persistence_path = resolved_persistence
        self.max_body_bytes = max(1024, int(max_body_bytes))

        self._lock = threading.RLock()
        self._condition = threading.Condition(self._lock)
        self._tokens: Dict[str, OOBToken] = {}
        self._callbacks: Dict[str, List[Dict[str, Any]]] = {}
        self._unmatched_hits: List[Dict[str, Any]] = []
        self._httpd: Optional[_QuietThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

        if self.persistence_path and self.persistence_path.is_file():
            self._load_state()

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._httpd is not None and self._thread is not None and self._thread.is_alive()

    @property
    def base_url(self) -> str:
        with self._lock:
            return f"http://{self.host}:{self.port}"

    def __enter__(self) -> "OOBServer":
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop()

    def start(self) -> int:
        """Start the HTTP loopback listener in a background thread and return bound port."""
        with self._lock:
            if self._httpd is not None:
                return self.port

            parent = self

            class _OOBRequestHandler(BaseHTTPRequestHandler):
                protocol_version = "HTTP/1.1"

                def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                    # Keep test and CLI output clean.
                    return

                def _handle_any(self) -> None:
                    length = 0
                    try:
                        length = int(self.headers.get("Content-Length", "0") or "0")
                    except ValueError:
                        length = 0
                    to_read = min(max(0, length), parent.max_body_bytes + 1)
                    raw_body = self.rfile.read(to_read) if to_read > 0 else b""
                    truncated = len(raw_body) > parent.max_body_bytes
                    raw_body = raw_body[: parent.max_body_bytes]

                    parsed = urllib.parse.urlparse(self.path)
                    if parsed.path.rstrip("/") == "/_dns" and self.command.upper() == "POST":
                        parent._handle_dns_webhook(raw_body, self.client_address[0] if self.client_address else "")
                        resp_bytes = b'{"status":"recorded"}'
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(resp_bytes)))
                        self.end_headers()
                        self.wfile.write(resp_bytes)
                        return

                    headers_dict = {str(k).lower(): str(v) for k, v in self.headers.items()}
                    body_text = raw_body.decode("utf-8", errors="replace")
                    remote_ip = self.client_address[0] if self.client_address else ""

                    parent._record_http_request(
                        method=self.command.upper(),
                        raw_path=self.path,
                        headers=headers_dict,
                        body=body_text,
                        body_truncated=truncated,
                        remote_addr=remote_ip,
                    )

                    path_lower = parsed.path.lower()
                    if path_lower.endswith(".js"):
                        ctype = "application/javascript; charset=utf-8"
                        payload = b"/* moros oob ok */"
                    elif path_lower.endswith((".xml", ".dtd")):
                        ctype = "application/xml; charset=utf-8"
                        payload = b"<!-- moros oob ok -->"
                    else:
                        ctype = "text/plain; charset=utf-8"
                        payload = b"ok"

                    self.send_response(200)
                    self.send_header("Content-Type", ctype)
                    self.send_header("Content-Length", str(len(payload)))
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.close_connection = True
                    if self.command.upper() != "HEAD":
                        self.wfile.write(payload)

                def do_GET(self) -> None:
                    self._handle_any()

                def do_POST(self) -> None:
                    self._handle_any()

                def do_PUT(self) -> None:
                    self._handle_any()

                def do_HEAD(self) -> None:
                    self._handle_any()

                def do_OPTIONS(self) -> None:
                    self._handle_any()

                def do_DELETE(self) -> None:
                    self._handle_any()

                def do_PATCH(self) -> None:
                    self._handle_any()

            httpd = _QuietThreadingHTTPServer((self.host, self._requested_port), _OOBRequestHandler)
            self.port = int(httpd.server_address[1])
            self._httpd = httpd
            thread = threading.Thread(target=httpd.serve_forever, name=f"oob-server-{self.port}", daemon=True)
            self._thread = thread
            thread.start()
            return self.port

    def stop(self) -> None:
        """Stop the HTTP loopback listener and join the server thread."""
        with self._lock:
            httpd = self._httpd
            thread = self._thread
            self._httpd = None
            self._thread = None

        if httpd is not None:
            try:
                httpd.shutdown()
            except Exception:
                pass
            try:
                httpd.server_close()
            except Exception:
                pass
        if thread is not None and thread.is_alive():
            thread.join(timeout=2.0)

    def register_token(
        self,
        skill: str,
        target: str,
        url: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> OOBToken:
        """Create and register a unique OOB canary token for correlation."""
        token_str = secrets.token_hex(12)
        with self._lock:
            while token_str in self._tokens:
                token_str = secrets.token_hex(12)

            callback_url = f"http://{self.host}:{self.port}/oob/{token_str}"
            dns_canary = f"{token_str}.{self.callback_domain}"
            token_obj = OOBToken(
                token=token_str,
                skill=str(skill or "").strip(),
                target=str(target or "").strip(),
                url=str(url or "").strip(),
                callback_url=callback_url,
                dns_canary=dns_canary,
                metadata=dict(metadata or {}),
            )
            self._tokens[token_str] = token_obj
            self._callbacks.setdefault(token_str, [])
            self._save_state_locked()
            return token_obj

    def get_token(self, token: Union[str, OOBToken]) -> Optional[OOBToken]:
        token_str = token.token if isinstance(token, OOBToken) else str(token)
        with self._lock:
            return self._tokens.get(token_str)

    def list_tokens(self, skill: Optional[str] = None) -> List[OOBToken]:
        with self._lock:
            tokens = list(self._tokens.values())
            if skill:
                skill_norm = skill.strip().lower()
                tokens = [t for t in tokens if t.skill.lower() == skill_norm]
            return tokens

    def poll_callbacks(
        self,
        token: Union[str, OOBToken],
        consume: bool = False,
    ) -> List[Dict[str, Any]]:
        """Return recorded callbacks for a token; optionally consume them."""
        token_str = token.token if isinstance(token, OOBToken) else str(token)
        with self._lock:
            events = list(self._callbacks.get(token_str, []))
            if consume and token_str in self._callbacks:
                self._callbacks[token_str] = []
                self._save_state_locked()
            return [dict(item) for item in events]

    def list_callbacks(
        self,
        token: Optional[Union[str, OOBToken]] = None,
        consume: bool = False,
    ) -> List[Dict[str, Any]]:
        """Alias for poll_callbacks(); when token is omitted, returns all recorded callbacks."""
        if token is not None:
            return self.poll_callbacks(token, consume=consume)
        with self._lock:
            all_events: List[Dict[str, Any]] = []
            for tok_str, events in self._callbacks.items():
                for item in events:
                    all_events.append(dict(item))
                if consume:
                    self._callbacks[tok_str] = []
            if consume:
                self._save_state_locked()
            return all_events

    def has_callbacks(self, token: Union[str, OOBToken]) -> bool:
        token_str = token.token if isinstance(token, OOBToken) else str(token)
        with self._lock:
            return bool(self._callbacks.get(token_str))

    def wait_for_callback(
        self,
        token: Union[str, OOBToken],
        timeout: float = 5.0,
    ) -> List[Dict[str, Any]]:
        """Block until at least one callback is recorded for token or timeout expires."""
        token_str = token.token if isinstance(token, OOBToken) else str(token)
        deadline = time.monotonic() + max(0.0, float(timeout))
        with self._condition:
            while not self._callbacks.get(token_str):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._condition.wait(timeout=remaining)
            return [dict(item) for item in self._callbacks.get(token_str, [])]

    def unmatched_callbacks(self) -> List[Dict[str, Any]]:
        """Return HTTP/DNS hits that did not match any registered token."""
        with self._lock:
            return [dict(item) for item in self._unmatched_hits]

    def record_dns_hit(
        self,
        query_name: str,
        query_type: str = "A",
        source_ip: str = "127.0.0.1",
        raw: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Correlate a DNS lookup for a canary subdomain and store it under its token."""
        qname = str(query_name or "").strip().lower().rstrip(".")
        matched_token = self._match_token_in_host(qname)
        event = {
            "token": matched_token,
            "protocol": "dns",
            "query_name": qname,
            "query_type": str(query_type or "A").upper(),
            "remote_addr": str(source_ip or ""),
            "received_at": _utc_iso(),
            "received_at_epoch": time.time(),
            "raw": dict(raw or {}),
        }
        with self._condition:
            if matched_token:
                self._callbacks.setdefault(matched_token, []).append(event)
                self._condition.notify_all()
            else:
                self._unmatched_hits.append(event)
            self._save_state_locked()
        return dict(event)

    def build_canary_templates(self, token_obj: OOBToken) -> Dict[str, str]:
        """Build benign loopback canary references for blind XSS, SSRF, and XXE verification."""
        cb_url = token_obj.callback_url
        dns_host = token_obj.dns_canary
        return {
            "xss-blind": f'<script src="{cb_url}.js"></script>',
            "ssrf-identify": cb_url,
            "ssrf-dns": f"http://{dns_host}/",
            "xxe-detect": (
                f'<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{cb_url}.dtd"> %xxe;]>'
            ),
        }

    def summarize_findings(self) -> List[Dict[str, Any]]:
        """Produce structured verification summaries for tokens that received callbacks."""
        with self._lock:
            summaries: List[Dict[str, Any]] = []
            for token_str, tok in self._tokens.items():
                events = self._callbacks.get(token_str, [])
                if not events:
                    continue
                protocols = sorted({str(ev.get("protocol", "http")) for ev in events})
                summaries.append({
                    "token": token_str,
                    "skill": tok.skill,
                    "target": tok.target,
                    "url": tok.url,
                    "callback_url": tok.callback_url,
                    "dns_canary": tok.dns_canary,
                    "confirmed": True,
                    "callback_count": len(events),
                    "protocols": protocols,
                    "first_seen": events[0].get("received_at"),
                    "last_seen": events[-1].get("received_at"),
                    "callbacks": [dict(ev) for ev in events],
                })
            return summaries

    def clear(self) -> None:
        """Clear all registered tokens, callbacks, and unmatched hits."""
        with self._condition:
            self._tokens.clear()
            self._callbacks.clear()
            self._unmatched_hits.clear()
            self._save_state_locked()
            self._condition.notify_all()

    def _handle_dns_webhook(self, raw_body: bytes, remote_ip: str) -> None:
        try:
            data = json.loads(raw_body.decode("utf-8", errors="replace") or "{}")
        except json.JSONDecodeError:
            data = {}
        if not isinstance(data, dict):
            data = {}
        qname = data.get("qname") or data.get("query_name") or data.get("host") or ""
        qtype = data.get("qtype") or data.get("query_type") or "A"
        src = data.get("source_ip") or remote_ip
        self.record_dns_hit(query_name=str(qname), query_type=str(qtype), source_ip=str(src), raw=data)

    def _record_http_request(
        self,
        method: str,
        raw_path: str,
        headers: Dict[str, str],
        body: str,
        body_truncated: bool,
        remote_addr: str,
    ) -> None:
        parsed = urllib.parse.urlparse(raw_path)
        query_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        host_header = headers.get("host", "")
        token_match = self._correlate_http_token(parsed.path, query_params, headers, body)
        protocol = "dns" if headers.get("x-oob-protocol", "").lower() == "dns" else "http"

        event = {
            "token": token_match,
            "protocol": protocol,
            "method": method,
            "path": parsed.path,
            "query": parsed.query,
            "query_params": query_params,
            "host": host_header,
            "headers": headers,
            "body": body,
            "body_bytes": len(body.encode("utf-8", errors="replace")),
            "body_truncated": body_truncated,
            "remote_addr": remote_addr,
            "received_at": _utc_iso(),
            "received_at_epoch": time.time(),
        }

        with self._condition:
            if token_match:
                self._callbacks.setdefault(token_match, []).append(event)
                self._condition.notify_all()
            else:
                self._unmatched_hits.append(event)
            self._save_state_locked()

    def _match_token_in_host(self, host_value: str) -> Optional[str]:
        host_only = str(host_value or "").split(":", 1)[0].strip().lower().rstrip(".")
        if not host_only:
            return None
        labels = [part for part in host_only.split(".") if part]
        with self._lock:
            for label in labels:
                if label in self._tokens:
                    return label
            for tok in self._tokens:
                if tok in host_only:
                    return tok
        return None

    def _correlate_http_token(
        self,
        path: str,
        query_params: Dict[str, List[str]],
        headers: Dict[str, str],
        body: str,
    ) -> Optional[str]:
        with self._lock:
            if not self._tokens:
                return None

            # 1. Path segments (supporting /oob/<token>, /oob/<token>.js, /<token>)
            for segment in (path or "").split("/"):
                seg = segment.strip()
                if not seg:
                    continue
                if seg in self._tokens:
                    return seg
                stem = seg.split(".", 1)[0]
                if stem in self._tokens:
                    return stem

            # 2. Query parameters (?token=<token> or any param value)
            for values in query_params.values():
                for val in values:
                    clean = str(val).strip()
                    if clean in self._tokens:
                        return clean
                    stem = clean.split(".", 1)[0]
                    if stem in self._tokens:
                        return stem

            # 3. Explicit X-OOB-Token header or Host subdomain canary
            explicit = headers.get("x-oob-token", "").strip()
            if explicit in self._tokens:
                return explicit

            host_match = self._match_token_in_host(headers.get("host", ""))
            if host_match:
                return host_match

            # 4. Fallback substring match in path, referer, or body
            referer = headers.get("referer", "")
            for tok in self._tokens:
                if tok in path or tok in referer or tok in body:
                    return tok

        return None

    def _save_state_locked(self) -> None:
        if not self.persistence_path:
            return
        try:
            self.persistence_path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "tokens": {k: v.to_dict() for k, v in self._tokens.items()},
                "callbacks": self._callbacks,
                "unmatched_hits": self._unmatched_hits,
            }
            self.persistence_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except OSError:
            pass

    def _load_state(self) -> None:
        try:
            data = json.loads(self.persistence_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(data, dict):
            return
        with self._lock:
            for tok_id, item in (data.get("tokens") or {}).items():
                if not isinstance(item, dict):
                    continue
                self._tokens[tok_id] = OOBToken(
                    token=str(item.get("token", tok_id)),
                    skill=str(item.get("skill", "")),
                    target=str(item.get("target", "")),
                    url=str(item.get("url", "")),
                    callback_url=str(item.get("callback_url", "")),
                    dns_canary=str(item.get("dns_canary", "")),
                    created_at=float(item.get("created_at", time.time())),
                    created_at_iso=str(item.get("created_at_iso", _utc_iso())),
                    metadata=dict(item.get("metadata") or {}),
                )
            for tok_id, events in (data.get("callbacks") or {}).items():
                if isinstance(events, list):
                    self._callbacks[tok_id] = list(events)
            unmatched = data.get("unmatched_hits")
            if isinstance(unmatched, list):
                self._unmatched_hits = list(unmatched)
