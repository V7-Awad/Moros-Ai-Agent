"""Bounded HTTP client for scope-enforced, HITL-gated assessment checks."""

import base64
import hashlib
import http.client
import http.cookiejar
import json
import math
import os
import re
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Union
try:
    from scope_validator import ScopeValidator
except ImportError:
    from tools.scope_validator import ScopeValidator


SAFE_METHODS = frozenset({"GET", "HEAD"})
STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_TRANSIENT_STATUS_CODES = frozenset({429, 502, 503, 504})
_ALLOWED_PROXY_SCHEMES = frozenset({"http", "https", "socks5"})
_USERINFO_IN_URL_RE = re.compile(r"((?:https?|socks5)://)[^/\s@]+@", re.IGNORECASE)
_SENSITIVE_HEADER_NAMES = frozenset({
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
})
_SENSITIVE_HEADER_KEYWORDS = (
    "auth",
    "token",
    "secret",
    "key",
    "cookie",
    "session",
    "password",
    "credential",
)


def redact_headers(headers: Optional[Dict[str, Any]]) -> Dict[str, str]:
    """Return a copy of headers with sensitive credential values masked."""
    redacted: Dict[str, str] = {}
    for key, value in (headers or {}).items():
        k_str = str(key)
        k_low = k_str.lower()
        if k_low in _SENSITIVE_HEADER_NAMES or any(word in k_low for word in _SENSITIVE_HEADER_KEYWORDS):
            redacted[k_str] = "[REDACTED]"
        else:
            redacted[k_str] = str(value)[:500]
    return redacted


def is_gated_post_enabled() -> bool:
    """Return True when MOROS_ALLOW_GATED_POST is explicitly enabled."""
    return os.environ.get("MOROS_ALLOW_GATED_POST", "").strip().lower() in {"1", "true", "yes"}


def check_checkpoint_approval(
    checkpoint_manager: Any,
    checkpoint_type: str,
    target_url: str,
    method: str = "POST",
    reason: str = "",
    risk_level: str = "MEDIUM",
) -> bool:
    """Verify HITL approval for a state-changing probe via CheckpointManager without hanging."""
    if not is_gated_post_enabled() or checkpoint_manager is None:
        return False

    method_clean = (method or "POST").upper()
    try:
        existing = checkpoint_manager.list_checkpoints()
    except Exception:
        existing = []

    for cp in existing:
        if (
            str(cp.get("method", "")).upper() == method_clean
            and cp.get("target_url") == target_url
        ):
            status = cp.get("status")
            if status == "APPROVED":
                return True
            if status == "REJECTED" and (not checkpoint_type or cp.get("type") == checkpoint_type):
                return False

    blocking = os.environ.get("MOROS_HITL_BLOCKING", "").strip().lower() in {"1", "true", "yes"}
    timeout = 60 if blocking else 0
    try:
        cp = checkpoint_manager.request_approval(
            checkpoint_type=checkpoint_type,
            target_url=target_url,
            method=method_clean,
            reason=reason,
            risk_level=risk_level,
            blocking=blocking,
            timeout_seconds=timeout,
        )
        return isinstance(cp, dict) and cp.get("status") == "APPROVED"
    except Exception:
        return False


def is_in_target_scope(host: str, target: str) -> bool:
    """Return True if host is the exact target or a direct subdomain/www-equivalent."""
    h = (host or "").lower().rstrip(".")
    t = (target or "").lower().rstrip(".")
    t_bare = t.removeprefix("www.")
    h_bare = h.removeprefix("www.")
    return h == t or h_bare == t_bare or h.endswith("." + t_bare)


def _redact_proxy_url(proxy_url: str) -> str:
    """Return proxy URL with any embedded userinfo credentials masked."""
    return _USERINFO_IN_URL_RE.sub(r"\1[REDACTED]@", str(proxy_url or ""))


def _normalize_proxy_url(proxy: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """Validate and normalize proxy URL, returning (internal_url, redacted_url)."""
    raw = (os.environ.get("MOROS_PROXY", "") if proxy is None else str(proxy)).strip()
    if not raw:
        return None, None
    if any(ch.isspace() or ord(ch) < 32 for ch in raw):
        raise ValueError("Proxy URL contains invalid whitespace or control characters")

    has_scheme = "://" in raw
    if not has_scheme:
        if any(ch in raw for ch in ("/", "?", "#")):
            raise ValueError("Proxy URL must use http://, https://, socks5://, or valid host:port")
        candidate = f"http://{raw}"
    else:
        candidate = raw

    parsed = urllib.parse.urlparse(candidate)
    scheme = (parsed.scheme or "").lower()
    if scheme not in _ALLOWED_PROXY_SCHEMES:
        raise ValueError(f"Unsupported proxy URL scheme '{scheme}'; allowed: http, https, socks5")

    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Proxy URL contains an invalid port") from exc

    host = parsed.hostname
    if not host:
        raise ValueError("Proxy URL must include a valid hostname")
    if port is not None and not (1 <= port <= 65535):
        raise ValueError("Proxy port must be between 1 and 65535")
    if not has_scheme and port is None:
        raise ValueError("Bare proxy host must include :port (e.g. 127.0.0.1:8080)")
    if parsed.path not in ("", "/") or parsed.params or parsed.query or parsed.fragment:
        raise ValueError("Proxy URL must not include path, query, or fragment components")

    host_fmt = f"[{host}]" if ":" in host else host
    host_port = f"{host_fmt}:{port}" if port is not None else host_fmt
    if parsed.username is not None or parsed.password is not None:
        normalized = f"{scheme}://{parsed.netloc}"
        redacted = f"{scheme}://[REDACTED]@{host_port}"
    else:
        normalized = f"{scheme}://{host_port}"
        redacted = normalized
    return normalized, redacted


def _get_header_ci(headers: Any, name: str) -> Optional[str]:
    """Return a header value by case-insensitive name lookup."""
    if not headers:
        return None
    target = name.lower()
    if hasattr(headers, "items"):
        for key, value in headers.items():
            if str(key).lower() == target:
                return str(value).strip()
    return None


def _is_transient_network_error(exc: BaseException) -> bool:
    """Return True for transient timeout/reset socket errors eligible for safe retry."""
    if isinstance(exc, (TimeoutError, socket.timeout, ConnectionResetError, BrokenPipeError)):
        return True
    if isinstance(exc, urllib.error.URLError):
        reason = getattr(exc, "reason", None)
        if isinstance(reason, (TimeoutError, socket.timeout, ConnectionResetError, BrokenPipeError)):
            return True
        if reason is not None and "timed out" in str(reason).lower():
            return True
    return "timed out" in str(exc).lower()


class _ExplicitProxyHandler(urllib.request.ProxyHandler):
    """ProxyHandler that routes traffic through an explicit proxy even on loopback targets."""

    def proxy_open(self, req, proxy, type):
        orig_type = req.type
        parsed = urllib.parse.urlparse(proxy if "://" in proxy else f"{type}://{proxy}")
        proxy_type = (parsed.scheme or orig_type).lower()
        if parsed.username is not None:
            user = urllib.parse.unquote(parsed.username)
            password = urllib.parse.unquote(parsed.password or "")
            creds = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
            req.add_header("Proxy-authorization", "Basic " + creds)
        host = parsed.hostname or ""
        host_fmt = f"[{host}]" if ":" in host else host
        hostport = f"{host_fmt}:{parsed.port}" if parsed.port is not None else host_fmt
        req.set_proxy(hostport, proxy_type)
        if orig_type == proxy_type or orig_type == "https":
            return None
        return self.parent.open(req, timeout=req.timeout)


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow redirects only when they remain on the exact configured host."""

    def __init__(self, target_host: str, on_blocked_redirect=None):
        super().__init__()
        self.target_host = target_host
        self.on_blocked_redirect = on_blocked_redirect

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlparse(newurl)
        redirect_host = (parsed.hostname or "").lower().rstrip(".")
        if (
            parsed.scheme in {"http", "https"}
            and redirect_host == self.target_host
            and parsed.port in {None, 80, 443}
        ):
            orig_method = req.get_method().upper()
            req_headers = dict(req.headers)
            if code in (301, 302, 303) and orig_method in STATE_CHANGING_METHODS:
                redirect_method = "GET"
                redirect_data = None
                req_headers = {
                    k: v for k, v in req_headers.items()
                    if k.lower() not in {"content-length", "content-type"}
                }
            else:
                redirect_method = orig_method
                redirect_data = getattr(req, "data", None)
            return urllib.request.Request(
                newurl,
                data=redirect_data,
                headers=req_headers,
                origin_req_host=req.origin_req_host,
                unverifiable=req.unverifiable,
                method=redirect_method,
            )
        if self.on_blocked_redirect:
            self.on_blocked_redirect({
                "from": urllib.parse.urlparse(req.full_url).hostname,
                "to": redirect_host,
                "status_code": code,
            })
        return None


class ScopedHttpClient:
    def __init__(self, target: str, max_requests: int = 150, delay_seconds: float = 0.3,
                 timeout_seconds: float = 15.0, max_body_bytes: int = 5_242_880,
                 auth_headers: Optional[Dict[str, str]] = None,
                 cookies: Optional[str] = None,
                 scope_validator: Optional[ScopeValidator] = None,
                 allow_state_changing: bool = False,
                 approval_callback: Optional[Callable[[str, str, str], bool]] = None,
                 proxy: Optional[str] = None,
                 max_retries: Optional[int] = None,
                 retry_backoff_seconds: float = 0.5,
                 max_retry_wait: float = 5.0,
                 enable_cookie_jar: Optional[bool] = None):
        parsed = urllib.parse.urlparse(target if "://" in target else f"https://{target}")
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("Target must be an HTTP(S) URL or hostname without credentials")
        if parsed.port not in {None, 80, 443}:
            raise ValueError("Custom target ports are disabled in the default HTTP policy")
        self.target = parsed.hostname.lower().rstrip(".")
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        self.max_requests = max(1, int(max_requests))
        self.delay_seconds = max(0.0, float(delay_seconds))
        self.timeout_seconds = max(1.0, float(timeout_seconds))
        self.max_body_bytes = max(1024, int(max_body_bytes))
        self.request_count = 0
        self._last_request_at = 0.0
        self._lock = threading.Lock()
        self._network_lock = threading.Lock()
        self.policy_violations: List[Dict[str, Any]] = []
        self.request_logs: List[Dict[str, Any]] = []
        self.stop_requested = False
        self.allow_state_changing = bool(allow_state_changing)
        self.approval_callback = approval_callback
        self._proxy_url, self.proxy = _normalize_proxy_url(proxy)

        if max_retries is None:
            raw_retries = os.environ.get("MOROS_HTTP_RETRIES", "").strip()
            if raw_retries:
                try:
                    self.max_retries = max(0, int(raw_retries))
                except ValueError:
                    self.max_retries = 2
            else:
                self.max_retries = 2
        else:
            self.max_retries = max(0, int(max_retries))
        self.retry_backoff_seconds = max(0.0, float(retry_backoff_seconds))
        self.max_retry_wait = max(0.0, float(max_retry_wait))

        if enable_cookie_jar is None:
            self.enable_cookie_jar = os.environ.get("MOROS_COOKIE_JAR", "").strip().lower() in {"1", "true", "yes"}
        else:
            self.enable_cookie_jar = bool(enable_cookie_jar)

        # Authentication & Session support
        self.auth_headers = dict(auth_headers or {})
        env_auth = os.environ.get("MOROS_AUTH_HEADER", "").strip()
        if env_auth and ":" in env_auth:
            k, v = env_auth.split(":", 1)
            self.auth_headers[k.strip()] = v.strip()

        self.cookies = cookies or os.environ.get("MOROS_AUTH_COOKIE", "").strip()
        self.scope_validator = scope_validator or ScopeValidator(self.target)
        policy = getattr(self.scope_validator, "policy", {})
        if policy.get("max_requests"):
            self.max_requests = min(self.max_requests, int(policy["max_requests"]))
        if policy.get("minimum_delay_seconds") is not None:
            self.delay_seconds = max(self.delay_seconds, float(policy["minimum_delay_seconds"]))
        if not policy.get("allow_authentication", True):
            # Respect scope restrictions even when credentials are present in the
            # user's environment; do not silently attach them to target requests.
            self.auth_headers.clear()
            self.cookies = ""
            self.enable_cookie_jar = False

        self.cookie_jar: Optional[http.cookiejar.CookieJar] = (
            http.cookiejar.CookieJar() if self.enable_cookie_jar else None
        )
        self._opener = self._build_opener()

    def _build_opener(self) -> urllib.request.OpenerDirector:
        handlers: List[Any] = [_SafeRedirectHandler(self.target, self._record_policy_violation)]
        if self._proxy_url:
            handlers.append(_ExplicitProxyHandler({"http": self._proxy_url, "https": self._proxy_url}))
        if self.cookie_jar is not None:
            handlers.append(urllib.request.HTTPCookieProcessor(self.cookie_jar))
        return urllib.request.build_opener(*handlers)

    def _redact_proxy_secrets(self, text: str) -> str:
        cleaned = _redact_proxy_url(text or "")
        if self._proxy_url and self.proxy and self._proxy_url != self.proxy:
            cleaned = cleaned.replace(self._proxy_url, self.proxy)
        return cleaned

    def _compute_retry_wait(self, attempt: int, retry_after_raw: Optional[str]) -> float:
        """Compute bounded wait time in seconds before the next retry attempt."""
        if retry_after_raw is not None:
            raw = retry_after_raw.strip()
            if raw:
                try:
                    parsed = float(raw)
                    if math.isfinite(parsed):
                        return min(max(0.0, parsed), self.max_retry_wait)
                except ValueError:
                    pass
        backoff = self.retry_backoff_seconds * (2 ** attempt)
        return min(max(0.0, backoff), self.max_retry_wait)

    def _build_attempt_outcome(
        self,
        method: str,
        status_code: int,
        response_url: str,
        headers: Any,
        body: bytes,
        started: float,
        attempt: int,
    ) -> tuple[Dict[str, Any], Optional[str], bool]:
        result = self._response_result(status_code, response_url, headers, body, started)
        result["retries"] = attempt
        retry_after_raw = _get_header_ci(headers, "Retry-After")
        should_retry = method in SAFE_METHODS and status_code in _TRANSIENT_STATUS_CODES
        return result, retry_after_raw, should_retry

    def get(self, url_or_path: str, headers: Optional[Dict[str, str]] = None,
            params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Convenience GET wrapper with optional extra headers."""
        return self.request(url_or_path, method="GET", params=params, extra_headers=headers)

    def _record_policy_violation(self, details: Dict[str, Any]) -> None:
        with self._lock:
            self.policy_violations.append({"kind": "blocked_redirect", **details})
            self.stop_requested = True

    def _record_request_log(
        self,
        method: str,
        url: str,
        headers: Dict[str, Any],
        body_bytes: Optional[bytes],
        result: Dict[str, Any],
        attempt: int = 0,
    ) -> None:
        parsed = urllib.parse.urlparse(url)
        safe_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
        entry: Dict[str, Any] = {
            "method": method,
            "url": safe_url,
            "headers": redact_headers(headers),
            "has_body": body_bytes is not None,
            "body_bytes": len(body_bytes) if body_bytes is not None else 0,
            "status": result.get("status"),
        }
        if self.proxy:
            entry["proxy"] = self.proxy
        if attempt > 0:
            entry["retry_attempt"] = attempt
        if result.get("headers"):
            entry["response_headers"] = redact_headers(result["headers"])
        if "status_code" in result:
            entry["status_code"] = result["status_code"]
        if "duration_s" in result:
            entry["duration_s"] = result["duration_s"]
        with self._lock:
            self.request_logs.append(entry)

    def head(self, url_or_path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Convenience HEAD wrapper."""
        return self.request(url_or_path, method="HEAD", params=params)

    def post(
        self,
        url_or_path: str,
        data: Optional[Union[str, bytes, Dict[str, Any]]] = None,
        json_body: Any = None,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Convenience POST wrapper gated by allow_state_changing and HITL approval."""
        merged_headers: Optional[Dict[str, str]] = None
        if headers or extra_headers:
            merged_headers = {}
            if headers:
                merged_headers.update(headers)
            if extra_headers:
                merged_headers.update(extra_headers)
        return self.request(
            url_or_path,
            method="POST",
            params=params,
            data=data,
            json_body=json_body,
            extra_headers=merged_headers,
        )

    @staticmethod
    def _encode_body(
        data: Optional[Union[str, bytes, Dict[str, Any]]],
        json_body: Any,
    ) -> tuple[Optional[bytes], Optional[str], str]:
        if json_body is not None and data is not None:
            raise ValueError("Cannot specify both 'data' and 'json_body'")
        if json_body is not None:
            raw_text = json.dumps(json_body, ensure_ascii=False)
            return raw_text.encode("utf-8"), "application/json", raw_text[:300]
        if data is None:
            return None, None, ""
        if isinstance(data, bytes):
            preview = data[:300].decode("utf-8", errors="replace")
            return data, None, preview
        if isinstance(data, dict):
            encoded = urllib.parse.urlencode(data, doseq=True)
            return encoded.encode("utf-8"), "application/x-www-form-urlencoded", encoded[:300]
        text_data = str(data)
        return text_data.encode("utf-8"), "text/plain; charset=utf-8", text_data[:300]

    def request(
        self,
        url_or_path: str,
        method: str = "GET",
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Union[str, bytes, Dict[str, Any]]] = None,
        json_body: Any = None,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        method = (method or "GET").upper()
        if self.stop_requested:
            return {"status": "blocked_scope", "reason": "The run stopped after a scope-policy violation."}

        if method in STATE_CHANGING_METHODS:
            if not self.allow_state_changing:
                reason = "Only GET and HEAD are allowed by the default policy."
                self._record_policy_violation({"kind": "blocked_method", "method": method, "reason": reason})
                return {"status": "blocked_scope", "reason": reason}
            if not getattr(self.scope_validator, "policy", {}).get("allow_active_vulnerability_checks", True):
                reason = "State-changing HTTP methods are disabled by the saved scope policy."
                self._record_policy_violation({"kind": "blocked_method", "method": method, "reason": reason})
                return {"status": "blocked_scope", "reason": reason}
        elif method not in SAFE_METHODS:
            reason = "Only GET and HEAD are allowed by the default policy."
            self._record_policy_violation({"kind": "blocked_method", "method": method, "reason": reason})
            return {"status": "blocked_scope", "reason": reason}

        if extra_headers:
            if not getattr(self.scope_validator, "policy", {}).get("allow_authentication", True):
                reason = "Custom headers are disabled by the saved scope policy."
                self._record_policy_violation({"kind": "blocked_custom_headers", "reason": reason})
                return {"status": "blocked_scope", "reason": reason}

        raw = str(url_or_path or "")
        url = urllib.parse.urljoin(self.base_url + "/", raw)
        parsed = urllib.parse.urlparse(url)

        # Check host and port
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.port not in {None, 80, 443}:
            reason = "Disallowed port or invalid URL scheme"
            self._record_policy_violation({"kind": "invalid_target_url", "url": url, "reason": reason})
            return {"status": "blocked_scope", "reason": reason}

        # Check strict scope rules
        allowed, reason = self.scope_validator.is_allowed(parsed.hostname)
        if not allowed:
            self._record_policy_violation({"kind": "blocked_host", "host": parsed.hostname, "reason": reason})
            return {"status": "blocked", "reason": reason}

        if params:
            query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
            query.extend((str(key), str(value)) for key, value in params.items())
            parsed = parsed._replace(query=urllib.parse.urlencode(query, doseq=True))
            url = urllib.parse.urlunparse(parsed)

        body_bytes, inferred_content_type, body_preview = self._encode_body(data, json_body)
        safe_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))

        if method in STATE_CHANGING_METHODS:
            if self.approval_callback is None or not callable(self.approval_callback):
                reason = f"HITL approval_callback is required for {method} requests."
                self._record_policy_violation({
                    "kind": "unapproved_state_changing",
                    "method": method,
                    "url": safe_url,
                    "reason": reason,
                })
                return {"status": "blocked_scope", "reason": reason}
            try:
                approved = bool(self.approval_callback(method, url, body_preview))
            except Exception:
                approved = False
            if not approved:
                reason = f"HITL approval denied for {method} {safe_url}."
                self._record_policy_violation({
                    "kind": "hitl_rejected",
                    "method": method,
                    "url": safe_url,
                    "reason": reason,
                })
                return {"status": "blocked_scope", "reason": reason}

        headers: Dict[str, str] = {"User-Agent": "MorosAI/1.0 (authorized assessment; non-destructive checks)"}
        bug_bounty_id = os.environ.get("MOROS_BUG_BOUNTY_ID", "").strip()
        if bug_bounty_id:
            headers["X-Bug-Bounty"] = bug_bounty_id

        # Attach custom authentication headers
        if self.auth_headers:
            headers.update(self.auth_headers)

        if extra_headers:
            headers.update(extra_headers)

        # Attach session cookies
        if self.cookies:
            headers["Cookie"] = self.cookies

        if inferred_content_type and not any(k.lower() == "content-type" for k in headers):
            headers["Content-Type"] = inferred_content_type

        allowed_retries = self.max_retries if method in SAFE_METHODS else 0
        result: Dict[str, Any] = {}
        for attempt in range(allowed_retries + 1):
            should_retry = False
            retry_after_raw: Optional[str] = None
            with self._network_lock:
                if self.stop_requested:
                    return {"status": "blocked_scope", "reason": "The run stopped after a scope-policy violation."}
                with self._lock:
                    if self.request_count >= self.max_requests:
                        if attempt == 0:
                            return {"status": "budget_exhausted", "reason": f"Request budget ({self.max_requests}) exhausted."}
                        return result
                    wait_for = self.delay_seconds - (time.monotonic() - self._last_request_at)
                    if wait_for > 0:
                        time.sleep(wait_for)
                    self.request_count += 1
                    self._last_request_at = time.monotonic()

                request = urllib.request.Request(url, data=body_bytes, headers=headers, method=method)
                started = time.monotonic()
                try:
                    with self._opener.open(request, timeout=self.timeout_seconds) as response:
                        body = b"" if method == "HEAD" else response.read(self.max_body_bytes + 1)
                        result, retry_after_raw, should_retry = self._build_attempt_outcome(
                            method, response.status, response.geturl(), response.headers, body, started, attempt
                        )
                except urllib.error.HTTPError as response:
                    try:
                        body = b"" if method == "HEAD" else response.read(self.max_body_bytes + 1)
                    except Exception:
                        body = b""
                    try:
                        result, retry_after_raw, should_retry = self._build_attempt_outcome(
                            method, response.code, response.geturl(), response.headers, body, started, attempt
                        )
                    finally:
                        try:
                            response.close()
                        except Exception:
                            pass
                except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException) as exc:
                    err_text = self._redact_proxy_secrets(str(getattr(exc, "reason", exc)))[:300]
                    result = {
                        "status": "network_error",
                        "url": url,
                        "method": method,
                        "error": err_text,
                        "duration_s": round(time.monotonic() - started, 3),
                        "retries": attempt,
                    }
                    should_retry = method in SAFE_METHODS and _is_transient_network_error(exc)

                logged_headers = dict(headers)
                existing_lower = {k.lower() for k in logged_headers}
                for hdr_name, hdr_val in request.header_items():
                    if hdr_name.lower() not in existing_lower:
                        logged_headers[hdr_name] = hdr_val
                        existing_lower.add(hdr_name.lower())
                self._record_request_log(method, url, logged_headers, body_bytes, result, attempt=attempt)

            if not should_retry or attempt >= allowed_retries or self.stop_requested:
                return result
            with self._lock:
                if self.request_count >= self.max_requests:
                    return result
            retry_wait = self._compute_retry_wait(attempt, retry_after_raw)
            if retry_wait > 0:
                time.sleep(retry_wait)

        return result

    def record_external_requests(self, count: int) -> None:
        """Account for requests made by an equally scoped browser worker."""
        count = max(0, int(count))
        with self._lock:
            if self.request_count + count > self.max_requests:
                raise RuntimeError("External worker exceeded the shared HTTP request budget")
            self.request_count += count

    def _response_result(self, status_code: int, url: str, headers: Any, body: bytes, started: float) -> Dict[str, Any]:
        truncated = len(body) > self.max_body_bytes
        body = body[:self.max_body_bytes]
        allowed_headers = {
            "content-type", "server", "strict-transport-security",
            "content-security-policy", "x-content-type-options",
            "x-frame-options", "referrer-policy",
            # CORS audit headers
            "access-control-allow-origin", "access-control-allow-credentials",
            "access-control-allow-methods", "access-control-allow-headers",
            "access-control-expose-headers", "access-control-max-age",
            # Redirect & auth
            "location", "www-authenticate",
            # Session & cookies
            "set-cookie",
            # Rate limiting headers
            "retry-after", "x-ratelimit-limit", "x-ratelimit-remaining",
            "x-ratelimit-reset", "ratelimit-limit", "ratelimit-remaining",
            "ratelimit-reset",
            # Security & fingerprinting
            "x-powered-by", "x-xss-protection", "permissions-policy",
            "cross-origin-opener-policy", "cross-origin-embedder-policy",
            "cross-origin-resource-policy",
        }
        parsed = urllib.parse.urlparse(url)
        safe_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
        return {
            "status": "response", "status_code": status_code, "url": safe_url,
            "headers": {str(key).lower(): str(value)[:500] for key, value in headers.items()
                        if str(key).lower() in allowed_headers},
            "body": body.decode("utf-8", errors="replace"),
            "body_bytes": len(body), "body_truncated": truncated,
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "duration_s": round(time.monotonic() - started, 3),
        }
