"""Bounded HTTP client for non-destructive, same-host assessment checks."""

import os
import hashlib
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional
try:
    from scope_validator import ScopeValidator
except ImportError:
    from tools.scope_validator import ScopeValidator


def is_in_target_scope(host: str, target: str) -> bool:
    """Return True if host is the exact target or a direct subdomain/www-equivalent."""
    h = (host or "").lower().rstrip(".")
    t = (target or "").lower().rstrip(".")
    t_bare = t.removeprefix("www.")
    h_bare = h.removeprefix("www.")
    return h == t or h_bare == t_bare or h.endswith("." + t_bare)


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow redirects only when they remain on the exact configured host."""

    def __init__(self, target_host: str, on_blocked_redirect=None):
        super().__init__()
        self.target_host = target_host
        self.on_blocked_redirect = on_blocked_redirect

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlparse(newurl)
        redirect_host = (parsed.hostname or "").lower().rstrip(".")
        if parsed.scheme in {"http", "https"} and redirect_host == self.target_host:
            return urllib.request.Request(
                newurl,
                headers=dict(req.headers),
                origin_req_host=req.origin_req_host,
                unverifiable=req.unverifiable,
                method=req.get_method(),
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
                 scope_validator: Optional[ScopeValidator] = None):
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
        self.stop_requested = False
        self._opener = urllib.request.build_opener(
            _SafeRedirectHandler(self.target, self._record_policy_violation)
        )

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

    def get(self, url_or_path: str, headers: Optional[Dict[str, str]] = None,
            params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Convenience GET wrapper with optional extra headers."""
        if headers:
            if not getattr(self.scope_validator, "policy", {}).get("allow_authentication", True):
                self._record_policy_violation({"kind": "blocked_custom_headers", "reason": "Custom headers disabled by saved scope policy."})
                return {"status": "blocked_scope", "reason": "Custom headers are disabled by the saved scope policy."}
            saved = dict(self.auth_headers)
            self.auth_headers.update(headers)
            result = self.request(url_or_path, method="GET", params=params)
            self.auth_headers = saved
            return result
        return self.request(url_or_path, method="GET", params=params)

    def _record_policy_violation(self, details: Dict[str, Any]) -> None:
        with self._lock:
            self.policy_violations.append({"kind": "blocked_redirect", **details})
            self.stop_requested = True

    def head(self, url_or_path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Convenience HEAD wrapper."""
        return self.request(url_or_path, method="HEAD", params=params)

    def request(self, url_or_path: str, method: str = "GET", params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        method = method.upper()
        if self.stop_requested:
            return {"status": "blocked_scope", "reason": "The run stopped after a scope-policy violation."}
        if method not in {"GET", "HEAD"}:
            reason = "Only GET and HEAD are allowed by the default policy."
            self._record_policy_violation({"kind": "blocked_method", "method": method, "reason": reason})
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

        headers = {"User-Agent": "MorosAI/1.0 (authorized assessment; non-destructive checks)"}
        bug_bounty_id = os.environ.get("MOROS_BUG_BOUNTY_ID", "").strip()
        if bug_bounty_id:
            headers["X-Bug-Bounty"] = bug_bounty_id

        # Attach custom authentication headers
        if self.auth_headers:
            headers.update(self.auth_headers)

        # Attach session cookies
        if self.cookies:
            headers["Cookie"] = self.cookies
        request = urllib.request.Request(url, headers=headers, method=method)
        with self._network_lock:
            if self.stop_requested:
                return {"status": "blocked_scope", "reason": "The run stopped after a scope-policy violation."}
            with self._lock:
                if self.request_count >= self.max_requests:
                    return {"status": "budget_exhausted", "reason": f"Request budget ({self.max_requests}) exhausted."}
                wait_for = self.delay_seconds - (time.monotonic() - self._last_request_at)
                if wait_for > 0:
                    time.sleep(wait_for)
                self.request_count += 1
                self._last_request_at = time.monotonic()
            started = time.monotonic()
            try:
                with self._opener.open(request, timeout=self.timeout_seconds) as response:
                    body = b"" if method == "HEAD" else response.read(self.max_body_bytes + 1)
                    return self._response_result(response.status, response.geturl(), response.headers, body, started)
            except urllib.error.HTTPError as response:
                try:
                    body = b"" if method == "HEAD" else response.read(self.max_body_bytes + 1)
                except Exception:
                    body = b""
                return self._response_result(response.code, response.geturl(), response.headers, body, started)
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                return {
                    "status": "network_error", "url": url, "method": method,
                    "error": str(getattr(exc, "reason", exc))[:300],
                    "duration_s": round(time.monotonic() - started, 3),
                }

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
