"""Bounded HTTP client for non-destructive, same-host assessment checks."""

import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Do not silently follow redirects outside the selected assessment host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class ScopedHttpClient:
    def __init__(self, target: str, max_requests: int = 40, delay_seconds: float = 0.4,
                 timeout_seconds: float = 8.0, max_body_bytes: int = 512_000):
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
        self._opener = urllib.request.build_opener(_NoRedirect())

    def request(self, url_or_path: str, method: str = "GET", params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        method = method.upper()
        if method not in {"GET", "HEAD"}:
            return {"status": "blocked", "reason": "Only GET and HEAD are allowed by the default policy."}

        raw = str(url_or_path or "")
        url = urllib.parse.urljoin(self.base_url + "/", raw)
        parsed = urllib.parse.urlparse(url)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.hostname.lower().rstrip(".") != self.target
                or parsed.username or parsed.password or parsed.port not in {None, 80, 443}):
            return {"status": "blocked", "reason": "URL is outside the exact target host or uses a disallowed port."}

        if params:
            query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
            query.extend((str(key), str(value)) for key, value in params.items())
            parsed = parsed._replace(query=urllib.parse.urlencode(query, doseq=True))
            url = urllib.parse.urlunparse(parsed)

        with self._lock:
            if self.request_count >= self.max_requests:
                return {"status": "budget_exhausted", "reason": f"Request budget ({self.max_requests}) exhausted."}
            wait_for = self.delay_seconds - (time.monotonic() - self._last_request_at)
            if wait_for > 0:
                time.sleep(wait_for)
            self.request_count += 1
            self._last_request_at = time.monotonic()

        headers = {"User-Agent": "MorosAI/1.0 (authorized assessment; non-destructive checks)"}
        bug_bounty_id = os.environ.get("MOROS_BUG_BOUNTY_ID", "").strip()
        if bug_bounty_id:
            headers["X-Bug-Bounty"] = bug_bounty_id
        request = urllib.request.Request(url, headers=headers, method=method)
        started = time.monotonic()
        try:
            with self._opener.open(request, timeout=self.timeout_seconds) as response:
                body = b"" if method == "HEAD" else response.read(self.max_body_bytes + 1)
                return self._response_result(response.status, response.url, response.headers, body, started)
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

    def _response_result(self, status_code: int, url: str, headers: Any, body: bytes, started: float) -> Dict[str, Any]:
        truncated = len(body) > self.max_body_bytes
        body = body[:self.max_body_bytes]
        return {
            "status": "response", "status_code": status_code, "url": url,
            "headers": {str(key).lower(): str(value)[:500] for key, value in headers.items()},
            "body": body.decode("utf-8", errors="replace"),
            "body_bytes": len(body), "body_truncated": truncated,
            "duration_s": round(time.monotonic() - started, 3),
        }
