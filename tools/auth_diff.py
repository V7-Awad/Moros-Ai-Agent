#!/usr/bin/env python3
"""
auth_diff.py — Dual-Session & Multi-Role Authorization Diffing for Moros AI.

Compares HTTP responses across User A (owner/primary), User B (secondary peer or
lower-privilege role), and Unauthenticated sessions using ScopedHttpClient and
ScopeValidator to detect BOLA/IDOR and Broken Access Control without ever
bypassing target scope boundaries or policy restrictions.
"""

from dataclasses import dataclass, field
import difflib
import json
import re
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple
import urllib.parse

try:
    from tools.scope_validator import ScopeValidator
    from tools.scoped_http import ScopedHttpClient
except ImportError:
    from scope_validator import ScopeValidator
    from scoped_http import ScopedHttpClient


_ISO_TIMESTAMP_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"
)
_VOLATILE_JSON_KEYS = {
    "timestamp",
    "created_at",
    "updated_at",
    "server_time",
    "request_id",
    "trace_id",
    "correlation_id",
    "elapsed_ms",
    "duration_ms",
    "nonce",
    "csrf_token",
}
_LOGIN_INDICATORS = (
    "type=\"password\"",
    "type='password'",
    "name=\"password\"",
    "name='password'",
    "sign in",
    "log in",
    "login required",
    "authentication required",
    "unauthorized",
)


@dataclass
class SessionContext:
    """Represents one authenticated or unauthenticated testing session/role."""

    name: str
    role: str = "user"
    auth_headers: Dict[str, str] = field(default_factory=dict)
    cookies: str = ""
    owned_ids: List[str] = field(default_factory=list)
    client: Optional[Any] = None

    @property
    def is_authenticated(self) -> bool:
        return bool(self.auth_headers or (self.cookies or "").strip())


def _normalize_json_value(obj: Any) -> Any:
    if isinstance(obj, dict):
        cleaned = {}
        for key in sorted(obj.keys(), key=lambda k: str(k)):
            key_lower = str(key).lower()
            if key_lower in _VOLATILE_JSON_KEYS:
                cleaned[str(key)] = "<volatile>"
            else:
                cleaned[str(key)] = _normalize_json_value(obj[key])
        return cleaned
    if isinstance(obj, list):
        return [_normalize_json_value(item) for item in obj]
    if isinstance(obj, str):
        return _ISO_TIMESTAMP_RE.sub("<timestamp>", obj)
    return obj


def _flatten_json_keys(obj: Any, prefix: str = "") -> set:
    keys = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else str(k)
            keys.add(path)
            keys.update(_flatten_json_keys(v, path))
    elif isinstance(obj, list) and obj:
        keys.update(_flatten_json_keys(obj[0], f"{prefix}[]"))
    return keys


def normalize_response_body(body: str, content_type: str = "") -> str:
    """Normalize volatile tokens/timestamps before comparing two response bodies."""
    raw = str(body or "")
    if not raw:
        return ""

    stripped = raw.strip()
    is_json = "json" in (content_type or "").lower() or stripped.startswith(("{", "["))
    if is_json:
        try:
            parsed = json.loads(stripped)
            normalized = _normalize_json_value(parsed)
            return json.dumps(normalized, sort_keys=True, separators=(",", ":"))
        except (json.JSONDecodeError, TypeError, ValueError):
            pass

    text = _ISO_TIMESTAMP_RE.sub("<timestamp>", stripped)
    text = re.sub(r"\s+", " ", text)
    return text


def compute_response_similarity(
    body_a: str,
    body_b: str,
    content_type_a: str = "",
    content_type_b: str = "",
) -> float:
    """Compute a normalized [0.0, 1.0] similarity ratio between two HTTP bodies."""
    norm_a = normalize_response_body(body_a, content_type_a)[:50_000]
    norm_b = normalize_response_body(body_b, content_type_b)[:50_000]
    if not norm_a and not norm_b:
        return 1.0
    if not norm_a or not norm_b:
        return 0.0
    if norm_a == norm_b:
        return 1.0

    seq_ratio = difflib.SequenceMatcher(None, norm_a, norm_b).ratio()

    # For JSON responses, blend structural key overlap to distinguish same-schema
    # per-user profiles (low value overlap) vs identical resource leaks.
    if norm_a.startswith(("{", "[")) and norm_b.startswith(("{", "[")):
        try:
            obj_a = json.loads(norm_a)
            obj_b = json.loads(norm_b)
            keys_a = _flatten_json_keys(obj_a)
            keys_b = _flatten_json_keys(obj_b)
            if keys_a and keys_b:
                key_jaccard = len(keys_a & keys_b) / len(keys_a | keys_b)
                if key_jaccard < 0.5:
                    return round(min(seq_ratio, key_jaccard), 4)
        except (json.JSONDecodeError, TypeError, ValueError):
            pass

    return round(seq_ratio, 4)


def _looks_like_login_or_error_page(resp: Dict[str, Any], baseline_resp: Dict[str, Any]) -> bool:
    """Return True when a 2xx response looks like a login shell or auth error."""
    url = str(resp.get("url", "")).lower()
    baseline_url = str(baseline_resp.get("url", "")).lower()
    if url != baseline_url and any(tok in url for tok in ("/login", "/signin", "/auth", "/sso")):
        return True

    body = str(resp.get("body", "")).lower()
    ctype = str((resp.get("headers") or {}).get("content-type", "")).lower()
    baseline_ctype = str((baseline_resp.get("headers") or {}).get("content-type", "")).lower()

    if "json" in baseline_ctype and "html" in ctype:
        return True

    if any(indicator in body for indicator in _LOGIN_INDICATORS) and "password" in body:
        return True

    stripped = body.strip()
    if stripped.startswith("{"):
        try:
            parsed = json.loads(stripped)
            if isinstance(parsed, dict) and set(parsed.keys()) <= {"error", "message", "detail", "status", "ok"}:
                if parsed.get("ok") is False or parsed.get("error") or "unauthorized" in str(parsed).lower() or "forbidden" in str(parsed).lower():
                    return True
        except (json.JSONDecodeError, TypeError, ValueError):
            pass
    return False


def _is_success_response(resp: Dict[str, Any]) -> bool:
    if not isinstance(resp, dict) or resp.get("status") != "response":
        return False
    code = int(resp.get("status_code") or 0)
    return 200 <= code < 300


def _is_denied_response(resp: Dict[str, Any]) -> bool:
    if not isinstance(resp, dict) or resp.get("status") != "response":
        return False
    code = int(resp.get("status_code") or 0)
    return code in {401, 403, 404, 410}


def _summarize_session_response(resp: Dict[str, Any]) -> Dict[str, Any]:
    headers = resp.get("headers") or {}
    body = str(resp.get("body", ""))
    return {
        "status": resp.get("status"),
        "status_code": resp.get("status_code"),
        "url": resp.get("url"),
        "content_type": headers.get("content-type", ""),
        "body_bytes": resp.get("body_bytes", len(body.encode("utf-8", errors="replace"))),
        "body_sha256": resp.get("body_sha256", ""),
        "body_preview": body[:200],
        "reason": resp.get("reason", ""),
    }


def _contains_owned_ids(body: str, owned_ids: Iterable[str]) -> List[str]:
    text = str(body or "")
    if not text:
        return []
    matched: List[str] = []
    for oid in owned_ids:
        val = str(oid or "").strip()
        if not val:
            continue
        # Use boundary-aware search when identifier is short/numeric so "1" doesn't match "2001".
        if len(val) <= 4 and val.isdigit():
            if re.search(rf"(?<![0-9a-zA-Z_]){re.escape(val)}(?![0-9a-zA-Z_])", text):
                matched.append(val)
        elif val in text:
            matched.append(val)
    return matched


class AuthDiffChecker:
    """
    Compare HTTP responses across User A, User B, and Unauthenticated sessions
    using ScopedHttpClient and ScopeValidator without bypassing scope.
    """

    def __init__(
        self,
        target: str,
        scope_validator: Optional[ScopeValidator] = None,
        user_a: Optional[SessionContext] = None,
        user_b: Optional[SessionContext] = None,
        unauthenticated: Optional[SessionContext] = None,
        extra_sessions: Optional[List[SessionContext]] = None,
        max_requests_per_session: int = 50,
        delay_seconds: float = 0.2,
        timeout_seconds: float = 15.0,
        similarity_threshold: float = 0.85,
        client_factory: Optional[Callable[[SessionContext], Any]] = None,
    ):
        parsed = urllib.parse.urlparse(target if "://" in target else f"https://{target}")
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("Target must be an HTTP(S) URL or hostname without credentials")
        if parsed.port not in {None, 80, 443}:
            raise ValueError("Custom target ports are disabled in the default HTTP policy")

        self.target = parsed.hostname.lower().rstrip(".")
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        self.scope_validator = scope_validator or ScopeValidator(self.target)
        self.max_requests_per_session = max(1, int(max_requests_per_session))
        self.delay_seconds = max(0.0, float(delay_seconds))
        self.timeout_seconds = max(1.0, float(timeout_seconds))
        self.similarity_threshold = min(1.0, max(0.1, float(similarity_threshold)))
        self._client_factory = client_factory

        self.sessions: Dict[str, SessionContext] = {}
        self.clients: Dict[str, Any] = {}

        default_user_a = user_a or SessionContext(name="user_a", role="owner")
        default_user_b = user_b or SessionContext(name="user_b", role="peer")
        default_unauth = unauthenticated or SessionContext(name="unauthenticated", role="unauthenticated")

        # Never allow credentials on the unauthenticated baseline context.
        default_unauth = SessionContext(
            name=default_unauth.name or "unauthenticated",
            role="unauthenticated",
            auth_headers={},
            cookies="",
            owned_ids=[],
            client=default_unauth.client,
        )

        ordered_sessions = [default_user_a, default_user_b, default_unauth]
        if extra_sessions:
            ordered_sessions.extend(extra_sessions)

        for sess in ordered_sessions:
            self.sessions[sess.name] = sess
            self.clients[sess.name] = self._build_client_for_session(sess)

    def _build_client_for_session(self, session: SessionContext) -> Any:
        if session.client is not None:
            client = session.client
            # Enforce the shared scope_validator if the injected client supports it.
            if hasattr(client, "scope_validator") and client.scope_validator is not self.scope_validator:
                client.scope_validator = self.scope_validator
            if session.role == "unauthenticated" or session.name == "unauthenticated":
                if hasattr(client, "auth_headers") and isinstance(client.auth_headers, dict):
                    client.auth_headers.clear()
                if hasattr(client, "cookies"):
                    client.cookies = ""
            return client

        if self._client_factory is not None:
            return self._client_factory(session)

        client = ScopedHttpClient(
            target=self.base_url,
            max_requests=self.max_requests_per_session,
            delay_seconds=self.delay_seconds,
            timeout_seconds=self.timeout_seconds,
            auth_headers=dict(session.auth_headers) if session.role != "unauthenticated" else {},
            cookies=session.cookies if session.role != "unauthenticated" else "",
            scope_validator=self.scope_validator,
        )
        # Ensure env-var credentials (MOROS_AUTH_HEADER / MOROS_AUTH_COOKIE) never
        # leak into the unauthenticated baseline client or overwrite explicit contexts.
        if session.role == "unauthenticated" or session.name == "unauthenticated":
            client.auth_headers.clear()
            client.cookies = ""
        elif session.auth_headers or session.cookies:
            client.auth_headers = dict(session.auth_headers)
            client.cookies = session.cookies
            if not getattr(self.scope_validator, "policy", {}).get("allow_authentication", True):
                client.auth_headers.clear()
                client.cookies = ""
        return client

    def is_url_allowed(self, url_or_path: str) -> Tuple[bool, str]:
        """Validate URL scheme, port, and ScopeValidator rules before any request."""
        raw = str(url_or_path or "").strip()
        if not raw:
            return False, "URL or path is empty"
        full_url = urllib.parse.urljoin(self.base_url + "/", raw)
        parsed = urllib.parse.urlparse(full_url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.port not in {None, 80, 443}
        ):
            return False, "Disallowed port or invalid URL scheme"
        return self.scope_validator.is_allowed(parsed.hostname)

    def check_endpoint(
        self,
        url_or_path: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        owner_session: str = "user_a",
    ) -> Dict[str, Any]:
        """Request one endpoint across all configured sessions and diff authorization."""
        full_url = urllib.parse.urljoin(self.base_url + "/", str(url_or_path or "").strip())
        allowed, reason = self.is_url_allowed(full_url)
        if not allowed:
            return {
                "url": full_url,
                "vulnerable": False,
                "finding_type": "scope_blocked",
                "severity": "INFO",
                "cwe": "",
                "title": f"Scope blocked for {full_url}",
                "description": reason,
                "confidence": "high",
                "similarity_user_a_vs_b": None,
                "similarity_user_a_vs_unauth": None,
                "responses": {},
                "evidence": {"scope_reason": reason},
                "status": "blocked_scope",
                "validation_status": "blocked_scope",
            }

        policy = getattr(self.scope_validator, "policy", {})
        if not policy.get("allow_authentication", True):
            return {
                "url": full_url,
                "vulnerable": False,
                "finding_type": "scope_blocked",
                "severity": "INFO",
                "cwe": "",
                "title": f"Authenticated diffing disabled by scope policy for {full_url}",
                "description": "Scope policy sets allow_authentication=False; multi-session auth diffing is skipped.",
                "confidence": "high",
                "similarity_user_a_vs_b": None,
                "similarity_user_a_vs_unauth": None,
                "responses": {},
                "evidence": {"policy_allow_authentication": False},
                "status": "blocked_scope",
                "validation_status": "blocked_scope",
            }

        responses: Dict[str, Dict[str, Any]] = {}
        for name, sess in self.sessions.items():
            client = self.clients[name]
            extra_headers = headers if (headers and sess.role != "unauthenticated") else None
            responses[name] = client.get(full_url, headers=extra_headers, params=params)

        owner_ctx = self.sessions.get(owner_session)
        owner_ids = owner_ctx.owned_ids if owner_ctx else []
        return self.compare_responses(
            url=full_url,
            responses=responses,
            owner_session=owner_session,
            owner_ids=owner_ids,
        )

    def compare_responses(
        self,
        url: str,
        responses: Dict[str, Dict[str, Any]],
        owner_session: str = "user_a",
        owner_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Analyze session responses and classify BOLA/IDOR or Broken Access Control."""
        summarized = {name: _summarize_session_response(resp) for name, resp in responses.items()}

        blocked = [
            (name, resp)
            for name, resp in responses.items()
            if resp.get("status") in {"blocked", "blocked_scope"}
        ]
        if blocked:
            first_name, first_resp = blocked[0]
            return {
                "url": url,
                "vulnerable": False,
                "finding_type": "scope_blocked",
                "severity": "INFO",
                "cwe": "",
                "title": f"Scope blocked during {first_name} request to {url}",
                "description": str(first_resp.get("reason") or "Request blocked by scope policy"),
                "confidence": "high",
                "similarity_user_a_vs_b": None,
                "similarity_user_a_vs_unauth": None,
                "responses": summarized,
                "evidence": {"blocked_session": first_name, "reason": first_resp.get("reason", "")},
                "status": "blocked_scope",
                "validation_status": "blocked_scope",
            }

        budget_hit = [
            name for name, resp in responses.items() if resp.get("status") == "budget_exhausted"
        ]
        if budget_hit:
            return {
                "url": url,
                "vulnerable": False,
                "finding_type": "budget_exhausted",
                "severity": "INFO",
                "cwe": "",
                "title": f"HTTP budget exhausted on {url}",
                "description": f"Session(s) {', '.join(budget_hit)} exhausted request budget.",
                "confidence": "low",
                "similarity_user_a_vs_b": None,
                "similarity_user_a_vs_unauth": None,
                "responses": summarized,
                "evidence": {"budget_exhausted_sessions": budget_hit},
                "status": "budget_exhausted",
                "validation_status": "inconclusive",
            }

        peer_session = "user_b" if owner_session != "user_b" else "user_a"
        resp_a = responses.get(owner_session, {})
        resp_b = responses.get(peer_session, {})
        resp_unauth = responses.get("unauthenticated", {})

        ctype_a = str((resp_a.get("headers") or {}).get("content-type", ""))
        ctype_b = str((resp_b.get("headers") or {}).get("content-type", ""))
        ctype_u = str((resp_unauth.get("headers") or {}).get("content-type", ""))

        sim_ab: Optional[float] = None
        sim_au: Optional[float] = None
        if _is_success_response(resp_a) and _is_success_response(resp_b):
            sim_ab = compute_response_similarity(
                resp_a.get("body", ""), resp_b.get("body", ""), ctype_a, ctype_b
            )
        if _is_success_response(resp_a) and _is_success_response(resp_unauth):
            sim_au = compute_response_similarity(
                resp_a.get("body", ""), resp_unauth.get("body", ""), ctype_a, ctype_u
            )

        a_ok = _is_success_response(resp_a) and not _looks_like_login_or_error_page(resp_a, resp_a)
        b_ok = _is_success_response(resp_b) and not _looks_like_login_or_error_page(resp_b, resp_a)
        u_ok = _is_success_response(resp_unauth) and not _looks_like_login_or_error_page(resp_unauth, resp_a)

        # Case 1: Unauthenticated request succeeded with equivalent content -> Broken Access Control.
        if a_ok and u_ok and sim_au is not None and sim_au >= self.similarity_threshold:
            return {
                "url": url,
                "vulnerable": True,
                "finding_type": "broken_access_control",
                "severity": "HIGH",
                "cwe": "CWE-862",
                "title": f"Missing / Broken Access Control on {url}",
                "description": (
                    f"Unauthenticated request returned HTTP {resp_unauth.get('status_code')} "
                    f"with {sim_au:.0%} body similarity to authenticated {owner_session}."
                ),
                "confidence": "high" if sim_au >= 0.95 else "medium",
                "similarity_user_a_vs_b": sim_ab,
                "similarity_user_a_vs_unauth": sim_au,
                "responses": summarized,
                "evidence": {
                    "owner_session": owner_session,
                    "unauthenticated_status": resp_unauth.get("status_code"),
                    "similarity": sim_au,
                },
                "status": "candidate",
                "validation_status": "unverified",
            }

        # Case 2: Cross-user BOLA / IDOR (User B accesses User A's resource while Unauth is denied).
        leaked_ids_b = _contains_owned_ids(resp_b.get("body", ""), owner_ids or []) if b_ok else []
        if a_ok and b_ok and (
            (sim_ab is not None and sim_ab >= self.similarity_threshold) or bool(leaked_ids_b)
        ):
            unauth_denied = _is_denied_response(resp_unauth) or not u_ok
            return {
                "url": url,
                "vulnerable": True,
                "finding_type": "bola_idor",
                "severity": "HIGH",
                "cwe": "CWE-639",
                "title": f"Potential BOLA / IDOR on {url}",
                "description": (
                    f"Secondary session '{peer_session}' received HTTP {resp_b.get('status_code')} "
                    f"(similarity={sim_ab}, leaked_owner_ids={leaked_ids_b}) matching '{owner_session}' "
                    f"while unauthenticated access was {'denied' if unauth_denied else 'also permitted'}."
                ),
                "confidence": "high" if (unauth_denied and ((sim_ab or 0.0) >= 0.9 or leaked_ids_b)) else "medium",
                "similarity_user_a_vs_b": sim_ab,
                "similarity_user_a_vs_unauth": sim_au,
                "responses": summarized,
                "evidence": {
                    "owner_session": owner_session,
                    "peer_session": peer_session,
                    "similarity": sim_ab,
                    "leaked_owner_ids": leaked_ids_b,
                    "unauthenticated_status": resp_unauth.get("status_code"),
                },
                "status": "candidate",
                "validation_status": "unverified",
            }

        # Case 3: Additional configured roles (e.g. readonly/guest) matching privileged owner.
        for extra_name, extra_resp in responses.items():
            if extra_name in {owner_session, peer_session, "unauthenticated"}:
                continue
            if a_ok and _is_success_response(extra_resp) and not _looks_like_login_or_error_page(extra_resp, resp_a):
                ctype_e = str((extra_resp.get("headers") or {}).get("content-type", ""))
                sim_ae = compute_response_similarity(
                    resp_a.get("body", ""), extra_resp.get("body", ""), ctype_a, ctype_e
                )
                leaked_ids_e = _contains_owned_ids(extra_resp.get("body", ""), owner_ids or [])
                if sim_ae >= self.similarity_threshold or leaked_ids_e:
                    return {
                        "url": url,
                        "vulnerable": True,
                        "finding_type": "privilege_escalation",
                        "severity": "HIGH",
                        "cwe": "CWE-269",
                        "title": f"Horizontal/Vertical Authorization Bypass via '{extra_name}' on {url}",
                        "description": (
                            f"Session '{extra_name}' received HTTP {extra_resp.get('status_code')} "
                            f"with {sim_ae:.0%} similarity to '{owner_session}'."
                        ),
                        "confidence": "high" if sim_ae >= 0.9 or leaked_ids_e else "medium",
                        "similarity_user_a_vs_b": sim_ab,
                        "similarity_user_a_vs_unauth": sim_au,
                        "responses": summarized,
                        "evidence": {
                            "owner_session": owner_session,
                            "bypass_session": extra_name,
                            "similarity": sim_ae,
                            "leaked_owner_ids": leaked_ids_e,
                        },
                        "status": "candidate",
                        "validation_status": "unverified",
                    }

        # Case 4: Anomaly where owner was denied, yet unauthenticated or peer session succeeded.
        if not a_ok and (u_ok or b_ok):
            actor = "unauthenticated" if u_ok else peer_session
            return {
                "url": url,
                "vulnerable": True,
                "finding_type": "broken_access_control",
                "severity": "MEDIUM",
                "cwe": "CWE-284",
                "title": f"Inconsistent Access Control ({actor} allowed while {owner_session} denied) on {url}",
                "description": (
                    f"Session '{actor}' received HTTP {responses[actor].get('status_code')} "
                    f"while '{owner_session}' received HTTP {resp_a.get('status_code')}."
                ),
                "confidence": "medium",
                "similarity_user_a_vs_b": sim_ab,
                "similarity_user_a_vs_unauth": sim_au,
                "responses": summarized,
                "evidence": {"allowed_session": actor, "owner_status": resp_a.get("status_code")},
                "status": "candidate",
                "validation_status": "unverified",
            }

        # Case 5: Properly isolated (401/403/404 or distinct per-user profile data like /api/me).
        if a_ok and b_ok and sim_ab is not None and sim_ab < self.similarity_threshold and not u_ok:
            return {
                "url": url,
                "vulnerable": False,
                "finding_type": "tenant_isolated",
                "severity": "INFO",
                "cwe": "",
                "title": f"Tenant/User-Scoped Isolation Verified on {url}",
                "description": (
                    f"User A and User B both received 2xx responses with distinct payloads "
                    f"(similarity={sim_ab:.0%}) and unauthenticated access was denied."
                ),
                "confidence": "high",
                "similarity_user_a_vs_b": sim_ab,
                "similarity_user_a_vs_unauth": sim_au,
                "responses": summarized,
                "evidence": {"similarity": sim_ab},
                "status": "passed",
                "validation_status": "verified_negative",
            }

        if a_ok and (_is_denied_response(resp_b) or not b_ok) and (_is_denied_response(resp_unauth) or not u_ok):
            return {
                "url": url,
                "vulnerable": False,
                "finding_type": "access_controlled",
                "severity": "INFO",
                "cwe": "",
                "title": f"Access Control Enforced on {url}",
                "description": "Unauthorized and secondary sessions were denied.",
                "confidence": "high",
                "similarity_user_a_vs_b": sim_ab,
                "similarity_user_a_vs_unauth": sim_au,
                "responses": summarized,
                "evidence": {},
                "status": "passed",
                "validation_status": "verified_negative",
            }

        return {
            "url": url,
            "vulnerable": False,
            "finding_type": "inconclusive",
            "severity": "INFO",
            "cwe": "",
            "title": f"Inconclusive Authorization Diff on {url}",
            "description": f"Baseline session '{owner_session}' did not return a usable 2xx response.",
            "confidence": "low",
            "similarity_user_a_vs_b": sim_ab,
            "similarity_user_a_vs_unauth": sim_au,
            "responses": summarized,
            "evidence": {"owner_status": resp_a.get("status_code", resp_a.get("status"))},
            "status": "inconclusive",
            "validation_status": "inconclusive",
        }

    def check_endpoints(
        self,
        endpoints: List[str],
        params: Optional[Dict[str, Any]] = None,
        owner_session: str = "user_a",
    ) -> Dict[str, Any]:
        """Run authorization diffing across a list of endpoints respecting budgets and scope."""
        results: List[Dict[str, Any]] = []
        findings: List[Dict[str, Any]] = []
        scope_blocked_count = 0

        for ep in endpoints:
            res = self.check_endpoint(ep, params=params, owner_session=owner_session)
            results.append(res)
            if res.get("vulnerable"):
                findings.append(res)
            if res.get("finding_type") == "scope_blocked":
                scope_blocked_count += 1
            if res.get("finding_type") == "budget_exhausted":
                break
            if any(getattr(client, "stop_requested", False) for client in self.clients.values()):
                break

        return {
            "target": self.target,
            "total_checked": len(results),
            "vulnerable_count": len(findings),
            "scope_blocked_count": scope_blocked_count,
            "findings": findings,
            "results": results,
        }

    def compare_id_enumeration(
        self,
        url_template: str,
        user_a_id: str,
        user_b_id: str,
    ) -> Dict[str, Any]:
        """
        Test symmetric cross-object access on a parameterized template (e.g. '/api/orders/{id}').
        Verifies User B requesting User A's object ID and User A requesting User B's object ID.
        """
        url_for_a = url_template.replace("{id}", str(user_a_id))
        url_for_b = url_template.replace("{id}", str(user_b_id))

        check_a = self.check_endpoint(url_for_a, owner_session="user_a")
        check_b = self.check_endpoint(url_for_b, owner_session="user_b")

        vulnerable = bool(check_a.get("vulnerable") or check_b.get("vulnerable"))
        return {
            "url_template": url_template,
            "user_a_resource": check_a,
            "user_b_resource": check_b,
            "vulnerable": vulnerable,
        }
