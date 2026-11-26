#!/usr/bin/env python3
"""
agent_security.py — OWASP Agentic Security Controls for Moros.

Maps the OWASP Agentic AI Top 10 to concrete Moros controls:
  ASI01 - Prompt Injection        -> spotlighting + injection detection
  ASI02 - Broken Authz / Privesc  -> tool permission scoping
  ASI03 - Excessive Agency         -> action budget caps
  ASI04 - Insufficient Logging    -> handled by trace_logger.py
  ASI05 - Unsafe Output Handling  -> output sanitization
  ASI06 - Insecure Plugins/Tools  -> MCP tool allowlisting
  ASI07 - Resource Overconsumption -> budget caps (cost_tracker.py)
  ASI08 - Excessive Data Exposure  -> secret redaction (llm_client.py)
  ASI09 - Denial of Service       -> request rate limits (scoped_http.py)
  ASI10 - Trust Boundary Violation -> scope_validator.py

This module handles ASI01, ASI02, ASI03, ASI05.
"""

import logging
import re
from typing import Any, Dict, List, Set, Tuple

logger = logging.getLogger("agent-security")

# ── Spotlighting (ASI01) ─────────────────────────────────────────
# Wraps untrusted content with data markers so the LLM can distinguish
# instructions from data, reducing prompt injection effectiveness.

_SPOTLIGHT_PREFIX = "«DATA_BEGIN»"
_SPOTLIGHT_SUFFIX = "«DATA_END»"

# Common prompt injection patterns in web content.
_INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"you\s+are\s+now\s+a",
    r"system\s*:\s*you\s+are",
    r"forget\s+(all\s+)?(your\s+)?(previous|prior)\s+(instructions|rules|constraints)",
    r"new\s+instruction\s*:",
    r"override\s+system\s+prompt",
    r"disregard\s+(your|the)\s+(system|original)\s+(prompt|instructions)",
    r"</?(system|user|assistant)\s*>",
    r"\[INST\].*?\[/INST\]",
    r"<\|im_start\|>",
    r"human\s*:\s*assistant\s*:",
    r"act\s+as\s+(if\s+you\s+are\s+)?(a\s+)?different",
    r"do\s+not\s+follow\s+your\s+rules",
    r"pretend\s+you",
]

_COMPILED_INJECTION_PATTERNS = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in _INJECTION_PATTERNS]


def spotlight(content: str) -> str:
    """
    Wrap untrusted content with data markers (Spotlighting technique).

    This tells the LLM "everything between these markers is DATA,
    not instructions to follow."
    """
    if not content:
        return content
    # Strip any embedded spotlight markers to prevent delimiter breakout
    safe_content = content.replace(_SPOTLIGHT_PREFIX, "").replace(_SPOTLIGHT_SUFFIX, "")
    return f"{_SPOTLIGHT_PREFIX}\n{safe_content}\n{_SPOTLIGHT_SUFFIX}"


def detect_injection(text: str) -> List[Dict[str, Any]]:
    """
    Scan text for prompt injection patterns.
    Returns list of detections with pattern and location.
    """
    if not text:
        return []

    detections = []
    for i, pattern in enumerate(_COMPILED_INJECTION_PATTERNS):
        for match in pattern.finditer(text):
            detections.append({
                "pattern_index": i,
                "pattern": _INJECTION_PATTERNS[i],
                "matched_text": match.group()[:200],
                "start": match.start(),
                "end": match.end(),
                "severity": "high" if i < 4 else "medium",
            })

    return detections


def sanitize_for_prompt(text: str, max_length: int = 50000,
                        strip_injections: bool = False) -> str:
    """
    Sanitize untrusted text before including it in an LLM prompt.

    - Truncates to max_length
    - Optionally strips detected injection attempts
    - Applies spotlighting
    """
    if not text or max_length <= 0:
        return ""

    # Truncate
    if len(text) > max_length:
        text = text[:max_length] + "\n[... truncated ...]"

    # Strip injections if requested
    if strip_injections:
        for pattern in _COMPILED_INJECTION_PATTERNS:
            text = pattern.sub("[REDACTED_INJECTION]", text)

    return spotlight(text)


# ── Tool Permission Scoping (ASI02) ─────────────────────────────

# Skill categories and their allowed tool sets.
# Recon skills only get read-only tools; active skills get write tools
# but only within scope.
SKILL_TOOL_PERMISSIONS: Dict[str, Set[str]] = {
    "recon": {
        "http_get", "dns_lookup", "ct_log_query", "whois_lookup",
        "wayback_fetch", "js_fetch", "tech_detect", "port_scan",
        "subdomain_enum", "read_file", "write_file",
    },
    "analysis": {
        "http_get", "read_file", "write_file", "js_beautify",
        "js_analyze", "secret_scan", "endpoint_extract",
    },
    "active": {
        "http_get", "http_post", "read_file", "write_file",
        "curl_exec", "generate_poc",
    },
    "reporting": {
        "read_file", "write_file", "sarif_export",
    },
}

# Map skill names to categories for automatic scoping.
_SKILL_CATEGORY_MAP = {
    "recon-subdomain": "recon",
    "js-discover": "recon",
    "js-analyze": "analysis",
    "content-discovery": "recon",
    "api-spec-discovery": "recon",
    "secret-scan": "analysis",
    "xss-reflected": "active",
    "xss-stored": "active",
    "xss-dom": "active",
    "xss-blind": "active",
    "ssrf-identify": "active",
    "ssrf-post-exploit": "active",
    "idp-race-condition": "active",
    "auth-password-reset-bruteforce": "active",
    "crlf-injection": "active",
    "open-redirect": "active",
    "cors-misconfiguration": "active",
    "jwt-analysis": "analysis",
    "xxe-detect": "active",
    "graphql-introspection": "recon",
    "subdomain-takeover": "active",
    "report-conglomeration": "reporting",
    "review-skill": "reporting",
}


def get_allowed_tools(skill_name: str) -> Set[str]:
    """Return the set of tools a given skill is allowed to use."""
    category = _SKILL_CATEGORY_MAP.get(skill_name, "recon")
    return set(SKILL_TOOL_PERMISSIONS.get(category, SKILL_TOOL_PERMISSIONS["recon"]))


def check_tool_permission(skill_name: str, tool_name: str) -> Tuple[bool, str]:
    """Check whether a skill is allowed to use a specific tool."""
    allowed = get_allowed_tools(skill_name)
    if tool_name in allowed:
        return True, ""
    return False, (
        f"Skill '{skill_name}' is not authorized to use tool '{tool_name}'. "
        f"Allowed tools: {', '.join(sorted(allowed))}"
    )


# ── Action Budget Caps (ASI03) ───────────────────────────────────

class ActionBudget:
    """
    Configurable action budget that triggers a human-in-the-loop gate
    when the agent exceeds N actions in a single skill run.
    """

    def __init__(self, max_actions: int = 50, max_http_writes: int = 10):
        self.max_actions = max_actions
        self.max_http_writes = max_http_writes
        self._action_count = 0
        self._http_write_count = 0
        self._exceeded = False

    def record_action(self, action_type: str = "generic") -> Tuple[bool, str]:
        """
        Record an action. Returns (should_continue, reason).
        If budget exceeded, returns (False, reason) to signal HITL gate.
        """
        self._action_count += 1

        if action_type in ("http_post", "http_put", "http_delete", "http_patch"):
            self._http_write_count += 1
            if self._http_write_count >= self.max_http_writes:
                self._exceeded = True
                return False, (
                    f"HTTP write budget exceeded ({self._http_write_count}/{self.max_http_writes}). "
                    "Pausing for operator review."
                )

        if self._action_count >= self.max_actions:
            self._exceeded = True
            return False, (
                f"Action budget exceeded ({self._action_count}/{self.max_actions}). "
                "Pausing for operator review."
            )

        return True, ""

    def reset(self):
        self._action_count = 0
        self._http_write_count = 0
        self._exceeded = False

    @property
    def exceeded(self) -> bool:
        return self._exceeded

    def get_state(self) -> Dict[str, Any]:
        return {
            "actions_used": self._action_count,
            "max_actions": self.max_actions,
            "http_writes_used": self._http_write_count,
            "max_http_writes": self.max_http_writes,
            "exceeded": self._exceeded,
        }


# ── Output Sanitization (ASI05) ─────────────────────────────────

def sanitize_output(text: str) -> str:
    """
    Sanitize agent output before presenting to user.
    Strips any leaked system prompt fragments or internal markers.
    """
    if not text:
        return ""
    # Remove any spotlighting markers that leaked through
    text = text.replace(_SPOTLIGHT_PREFIX, "").replace(_SPOTLIGHT_SUFFIX, "")
    # Remove any raw API keys that might have leaked
    text = re.sub(r"\b(sk-[a-zA-Z0-9_\-\.]{20,})\b", "[REDACTED]", text)
    text = re.sub(r"AIza[0-9A-Za-z\-_]{30,45}", "[REDACTED]", text)
    return text


# ── OWASP Agentic Top 10 Control Matrix ─────────────────────────

OWASP_CONTROL_MAP = {
    "ASI01_PROMPT_INJECTION": {
        "control": "Spotlighting + injection detection",
        "module": "agent_security.py",
        "functions": ["spotlight", "detect_injection", "sanitize_for_prompt"],
    },
    "ASI02_BROKEN_AUTHZ": {
        "control": "Per-skill tool permission scoping",
        "module": "agent_security.py",
        "functions": ["get_allowed_tools", "check_tool_permission"],
    },
    "ASI03_EXCESSIVE_AGENCY": {
        "control": "Action budget caps with HITL gates",
        "module": "agent_security.py",
        "functions": ["ActionBudget"],
    },
    "ASI04_INSUFFICIENT_LOGGING": {
        "control": "OpenTelemetry-compatible structured tracing",
        "module": "trace_logger.py",
        "functions": ["TraceLogger"],
    },
    "ASI05_UNSAFE_OUTPUT": {
        "control": "Output sanitization before presentation",
        "module": "agent_security.py",
        "functions": ["sanitize_output"],
    },
    "ASI06_INSECURE_PLUGINS": {
        "control": "MCP tool allowlisting",
        "module": "mcp_client.py",
        "functions": ["MCPClient.tool_allowlist"],
    },
    "ASI07_RESOURCE_OVERCONSUMPTION": {
        "control": "Per-task budget caps and cost tracking",
        "module": "cost_tracker.py",
        "functions": ["CostTracker"],
    },
    "ASI08_DATA_EXPOSURE": {
        "control": "Secret redaction in all LLM I/O",
        "module": "llm_client.py",
        "functions": ["redact_secrets"],
    },
    "ASI09_DENIAL_OF_SERVICE": {
        "control": "HTTP request rate limits and caps",
        "module": "scoped_http.py",
        "functions": ["ScopedHttpClient"],
    },
    "ASI10_TRUST_BOUNDARY": {
        "control": "Scope validation for all targets",
        "module": "scope_validator.py",
        "functions": ["ScopeValidator"],
    },
}


def get_security_posture() -> Dict[str, Any]:
    """Return the current OWASP Agentic security control status."""
    return {
        "framework": "OWASP Agentic AI Top 10 (2026)",
        "controls": OWASP_CONTROL_MAP,
        "coverage": f"{len(OWASP_CONTROL_MAP)}/10",
    }
