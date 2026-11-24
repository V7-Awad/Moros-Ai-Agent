#!/usr/bin/env python3
"""
tech_profiler.py — Automated Technology Stack Fingerprinting & Skill Router.

Detects languages, web frameworks, CMS, and API architectures to dynamically
prioritize the most relevant offensive security micro-skills.
"""

from __future__ import annotations
import re
from typing import Any, Dict, List, Set


TECH_SIGNATURES: Dict[str, Dict[str, Any]] = {
    # Backend Frameworks
    "Spring Boot": {
        "headers": {"x-application-context": r".*"},
        "cookies": ["jsessionid"],
        "body": [r"whitelabel error page", r"org\.springframework"],
        "boost_skills": ["ssti-detect", "content-discovery", "api-spec-discovery"],
    },
    "Django / Python": {
        "headers": {},
        "cookies": ["csrftoken", "sessionid"],
        "body": [r"csrfmiddlewaretoken", r"django"],
        "boost_skills": ["idor-audit", "sqli-heuristic", "cors-audit"],
    },
    "Laravel / PHP": {
        "headers": {"x-powered-by": r"php"},
        "cookies": ["laravel_session", "xsrf-token", "phpsessid"],
        "body": [r"whoops! there was an error", r"laravel"],
        "boost_skills": ["idor-audit", "sqli-heuristic", "crlf-injection"],
    },
    "Node.js / Express": {
        "headers": {"x-powered-by": r"express"},
        "cookies": ["connect.sid", "express.sid"],
        "body": [r"cannot get /", r"express"],
        "boost_skills": ["prototype-pollution", "jwt-analysis", "websocket-audit"],
    },
    "ASP.NET": {
        "headers": {"x-powered-by": r"asp\.net", "x-aspnet-version": r".*"},
        "cookies": ["asp.net_sessionid", "__requestverificationtoken"],
        "body": [r"__viewstate", r"__eventvalidation"],
        "boost_skills": ["path-traversal", "xxe-detect", "auth-password-reset-bruteforce"],
    },
    # Frontends & CMS
    "WordPress": {
        "headers": {},
        "cookies": ["wordpress_", "wp-settings-"],
        "body": [r"wp-content", r"wp-includes", r"xmlrpc\.php"],
        "boost_skills": ["content-discovery", "subdomain-takeover", "xss-stored"],
    },
    "Next.js / React": {
        "headers": {"x-powered-by": r"next\.js"},
        "cookies": [],
        "body": [r"__next_data__", r"/_next/static/", r"react-root"],
        "boost_skills": ["js-analyze", "prototype-pollution", "cors-audit"],
    },
    # API Standards
    "GraphQL": {
        "headers": {},
        "cookies": [],
        "body": [r"graphql", r"__schema", r"apollo", r"relay"],
        "boost_skills": ["graphql-audit", "idor-audit"],
    },
}


class TechProfiler:
    """Profiles target technology stack and recommends skill priorities."""

    def __init__(self):
        pass

    def profile_target(
        self,
        headers: Dict[str, str],
        body: str = "",
        cookies: str = "",
        endpoints: List[str] = None
    ) -> Dict[str, Any]:
        """Inspect HTTP responses and routes to identify technologies."""
        h_lower = {k.lower(): str(v).lower() for k, v in headers.items()}
        body_lower = (body or "").lower()
        cookie_lower = (cookies or h_lower.get("set-cookie", "")).lower()
        endpoints = endpoints or []

        detected_techs = []
        prioritized_skills: Set[str] = set()

        for tech_name, sig in TECH_SIGNATURES.items():
            matched = False

            # Header regex match
            for hk, regex in sig["headers"].items():
                if hk in h_lower and re.search(regex, h_lower[hk], re.IGNORECASE):
                    matched = True
                    break

            # Cookie check
            if not matched:
                for c in sig["cookies"]:
                    if c in cookie_lower:
                        matched = True
                        break

            # Body regex check
            if not matched:
                for b_pattern in sig["body"]:
                    if re.search(b_pattern, body_lower, re.IGNORECASE):
                        matched = True
                        break

            # Endpoint check (e.g. /graphql)
            if not matched and tech_name == "GraphQL":
                if any("graphql" in str(ep).lower() for ep in endpoints):
                    matched = True

            if matched:
                detected_techs.append(tech_name)
                prioritized_skills.update(sig.get("boost_skills", []))

        return {
            "technologies": detected_techs,
            "count": len(detected_techs),
            "prioritized_skills": sorted(list(prioritized_skills)),
        }
