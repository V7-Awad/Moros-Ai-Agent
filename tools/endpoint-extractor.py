#!/usr/bin/env python3
"""
endpoint-extractor.py — API endpoint and parameter extractor from JavaScript files.

Parses beautified JavaScript to extract API endpoints, routes, parameters,
and their associated functions. Categorizes endpoints by functional area.

Usage:
    python tools/endpoint-extractor.py \
        --input-dir "targets/example.com/output/js/beautified/" \
        --output-endpoints "targets/example.com/output/js/endpoints.json" \
        --output-params "targets/example.com/output/js/parameters.json" \
        --output-curl "targets/example.com/output/js/curl-commands.sh"
"""

import argparse
import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S"
)
logger = logging.getLogger("endpoint-extractor")

# Patterns for detecting API endpoints in JS code
ENDPOINT_PATTERNS = [
    # fetch() calls
    (r"""fetch\s*\(\s*[`'"]((?:/|https?://)[^`'"]*)[`'"]\s*""", "fetch"),
    # axios calls
    (r"""axios\.(get|post|put|patch|delete)\s*\(\s*[`'"]((?:/|https?://)[^`'"]*)[`'"]\s*""", "axios"),
    # XMLHttpRequest
    (r"""\.open\s*\(\s*['"](\w+)['"]\s*,\s*[`'"]((?:/|https?://)[^`'"]*)[`'"]\s*""", "xhr"),
    # jQuery ajax
    (r"""(?:\$\.ajax|\$\.get|\$\.post)\s*\(\s*(?:\{[^}]*url\s*:\s*)?[`'"]((?:/|https?://)[^`'"]*)[`'"]\s*""", "jquery"),
    # Route definitions (React Router, Express, etc.)
    (r"""(?:path|route)\s*[:=]\s*[`'"]((?:/)[^`'"]*)[`'"]\s*""", "route"),
    # String concatenation with base URL
    (r"""(?:baseUrl|apiUrl|baseURL|API_URL|apiBase|BASE_URL)\s*\+\s*[`'"]((?:/)[^`'"]*)[`'"]\s*""", "base-url-concat"),
    # Template literals with API paths
    (r"""`\$\{[^}]+\}(/api[^`]*)`""", "template-literal"),
    # GraphQL endpoints
    (r"""[`'"]((?:/graphql|/api/graphql)[^`'"]*)[`'"]\s*""", "graphql"),
    # WebSocket URLs
    (r"""[`'"](wss?://[^`'"]*)[`'"]\s*""", "websocket"),
]

# Patterns for detecting parameters
PARAM_PATTERNS = [
    # Query parameters in URL strings
    (r"""[?&](\w+)=""", "query-param"),
    # JSON body fields
    (r"""(?:body|data|params)\s*[:=]\s*\{([^}]+)\}""", "body-field"),
    # Form data
    (r"""(?:append|set)\s*\(\s*['"](\w+)['"]""", "form-data"),
    # URLSearchParams
    (r"""URLSearchParams\s*\([^)]*['"](\w+)['"]""", "url-search-params"),
]

# Category detection keywords
CATEGORY_KEYWORDS = {
    "admin": ["admin", "dashboard", "manage", "settings", "config", "system"],
    "auth": ["auth", "login", "logout", "register", "password", "token", "session", "oauth"],
    "user": ["user", "profile", "account", "member", "subscription"],
    "api": ["api", "v1", "v2", "v3", "rest", "graphql"],
    "public": ["public", "static", "assets", "images", "css", "js"],
    "internal": ["internal", "debug", "test", "dev", "staging", "health", "metrics"],
    "payment": ["payment", "billing", "invoice", "stripe", "checkout", "order"],
    "upload": ["upload", "file", "media", "attachment", "document"],
}


def categorize_endpoint(url: str) -> str:
    """Guess the functional category of an endpoint."""
    url_lower = url.lower()
    for category, keywords in CATEGORY_KEYWORDS.items():
        for keyword in keywords:
            if keyword in url_lower:
                return category
    return "unknown"


def infer_method(source_type: str, context: str = "") -> str:
    """Infer the HTTP method from the detection context."""
    context_lower = context.lower() if context else ""

    if "delete" in context_lower:
        return "DELETE"
    if "put" in context_lower or "update" in context_lower:
        return "PUT"
    if "patch" in context_lower:
        return "PATCH"
    if "post" in context_lower or "create" in context_lower or "submit" in context_lower:
        return "POST"

    if source_type == "axios":
        # axios method is captured in the regex
        return "GET"

    return "GET"


def extract_endpoints(filepath: Path) -> list:
    """Extract all endpoints from a JS file."""
    endpoints = []

    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        logger.error(f"Error reading {filepath}: {e}")
        return endpoints

    lines = content.split("\n")

    for pattern, source_type in ENDPOINT_PATTERNS:
        for match in re.finditer(pattern, content, re.MULTILINE):
            groups = match.groups()

            # Different patterns capture URL in different groups
            if source_type == "axios":
                method = groups[0].upper()
                url = groups[1]
            elif source_type == "xhr":
                method = groups[0].upper()
                url = groups[1]
            else:
                url = groups[0]
                line_num = content[:match.start()].count("\n") + 1
                context = lines[line_num - 1] if line_num <= len(lines) else ""
                method = infer_method(source_type, context)

            line_num = content[:match.start()].count("\n") + 1

            # Extract inline parameters
            params = []
            param_matches = re.findall(r'[?&](\w+)=', url)
            params.extend(param_matches)

            endpoints.append({
                "url": url,
                "method": method,
                "source_file": str(filepath),
                "line_number": line_num,
                "detection_source": source_type,
                "category": categorize_endpoint(url),
                "parameters": params,
                "context": lines[line_num - 1].strip()[:200] if line_num <= len(lines) else "",
            })

    return endpoints


def generate_curl_commands(endpoints: list, target_domain: str) -> str:
    """Generate curl commands for all endpoints."""
    commands = [
        "#!/bin/bash",
        f"# Curl commands for {target_domain}",
        f"# Generated: {datetime.now(timezone.utc).isoformat()}",
        f"# Total endpoints: {len(endpoints)}",
        "",
        f'BASE_URL="https://{target_domain}"',
        "",
    ]

    for i, ep in enumerate(endpoints, 1):
        url = ep["url"]
        method = ep["method"]

        # Resolve relative URLs
        if url.startswith("/"):
            curl_url = f"$BASE_URL{url}"
        else:
            curl_url = url

        cmd_parts = [f"# Endpoint {i}: {ep.get('category', 'unknown')} — {url}"]
        cmd = f'curl -s -o /dev/null -w "%{{http_code}}" -X {method}'
        cmd += f' "{curl_url}"'
        cmd += ' -H "User-Agent: Mozilla/5.0"'
        cmd += ' -H "Accept: application/json"'

        if method in ("POST", "PUT", "PATCH"):
            cmd += " -H \"Content-Type: application/json\""
            if ep.get("parameters"):
                body = {p: f"<{p}>" for p in ep["parameters"]}
                cmd += f" -d '{json.dumps(body)}'"

        cmd_parts.append(cmd)
        cmd_parts.append("")
        commands.extend(cmd_parts)

    return "\n".join(commands)


def main():
    parser = argparse.ArgumentParser(description="Extract API endpoints from JavaScript")
    parser.add_argument("--input-dir", required=True, help="Directory with JS files")
    parser.add_argument("--output-endpoints", required=True, help="Output endpoints JSON")
    parser.add_argument("--output-params", required=True, help="Output parameters JSON")
    parser.add_argument("--output-curl", required=True, help="Output curl commands script")
    parser.add_argument("--target-domain", default="TARGET", help="Target domain for curl URLs")

    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    if not input_dir.exists():
        logger.error(f"Input directory does not exist: {input_dir}")
        sys.exit(1)

    js_files = list(input_dir.rglob("*.js"))
    logger.info(f"Scanning {len(js_files)} JS files for endpoints")

    all_endpoints = []
    for js_file in js_files:
        endpoints = extract_endpoints(js_file)
        all_endpoints.extend(endpoints)

    # Deduplicate by URL + method
    seen = set()
    unique_endpoints = []
    for ep in all_endpoints:
        key = f"{ep['method']}:{ep['url']}"
        if key not in seen:
            seen.add(key)
            unique_endpoints.append(ep)

    logger.info(f"Found {len(unique_endpoints)} unique endpoints "
                f"(from {len(all_endpoints)} total detections)")

    # Write endpoints
    endpoints_output = {
        "target_dir": str(input_dir),
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "total_endpoints": len(unique_endpoints),
        "endpoints": unique_endpoints,
    }

    output_path = Path(args.output_endpoints)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(endpoints_output, indent=2), encoding="utf-8")

    # Write parameters
    all_params = {}
    for ep in unique_endpoints:
        for param in ep.get("parameters", []):
            if param not in all_params:
                all_params[param] = {
                    "name": param,
                    "found_in_endpoints": [],
                }
            all_params[param]["found_in_endpoints"].append(ep["url"])

    params_output = {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "total_parameters": len(all_params),
        "parameters": list(all_params.values()),
    }

    params_path = Path(args.output_params)
    params_path.parent.mkdir(parents=True, exist_ok=True)
    params_path.write_text(json.dumps(params_output, indent=2), encoding="utf-8")

    # Write curl commands
    curl_content = generate_curl_commands(unique_endpoints, args.target_domain)
    curl_path = Path(args.output_curl)
    curl_path.parent.mkdir(parents=True, exist_ok=True)
    curl_path.write_text(curl_content, encoding="utf-8")

    logger.info(f"Endpoints: {args.output_endpoints}")
    logger.info(f"Parameters: {args.output_params}")
    logger.info(f"Curl commands: {args.output_curl}")


if __name__ == "__main__":
    main()
