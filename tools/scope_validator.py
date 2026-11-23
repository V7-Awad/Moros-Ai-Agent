#!/usr/bin/env python3
"""
scope_validator.py — Strict Scope & Policy Engine for Moros AI.

Enforces in-scope and out-of-scope boundaries:
- Supports wildcards (*.target.com, api-*.target.com)
- Explicit out-of-scope blacklists (blog.target.com, zendesk.com)
- Automatic parsing from scope.json or scope-of-work.md
"""

import fnmatch
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class ScopeValidator:
    def __init__(
        self,
        target: str,
        in_scope: Optional[List[str]] = None,
        out_of_scope: Optional[List[str]] = None,
        target_dir: Optional[Path] = None,
    ):
        self.target = (target or "").lower().rstrip(".")
        self.in_scope: List[str] = [s.lower().strip() for s in (in_scope or []) if s.strip()]
        self.out_of_scope: List[str] = [s.lower().strip() for s in (out_of_scope or []) if s.strip()]

        if target_dir:
            self._load_from_target_dir(Path(target_dir))

        # Default in-scope if empty
        if not self.in_scope and self.target:
            t_bare = self.target.removeprefix("www.")
            self.in_scope = [self.target, f"*.{t_bare}", t_bare]

    def _load_from_target_dir(self, target_dir: Path):
        """Parse scope rules from scope.json or scope-of-work.md."""
        scope_json = target_dir / "scope.json"
        if scope_json.is_file():
            try:
                data = json.loads(scope_json.read_text(encoding="utf-8"))
                for s in data.get("in_scope", []):
                    if s.lower().strip() not in self.in_scope:
                        self.in_scope.append(s.lower().strip())
                for s in data.get("out_of_scope", []):
                    if s.lower().strip() not in self.out_of_scope:
                        self.out_of_scope.append(s.lower().strip())
                return
            except Exception:
                pass

        # Try parsing scope-of-work.md
        for md_file in target_dir.glob("scope-of-work.*"):
            try:
                text = md_file.read_text(encoding="utf-8", errors="ignore")
                in_section = re.search(r"##\s*In\s*Scope(.*?)(?=\n##|\Z)", text, re.DOTALL | re.IGNORECASE)
                if in_section:
                    items = re.findall(r"-\s*`?([a-zA-Z0-9_\-\.\*]+)`?", in_section.group(1))
                    for item in items:
                        if item.lower().strip() not in self.in_scope:
                            self.in_scope.append(item.lower().strip())

                out_section = re.search(r"##\s*Out\s*of\s*Scope(.*?)(?=\n##|\Z)", text, re.DOTALL | re.IGNORECASE)
                if out_section:
                    items = re.findall(r"-\s*`?([a-zA-Z0-9_\-\.\*]+)`?", out_section.group(1))
                    for item in items:
                        if item.lower().strip() not in self.out_of_scope:
                            self.out_of_scope.append(item.lower().strip())
            except Exception:
                pass

    def is_allowed(self, host_or_url: str) -> Tuple[bool, str]:
        """Verify whether a hostname or URL is permitted by scope rules."""
        if not host_or_url:
            return False, "Host or URL is empty"

        h = host_or_url.lower()
        if "://" in h:
            import urllib.parse
            parsed = urllib.parse.urlparse(h)
            h = parsed.hostname or ""

        h = h.rstrip(".")
        if not h:
            return False, "Could not extract valid hostname"

        # 1. Out-of-scope check (highest priority: prevent accidental out-of-bounds hits)
        for out_rule in self.out_of_scope:
            clean_rule = out_rule.rstrip(".")
            if fnmatch.fnmatch(h, clean_rule) or h == clean_rule:
                return False, f"Blocked: Host '{h}' matches OUT-OF-SCOPE rule '{clean_rule}'"
            if clean_rule.startswith("*.") and h.endswith(clean_rule[1:]):
                return False, f"Blocked: Host '{h}' matches OUT-OF-SCOPE wildcard '{clean_rule}'"

        # 2. In-scope check
        for in_rule in self.in_scope:
            clean_rule = in_rule.rstrip(".")
            if fnmatch.fnmatch(h, clean_rule) or h == clean_rule:
                return True, f"Allowed: Host '{h}' matches in-scope rule '{clean_rule}'"
            if clean_rule.startswith("*.") and (h.endswith(clean_rule[1:]) or h == clean_rule[2:]):
                return True, f"Allowed: Host '{h}' matches in-scope wildcard '{clean_rule}'"
            if h.endswith("." + clean_rule.removeprefix("www.")):
                return True, f"Allowed: Subdomain of '{clean_rule}'"

        return False, f"Blocked: Host '{h}' does not match any authorized in-scope rules"
