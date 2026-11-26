#!/usr/bin/env python3
"""
skill_registry.py — Dynamic Skill Engine & Auto-Discovery for Moros AI.

Enables unlimited custom security skills:
- Automatically discovers all skills installed in `skills/`
- Supports custom skill creation from Web Dashboard or CLI
- Manages execution dependencies and ordering dynamically
- Allows operators to extend Moros AI with arbitrary pentesting checks
"""

import json
import logging
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("skill-registry")

PROJECT_ROOT = Path(__file__).parent.parent.resolve()
SKILLS_DIR = PROJECT_ROOT / "skills"

# Core built-in skills
CORE_SKILLS = {
    "recon-subdomain",
    "deep-recon",
    "api-spec-discovery",
    "js-discover",
    "js-analyze",
    "content-discovery",
    "xss-reflected",
    "xss-stored",
    "xss-dom",
    "xss-blind",
    "ssrf-identify",
    "ssrf-post-exploit",
    "idp-race-condition",
    "auth-password-reset-bruteforce",
    "review-skill",
    "report-conglomeration",
}


class SkillRegistry:
    """Manages dynamic skill discovery, creation, and execution chaining."""

    def __init__(self, skills_dir: Optional[Path] = None):
        self.skills_dir = Path(skills_dir) if skills_dir else SKILLS_DIR
        self.skills_dir.mkdir(parents=True, exist_ok=True)

    def list_skills(self) -> List[Dict[str, Any]]:
        """Discover and return all installed skills (built-in and custom)."""
        skills = []
        if not self.skills_dir.exists():
            return skills

        for item in sorted(self.skills_dir.iterdir()):
            if item.is_dir():
                skill_id = item.name
                skill_file = item / "SKILL.md"
                meta = self._parse_skill_md(skill_file, skill_id)
                skills.append(meta)

        return skills

    def get_skill(self, skill_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve details for a specific skill."""
        target_dir = self.skills_dir / skill_id
        if not target_dir.is_dir():
            return None
        return self._parse_skill_md(target_dir / "SKILL.md", skill_id)

    def get_execution_order(self, requested_skills: Optional[List[str]] = None) -> List[str]:
        """Compute the dynamic dependency order for all active skills."""
        all_skills = [s["id"] for s in self.list_skills()]
        
        # Recon & discovery always run first
        order = []
        recon_priority = [
            "recon-subdomain",
            "deep-recon",
            "api-spec-discovery",
            "js-discover",
            "js-analyze",
            "content-discovery",
        ]
        for p in recon_priority:
            if p in all_skills:
                order.append(p)

        # Mid-tier vulnerability & custom skills
        for s in all_skills:
            if s not in order and s not in ("review-skill", "report-conglomeration"):
                order.append(s)

        # Verification and report always run last
        if "review-skill" in all_skills:
            order.append("review-skill")
        if "report-conglomeration" in all_skills:
            order.append("report-conglomeration")

        if requested_skills and requested_skills != ["all"]:
            req_set = set(requested_skills)
            return [s for s in order if s in req_set]

        return order

    def create_custom_skill(
        self,
        skill_id: str,
        title: str,
        description: str,
        category: str = "Custom Audit",
        checklist: Optional[List[str]] = None,
        methodology: str = "",
    ) -> Dict[str, Any]:
        """Create a new custom skill folder and SKILL.md template."""
        clean_id = re.sub(r"[^a-zA-Z0-9_-]", "-", skill_id.lower()).strip("-")
        if not clean_id:
            raise ValueError("Skill identifier cannot be empty")

        skill_dir = self.skills_dir / clean_id
        if skill_dir.exists():
            raise ValueError(f"Skill '{clean_id}' already exists")

        skill_dir.mkdir(parents=True, exist_ok=True)
        checklist_items = checklist or [
            f"Review target endpoints for {title}",
            "Analyze input parameters and server response reflections",
            "Generate reproducible cURL verification proofs",
        ]
        checklist_md = "\n".join(f"- [ ] {item}" for item in checklist_items)

        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        content = f"""# {title} (`{clean_id}`)

**Category:** {category}  
**Author:** Custom Operator  
**Created:** {now_iso}  
**Type:** Dynamic Custom Skill  

## Description
{description}

## Methodology & Objectives
{methodology or description}

## Verification Checklist
{checklist_md}

## Safety & Scope Constraints
- Strict scope adherence: only assess assets explicitly authorized in scope.
- Enforce non-destructive payloads and rate limits.
"""
        skill_file = skill_dir / "SKILL.md"
        skill_file.write_text(content, encoding="utf-8")

        # Save manifest
        manifest = {
            "id": clean_id,
            "title": title,
            "category": category,
            "description": description,
            "is_custom": True,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        (skill_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        logger.info(f"Created custom skill '{clean_id}' at {skill_dir}")
        return manifest

    def delete_custom_skill(self, skill_id: str) -> bool:
        """Delete a custom skill (built-in core skills are protected)."""
        clean_id = re.sub(r"[^a-zA-Z0-9_-]", "-", skill_id.lower()).strip("-")
        if clean_id in CORE_SKILLS:
            raise ValueError(f"Cannot delete built-in core skill '{clean_id}'")

        skill_dir = self.skills_dir / clean_id
        if skill_dir.is_dir():
            shutil.rmtree(skill_dir)
            logger.info(f"Deleted custom skill '{clean_id}'")
            return True
        return False

    @staticmethod
    def _parse_frontmatter(text: str) -> Dict[str, Any]:
        """Parse AAIF Agent Skills YAML-style frontmatter block if present."""
        fm_match = re.match(r"^---\s*\n(.*?)\n---\s*(?:\n|$)", text, re.DOTALL)
        if not fm_match:
            return {}
        block = fm_match.group(1)
        data: Dict[str, Any] = {}
        current_key = None
        buffer: List[str] = []

        def flush():
            nonlocal current_key, buffer
            if current_key and buffer:
                val = " ".join(line.strip() for line in buffer if line.strip()).strip()
                if val.startswith(('"', "'")) and val.endswith(('"', "'")) and len(val) >= 2:
                    val = val[1:-1]
                data[current_key] = val
            current_key = None
            buffer = []

        for line in block.splitlines():
            if not line.strip() or line.strip().startswith("#"):
                continue
            kv = re.match(r"^([a-zA-Z0-9_-]+)\s*:\s*(.*)$", line)
            if kv and not line.startswith((" ", "\t")):
                flush()
                key = kv.group(1).strip()
                val = kv.group(2).strip()
                if val in (">", "|", ">-", "|-", ""):
                    current_key = key
                else:
                    if val.startswith(('"', "'")) and val.endswith(('"', "'")) and len(val) >= 2:
                        val = val[1:-1]
                    data[key] = val
            elif current_key and line.startswith((" ", "\t")):
                buffer.append(line)
        flush()
        return data

    def export_aaif_manifest(self, skill_id: str) -> Optional[Dict[str, Any]]:
        """Export skill metadata in AAIF Agent Skills standard descriptor format."""
        skill = self.get_skill(skill_id)
        if not skill:
            return None
        return {
            "schema": "https://agentskills.io/schema/v1",
            "name": skill["id"],
            "title": skill["title"],
            "description": skill["description"],
            "category": skill["category"],
            "dependencies": skill.get("dependencies", []),
            "checklist": skill.get("checklist", []),
        }

    def _parse_skill_md(self, skill_file: Path, skill_id: str) -> Dict[str, Any]:
        """Parse title, description, AAIF frontmatter, and checklist from SKILL.md."""
        is_custom = skill_id not in CORE_SKILLS
        title = skill_id.replace("-", " ").title()
        description = "Specialized security skill for autonomous offensive assessment."
        category = "Core Offensive" if not is_custom else "Custom Security"
        checklist = []
        dependencies = []
        frontmatter: Dict[str, Any] = {}

        if skill_file.is_file():
            try:
                text = skill_file.read_text(encoding="utf-8")
                frontmatter = self._parse_frontmatter(text)
                if frontmatter.get("name"):
                    title = str(frontmatter["name"]).replace("-", " ").title()
                if frontmatter.get("description"):
                    description = str(frontmatter["description"])
                if frontmatter.get("category"):
                    category = str(frontmatter["category"])

                # Extract Title (markdown heading takes display precedence when present)
                m_title = re.search(r"^#\s+(.+)$", text, re.MULTILINE)
                if m_title:
                    raw_title = m_title.group(1).strip()
                    title = re.sub(r"\(`[^`]+`\)", "", raw_title).strip()

                # Extract Category
                m_cat = re.search(r"\*\*Category:\*\*\s*(.+)$", text, re.MULTILINE)
                if m_cat:
                    category = m_cat.group(1).strip()

                # Extract Description section if present
                m_desc = re.search(r"## Description\s*\n(.*?)(?=\n##|\Z)", text, re.DOTALL)
                if m_desc:
                    description = m_desc.group(1).strip()

                # Extract Checklist
                checklist = re.findall(r"^-\s*\[[ xX]\]\s*(.+)$", text, re.MULTILINE)

                # Extract Dependencies
                m_deps = re.search(r"## Dependencies\s*\n(.*?)(?=\n##|\Z)", text, re.DOTALL)
                if m_deps:
                    dependencies = re.findall(r"-\s*`?([a-zA-Z0-9_-]+)`?", m_deps.group(1))
            except Exception as e:
                logger.warning(f"Failed to parse {skill_file}: {e}")

        # Check for manifest
        manifest_file = skill_file.parent / "manifest.json"
        if manifest_file.is_file():
            try:
                m_data = json.loads(manifest_file.read_text(encoding="utf-8"))
                title = m_data.get("title", title)
                category = m_data.get("category", category)
                description = m_data.get("description", description)
                is_custom = m_data.get("is_custom", is_custom)
                if "dependencies" in m_data:
                    dependencies = m_data["dependencies"]
            except Exception:
                pass

        return {
            "id": skill_id,
            "title": title,
            "category": category,
            "description": description,
            "is_custom": is_custom,
            "checklist": checklist,
            "dependencies": dependencies,
            "path": str(skill_file.parent),
        }
