"""
test_skill_registry.py — Comprehensive tests for Moros AI Dynamic Skill Registry.
"""

import shutil
import tempfile
from pathlib import Path
import pytest

from tools.skill_registry import SkillRegistry, CORE_SKILLS


@pytest.fixture
def temp_skills_dir():
    temp_dir = Path(tempfile.mkdtemp(prefix="moros_test_skills_"))
    # Copy a few core skills for testing
    built_in = ["recon-subdomain", "js-discover", "review-skill", "report-conglomeration"]
    for s in built_in:
        s_dir = temp_dir / s
        s_dir.mkdir(parents=True)
        (s_dir / "SKILL.md").write_text(f"# {s}\n\n## Description\nBuilt-in {s}\n\n- [ ] Task 1\n", encoding="utf-8")
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


def test_list_skills(temp_skills_dir):
    registry = SkillRegistry(skills_dir=temp_skills_dir)
    skills = registry.list_skills()
    skill_ids = [s["id"] for s in skills]
    assert "recon-subdomain" in skill_ids
    assert "js-discover" in skill_ids
    assert len(skills) == 4


def test_create_and_get_custom_skill(temp_skills_dir):
    registry = SkillRegistry(skills_dir=temp_skills_dir)
    created = registry.create_custom_skill(
        skill_id="idor-checker",
        title="Insecure Direct Object Reference Hunter",
        category="Authentication & Session",
        description="Scans endpoints for parameter tampering and unauthorized resource access.",
        checklist=["Inspect numeric IDs", "Test unauthorized replay", "Capture proof-of-concept curl"]
    )
    assert created["id"] == "idor-checker"
    assert created["is_custom"] is True

    skill = registry.get_skill("idor-checker")
    assert skill is not None
    assert skill["title"] == "Insecure Direct Object Reference Hunter"
    assert skill["category"] == "Authentication & Session"
    assert len(skill["checklist"]) == 3
    assert "Inspect numeric IDs" in skill["checklist"]


def test_execution_order_with_custom_skill(temp_skills_dir):
    registry = SkillRegistry(skills_dir=temp_skills_dir)
    registry.create_custom_skill(
        skill_id="custom-jwt-audit",
        title="JWT Token Security Auditor",
        description="Tests JWT signature bypasses.",
    )
    order = registry.get_execution_order()
    # Recon should be early
    assert order.index("recon-subdomain") < order.index("custom-jwt-audit")
    # Review and report should be at the end
    assert order.index("custom-jwt-audit") < order.index("review-skill")
    assert order.index("custom-jwt-audit") < order.index("report-conglomeration")


def test_core_skill_delete_protection(temp_skills_dir):
    registry = SkillRegistry(skills_dir=temp_skills_dir)
    with pytest.raises(ValueError, match="Cannot delete built-in core skill"):
        registry.delete_custom_skill("recon-subdomain")


def test_delete_custom_skill(temp_skills_dir):
    registry = SkillRegistry(skills_dir=temp_skills_dir)
    registry.create_custom_skill(
        skill_id="temporary-audit",
        title="Temporary Audit",
        description="One-time check.",
    )
    assert registry.get_skill("temporary-audit") is not None

    deleted = registry.delete_custom_skill("temporary-audit")
    assert deleted is True
    assert registry.get_skill("temporary-audit") is None
