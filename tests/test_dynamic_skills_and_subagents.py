import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from tools.agent_runtime import AgentContext, AgentRunner, build_default_agent_tools
from tools.skill_registry import SkillRegistry
from tools.llm_client import LLMClient


def test_dynamic_skills_discovery():
    registry = SkillRegistry()
    skills = registry.list_skills()
    skill_ids = [s["id"] for s in skills]

    # Verify new high-impact skills are discovered
    assert "jwt-analysis" in skill_ids
    assert "cors-audit" in skill_ids
    assert "graphql-audit" in skill_ids
    assert "prototype-pollution" in skill_ids
    assert "open-redirect" in skill_ids
    assert "sqli-heuristic" in skill_ids
    assert "websocket-audit" in skill_ids
    assert len(skills) >= 22


def test_build_default_agent_tools_with_subagents(tmp_path):
    ctx = AgentContext(
        target="example.com",
        target_dir=tmp_path,
        skill="test-orchestrator",
        run_id="run-subagent-test"
    )

    tools = build_default_agent_tools(ctx, allow_subagents=True)
    schema_names = [s["name"] for s in tools.list_schemas()]

    assert "http_get" in schema_names
    assert "search_code" in schema_names
    assert "get_endpoints" in schema_names
    assert "record_finding" in schema_names
    assert "spawn_subagent" in schema_names


def test_spawn_subagent_execution(tmp_path):
    ctx = AgentContext(
        target="example.com",
        target_dir=tmp_path,
        skill="parent-agent",
        run_id="run-test"
    )

    class MockSubLLM:
        def __init__(self):
            self.provider = "mock"
            self.model = "mock-agent"
        def is_available(self):
            return True
        def complete(self, prompt, **kwargs):
            return 'Thought: Child subagent analyzing.\nFinal Answer: Subagent verified no vulnerability on endpoint.'

    tools = build_default_agent_tools(ctx, llm_client=MockSubLLM(), allow_subagents=True)
    res = tools.execute("spawn_subagent", {
        "role": "JWT-Auditor",
        "goal": "Verify JWT token claims on /api/v1/auth",
        "target_url": "https://example.com/api/v1/auth"
    })

    assert res["status"] == "success"
    assert res["result"]["role"] == "JWT-Auditor"
    assert "Subagent verified" in res["result"]["summary"]


def test_custom_skill_execution_via_script(tmp_path):
    from tools.skill_runner import SkillRunner
    out_dir = tmp_path / "output"
    out_dir.mkdir(parents=True)
    runner = SkillRunner("example.com", tmp_path)
    runner.scope_authorized = True

    # Test executing jwt-analysis
    res = runner.run_custom_skill("jwt-analysis")
    assert res["status"] == "COMPLETED"
    assert res["skill"] == "jwt-analysis"
    assert (out_dir / "findings" / "candidates-jwt-analysis.json").exists()


def test_custom_script_with_direct_network_calls_is_blocked(tmp_path):
    from tools.skill_runner import SkillRunner

    runner = SkillRunner("example.com", tmp_path)
    result = runner.run_custom_skill("path-traversal")

    assert result["status"] == "BLOCKED_SCOPE"
    assert "shared scope-enforced HTTP client" in result["summary"]
