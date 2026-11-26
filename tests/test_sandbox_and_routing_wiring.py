#!/usr/bin/env python3
"""Tests for tool permission scoping, per-step model routing, sandboxed custom skills, and Juice Shop eval."""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

PROJECT_ROOT = Path(__file__).parent.parent.resolve()
TOOLS_DIR = PROJECT_ROOT / "tools"
EVALS_DIR = PROJECT_ROOT / "evals"
for p in (str(PROJECT_ROOT), str(TOOLS_DIR), str(EVALS_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

from agent_runtime import (
    AgentContext,
    AgentRunner,
    ToolRegistry,
    build_default_agent_tools,
)
from agent_security import SKILL_TOOL_PERMISSIONS, check_tool_permission, get_allowed_tools
from cost_tracker import CostTracker
from juice_shop_benchmark import JuiceShopBenchmark, VulnerableAppSimulator
from model_router import ModelRouter
from trace_logger import TraceLogger


class TestSkillToolPermissionScoping:
    DEFAULT_AGENT_TOOLS = (
        "search_code",
        "get_endpoints",
        "record_finding",
        "spawn_subagent",
        "spawn_subagents_parallel",
        "http_get",
    )

    @pytest.mark.parametrize("tier", ["recon", "analysis", "active"])
    def test_default_agent_tools_allowed_for_operational_tiers(self, tier):
        allowed = SKILL_TOOL_PERMISSIONS[tier]
        for tool_name in self.DEFAULT_AGENT_TOOLS:
            assert tool_name in allowed, f"{tool_name} missing from tier {tier}"

    def test_reporting_tier_allows_local_reporting_tools_only(self):
        allowed = get_allowed_tools("report-conglomeration")
        for tool_name in ("read_file", "write_file", "sarif_export", "search_code", "get_endpoints", "record_finding"):
            assert tool_name in allowed
        assert "http_post" not in allowed
        assert "http_get" not in allowed
        assert "spawn_subagent" not in allowed

    def test_enforce_permissions_works_with_default_tools_without_false_denials(self, tmp_path):
        (tmp_path / "output" / "js").mkdir(parents=True)
        (tmp_path / "output" / "recon").mkdir(parents=True)
        (tmp_path / "output" / "js" / "app.js").write_text("const apiToken = 'abc';\n", encoding="utf-8")
        (tmp_path / "output" / "recon" / "endpoints.txt").write_text("/api/v1/users\n", encoding="utf-8")

        mock_http = MagicMock()
        mock_http.target = "example.com"
        mock_http.request_count = 0
        mock_http.get.return_value = {
            "status": "response",
            "status_code": 200,
            "url": "https://example.com/api/v1/users",
            "headers": {"content-type": "application/json"},
            "body": '{"users": []}',
        }

        class ScriptedLLM:
            provider = "mock"
            model = "mock-model"
            last_error = None
            last_usage = {"input_tokens": 40, "output_tokens": 20}

            def __init__(self):
                self.actions = [
                    'Thought: list endpoints\nAction: get_endpoints(filter_keyword="api")',
                    'Thought: search code\nAction: search_code(query="apiToken")',
                    'Thought: fetch endpoint\nAction: http_get(url="https://example.com/api/v1/users")',
                    'Thought: record finding\nAction: record_finding(title="Token Ref", severity="LOW", url="https://example.com/api/v1/users")',
                    'Thought: done\nFinal Answer: Completed recon audit cleanly.',
                ]

            def is_available(self):
                return True

            def complete(self, prompt, **kwargs):
                assert "not authorized" not in prompt
                return self.actions.pop(0)

        ctx = AgentContext(target="example.com", target_dir=tmp_path, skill="recon-subdomain", run_id="perm-e2e")
        tools = build_default_agent_tools(ctx, llm_client=ScriptedLLM(), allow_subagents=True, http_client=mock_http)
        runner = AgentRunner(llm_client=ScriptedLLM(), enforce_permissions=True)

        result = runner.run(ctx, tools, "System", "Run recon", persist_conversation=False)
        assert result.status == "completed"
        assert "Completed recon audit cleanly." in result.summary
        assert (tmp_path / "output" / "findings" / "candidates-recon-subdomain.json").is_file()

        ok_sub, _ = check_tool_permission("recon-subdomain", "spawn_subagent")
        ok_par, _ = check_tool_permission("recon-subdomain", "spawn_subagents_parallel")
        ok_post, _ = check_tool_permission("recon-subdomain", "http_post")
        assert ok_sub is True
        assert ok_par is True
        assert ok_post is False


class TestPerStepDynamicRouting:
    def test_per_step_routing_disabled_by_default_does_not_call_select_model(self, tmp_path):
        router = ModelRouter(budget_usd=5.0, available_providers=["deepseek", "openai"])
        select_spy = MagicMock(wraps=router.select_model)
        router.select_model = select_spy

        class SimpleLLM:
            provider = "mock"
            model = "mock-base"
            last_error = None
            last_usage = {"input_tokens": 20, "output_tokens": 10}

            def is_available(self):
                return True

            def complete(self, prompt, **kwargs):
                return "Thought: done\nFinal Answer: Ok"

        ctx = AgentContext(target="example.com", target_dir=tmp_path, skill="js-analyze", run_id="no-route")
        runner = AgentRunner(llm_client=SimpleLLM(), model_router=router)
        assert runner.per_step_routing is False

        res = runner.run(ctx, ToolRegistry(), "Sys", "format list", persist_conversation=False)
        assert res.status == "completed"
        assert select_spy.call_count == 0
        assert res.usage["model"] == "mock-base"

    def test_per_step_routing_calls_select_model_each_step_with_mock_llm(self, tmp_path):
        router = ModelRouter(budget_usd=5.0, available_providers=["deepseek", "openai"])
        seen_prompts = []
        original_select = router.select_model

        def spying_select(prompt, *args, **kwargs):
            seen_prompts.append(prompt)
            return original_select(prompt, *args, **kwargs)

        router.select_model = spying_select

        tracker = CostTracker(target_dir=tmp_path, budget_cap_usd=5.0)
        tracer = TraceLogger(target_dir=tmp_path)
        trace_id = tracer.start_trace("route-trace")

        class TwoStepMockLLM:
            provider = "mock"
            model = "mock-llm"
            last_error = None
            last_usage = {"input_tokens": 100, "output_tokens": 40}

            def __init__(self):
                self.calls = 0

            def is_available(self):
                return True

            def complete(self, prompt, **kwargs):
                self.calls += 1
                if self.calls == 1:
                    return 'Thought: check tool\nAction: inspect()'
                return "Thought: done\nFinal Answer: Escalated analysis complete"

        reg = ToolRegistry()
        reg.register(
            "inspect",
            lambda: {"note": "Need to exploit bypass and audit injection payload chain"},
            "Inspect endpoint",
        )

        ctx = AgentContext(target="example.com", target_dir=tmp_path, skill="js-analyze", run_id="step-route")
        runner = AgentRunner(
            llm_client=TwoStepMockLLM(),
            cost_tracker=tracker,
            tracer=tracer,
            model_router=router,
            trace_id=trace_id,
            per_step_routing=True,
        )
        res = runner.run(ctx, reg, "Sys", "format and normalize list", persist_conversation=False)
        tracer.end_trace(trace_id)

        assert res.status == "completed"
        assert len(seen_prompts) == 2
        assert seen_prompts[0] == "format and normalize list"
        assert "exploit bypass" in seen_prompts[1]

        # Step 1 ("format and normalize list") -> simple -> deepseek/deepseek-chat
        # Step 2 (contains "exploit", "bypass", "audit", "inject", "payload", "chain") -> frontier -> openai/o4-mini
        llm_spans = [s for s in tracer.get_trace(trace_id) if s["type"] == "llm"]
        assert len(llm_spans) == 2
        assert llm_spans[0]["attributes"]["llm.provider"] == "deepseek"
        assert llm_spans[0]["attributes"]["llm.model"] == "deepseek-chat"
        assert llm_spans[1]["attributes"]["llm.provider"] == "openai"
        assert llm_spans[1]["attributes"]["llm.model"] == "o4-mini"
        assert res.usage["provider"] == "openai"
        assert res.usage["model"] == "o4-mini"

    def test_per_step_routing_handles_missing_router_gracefully(self, tmp_path):
        class OneShotLLM:
            provider = "mock"
            model = "mock-1"
            last_error = None
            last_usage = {"input_tokens": 10, "output_tokens": 5}

            def is_available(self):
                return True

            def complete(self, prompt, **kwargs):
                return "Final Answer: OK"

        ctx = AgentContext(target="example.com", target_dir=tmp_path, skill="js-analyze", run_id="no-router")
        runner = AgentRunner(llm_client=OneShotLLM(), model_router=None, per_step_routing=True)
        res = runner.run(ctx, ToolRegistry(), "Sys", "Goal", persist_conversation=False)
        assert res.status == "completed"
        assert res.summary == "OK"


class TestSandboxedCustomSkillExecution:
    def test_run_custom_skill_executes_inside_local_sandbox_with_scrubbed_env(self, tmp_path, monkeypatch):
        import sandbox_manager
        import skill_registry
        import tools.sandbox_manager as tsm
        import tools.skill_registry as tsr
        from tools.skill_runner import SkillRunner

        skills_dir = tmp_path / "skills"
        custom_dir = skills_dir / "sandbox-probe-skill"
        custom_dir.mkdir(parents=True)
        (custom_dir / "SKILL.md").write_text("# Sandbox Probe Skill\n", encoding="utf-8")
        (custom_dir / "run.py").write_text(
            "import argparse, json, os\n"
            "from pathlib import Path\n"
            "p = argparse.ArgumentParser()\n"
            "p.add_argument('--target', required=True)\n"
            "p.add_argument('--target-dir', required=True)\n"
            "p.add_argument('--output-dir', required=True)\n"
            "args = p.parse_args()\n"
            "out_dir = Path(args.output_dir)\n"
            "(out_dir / 'findings').mkdir(parents=True, exist_ok=True)\n"
            "payload = {\n"
            "  'cwd': os.getcwd(),\n"
            "  'openai_present': 'OPENAI_API_KEY' in os.environ,\n"
            "  'aws_present': 'AWS_SECRET_ACCESS_KEY' in os.environ,\n"
            "}\n"
            "(out_dir / 'sandbox-env-check.json').write_text(json.dumps(payload), encoding='utf-8')\n"
            "(out_dir / 'findings' / 'candidates-sandbox-probe-skill.json').write_text(\n"
            "  json.dumps({'findings': [{'title': 'Sandbox Verified', 'severity': 'LOW', 'url': 'https://example.com'}]}),\n"
            "  encoding='utf-8',\n"
            ")\n"
            "print('sandbox probe finished')\n",
            encoding="utf-8",
        )

        monkeypatch.setattr(skill_registry, "SKILLS_DIR", skills_dir)
        monkeypatch.setattr(tsr, "SKILLS_DIR", skills_dir)
        monkeypatch.setenv("OPENAI_API_KEY", "sk-should-be-scrubbed-1234567890")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "aws-secret-should-be-scrubbed")

        created_backends = []
        created_workspaces = []
        orig_create = sandbox_manager.create_sandbox

        def spy_create(backend="auto", **kwargs):
            created_backends.append(backend)
            sb = orig_create(backend, **kwargs)
            orig_start = sb.start

            def spy_start():
                orig_start()
                if sb.workspace is not None:
                    created_workspaces.append(sb.workspace)

            sb.start = spy_start
            return sb

        monkeypatch.setattr(sandbox_manager, "create_sandbox", spy_create)
        monkeypatch.setattr(tsm, "create_sandbox", spy_create)

        target_dir = tmp_path / "target"
        target_dir.mkdir()
        runner = SkillRunner("example.com", target_dir)
        runner.scope_authorized = True

        res = runner.run_custom_skill("sandbox-probe-skill")
        assert res["status"] == "COMPLETED"
        assert res["findings_count"] == 1
        assert created_backends == ["local"]
        assert len(created_workspaces) == 1
        # Workspace should be cleaned up on sandbox exit
        assert not created_workspaces[0].exists()

        recorded = json.loads(
            (target_dir / "output" / "findings" / "candidates-sandbox-probe-skill.json").read_text(encoding="utf-8")
        )
        assert recorded["findings"][0]["title"] == "Sandbox Verified"
        env_check = json.loads(
            (target_dir / "output" / "sandbox-env-check.json").read_text(encoding="utf-8")
        )
        assert env_check["openai_present"] is False
        assert env_check["aws_present"] is False
        assert Path(env_check["cwd"]).name.startswith("moros-sandbox-")
        # Check stdout log proves script ran inside the isolated temp workspace
        stdout_log = (target_dir / "output" / "logs" / "sandbox-probe-skill" / "script-stdout.log").read_text(encoding="utf-8")
        assert "sandbox probe finished" in stdout_log

    def test_run_custom_skill_falls_back_safely_when_sandbox_raises(self, tmp_path, monkeypatch):
        import sandbox_manager
        import skill_registry
        import tools.sandbox_manager as tsm
        import tools.skill_registry as tsr
        from tools.skill_runner import SkillRunner

        skills_dir = tmp_path / "skills"
        custom_dir = skills_dir / "fallback-probe-skill"
        custom_dir.mkdir(parents=True)
        (custom_dir / "SKILL.md").write_text("# Fallback Probe Skill\n", encoding="utf-8")
        (custom_dir / "run.py").write_text(
            "import argparse, json\n"
            "from pathlib import Path\n"
            "p = argparse.ArgumentParser()\n"
            "p.add_argument('--target', required=True)\n"
            "p.add_argument('--target-dir', required=True)\n"
            "p.add_argument('--output-dir', required=True)\n"
            "args = p.parse_args()\n"
            "out_dir = Path(args.output_dir)\n"
            "(out_dir / 'findings').mkdir(parents=True, exist_ok=True)\n"
            "(out_dir / 'findings' / 'candidates-fallback-probe-skill.json').write_text("
            "json.dumps({'findings': [{'title': 'Fallback OK', 'severity': 'INFO', 'url': 'https://example.com'}]}), encoding='utf-8')\n",
            encoding="utf-8",
        )

        monkeypatch.setattr(skill_registry, "SKILLS_DIR", skills_dir)
        monkeypatch.setattr(tsr, "SKILLS_DIR", skills_dir)

        def fail_sandbox(backend="auto", **kwargs):
            raise RuntimeError("simulated sandbox failure")

        monkeypatch.setattr(sandbox_manager, "create_sandbox", fail_sandbox)
        monkeypatch.setattr(tsm, "create_sandbox", fail_sandbox)

        target_dir = tmp_path / "target"
        target_dir.mkdir()
        runner = SkillRunner("example.com", target_dir)
        res = runner.run_custom_skill("fallback-probe-skill")

        assert res["status"] == "COMPLETED"
        assert res["findings_count"] == 1
        audit_log = (target_dir / "output" / "logs" / "fallback-probe-skill" / "step-custom-audit.log").read_text(encoding="utf-8")
        assert "falling back" in audit_log.lower()


class TestJuiceShopBenchmarkIntegration:
    def test_benchmark_metrics_and_vuln_coverage(self):
        report = JuiceShopBenchmark().run_all()
        assert report["total_cases"] == 14
        assert report["true_positives"] == 7
        assert report["false_positives"] == 0
        assert report["true_negatives"] == 7
        assert report["false_negatives"] == 0
        assert report["true_positive_rate"] == 1.0
        assert report["false_positive_rate"] == 0.0
        assert set(report["by_vuln_type"].keys()) == {
            "xss", "sqli", "idor", "path_traversal", "jwt_alg_none", "open_redirect", "cors"
        }

    def test_simulator_server_binds_ephemeral_port_and_cleans_up(self):
        with VulnerableAppSimulator() as sim:
            assert sim.base_url.startswith("http://127.0.0.1:")
            assert sim._server is not None
        assert sim._server is None

    def test_benchmark_cli_json_output(self, capsys, monkeypatch):
        import juice_shop_benchmark

        monkeypatch.setattr(sys, "argv", ["juice_shop_benchmark.py", "--json"])
        juice_shop_benchmark.main()
        out = capsys.readouterr().out
        parsed = json.loads(out)
        assert parsed["true_positive_rate"] == 1.0
        assert parsed["false_positive_rate"] == 0.0
