import json
import pytest
from pathlib import Path
from tools.agent_runtime import AgentContext, AgentResult, ToolRegistry, AgentRunner


def test_tool_registry_registration_and_execution():
    registry = ToolRegistry()

    def sample_tool(val: int):
        return {"doubled": val * 2}

    registry.register("sample", sample_tool, "A sample test tool")
    assert registry.get("sample") is not None
    assert len(registry.list_schemas()) == 1

    # Execute successfully
    res = registry.execute("sample", {"val": 21})
    assert res["status"] == "success"
    assert res["result"]["doubled"] == 42

    # Execute nonexistent
    err = registry.execute("unknown", {})
    assert err["status"] == "error"
    assert "not found" in err["error"]


def test_agent_context_and_result_dataclasses(tmp_path):
    ctx = AgentContext(
        target="example.com",
        target_dir=tmp_path,
        skill="js-analyze",
        run_id="test-run-1"
    )
    assert ctx.target == "example.com"
    assert ctx.budget["max_steps"] == 6

    res = AgentResult(
        status="completed",
        summary="Test analysis complete",
        findings=[{"type": "XSS"}],
        artifacts=["/path/to/art.json"]
    )
    res_dict = res.to_dict()
    assert res_dict["status"] == "completed"
    assert len(res_dict["findings"]) == 1


class MockLLM:
    def __init__(self, responses):
        self.responses = list(responses)
        self.provider = "mock"
        self.model = "mock-model"

    def is_available(self):
        return True

    def complete(self, prompt, system_prompt=None, temperature=0.1, max_tokens=4000, **kwargs):
        if self.responses:
            return self.responses.pop(0)
        return "Final Answer: No more responses"


def test_agent_runner_react_loop(tmp_path):
    registry = ToolRegistry()
    registry.register("dummy_tool", lambda text: {"echo": text}, "Echo tool")

    mock_llm = MockLLM([
        'Thought: I need to test the dummy tool.\nAction: dummy_tool(text="hello")',
        'Thought: Tool returned the echo.\nFinal Answer: Test completed successfully with echo.'
    ])

    runner = AgentRunner(llm_client=mock_llm)
    ctx = AgentContext(
        target="test.local",
        target_dir=tmp_path,
        skill="test-skill",
        run_id="run-react"
    )

    result = runner.run(
        context=ctx,
        tools=registry,
        system_prompt="Test system prompt",
        user_goal="Test user goal"
    )

    assert result.status == "completed"
    assert "Test completed successfully" in result.summary
    assert len(result.reasoning_steps) >= 2


class UnavailableLLM:
    def is_available(self):
        return False


def test_agent_runner_llm_unavailable_fallback(tmp_path):
    registry = ToolRegistry()
    runner = AgentRunner(llm_client=UnavailableLLM())

    ctx = AgentContext(
        target="test.local",
        target_dir=tmp_path,
        skill="test-fallback",
        run_id="run-fallback"
    )

    def fallback(c):
        return AgentResult(
            status="completed",
            summary="Fallback executed deterministic logic",
            findings=[{"id": "F1"}]
        )

    result = runner.run(
        context=ctx,
        tools=registry,
        system_prompt="System",
        user_goal="Goal",
        fallback_fn=fallback
    )

    assert result.status == "llm_unavailable"
    assert "Fallback executed" in result.summary
    assert len(result.findings) == 1
