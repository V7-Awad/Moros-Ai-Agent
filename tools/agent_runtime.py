#!/usr/bin/env python3
"""
agent_runtime.py — Explicit Agent Runtime & ReAct Tool Loop for Moros AI.

Implements Priority 0 & Priority 1 of the Moros AI Architecture:
- Structured AgentContext & AgentResult interfaces
- Bounded tool registry with execution timeouts
- Multi-step ReAct (Reasoning + Action) execution loop
- Full conversation persistence (system, user, assistant, tool, observation)
- Explicit LLM_UNAVAILABLE state detection & handling
"""

import json
import logging
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

# Ensure sibling modules are importable when run from any working directory.
_tools_dir = Path(__file__).parent.resolve()
if str(_tools_dir) not in sys.path:
    sys.path.insert(0, str(_tools_dir))

from conversation_store import ConversationStore, safe_agent_name
from llm_client import LLMClient

logger = logging.getLogger("agent-runtime")


@dataclass
class AgentContext:
    target: str
    target_dir: Path
    skill: str
    run_id: str
    scope: Dict[str, Any] = field(default_factory=dict)
    artifacts: List[Dict[str, Any]] = field(default_factory=list)
    conversation: List[Dict[str, Any]] = field(default_factory=list)
    budget: Dict[str, Any] = field(default_factory=lambda: {
        "max_steps": 6,
        "max_tokens": 4000,
        "timeout_seconds": 180,
    })


@dataclass
class AgentResult:
    status: str  # "completed", "failed", "blocked", "llm_unavailable"
    summary: str
    findings: List[Dict[str, Any]] = field(default_factory=list)
    artifacts: List[str] = field(default_factory=list)
    next_actions: List[str] = field(default_factory=list)
    usage: Dict[str, Any] = field(default_factory=dict)
    reasoning_steps: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "summary": self.summary,
            "findings": self.findings,
            "artifacts": self.artifacts,
            "next_actions": self.next_actions,
            "usage": self.usage,
            "reasoning_steps": self.reasoning_steps,
        }


class ToolDefinition:
    def __init__(self, name: str, func: Callable, description: str, parameters: Dict[str, Any] = None):
        self.name = name
        self.func = func
        self.description = description
        self.parameters = parameters or {}

    def to_schema(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.parameters,
        }


class ToolRegistry:
    def __init__(self):
        self._tools: Dict[str, ToolDefinition] = {}

    def register(self, name: str, func: Callable, description: str, parameters: Dict[str, Any] = None):
        self._tools[name] = ToolDefinition(name, func, description, parameters)

    def get(self, name: str) -> Optional[ToolDefinition]:
        return self._tools.get(name)

    def list_schemas(self) -> List[Dict[str, Any]]:
        return [t.to_schema() for t in self._tools.values()]

    def execute(self, name: str, kwargs: Dict[str, Any] = None, timeout_seconds: int = 60) -> Dict[str, Any]:
        tool = self._tools.get(name)
        if not tool:
            return {"status": "error", "error": f"Tool '{name}' not found in registry"}

        kwargs = kwargs or {}
        start_time = time.time()
        try:
            result = tool.func(**kwargs)
            duration = round(time.time() - start_time, 3)
            return {"status": "success", "tool": name, "result": result, "duration_s": duration}
        except Exception as e:
            duration = round(time.time() - start_time, 3)
            logger.warning(f"Tool {name} failed: {e}")
            return {"status": "error", "tool": name, "error": str(e), "duration_s": duration}


class AgentRunner:
    """Orchestrates an agent session through an explicit ReAct decision loop."""

    def __init__(self, llm_client: Optional[LLMClient] = None):
        self.llm = llm_client or LLMClient(provider="auto")

    def run(self, context: AgentContext, tools: ToolRegistry, system_prompt: str, user_goal: str,
            fallback_fn: Optional[Callable[[AgentContext], AgentResult]] = None) -> AgentResult:
        """Execute the agent loop for a skill."""
        store = ConversationStore(context.target_dir)
        agent_id = safe_agent_name(context.skill)

        # 1. Record System & User Prompts in Persistent Conversation
        store.append(agent_id, "system", system_prompt, run_id=context.run_id)
        store.append(agent_id, "user", user_goal, run_id=context.run_id)

        # 2. Check if LLM Backend is Available
        if not self.llm.is_available():
            logger.info(f"[{agent_id}] No LLM provider configured. Operating in LLM_UNAVAILABLE mode.")
            store.append(
                agent_id,
                "assistant",
                f"[{agent_id.upper()}] No external LLM provider configured (OPENAI_API_KEY / ANTHROPIC_API_KEY / Ollama). "
                "Executing deterministic tool pipeline with full audit recording.",
                status="llm_unavailable",
                run_id=context.run_id
            )

            if fallback_fn:
                result = fallback_fn(context)
                result.status = "llm_unavailable"
                result.reasoning_steps.append("Executed deterministic tool pipeline (LLM_UNAVAILABLE).")
                store.append(agent_id, "assistant", f"Pipeline completed: {result.summary}", run_id=context.run_id)
                return result
            else:
                return AgentResult(
                    status="llm_unavailable",
                    summary="Skill halted: LLM provider is unavailable and no deterministic fallback was specified.",
                    usage={"steps": 0, "tokens": 0}
                )

        # 3. LLM is Available: Execute ReAct Tool Loop
        max_steps = context.budget.get("max_steps", 25)
        tool_schemas = tools.list_schemas()
        tool_prompt = self._format_tools_prompt(tool_schemas)

        full_system_prompt = (
            f"{system_prompt}\n\n"
            f"### Available Tools\n{tool_prompt}\n\n"
            "### Format Rules\n"
            "To invoke a tool, output exactly:\n"
            "Thought: <your security analysis and plan>\n"
            "Action: <tool_name>(\"arg_name\"=value)\n\n"
            "When analysis is complete, output:\n"
            "Thought: <final reasoning>\n"
            "Final Answer: <concise summary of findings and next actions>\n"
        )

        current_prompt = user_goal
        history: List[Dict[str, str]] = [{"role": "user", "content": user_goal}]
        reasoning_steps: List[str] = []
        findings_accumulated: List[Dict[str, Any]] = []
        artifacts_accumulated: List[str] = []
        llm_failure = None

        step = 0
        started_at = time.monotonic()
        while step < max_steps:
            if time.monotonic() - started_at >= context.budget.get("timeout_seconds", 600):
                return AgentResult(
                    status="timeout",
                    summary=f"{agent_id} stopped after reaching its time budget.",
                    findings=findings_accumulated,
                    artifacts=artifacts_accumulated,
                    usage={"steps": step, "provider": self.llm.provider, "model": self.llm.model},
                    reasoning_steps=reasoning_steps,
                )
            step += 1
            logger.info(f"[{agent_id}] ReAct Step {step}/{max_steps}")

            # Send prompt to LLM (expanded context window)
            step_prompt = "\n\n".join(
                f"{item['role'].upper()}: {item['content']}"
                for item in history[-40:]
            )[-48000:]
            llm_response = self.llm.complete(
                step_prompt,
                system_prompt=full_system_prompt,
                temperature=0.1,
                max_tokens=context.budget.get("max_tokens", 8192),
            )

            if not llm_response:
                llm_failure = self.llm.last_error or "empty response"
                logger.warning(f"[{agent_id}] LLM request failed on step {step}: {llm_failure}")
                break

            # Record Assistant Thought
            store.append(agent_id, "assistant", llm_response, step=step, run_id=context.run_id)
            history.append({"role": "assistant", "content": llm_response})

            # Check for Final Answer
            final_match = re.search(r"Final Answer:\s*(.+)", llm_response, re.DOTALL | re.IGNORECASE)
            if final_match:
                final_text = final_match.group(1).strip()
                reasoning_steps.append(f"Step {step}: Concluded with final answer.")
                return AgentResult(
                    status="completed",
                    summary=final_text,
                    findings=findings_accumulated,
                    artifacts=artifacts_accumulated,
                    next_actions=["review-skill", "report-conglomeration"],
                    usage={"steps": step, "model": self.llm.model, "provider": self.llm.provider},
                    reasoning_steps=reasoning_steps
                )

            # Extract Action: tool_name(...)
            action_match = re.search(r"Action:\s*([a-zA-Z0-9_-]+)\s*\((.*?)\)", llm_response, re.DOTALL)
            if not action_match:
                # No tool called, extract general thought
                thought_match = re.search(r"Thought:\s*(.+)", llm_response, re.DOTALL)
                thought_text = thought_match.group(1).strip() if thought_match else llm_response.strip()
                reasoning_steps.append(f"Step {step}: {thought_text[:120]}...")
                current_prompt = "Observation: No tool action was specified. If you are finished, output 'Final Answer: <summary>'. Otherwise, call a valid Action."
                history.append({"role": "user", "content": current_prompt})
                continue

            tool_name = action_match.group(1).strip()
            args_str = action_match.group(2).strip()
            parsed_args = self._parse_tool_args(args_str)

            reasoning_steps.append(f"Step {step}: Invoked {tool_name}")
            store.append(agent_id, "tool_call", f"Calling {tool_name} with args {parsed_args}", tool=tool_name, run_id=context.run_id)

            # Execute tool safely via registry
            tool_output = tools.execute(tool_name, parsed_args, timeout_seconds=context.budget.get("timeout_seconds", 120))
            obs_str = json.dumps(tool_output, default=str)

            # Collect artifacts / findings if returned
            if tool_output.get("status") == "success":
                res = tool_output.get("result", {})
                if isinstance(res, dict):
                    if "findings" in res and isinstance(res["findings"], list):
                        findings_accumulated.extend(res["findings"])
                    if "artifact" in res:
                        artifacts_accumulated.append(str(res["artifact"]))

            store.append(agent_id, "observation", obs_str[:8000], tool=tool_name, run_id=context.run_id)
            history.append({"role": "user", "content": f"Observation: {obs_str[:12000]}"})
            current_prompt = f"Observation: {obs_str[:12000]}\nWhat is your next Thought and Action?"

        # If model call failed, activate deterministic fallback if available
        if llm_failure:
            if fallback_fn:
                logger.info(f"[{agent_id}] Activating deterministic tool pipeline fallback after LLM failure: {llm_failure}")
                result = fallback_fn(context)
                result.status = "completed"
                result.reasoning_steps.append(f"Fallback triggered due to LLM error ({llm_failure}); deterministic pipeline completed.")
                store.append(agent_id, "assistant", f"Fallback completed: {result.summary}", run_id=context.run_id)
                return result
            status = "llm_error"
            summary = f"{agent_id} stopped because {self.llm.provider}/{self.llm.model} failed: {llm_failure}"
        elif step >= max_steps:
            status = "incomplete"
            summary = f"{agent_id} reached its {max_steps}-step limit without a final answer."
        else:
            status = "incomplete"
            summary = f"{agent_id} stopped without a final answer after {step} analysis steps."
        return AgentResult(
            status=status,
            summary=summary,
            findings=findings_accumulated,
            artifacts=artifacts_accumulated,
            next_actions=["review-skill"],
            usage={"steps": step, "model": self.llm.model, "provider": self.llm.provider},
            reasoning_steps=reasoning_steps
        )

    @staticmethod
    def _format_tools_prompt(schemas: List[Dict[str, Any]]) -> str:
        lines = []
        for s in schemas:
            lines.append(f"- **{s['name']}**: {s['description']}")
            if s.get("parameters"):
                lines.append(f"  Params: {json.dumps(s['parameters'])}")
        return "\n".join(lines)

    @staticmethod
    def _parse_tool_args(args_str: str) -> Dict[str, Any]:
        """Parse key=value or JSON arguments from tool call string."""
        if not args_str:
            return {}
        try:
            if args_str.startswith("{") and args_str.endswith("}"):
                return json.loads(args_str)
        except Exception:
            pass

        args = {}
        # Match param="val" or param=val
        matches = re.findall(r'([a-zA-Z0-9_-]+)\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^,\s\)]+))', args_str)
        for m in matches:
            k = m[0]
            val = m[1] or m[2] or m[3]
            args[k] = val
        return args
