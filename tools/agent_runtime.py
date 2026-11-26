#!/usr/bin/env python3
"""
agent_runtime.py — Agent Runtime & ReAct Tool Loop for Moros.

Provides:
- Structured AgentContext & AgentResult execution state
- Bounded tool registry with execution timeouts
- Multi-step ReAct (Reasoning + Action) execution loop
- Conversation persistence (system, user, assistant, tool, observation)
- Explicit LLM_UNAVAILABLE state detection & offline fallback
"""

import inspect
import json
import logging
import os
import re
import subprocess
import sys
import threading
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
from sandbox_manager import create_sandbox
from agent_security import (
    ActionBudget,
    check_tool_permission,
    detect_injection,
    sanitize_for_prompt,
    sanitize_output,
)

logger = logging.getLogger("agent-runtime")


def run_sandboxed_command(
    command: List[str],
    sandbox_mode: str = "local",
    timeout: int = 60,
    extra_env: Optional[Dict[str, str]] = None,
    cwd: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute a shell/custom command with optional SandboxManager isolation."""
    mode = (sandbox_mode or "local").strip().lower()
    if mode == "none":
        env = dict(os.environ)
        if extra_env:
            env.update(extra_env)
        started = time.monotonic()
        try:
            proc = subprocess.run(
                command,
                cwd=cwd,
                env=env,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return {
                "status": "success" if proc.returncode == 0 else "error",
                "exit_code": proc.returncode,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "duration_ms": round((time.monotonic() - started) * 1000, 1),
                "backend": "none",
                "timed_out": False,
            }
        except subprocess.TimeoutExpired as exc:
            return {
                "status": "error",
                "exit_code": -1,
                "stdout": (exc.stdout or "") if isinstance(exc.stdout, str) else "",
                "stderr": f"Command timed out after {timeout}s",
                "duration_ms": round((time.monotonic() - started) * 1000, 1),
                "backend": "none",
                "timed_out": True,
            }

    with create_sandbox(mode, extra_env=extra_env, scrub_secrets=True) as sb:
        res = sb.run_command(command, timeout=timeout, cwd=cwd)
    out = res.to_dict()
    out["status"] = "success" if res.exit_code == 0 and not res.timed_out else "error"
    return out


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
        "max_steps": 25,
        "max_tokens": 8192,
        "timeout_seconds": 600,
        "max_history_items": 40,
        "max_prompt_chars": 48000,
    })
    max_subagents: int = 5
    sandbox_mode: str = "local"


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
    def __init__(self, name: str, func: Callable, description: str,
                 parameters: Dict[str, Any] = None, sandboxed: bool = False):
        self.name = name
        self.func = func
        self.description = description
        self.parameters = parameters or {}
        self.sandboxed = sandboxed

    def to_schema(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.parameters,
        }


class ToolRegistry:
    def __init__(self):
        self._tools: Dict[str, ToolDefinition] = {}

    def register(self, name: str, func: Callable, description: str,
                 parameters: Dict[str, Any] = None, sandboxed: bool = False):
        self._tools[name] = ToolDefinition(name, func, description, parameters, sandboxed=sandboxed)

    def register_mcp_client(self, mcp_client, prefix: str = "") -> int:
        """Mount discovered tools from an external MCPClient into this registry."""
        count = 0
        for t in mcp_client.list_tools():
            raw_name = t["name"]
            tool_name = f"{prefix}{raw_name}" if prefix else f"mcp_{mcp_client.server_name}_{raw_name}"

            def _make_caller(client, remote_name):
                def _caller(**kwargs):
                    return client.call_tool(remote_name, kwargs)
                return _caller

            self.register(
                tool_name,
                _make_caller(mcp_client, raw_name),
                f"[MCP:{mcp_client.server_name}] {t.get('description', '')}",
                t.get("input_schema", {}).get("properties", {}),
            )
            count += 1
        return count

    def get(self, name: str) -> Optional[ToolDefinition]:
        return self._tools.get(name)

    def list_schemas(self) -> List[Dict[str, Any]]:
        return [t.to_schema() for t in self._tools.values()]

    def execute_sandboxed(self, command: List[str], sandbox_mode: str = "local",
                          timeout_seconds: int = 60, extra_env: Optional[Dict[str, str]] = None,
                          cwd: Optional[str] = None) -> Dict[str, Any]:
        """Run a subprocess command using SandboxManager isolation."""
        return run_sandboxed_command(
            command,
            sandbox_mode=sandbox_mode,
            timeout=timeout_seconds,
            extra_env=extra_env,
            cwd=cwd,
        )

    def execute(self, name: str, kwargs: Dict[str, Any] = None, timeout_seconds: int = 60,
                sandbox_mode: Optional[str] = None) -> Dict[str, Any]:
        tool = self._tools.get(name)
        if not tool:
            return {"status": "error", "error": f"Tool '{name}' not found in registry"}

        kwargs = dict(kwargs or {})
        if tool.sandboxed and sandbox_mode is not None:
            try:
                sig = inspect.signature(tool.func)
                if "sandbox_mode" in sig.parameters or any(
                    p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()
                ):
                    kwargs.setdefault("sandbox_mode", sandbox_mode)
            except (TypeError, ValueError):
                pass
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

    def __init__(self, llm_client: Optional[LLMClient] = None,
                 cost_tracker=None, tracer=None, memory_manager=None,
                 action_budget: Optional[ActionBudget] = None,
                 model_router=None, trace_id: Optional[str] = None,
                 enforce_permissions: bool = False,
                 max_subagents: Optional[int] = None,
                 sandbox_mode: Optional[str] = None,
                 per_step_routing: bool = False):
        self.llm = llm_client or LLMClient(provider="auto")
        self.cost_tracker = cost_tracker
        self.tracer = tracer
        self.memory_manager = memory_manager
        self.action_budget = action_budget
        self.model_router = model_router
        self.trace_id = trace_id
        self.enforce_permissions = enforce_permissions
        self.max_subagents = max(0, int(max_subagents)) if max_subagents is not None else None
        self.sandbox_mode = sandbox_mode.strip().lower() if sandbox_mode else None
        self.per_step_routing = per_step_routing

    def run(self, context: AgentContext, tools: ToolRegistry, system_prompt: str, user_goal: str,
            fallback_fn: Optional[Callable[[AgentContext], AgentResult]] = None,
            persist_conversation: bool = True) -> AgentResult:
        """Execute the agent loop for a skill."""
        store = ConversationStore(context.target_dir)
        agent_id = safe_agent_name(context.skill)
        record = store.append if persist_conversation else lambda *args, **kwargs: None

        active_trace_id = self.trace_id
        skill_span = None
        if self.tracer and active_trace_id:
            skill_span = self.tracer.start_span(
                f"skill/{context.skill}", active_trace_id, span_type="skill",
                attributes={"skill": context.skill, "target": context.target},
            )

        def _finish(result: AgentResult) -> AgentResult:
            if skill_span and self.tracer:
                st = "ok" if result.status in ("completed", "llm_unavailable") else "error"
                self.tracer.end_span(skill_span, status=st, error="" if st == "ok" else result.summary)
            return result

        # 1. Record System & User Prompts in Persistent Conversation
        record(agent_id, "system", system_prompt, run_id=context.run_id)
        record(agent_id, "user", user_goal, run_id=context.run_id)

        # 2. Check if LLM Backend is Available
        if not self.llm.is_available():
            logger.info(f"[{agent_id}] No LLM provider configured. Operating in LLM_UNAVAILABLE mode.")
            record(
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
                record(agent_id, "assistant", f"Pipeline completed: {result.summary}", run_id=context.run_id)
                return _finish(result)
            else:
                return _finish(AgentResult(
                    status="llm_unavailable",
                    summary="Skill halted: LLM provider is unavailable and no deterministic fallback was specified.",
                    usage={"steps": 0, "tokens": 0}
                ))

        # 3. LLM is Available: Execute ReAct Tool Loop
        max_steps = context.budget.get("max_steps", 25)
        tool_schemas = tools.list_schemas()
        tool_prompt = self._format_tools_prompt(tool_schemas)

        recalled_context = ""
        if self.memory_manager:
            try:
                recalled_context = self.memory_manager.build_target_context()
            except Exception as exc:
                logger.debug("Memory recall error: %s", exc)

        full_system_prompt = (
            f"{system_prompt}\n\n"
            + (f"### Prior Target Knowledge\n{recalled_context}\n\n" if recalled_context else "")
            + f"### Available Tools\n{tool_prompt}\n\n"
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
        last_provider = getattr(self.llm, "provider", "auto")
        last_model = getattr(self.llm, "model", "default")

        if self.max_subagents is not None:
            effective_max_subagents = self.max_subagents
        elif "max_subagents" in context.budget:
            effective_max_subagents = max(0, int(context.budget["max_subagents"]))
        else:
            effective_max_subagents = max(0, int(getattr(context, "max_subagents", 5)))
        effective_sandbox_mode = (
            self.sandbox_mode
            or getattr(context, "sandbox_mode", None)
            or os.environ.get("MOROS_SANDBOX_MODE", "local")
        ).strip().lower() or "local"
        subagent_calls = 0

        step = 0
        started_at = time.monotonic()
        while step < max_steps:
            if time.monotonic() - started_at >= context.budget.get("timeout_seconds", 600):
                return _finish(AgentResult(
                    status="timeout",
                    summary=f"{agent_id} stopped after reaching its time budget.",
                    findings=findings_accumulated,
                    artifacts=artifacts_accumulated,
                    usage={"steps": step, "provider": self.llm.provider, "model": self.llm.model},
                    reasoning_steps=reasoning_steps,
                ))
            if self.cost_tracker and self.cost_tracker.budget_exceeded:
                return _finish(AgentResult(
                    status="blocked",
                    summary=f"{agent_id} paused: LLM cost budget cap reached.",
                    findings=findings_accumulated,
                    artifacts=artifacts_accumulated,
                    usage={"steps": step, "provider": self.llm.provider, "model": self.llm.model},
                    reasoning_steps=reasoning_steps,
                ))
            step += 1
            logger.info(f"[{agent_id}] ReAct Step {step}/{max_steps}")

            step_llm, step_provider, step_model = self._resolve_step_llm(current_prompt, step)
            last_provider, last_model = step_provider, step_model

            # Send prompt to LLM (expanded context window)
            max_history_items = context.budget.get("max_history_items", 40)
            max_prompt_chars = context.budget.get("max_prompt_chars", 48000)
            step_prompt = "\n\n".join(
                f"{item['role'].upper()}: {item['content']}"
                for item in history[-max_history_items:]
            )[-max_prompt_chars:]
            llm_t0 = time.monotonic()
            llm_response = step_llm.complete(
                step_prompt,
                system_prompt=full_system_prompt,
                temperature=0.1,
                max_tokens=context.budget.get("max_tokens", 8192),
            )
            llm_ms = (time.monotonic() - llm_t0) * 1000

            if not llm_response:
                llm_failure = getattr(step_llm, "last_error", None) or "empty response"
                logger.warning(f"[{agent_id}] LLM request failed on step {step}: {llm_failure}")
                break

            usage = getattr(step_llm, "last_usage", None) or {
                "input_tokens": max(1, (len(step_prompt) + len(full_system_prompt)) // 4),
                "output_tokens": max(1, len(llm_response) // 4),
            }
            in_tok = int(usage.get("input_tokens", 0))
            out_tok = int(usage.get("output_tokens", 0))
            step_cost = 0.0
            if self.model_router:
                step_cost = self.model_router.record_usage(
                    in_tok, out_tok,
                    provider=step_provider,
                    model=step_model,
                )
            elif self.cost_tracker:
                step_cost = (in_tok * 0.5 / 1_000_000) + (out_tok * 1.5 / 1_000_000)
            if self.cost_tracker:
                self.cost_tracker.record(
                    skill=context.skill,
                    step=step,
                    provider=step_provider,
                    model=step_model,
                    input_tokens=in_tok,
                    output_tokens=out_tok,
                    cost_usd=step_cost,
                    duration_ms=llm_ms,
                )
            if self.tracer and active_trace_id:
                self.tracer.record_llm_call(
                    active_trace_id,
                    parent_id=skill_span.span_id if skill_span else "",
                    provider=step_provider,
                    model=step_model,
                    input_tokens=in_tok,
                    output_tokens=out_tok,
                    cost_usd=step_cost,
                    duration_ms=llm_ms,
                    prompt_preview=step_prompt[:200],
                )

            # Record Assistant Thought
            record(agent_id, "assistant", llm_response, step=step, run_id=context.run_id)
            history.append({"role": "assistant", "content": llm_response})

            # Live Terminal Visualizer: Display Thought
            thought_match = re.search(r"Thought:\s*(.+?)(?=\nAction:|\nFinal Answer:|\nAnswer:|\n\n|\Z)", llm_response, re.DOTALL | re.IGNORECASE)
            if thought_match:
                t_str = thought_match.group(1).strip().replace("\n", " ")
                print(f"  🧠 \033[36m[{agent_id.upper()} THOUGHT]\033[0m {t_str[:160]}...")

            # Check for Final Answer
            final_match = re.search(r"Final Answer:\s*(.+)", llm_response, re.DOTALL | re.IGNORECASE)
            if final_match:
                final_text = sanitize_output(final_match.group(1).strip())
                print(f"  🎯 \033[35m[{agent_id.upper()} FINAL ANSWER]\033[0m {final_text[:200]}")
                reasoning_steps.append(f"Step {step}: Concluded with final answer.")
                if self.memory_manager:
                    try:
                        self.memory_manager.clear_checkpoints(context.run_id)
                    except Exception:
                        pass
                return _finish(AgentResult(
                    status="completed",
                    summary=final_text,
                    findings=findings_accumulated,
                    artifacts=artifacts_accumulated,
                    next_actions=["review-skill", "report-conglomeration"],
                    usage={"steps": step, "model": last_model, "provider": last_provider},
                    reasoning_steps=reasoning_steps
                ))

            # Extract Action: tool_name(...)
            action_match = re.search(r"Action:\s*([a-zA-Z0-9_-]+)\s*\((.*?)\)", llm_response, re.DOTALL)
            if not action_match:
                # Direct conversational response (e.g. "PONG", greeting, direct answer without ReAct syntax)
                raw_text = llm_response.strip()
                thought_prefix_match = re.match(r"^Thought:\s*(.+?)(?:\n+(.*))?$", raw_text, re.DOTALL | re.IGNORECASE)
                if thought_prefix_match:
                    t_content = (thought_prefix_match.group(1) or "").strip()
                    remainder = (thought_prefix_match.group(2) or "").strip()
                    answer_text = remainder if remainder else t_content
                else:
                    answer_text = raw_text

                answer_text = sanitize_output(
                    re.sub(r"^(?:Answer|Response):\s*", "", answer_text, flags=re.IGNORECASE).strip()
                )
                if not answer_text:
                    answer_text = sanitize_output(raw_text)

                print(f"  🎯 \033[35m[{agent_id.upper()} DIRECT ANSWER]\033[0m {answer_text[:200]}")
                reasoning_steps.append(f"Step {step}: Direct response without tool invocation.")
                return _finish(AgentResult(
                    status="completed",
                    summary=answer_text,
                    findings=findings_accumulated,
                    artifacts=artifacts_accumulated,
                    next_actions=["review-skill", "report-conglomeration"],
                    usage={"steps": step, "model": last_model, "provider": last_provider},
                    reasoning_steps=reasoning_steps
                ))

            tool_name = action_match.group(1).strip()
            args_str = action_match.group(2).strip()
            parsed_args = self._parse_tool_args(args_str)

            if self.action_budget:
                allowed_budget, budget_reason = self.action_budget.record_action(tool_name)
                if not allowed_budget:
                    reasoning_steps.append(f"Step {step}: Halted by action budget gate ({budget_reason}).")
                    return _finish(AgentResult(
                        status="blocked",
                        summary=budget_reason,
                        findings=findings_accumulated,
                        artifacts=artifacts_accumulated,
                        usage={"steps": step, "model": self.llm.model, "provider": self.llm.provider},
                        reasoning_steps=reasoning_steps,
                    ))

            if self.enforce_permissions:
                perm_ok, perm_reason = check_tool_permission(context.skill, tool_name)
                if not perm_ok:
                    tool_output = {"status": "error", "error": perm_reason}
                    obs_str = json.dumps(tool_output, default=str)
                    record(agent_id, "observation", obs_str, tool=tool_name, run_id=context.run_id)
                    history.append({"role": "user", "content": f"Observation: {obs_str}"})
                    continue

            if tool_name == "spawn_subagent":
                if subagent_calls >= effective_max_subagents:
                    tool_output = {
                        "status": "error",
                        "error": f"Maximum subagents limit ({effective_max_subagents}) reached for this session.",
                    }
                    obs_str = json.dumps(tool_output, default=str)
                    record(agent_id, "observation", obs_str, tool=tool_name, run_id=context.run_id)
                    history.append({"role": "user", "content": f"Observation: {obs_str}"})
                    continue
                subagent_calls += 1
            elif tool_name == "spawn_subagents_parallel":
                remaining_sub = max(0, effective_max_subagents - subagent_calls)
                tasks_arg = parsed_args.get("tasks") if isinstance(parsed_args, dict) else None
                if remaining_sub <= 0:
                    tool_output = {
                        "status": "error",
                        "error": f"Maximum subagents limit ({effective_max_subagents}) reached for this session.",
                    }
                    obs_str = json.dumps(tool_output, default=str)
                    record(agent_id, "observation", obs_str, tool=tool_name, run_id=context.run_id)
                    history.append({"role": "user", "content": f"Observation: {obs_str}"})
                    continue
                if isinstance(tasks_arg, list):
                    if len(tasks_arg) > remaining_sub:
                        parsed_args["tasks"] = tasks_arg[:remaining_sub]
                    subagent_calls += len(parsed_args["tasks"])

            print(f"  ⚡ \033[33m[{agent_id.upper()} ACTION]\033[0m \033[1m{tool_name}\033[0m({args_str[:120]})")
            reasoning_steps.append(f"Step {step}: Invoked {tool_name}")
            record(agent_id, "tool_call", f"Calling {tool_name} with args {parsed_args}", tool=tool_name, run_id=context.run_id)

            # Execute tool safely via registry
            tool_t0 = time.monotonic()
            tool_def = tools.get(tool_name)
            exec_kwargs: Dict[str, Any] = {"timeout_seconds": context.budget.get("timeout_seconds", 120)}
            if tool_def and getattr(tool_def, "sandboxed", False):
                exec_kwargs["sandbox_mode"] = effective_sandbox_mode
            tool_output = tools.execute(tool_name, parsed_args, **exec_kwargs)
            tool_ms = (time.monotonic() - tool_t0) * 1000
            obs_str = json.dumps(tool_output, default=str)

            if self.tracer and active_trace_id:
                self.tracer.record_tool_call(
                    active_trace_id,
                    parent_id=skill_span.span_id if skill_span else "",
                    tool_name=tool_name,
                    args_summary=args_str[:300],
                    result_summary=obs_str[:300],
                    duration_ms=tool_ms,
                    success=(tool_output.get("status") == "success"),
                )

            injections = detect_injection(obs_str)
            if injections:
                logger.warning("[%s] Potential prompt injection detected in %s output (%d matches); sanitizing.",
                               agent_id, tool_name, len(injections))
                if self.memory_manager:
                    try:
                        self.memory_manager.record_event(
                            "prompt_injection_blocked",
                            f"Detected {len(injections)} injection pattern(s) in {tool_name} observation",
                            skill=context.skill, run_id=context.run_id,
                        )
                    except Exception:
                        pass
                safe_obs = sanitize_for_prompt(obs_str[:12000], max_length=12000, strip_injections=True)
            else:
                safe_obs = obs_str[:12000]

            status_icon = "✅" if tool_output.get("status") == "success" else "⚠️"
            obs_preview = obs_str[:140].replace("\n", " ")
            print(f"  👁️ \033[32m[{agent_id.upper()} OBSERVATION {status_icon}]\033[0m {obs_preview}...")

            # Collect artifacts / findings if returned
            if tool_output.get("status") == "success":
                res = tool_output.get("result", {})
                if isinstance(res, dict):
                    if "findings" in res and isinstance(res["findings"], list):
                        findings_accumulated.extend(res["findings"])
                    if "artifact" in res:
                        artifacts_accumulated.append(str(res["artifact"]))

            if self.memory_manager:
                try:
                    self.memory_manager.save_checkpoint(
                        context.run_id, context.skill, step,
                        {"findings_count": len(findings_accumulated), "last_tool": tool_name},
                    )
                except Exception:
                    pass

            record(agent_id, "observation", obs_str[:8000], tool=tool_name, run_id=context.run_id)
            history.append({"role": "user", "content": f"Observation: {safe_obs}"})
            current_prompt = f"Observation: {safe_obs}\nWhat is your next Thought and Action?"

        # If model call failed, activate deterministic fallback if available
        if llm_failure:
            if fallback_fn:
                logger.info(f"[{agent_id}] Activating deterministic tool pipeline fallback after LLM failure: {llm_failure}")
                result = fallback_fn(context)
                result.status = "completed"
                result.reasoning_steps.append(f"Fallback triggered due to LLM error ({llm_failure}); deterministic pipeline completed.")
                record(agent_id, "assistant", f"Fallback completed: {result.summary}", run_id=context.run_id)
                return _finish(result)
            status = "llm_error"
            summary = f"{agent_id} stopped because {self.llm.provider}/{self.llm.model} failed: {llm_failure}"
        elif step >= max_steps:
            status = "incomplete"
            summary = f"{agent_id} reached its {max_steps}-step limit without a final answer."
        else:
            status = "incomplete"
            summary = f"{agent_id} stopped without a final answer after {step} analysis steps."
        return _finish(AgentResult(
            status=status,
            summary=summary,
            findings=findings_accumulated,
            artifacts=artifacts_accumulated,
            next_actions=["review-skill"],
            usage={"steps": step, "model": last_model, "provider": last_provider},
            reasoning_steps=reasoning_steps
        ))

    def _resolve_step_llm(self, current_prompt: str, step: int):
        """Resolve (llm_client, provider, model) for a ReAct step using ModelRouter when enabled."""
        step_llm = self.llm
        step_provider = getattr(self.llm, "provider", "auto")
        step_model = getattr(self.llm, "model", "default")
        if self.per_step_routing and self.model_router is not None:
            try:
                decision = self.model_router.select_model(current_prompt)
                if decision and decision.provider and decision.provider != "auto":
                    if (
                        isinstance(self.llm, LLMClient)
                        and type(self.llm).complete is LLMClient.complete
                        and "complete" not in getattr(self.llm, "__dict__", {})
                    ):
                        candidate = LLMClient(provider=decision.provider, model=decision.model)
                        if candidate.is_available():
                            step_llm = candidate
                            step_provider = decision.provider
                            step_model = candidate.model or decision.model
                    else:
                        # Mock / custom test client: reflect routing selection in telemetry
                        step_provider = decision.provider
                        step_model = decision.model
            except Exception as exc:
                logger.debug("Per-step routing skipped on step %d: %s", step, exc)
        return step_llm, step_provider, step_model

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


def build_default_agent_tools(
    context: AgentContext,
    llm_client: Optional[LLMClient] = None,
    allow_subagents: bool = True,
    max_subagents: Optional[int] = None,
    http_client=None,
    sandbox_mode: Optional[str] = None,
) -> ToolRegistry:
    """
    Constructs a full-featured offensive security toolkit for Moros AI agents.
    Provides HTTP, Code Search, Endpoint Discovery, Finding Recording, and
    Dynamic Autonomous Subagent Spawning.
    """
    if max_subagents is None:
        raw_max = context.budget.get("max_subagents", getattr(context, "max_subagents", None))
        if raw_max is None:
            raw_max = os.environ.get("MOROS_MAX_SUBAGENTS", 5)
        try:
            effective_max_subagents = max(0, int(raw_max))
        except (TypeError, ValueError):
            effective_max_subagents = 5
    else:
        effective_max_subagents = max(0, int(max_subagents))

    effective_sandbox_mode = (
        sandbox_mode
        or getattr(context, "sandbox_mode", None)
        or os.environ.get("MOROS_SANDBOX_MODE", "local")
    ).strip().lower() or "local"

    registry = ToolRegistry()
    if http_client is None:
        from scoped_http import ScopedHttpClient
        from scope_validator import ScopeValidator
        request_budget = int(context.budget.get("request_budget", 100))
        request_delay = float(context.budget.get("request_delay", 0.3))
        http_client = ScopedHttpClient(
            context.target,
            max_requests=request_budget,
            delay_seconds=request_delay,
            scope_validator=ScopeValidator(context.target, target_dir=context.target_dir),
        )

    # Tool 1: http_get
    def http_get(url: str, headers: Dict[str, str] = None) -> Dict[str, Any]:
        """Perform a scoped GET request against a target URL."""
        try:
            resp = http_client.get(url, headers=headers) if headers else http_client.get(url)
            if resp.get("status") != "response":
                return {
                    "status": resp.get("status", "error"),
                    "reason": resp.get("reason", resp.get("error", "Request was blocked by scope policy.")),
                    "url": resp.get("url", url),
                    "method": "GET",
                    "request_count": http_client.request_count,
                }
            return {
                "status": "success",
                "status_code": resp.get("status_code"),
                "url": resp.get("url", url),
                "headers": resp.get("headers", {}),
                "body_preview": (resp.get("body", "") or "")[:1500],
                "body_len": len(resp.get("body", "") or ""),
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}

    registry.register(
        "http_get",
        http_get,
        "Fetch a URL via HTTP GET within authorized target scope.",
        {"url": "Target URL to request", "headers": "Optional request headers dictionary"}
    )

    # Tool 2: search_code
    def search_code(query: str, file_pattern: str = "*.js") -> Dict[str, Any]:
        """Search beautified JavaScript or output files for security patterns or keywords."""
        out_dir = context.target_dir / "output"
        matches = []
        if out_dir.exists():
            for f in out_dir.rglob(file_pattern):
                if f.is_file() and f.stat().st_size < 10_000_000:
                    try:
                        content = f.read_text(encoding="utf-8", errors="ignore")
                        for line_num, line in enumerate(content.splitlines(), start=1):
                            if query.lower() in line.lower():
                                matches.append({
                                    "file": f.name,
                                    "line": line_num,
                                    "snippet": line.strip()[:200],
                                })
                                if len(matches) >= 25:
                                    break
                    except Exception:
                        continue
                if len(matches) >= 25:
                    break
        return {"status": "success", "query": query, "matches_count": len(matches), "matches": matches}

    registry.register(
        "search_code",
        search_code,
        "Search downloaded JS bundles and artifacts for keywords (e.g. 'token', 'jwt', 'redirect', 'api').",
        {"query": "Keyword or pattern to search for", "file_pattern": "Glob pattern (default: *.js)"}
    )

    # Tool 3: get_endpoints
    def get_endpoints(filter_keyword: str = "") -> Dict[str, Any]:
        """Retrieve discovered target endpoints and routes."""
        endpoints = []
        for ep_rel in ["recon/endpoints.txt", "content/discovered-endpoints.txt", "api/openapi-endpoints.json"]:
            ep_file = context.target_dir / "output" / ep_rel
            if ep_file.exists():
                try:
                    if ep_file.suffix == ".json":
                        data = json.loads(ep_file.read_text(encoding="utf-8"))
                        if isinstance(data, list):
                            endpoints.extend([str(item.get("path", item)) for item in data])
                        elif isinstance(data, dict):
                            endpoints.extend(list(data.keys()))
                    else:
                        lines = [l.strip() for l in ep_file.read_text(encoding="utf-8").splitlines() if l.strip()]
                        endpoints.extend(lines)
                except Exception:
                    pass

        unique_eps = sorted(list(set(endpoints)))
        if filter_keyword:
            unique_eps = [e for e in unique_eps if filter_keyword.lower() in e.lower()]
        return {"status": "success", "total_found": len(unique_eps), "endpoints": unique_eps[:50]}

    registry.register(
        "get_endpoints",
        get_endpoints,
        "List discovered endpoints from reconnaissance, API specs, and content crawler.",
        {"filter_keyword": "Optional substring filter (e.g. 'auth', 'api', 'admin')"}
    )

    # Tool 4: record_finding
    def record_finding(title: str, severity: str, url: str, evidence: str = "", cwe: str = "CWE-200", notes: str = "") -> Dict[str, Any]:
        """Record an offensive security candidate finding into the assessment ledger."""
        finding = {
            "title": title,
            "severity": severity.upper(),
            "url": url,
            "cwe": cwe,
            "evidence": evidence,
            "notes": notes,
            "skill": context.skill,
            "status": "candidate",
            "validation_status": "unverified",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        findings_dir = context.target_dir / "output" / "findings"
        findings_dir.mkdir(parents=True, exist_ok=True)
        candidates_file = findings_dir / f"candidates-{safe_agent_name(context.skill)}.json"
        existing = []
        if candidates_file.exists():
            try:
                content = json.loads(candidates_file.read_text(encoding="utf-8"))
                existing = content if isinstance(content, list) else content.get("findings", [])
            except Exception:
                existing = []
        existing.append(finding)
        candidates_file.write_text(json.dumps({"target": context.target, "skill": context.skill, "findings": existing}, indent=2), encoding="utf-8")
        return {"status": "success", "recorded_finding": finding}

    registry.register(
        "record_finding",
        record_finding,
        "Record a suspected vulnerability candidate (e.g. DOM XSS, Open Redirect, JWT misconfig).",
        {"title": "Finding title", "severity": "LOW, MEDIUM, HIGH, CRITICAL", "url": "Affected URL/endpoint", "evidence": "Snippet or proof", "cwe": "CWE identifier", "notes": "Analysis notes"}
    )

    # Tool 5: spawn_subagent (Autonomous dynamic subagent delegation)
    if allow_subagents:
        subagents_spawned = [0]
        subagent_lock = threading.Lock()

        def spawn_subagent(role: str, goal: str, target_url: str = "", context_notes: str = "") -> Dict[str, Any]:
            """Autonomously spawn a specialized subagent to investigate a specific component or endpoint."""
            with subagent_lock:
                if subagents_spawned[0] >= effective_max_subagents:
                    return {"status": "error", "error": f"Maximum subagents limit ({effective_max_subagents}) reached for this session."}

                subagents_spawned[0] += 1
                sub_index = subagents_spawned[0]
            sub_id = f"subagent-{safe_agent_name(role)}-{sub_index}"
            logger.info(f"[{context.skill}] 🤖 Spawning autonomous subagent #{sub_index}: {role} ('{goal}')")

            sub_context = AgentContext(
                target=context.target,
                target_dir=context.target_dir,
                skill=sub_id,
                run_id=context.run_id,
                scope=context.scope,
                budget={"max_steps": 15, "max_tokens": 8192, "timeout_seconds": 300},
                max_subagents=0,
                sandbox_mode=effective_sandbox_mode,
            )

            # Child gets standard toolkit without recursive subagent spawning
            sub_tools = build_default_agent_tools(
                sub_context,
                llm_client=llm_client,
                allow_subagents=False,
                max_subagents=0,
                http_client=http_client,
                sandbox_mode=effective_sandbox_mode,
            )

            runner = AgentRunner(
                llm_client=llm_client,
                max_subagents=0,
                sandbox_mode=effective_sandbox_mode,
            )
            system_prompt = (
                f"Role: {role} security testing module for target '{context.target}'.\n"
                f"Objective: {goal}\n"
                "Available tools: http_get, search_code, get_endpoints, record_finding.\n"
                "Execute necessary investigation steps and conclude with 'Final Answer: <summary of verified findings>'."
            )
            user_prompt = f"Target URL: {target_url}\nContext: {context_notes}\nBegin autonomous investigation."

            result = runner.run(sub_context, sub_tools, system_prompt, user_prompt)
            return {
                "status": "success",
                "subagent_id": sub_id,
                "role": role,
                "result_status": result.status,
                "summary": result.summary,
                "findings_recorded": len(result.findings),
            }

        registry.register(
            "spawn_subagent",
            spawn_subagent,
            "Autonomously spawn a child specialist subagent to independently investigate a specific vector (e.g. JWT, GraphQL, Race Condition).",
            {"role": "Specialist name (e.g. 'JWT Hunter', 'SSRF Investigator')", "goal": "Specific objective", "target_url": "Target URL to examine", "context_notes": "Context notes for the subagent"}
        )

        def spawn_subagents_parallel(tasks: List[Dict[str, str]]) -> Dict[str, Any]:
            """Run multiple isolated subagent tasks in parallel and merge their results."""
            from concurrent.futures import ThreadPoolExecutor, as_completed

            if not isinstance(tasks, list) or not tasks:
                return {"status": "error", "error": "tasks must be a non-empty list of {role, goal, target_url?, context_notes?}"}

            with subagent_lock:
                remaining = max(0, effective_max_subagents - subagents_spawned[0])
            batch = tasks[:remaining]
            if not batch:
                return {"status": "error", "error": f"Maximum subagents limit ({effective_max_subagents}) reached."}

            results = []
            with ThreadPoolExecutor(max_workers=min(max(1, effective_max_subagents), len(batch), 8)) as pool:
                futures = [
                    pool.submit(
                        spawn_subagent,
                        role=t.get("role", "Specialist"),
                        goal=t.get("goal", ""),
                        target_url=t.get("target_url", ""),
                        context_notes=t.get("context_notes", ""),
                    )
                    for t in batch
                ]
                for fut in as_completed(futures):
                    try:
                        results.append(fut.result())
                    except Exception as exc:
                        results.append({"status": "error", "error": str(exc)})

            return {
                "status": "success",
                "completed_count": len(results),
                "results": results,
                "total_findings": sum(r.get("findings_recorded", 0) for r in results if isinstance(r, dict)),
            }

        registry.register(
            "spawn_subagents_parallel",
            spawn_subagents_parallel,
            "Fan out multiple isolated specialist subagents in parallel and merge their summaries.",
            {"tasks": "List of dicts with keys: role, goal, target_url, context_notes"}
        )

    return registry

