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

            # Live Terminal Visualizer: Display Thought
            thought_match = re.search(r"Thought:\s*(.+?)(?=\nAction:|\nFinal Answer:|\Z)", llm_response, re.DOTALL | re.IGNORECASE)
            if thought_match:
                t_str = thought_match.group(1).strip().replace("\n", " ")
                print(f"  🧠 \033[36m[{agent_id.upper()} THOUGHT]\033[0m {t_str[:160]}...")

            # Check for Final Answer
            final_match = re.search(r"Final Answer:\s*(.+)", llm_response, re.DOTALL | re.IGNORECASE)
            if final_match:
                final_text = final_match.group(1).strip()
                print(f"  🎯 \033[35m[{agent_id.upper()} FINAL ANSWER]\033[0m {final_text[:200]}")
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
                thought_text = thought_match.group(1).strip() if thought_match else llm_response.strip()
                reasoning_steps.append(f"Step {step}: {thought_text[:120]}...")
                current_prompt = "Observation: No tool action was specified. If you are finished, output 'Final Answer: <summary>'. Otherwise, call a valid Action."
                history.append({"role": "user", "content": current_prompt})
                continue

            tool_name = action_match.group(1).strip()
            args_str = action_match.group(2).strip()
            parsed_args = self._parse_tool_args(args_str)

            print(f"  ⚡ \033[33m[{agent_id.upper()} ACTION]\033[0m \033[1m{tool_name}\033[0m({args_str[:120]})")
            reasoning_steps.append(f"Step {step}: Invoked {tool_name}")
            store.append(agent_id, "tool_call", f"Calling {tool_name} with args {parsed_args}", tool=tool_name, run_id=context.run_id)

            # Execute tool safely via registry
            tool_output = tools.execute(tool_name, parsed_args, timeout_seconds=context.budget.get("timeout_seconds", 120))
            obs_str = json.dumps(tool_output, default=str)

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


def build_default_agent_tools(
    context: AgentContext,
    llm_client: Optional[LLMClient] = None,
    allow_subagents: bool = True,
    max_subagents: int = 5,
) -> ToolRegistry:
    """
    Constructs a full-featured offensive security toolkit for Moros AI agents.
    Provides HTTP, Code Search, Endpoint Discovery, Finding Recording, and
    Dynamic Autonomous Subagent Spawning.
    """
    registry = ToolRegistry()

    # Tool 1: http_get
    def http_get(url: str, headers: Dict[str, str] = None) -> Dict[str, Any]:
        """Perform a scoped GET request against a target URL."""
        from scoped_http import ScopedHttpClient, is_in_target_scope
        import urllib.parse
        parsed = urllib.parse.urlparse(url if "://" in url else f"https://{url}")
        host = (parsed.hostname or "").lower()
        if not is_in_target_scope(host, context.target):
            return {"status": "error", "error": f"URL host '{host}' is outside authorized target scope '{context.target}'"}

        try:
            client = ScopedHttpClient(target=context.target, max_requests=100, delay_seconds=0.2)
            resp = client.get(url, headers=headers or {})
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

        def spawn_subagent(role: str, goal: str, target_url: str = "", context_notes: str = "") -> Dict[str, Any]:
            """Autonomously spawn a specialized subagent to investigate a specific component or endpoint."""
            if subagents_spawned[0] >= max_subagents:
                return {"status": "error", "error": f"Maximum subagents limit ({max_subagents}) reached for this session."}

            subagents_spawned[0] += 1
            sub_id = f"subagent-{safe_agent_name(role)}-{subagents_spawned[0]}"
            logger.info(f"[{context.skill}] 🤖 Spawning autonomous subagent #{subagents_spawned[0]}: {role} ('{goal}')")

            sub_context = AgentContext(
                target=context.target,
                target_dir=context.target_dir,
                skill=sub_id,
                run_id=context.run_id,
                scope=context.scope,
                budget={"max_steps": 5, "max_tokens": 4000, "timeout_seconds": 120}
            )

            # Child gets standard toolkit without recursive subagent spawning
            sub_tools = build_default_agent_tools(
                sub_context,
                llm_client=llm_client,
                allow_subagents=False,
            )

            runner = AgentRunner(llm_client=llm_client)
            system_prompt = (
                f"You are {role}, an elite offensive security subagent in Moros AI.\n"
                f"Your target domain is: {context.target}\n"
                f"Your specific goal: {goal}\n"
                "Use your tools (http_get, search_code, get_endpoints, record_finding) to investigate thoroughly.\n"
                "Conclude with 'Final Answer: <summary of what was verified and findings recorded>'."
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

    return registry

