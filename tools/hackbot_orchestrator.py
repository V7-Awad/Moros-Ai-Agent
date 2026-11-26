#!/usr/bin/env python3
"""
hackbot-orchestrator.py — Main orchestrator for the Hackbot agent system.

Manages the execution pipeline: scope verification, skill sequencing,
multi-model runs, review-skill integration, and final report assembly.

Usage:
    python tools/hackbot-orchestrator.py --target "example.com" \
        --scope-file "targets/example.com/scope-of-work.pdf" \
        --skills "recon-subdomain,js-discover,js-analyze,content-discovery,xss-reflected" \
        --models "claude-sonnet,gpt-4o-mini" \
        --runs-per-skill 2
"""

import argparse
import json
import logging
import os
import sys
import threading
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

# Import LLM client and Skill execution runner
tools_dir = Path(__file__).parent.resolve()
project_root = tools_dir.parent.resolve()
if str(tools_dir) not in sys.path:
    sys.path.insert(0, str(tools_dir))
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from llm_client import LLMClient, load_dotenv_if_present, redact_secrets
from skill_runner import SkillRunner
from conversation_store import ConversationStore
from run_manager import RunManager
from scope_validator import ScopeValidator
from cost_tracker import CostTracker
from trace_logger import TraceLogger
from memory_manager import MemoryManager
from model_router import ModelRouter
from mcp_client import MCPClient

try:
    from learning_engine.engine import LearningEngine
except Exception:
    LearningEngine = None

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S"
)
logger = logging.getLogger("hackbot-orchestrator")

load_dotenv_if_present()

from skill_registry import SkillRegistry

# Dynamic Skill execution order (dependency chain)
def get_dynamic_skill_order() -> List[str]:
    try:
        return SkillRegistry().get_execution_order()
    except Exception:
        return [
            "recon-subdomain",
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
            "report-conglomeration",
        ]

SKILL_ORDER = get_dynamic_skill_order()

# Skills that require specific prior skills to have completed
SKILL_DEPENDENCIES = {
    "js-analyze": ["js-discover"],
    "api-spec-discovery": [],
    "content-discovery": ["js-analyze"],
    "xss-reflected": ["js-analyze"],
    "xss-stored": ["js-analyze"],
    "xss-dom": ["js-analyze"],
    "xss-blind": ["js-analyze"],
    "ssrf-identify": ["js-analyze"],
    "ssrf-post-exploit": ["ssrf-identify"],
    "idp-race-condition": ["js-analyze"],
    "auth-password-reset-bruteforce": ["js-analyze"],
    "report-conglomeration": [],  # Runs after all selected skills
}

MAX_REVIEW_RETRIES = 5


class HackbotOrchestrator:
    def __init__(self, target: str, target_dir: str, skills: list = None,
                 models: list = None, runs_per_skill: int = 1,
                 review_model: str = None, api_spec: str = None,
                 active_host_limit: int = 100, root_only_active: bool = False,
                 https_only: bool = False, max_http_requests: int = 150,
                 request_delay: float = 0.3, parallel: bool = False,
                 budget_usd: float = 10.0, mcp_servers: list = None,
                 enable_tracing: bool = True, smart_routing: bool = False,
                 max_subagents: int = 5, resume_run_id: Optional[str] = None,
                 proxy: Optional[str] = None, validate_candidates: bool = False):
        self.target = target
        self.target_dir = Path(target_dir)
        self.skills = list(skills or [])
        self.models = models or ["default"]
        self.runs_per_skill = runs_per_skill
        self.review_model = review_model
        self.api_spec = Path(api_spec).resolve() if api_spec else None
        self.active_host_limit = max(1, active_host_limit)
        self.root_only_active = root_only_active
        self.https_only = https_only
        self.max_http_requests = max(1, max_http_requests)
        self.request_delay = max(0.0, request_delay)
        self.parallel = parallel
        self.max_subagents = max(1, int(max_subagents))
        self.resume_run_id = str(resume_run_id).strip() if resume_run_id else None
        self.proxy = proxy.strip() if isinstance(proxy, str) and proxy.strip() else None
        self._has_prev_moros_proxy = False
        self._prev_moros_proxy = None
        if self.proxy:
            self._has_prev_moros_proxy = True
            self._prev_moros_proxy = os.environ.get("MOROS_PROXY")
            os.environ["MOROS_PROXY"] = self.proxy
        self.validate_candidates = bool(validate_candidates)
        self._resumed_completed_skills: set = set()
        self.budget_usd = float(budget_usd)
        self.smart_routing = bool(smart_routing)
        self.scope_authorized = False
        self.scope_blocked_skills: list = []
        self.scope_audit: dict = {}
        self._lock = threading.Lock()
        self.learning_engine = None
        self.learning_context: dict = {}
        self.learning_summary: dict = {}
        self._candidate_findings: list = []
        self.validation_results: list = []
        self.validation_summary: dict = {}
        self.advisory_prioritization: dict = {}
        self.detected_technologies: list = []

        self.execution_log: list = []
        self.skill_results: dict = {}  # skill -> [run results]
        self.failed_skills: list = []

        # Ensure output directories
        output_base = self.target_dir / "output"
        for subdir in ["recon", "js", "content-discovery", "findings", "logs", "report", "api", "runs", "costs", "traces"]:
            (output_base / subdir).mkdir(parents=True, exist_ok=True)
        self.conversations = ConversationStore(self.target_dir)

        # Initialize durable run tracking, telemetry, cost, and tiered memory.
        self.run_manager = RunManager(self.target_dir)
        self.current_run = None
        self.current_trace_id = None
        self.scope_validator = ScopeValidator(self.target, target_dir=self.target_dir)
        self.cost_tracker = CostTracker(self.target_dir, budget_cap_usd=self.budget_usd)
        self.tracer = TraceLogger(self.target_dir) if enable_tracing else None
        self.memory_manager = MemoryManager(self.target_dir)
        self.model_router = ModelRouter(budget_usd=self.budget_usd)
        self.mcp_clients = []
        for idx, spec in enumerate(mcp_servers or [], 1):
            try:
                spec_str = str(spec).strip()
                if spec_str.startswith(("http://", "https://")):
                    client = MCPClient(server_name=f"mcp-{idx}", transport="http", url=spec_str)
                else:
                    import shlex
                    client = MCPClient(server_name=f"mcp-{idx}", transport="stdio", command=shlex.split(spec_str))
                client.connect()
                client.discover_tools()
                self.mcp_clients.append(client)
            except Exception as exc:
                logger.warning("Failed to connect MCP server '%s': %s", spec, exc)

        # "default" must auto-detect configured providers; model labels are not providers.
        self.llm = self._llm_for_model(self.models[0] if self.models else "default")
        self.runner = SkillRunner(self.target, self.target_dir, self.llm,
                                  max_http_requests=self.max_http_requests,
                                  request_delay=self.request_delay)
        self.runner.cost_tracker = self.cost_tracker
        self.runner.tracer = self.tracer
        self.runner.memory_manager = self.memory_manager
        self.runner.model_router = self.model_router
        self.runner.mcp_clients = self.mcp_clients
        if hasattr(self.runner, "http"):
            self.runner.http.scope_validator = self.scope_validator

        # Load dynamic skill dependencies
        try:
            for s in SkillRegistry().list_skills():
                if s.get("dependencies"):
                    SKILL_DEPENDENCIES[s["id"]] = s["dependencies"]
        except Exception:
            pass

    @staticmethod
    def _llm_for_model(model_name: str) -> LLMClient:
        requested = (model_name or "default").strip()
        normalized = requested.lower()
        if normalized in {"", "default", "auto", "open-weight-local"}:
            return LLMClient(provider="auto")
        if "/" in requested:
            provider, model = requested.split("/", 1)
            return LLMClient(provider=provider, model=model)
        if normalized.startswith(("gpt-", "o1", "o3", "o4")):
            return LLMClient(provider="openai", model=requested)
        if normalized.startswith("claude-"):
            return LLMClient(provider="anthropic", model=requested)
        if normalized.startswith("gemini-"):
            return LLMClient(provider="gemini", model=requested)
        if normalized.startswith("deepseek-"):
            return LLMClient(provider="deepseek", model=requested)
        if normalized.startswith("grok-"):
            return LLMClient(provider="xai", model=requested)
        if normalized.startswith("mistral-") or normalized.startswith("codestral-"):
            return LLMClient(provider="mistral", model=requested)
        return LLMClient(provider="auto", model=requested)

    def verify_scope(self) -> bool:
        """Require a readable scope note that names this target and authorization."""
        allowed_suffixes = {".md", ".txt", ".yaml", ".yml", ".json"}
        scope_files = [p for p in self.target_dir.glob("scope-of-work.*")
                       if p.suffix.lower() in allowed_suffixes]
        target = self.target.lower()
        auth_terms = ("authorized", "authorised", "in scope", "scope of work", "scope-of-work")
        for scope_file in scope_files:
            try:
                content = scope_file.read_text(encoding="utf-8", errors="replace").lower()
            except OSError:
                continue
            if target in content and any(term in content for term in auth_terms):
                logger.warning("Scope note matches target and authorization wording; this is not independent proof of permission.")
                self._log_event("scope-check", "TEXT_MATCH", f"Scope text matched target in {scope_file}")
                return True

        reason = "No readable scope-of-work text names the target and authorization wording."
        logger.error("❌ Active checks disabled: %s", reason)
        self._log_event("scope-check", "FAILED", reason)
        return False

    def _check_dependency_artifact(self, dep_skill: str) -> bool:
        """Check whether the required artifact for a prerequisite skill exists on disk."""
        output_base = self.target_dir / "output"
        if dep_skill == "recon-subdomain":
            recon_dir = output_base / "recon"
            return (recon_dir / "subdomains.txt").is_file() or any(recon_dir.glob("*.json"))
        elif dep_skill == "js-discover":
            js_dir = output_base / "js"
            manifest = js_dir / "collection-manifest.json"
            raw_js = list((js_dir / "raw").rglob("*.js")) if (js_dir / "raw").exists() else []
            return manifest.is_file() or len(raw_js) > 0
        elif dep_skill == "js-analyze":
            ep_file = output_base / "js" / "endpoints.json"
            api_file = output_base / "api" / "endpoints.json"
            return ep_file.is_file() or api_file.is_file()
        elif dep_skill == "content-discovery":
            cd_file = output_base / "content-discovery" / "wordlist-combined.txt"
            return cd_file.is_file()
        elif dep_skill == "ssrf-identify":
            ssrf_file = output_base / "findings" / "ssrf-identify" / "candidates-ssrf-identify.json"
            return ssrf_file.is_file()
        return False

    def validate_dependencies(self) -> dict:
        """
        Verify that all skill dependencies are satisfied.
        Returns a dict of blocked_skill -> explanation reason.
        """
        blocked = {}
        completed_on_resume = getattr(self, "_resumed_completed_skills", set())
        for skill in self.skills:
            if skill in completed_on_resume:
                continue
            deps = SKILL_DEPENDENCIES.get(skill, [])
            for dep in deps:
                if dep in completed_on_resume:
                    continue
                if dep not in self.skills:
                    if not self._check_dependency_artifact(dep):
                        reason = f"Prerequisite skill '{dep}' is missing from run schedule and required artifact was not found on disk."
                        blocked[skill] = reason
                        logger.warning(f"🚫 Skill '{skill}' is BLOCKED: {reason}")
                        break
        return blocked

    def _init_learning_engine(self):
        """Instantiate LearningEngine safely without ever failing a scan."""
        if LearningEngine is None:
            return None
        try:
            try:
                return LearningEngine(root=self.target_dir)
            except TypeError:
                return LearningEngine()
        except Exception as exc:
            logger.debug("LearningEngine initialization error (non-fatal): %s", exc)
            return None

    @staticmethod
    def _preserve_dependency_order(skills_list: list[str]) -> list[str]:
        """Ensure any skill whose prerequisite also appears in skills_list runs after it."""
        ordered = list(skills_list)
        changed = True
        for _ in range(len(ordered) * 2):
            if not changed:
                break
            changed = False
            for idx, skill in enumerate(list(ordered)):
                for dep in SKILL_DEPENDENCIES.get(skill, []):
                    if dep in ordered:
                        dep_idx = ordered.index(dep)
                        if dep_idx > idx:
                            ordered.pop(idx)
                            ordered.insert(dep_idx, skill)
                            changed = True
                            break
                if changed:
                    break
        return ordered

    def apply_advisory_prioritization(self, techs: Optional[List[str]] = None) -> dict:
        """
        Compute and apply non-binding LearningEngine skill ordering hints.

        Uses `recommend_skills_for_tech` and `estimate_scan_value_and_cost` strictly as
        advisory ordering hints; never alters scope, permissions, budgets, or skill membership.
        """
        original_skills = list(getattr(self, "skills", []) or [])
        raw_techs = techs if techs is not None else getattr(self, "detected_technologies", [])
        tech_list = [str(t).strip().lower() for t in (raw_techs or []) if str(t).strip()]

        if not original_skills:
            result = {
                "advisory": True,
                "applied": False,
                "techs": tech_list,
                "original_skills": [],
                "ordered_skills": [],
                "recommendations": [],
                "value_estimate": {},
            }
            self.advisory_prioritization = result
            return result

        prereq_order = {
            "recon-subdomain": 0,
            "deep-recon": 1,
            "api-spec-discovery": 2,
            "js-discover": 3,
            "js-analyze": 4,
            "content-discovery": 5,
        }
        finalizer_order = {"review-skill": 0, "report-conglomeration": 1}

        recs: list = []
        estimate: dict = {}
        engine = getattr(self, "learning_engine", None)
        owns_engine = False
        if engine is None:
            engine = self._init_learning_engine()
            owns_engine = engine is not None

        try:
            if engine is not None:
                try:
                    recs = engine.recommend_skills_for_tech(
                        techs=tech_list or None,
                        target=self.target,
                        limit=max(10, len(original_skills)),
                    ) or []
                except Exception as exc:
                    logger.debug("LearningEngine recommend_skills_for_tech error (non-fatal): %s", exc)
                try:
                    estimate = engine.estimate_scan_value_and_cost(
                        skills=original_skills,
                        techs=tech_list or None,
                        target=self.target,
                    ) or {}
                except Exception as exc:
                    logger.debug("LearningEngine estimate_scan_value_and_cost error (non-fatal): %s", exc)
        finally:
            if owns_engine and engine is not None:
                try:
                    engine.close()
                except Exception:
                    pass

        score_by_skill: dict[str, float] = {}
        for rec in recs:
            if isinstance(rec, dict) and rec.get("skill_id") and rec.get("advisory", True):
                try:
                    score_by_skill[str(rec["skill_id"])] = float(rec.get("priority_score", 0.0) or 0.0)
                except (TypeError, ValueError):
                    continue

        prereqs = sorted([s for s in original_skills if s in prereq_order], key=lambda s: prereq_order[s])
        finalizers = sorted([s for s in original_skills if s in finalizer_order], key=lambda s: finalizer_order[s])
        middle = [s for s in original_skills if s not in prereq_order and s not in finalizer_order]

        if score_by_skill and middle:
            indexed_middle = list(enumerate(middle))
            indexed_middle.sort(key=lambda pair: (-score_by_skill.get(pair[1], -1.0), pair[0]))
            middle = self._preserve_dependency_order([s for _, s in indexed_middle])

        ordered = prereqs + middle + finalizers
        if sorted(ordered) == sorted(original_skills):
            self.skills = ordered
        else:
            ordered = original_skills

        result = {
            "advisory": True,
            "applied": ordered != original_skills,
            "techs": tech_list,
            "original_skills": original_skills,
            "ordered_skills": ordered,
            "recommendations": recs,
            "value_estimate": estimate,
        }
        self.advisory_prioritization = result
        return result

    def _collect_candidate_artifacts(self) -> tuple[list[dict], list[tuple[Path, object, list[dict]]]]:
        """Collect candidate finding records from output/findings/ generated for this run."""
        findings_dir = self.target_dir / "output" / "findings"
        if not findings_dir.is_dir():
            return [], []

        run_started = getattr(getattr(self, "runner", None), "run_started_at", None)
        started_ts = run_started.timestamp() if run_started is not None else None

        collected: list[dict] = []
        loaded_files: list[tuple[Path, object, list[dict]]] = []

        for path in sorted(findings_dir.rglob("*.json")):
            if not path.name.startswith(("candidates-", "confirmed-")):
                continue
            if started_ts is not None:
                try:
                    if path.stat().st_mtime < started_ts:
                        continue
                except OSError:
                    continue
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue

            if isinstance(raw, list):
                items = [row for row in raw if isinstance(row, dict)]
                container: object = raw
            elif isinstance(raw, dict):
                raw_items = raw.get("findings")
                if isinstance(raw_items, list):
                    items = [row for row in raw_items if isinstance(row, dict)]
                elif "title" in raw:
                    items = [raw]
                else:
                    items = []
                container = raw
            else:
                continue

            if items:
                loaded_files.append((path, container, items))
                collected.extend(items)

        return collected, loaded_files

    def _record_validation_outcomes_in_learning(
        self,
        results: list,
        validated_findings: list[dict],
    ) -> None:
        """Persist Phase 1 validation outcomes in LearningEngine as advisory signals."""
        if not results:
            return
        engine = getattr(self, "learning_engine", None)
        owns_engine = False
        if engine is None:
            engine = self._init_learning_engine()
            owns_engine = engine is not None
        if engine is None:
            return

        by_fid = {
            str(f.get("finding_id") or f.get("id") or ""): f
            for f in validated_findings
            if isinstance(f, dict)
        }
        run_id = (getattr(self, "current_run", None) or {}).get("run_id")

        try:
            for vr in results:
                status = str(getattr(vr, "status", "inconclusive") or "inconclusive").lower()
                outcome = status if status in {"confirmed", "false_positive", "inconclusive", "unverified"} else "unverified"
                finding_meta = by_fid.get(vr.finding_id, {})
                vuln_class = str(
                    finding_meta.get("vuln_class")
                    or finding_meta.get("type")
                    or vr.strategy
                    or "finding"
                )
                try:
                    engine.record_validation_outcome(
                        target=self.target,
                        finding_id=vr.finding_id,
                        vuln_class=vuln_class,
                        outcome=outcome,
                        confidence=float(vr.confidence),
                        strategy=vr.strategy,
                        run_id=run_id or vr.validation_run_id,
                        evidence_ids=list(vr.evidence_ids or []),
                        metadata={
                            "endpoint": vr.endpoint,
                            "validation_run_id": vr.validation_run_id,
                            "proof_artifact": vr.proof_artifact,
                        },
                    )
                except Exception as exc:
                    logger.debug("LearningEngine record_validation_outcome error (non-fatal): %s", exc)
        finally:
            if owns_engine:
                try:
                    engine.close()
                except Exception:
                    pass

    def run_validation_stage(self) -> dict:
        """
        Run deterministic Phase 1 ExploitValidator across deduplicated candidates.

        Respects ScopeValidator, ScopedHttpClient, remaining request/budget limits,
        and CheckpointManager HITL checkpoints, updating candidate artifacts on disk
        before report-conglomeration / AttackGraphBuilder.
        """
        from checkpoint_manager import CheckpointManager
        from exploit_validator import ExploitValidator
        from finding_dedupe import deduplicate_findings, finding_identity
        from scoped_http import ScopedHttpClient

        http_client = getattr(getattr(self, "runner", None), "http", None)
        if getattr(http_client, "stop_requested", False):
            summary = {"status": "BLOCKED_SCOPE", "total_candidates": 0, "validated": 0, "confirmed": 0, "results": []}
            self.validation_summary = summary
            return summary

        policy = getattr(getattr(self, "scope_validator", None), "policy", {})
        if not getattr(self, "scope_authorized", False):
            self.scope_authorized = self.verify_scope()
        if not self.scope_authorized or policy.get("allow_active_vulnerability_checks", True) is False:
            summary = {"status": "SKIPPED_SCOPE", "total_candidates": 0, "validated": 0, "confirmed": 0, "results": []}
            self.validation_summary = summary
            return summary

        raw_candidates, loaded_files = self._collect_candidate_artifacts()
        if not raw_candidates:
            summary = {"status": "COMPLETED", "total_candidates": 0, "validated": 0, "confirmed": 0, "results": []}
            self.validation_summary = summary
            return summary

        deduped = deduplicate_findings(raw_candidates)
        to_validate = [
            item for item in deduped
            if item.get("status") not in {"confirmed", "validated", "fixed", "false_positive", "accepted_risk"}
        ]
        if not to_validate:
            summary = {
                "status": "COMPLETED",
                "total_candidates": len(deduped),
                "validated": 0,
                "confirmed": sum(1 for item in deduped if item.get("status") == "confirmed"),
                "results": [],
            }
            self.validation_summary = summary
            return summary

        used_reqs = int(getattr(http_client, "request_count", 0) or 0)
        max_reqs = int(getattr(http_client, "max_requests", self.max_http_requests) or self.max_http_requests)
        remaining_budget = max(0, max_reqs - used_reqs)

        validator_target = getattr(http_client, "base_url", None) or self.target
        if "://" not in str(validator_target):
            if any(str(f.get("url") or f.get("endpoint") or "").startswith("http://") for f in to_validate):
                validator_target = f"http://{self.target}"

        # Only share runner.http directly if it was replaced/mocked by a test double;
        # otherwise let ExploitValidator construct per-finding ScopedHttpClient instances
        # so an intentional blocked_redirect (e.g. open-redirect proof) or gated POST
        # check does not halt unrelated findings or the outer orchestrator run.
        use_mocked_client = (
            http_client is not None
            and (
                type(http_client) is not ScopedHttpClient
                or getattr(getattr(http_client, "request", None), "__func__", None) is not ScopedHttpClient.request
            )
        )
        shared_client = http_client if use_mocked_client else None

        checkpoint_mgr = CheckpointManager(self.target, self.target_dir)
        validator = ExploitValidator(
            target=validator_target,
            target_dir=self.target_dir,
            scope_validator=self.scope_validator,
            http_client=shared_client,
            checkpoint_manager=checkpoint_mgr,
            max_requests=max(1, remaining_budget) if remaining_budget > 0 else 1,
            delay_seconds=self.request_delay,
        )
        if remaining_budget <= 0:
            validator.max_requests = 0

        results = validator.validate_findings(to_validate, mutate_findings=True)
        if shared_client is None and http_client is not None:
            if hasattr(http_client, "request_count"):
                http_client.request_count = int(getattr(http_client, "request_count", 0) or 0) + validator._total_requests_used
            if hasattr(http_client, "request_logs") and isinstance(http_client.request_logs, list):
                for r in results:
                    for step in (r.reproduction_steps or []):
                        if isinstance(step, dict) and step.get("url"):
                            http_client.request_logs.append({
                                "method": step.get("method", r.method),
                                "url": step.get("url"),
                                "status": "response",
                            })

        validated_by_identity = {finding_identity(item): item for item in to_validate}
        fields_to_sync = (
            "finding_id",
            "validation_run_id",
            "validation_result",
            "proof_artifact",
            "status",
            "validation_status",
            "confidence",
            "confidence_score",
        )
        for path, container, items in loaded_files:
            modified = False
            for item in items:
                matched = validated_by_identity.get(finding_identity(item))
                if not matched:
                    continue
                for key in fields_to_sync:
                    if key in matched:
                        item[key] = matched[key]
                existing_ids = list(item.get("evidence_ids") or [])
                for eid in (matched.get("evidence_ids") or []):
                    if eid not in existing_ids:
                        existing_ids.append(eid)
                item["evidence_ids"] = existing_ids
                modified = True
            if modified:
                try:
                    if isinstance(container, dict) and isinstance(container.get("findings"), list):
                        container["findings"] = items
                        payload = container
                    elif isinstance(container, list):
                        payload = items
                    else:
                        payload = items[0] if len(items) == 1 else items
                    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
                except OSError as exc:
                    logger.warning("Failed to update validated candidate artifact %s: %s", path, exc)

        self.validation_results = [r.to_dict() for r in results]
        self._record_validation_outcomes_in_learning(results, to_validate)

        confirmed_count = sum(1 for r in results if r.status == "confirmed")
        summary = {
            "status": "COMPLETED",
            "total_candidates": len(deduped),
            "validated": len(results),
            "confirmed": confirmed_count,
            "false_positive": sum(1 for r in results if r.status == "false_positive"),
            "inconclusive": sum(1 for r in results if r.status == "inconclusive"),
            "requests_used": sum(r.requests_used for r in results),
            "results": list(self.validation_results),
        }
        self.validation_summary = summary
        if hasattr(self, "conversations"):
            self._log_event(
                "exploit-validator",
                "COMPLETED",
                f"Validated {len(results)} candidate(s): {confirmed_count} confirmed, "
                f"{summary['false_positive']} false_positive, {summary['inconclusive']} inconclusive",
            )
        return summary

    def _extract_candidate_findings(self, skill_name: str, result: dict, skill_res: dict | None) -> list[dict]:
        """Collect candidate finding dicts produced by a skill run."""
        if isinstance(skill_res, dict) and isinstance(skill_res.get("findings"), list) and skill_res["findings"]:
            return [f for f in skill_res["findings"] if isinstance(f, dict)]

        findings_count = int(result.get("findings_count", 0) or 0)
        if findings_count <= 0:
            return []

        candidate_files = [
            self.target_dir / "output" / "findings" / skill_name / f"candidates-{skill_name}.json",
            self.target_dir / "output" / "findings" / f"candidates-{skill_name}.json",
        ]
        if skill_name == "js-analyze":
            candidate_files.append(self.target_dir / "output" / "js" / "secrets-findings.json")
        elif skill_name == "content-discovery":
            candidate_files.append(self.target_dir / "output" / "content-discovery" / "interesting-findings.json")

        for path in candidate_files:
            if not path.is_file():
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                items = data if isinstance(data, list) else data.get("findings", [])
                parsed = [item for item in items if isinstance(item, dict)]
                if parsed:
                    return parsed
            except (OSError, json.JSONDecodeError):
                continue

        return [{
            "title": f"{skill_name} candidate finding",
            "url": f"https://{self.target}/",
            "severity": "medium",
            "notes": result.get("notes", ""),
        }]

    @staticmethod
    def _normalize_severity_label(severity_val) -> str:
        text = str(severity_val or "medium").strip().lower()
        for level in ("critical", "high", "medium", "low", "info"):
            if level in text:
                return level
        return "medium"

    def _record_learning_findings(self, skill_name: str, result: dict, skill_res: dict | None) -> None:
        """Record candidate findings into LearningEngine and summary buffer safely."""
        if skill_name in {"review-skill", "report-conglomeration"}:
            return
        if result.get("status") in {"FAILED", "ERROR", "BLOCKED", "BLOCKED_SCOPE", "SKIPPED", "NOT_IMPLEMENTED"}:
            return

        findings = self._extract_candidate_findings(skill_name, result, skill_res)
        if not findings:
            return

        for f in findings:
            endpoint = str(
                f.get("url") or f.get("endpoint") or f.get("path")
                or f.get("source_artifact") or f"/{skill_name}"
            )
            vuln_class = str(f.get("vuln_class") or f.get("type") or skill_name or "finding")
            if not any(ch.isalnum() for ch in vuln_class):
                vuln_class = skill_name or "finding"
            signals = f.get("signals") if isinstance(f.get("signals"), dict) else {skill_name: 1}
            validation_state = str(f.get("validation_status") or f.get("status") or "observation")
            source_provenance = str(f.get("source_artifact") or f"skill:{skill_name}")
            summary_item = {
                "title": f.get("title") or f"{vuln_class} @ {endpoint}",
                "vuln_class": vuln_class,
                "severity": self._normalize_severity_label(f.get("severity")),
                "confidence": f.get("confidence"),
                "score": f.get("score", 0.0),
                "endpoint": endpoint,
            }
            with self._lock:
                self._candidate_findings.append(summary_item)
                if self.learning_engine is not None:
                    try:
                        self.learning_engine.after_finding(
                            target=self.target,
                            endpoint=endpoint,
                            vulnerability_class=vuln_class,
                            signals=signals,
                            validation_state=validation_state,
                            source_provenance=source_provenance,
                        )
                    except Exception as exc:
                        logger.debug("LearningEngine after_finding error (non-fatal): %s", exc)

    def run(self):
        """Execute the full orchestration pipeline."""
        model_error = self._model_preflight()
        if model_error:
            logger.error("Scan blocked before contacting target: %s", model_error)
            return {"status": "FAILED", "error": model_error, "target_requests_made": 0}

        logger.info("=" * 60)
        logger.info(f"HACKBOT ORCHESTRATOR — Target: {self.target}")
        logger.info(f"Skills: {', '.join(self.skills)}")
        logger.info(f"Models: {', '.join(self.models)}")
        logger.info(f"Runs per skill: {self.runs_per_skill}")
        logger.info("=" * 60)

        # Step 1: Initialize or resume durable run
        self.current_run = None
        self._resumed_completed_skills = set()
        resumed_plan = None
        if self.resume_run_id:
            requested_id = None if self.resume_run_id.lower() == "latest" else self.resume_run_id
            resumed_plan = self.run_manager.prepare_resume_plan(requested_id)
            if resumed_plan:
                self.current_run = self.run_manager.mark_run_resumed(resumed_plan["run_id"])
                self._resumed_completed_skills = set(self.current_run.get("skills_completed") or [])
                if not self.skills:
                    self.skills = list(self.current_run.get("skills_requested") or [])
                logger.info(
                    "♻️  Resuming run %s (skipping %d completed skill(s))",
                    self.current_run["run_id"],
                    len(self._resumed_completed_skills),
                )
            else:
                logger.warning(
                    "⚠️  No resumable run found for '%s'; starting a fresh run.",
                    self.resume_run_id,
                )

        if not self.current_run:
            self.current_run = self.run_manager.create_run(
                target=self.target,
                skills=self.skills,
                dry_run=False,
                models=",".join(self.models)
            )
        run_id = self.current_run["run_id"]
        if self.tracer:
            self.current_trace_id = self.tracer.start_trace(f"scan:{self.target}")
            self.runner.trace_id = self.current_trace_id
        try:
            self.runner.run_started_at = datetime.fromisoformat(
                self.current_run["started_at"].replace("Z", "+00:00")
            )
        except (ValueError, AttributeError, KeyError):
            self.runner.run_started_at = datetime.now(timezone.utc)

        self._candidate_findings = []
        self.learning_context = {}
        self.learning_summary = {}
        self.learning_engine = self._init_learning_engine()

        try:
            # Step 2: Verify scope
            self.scope_authorized = self.verify_scope()
            self.runner.scope_authorized = self.scope_authorized
            policy = getattr(self.scope_validator, "policy", {})
            if self.scope_authorized and not policy.get("allow_active_vulnerability_checks", True):
                # Keep reconnaissance and analysis of already collected/local evidence.
                # A scope note that forbids exploit payloads/state changes cannot be
                # treated as authorization for vulnerability probes by specialist skills.
                safe_skills = {"recon-subdomain", "api-spec-discovery", "js-discover", "js-analyze",
                               "review-skill", "report-conglomeration"}
                requested = list(self.skills)
                self.scope_blocked_skills = [s for s in requested if s not in safe_skills]
                self.skills = [s for s in requested if s in safe_skills]
                for blocked in self.scope_blocked_skills:
                    reason = "BLOCKED_SCOPE: saved scope profile forbids exploit payloads/state-changing actions; this specialist needs active checks."
                    self.skill_results[blocked] = [{"skill": blocked, "status": "BLOCKED_SCOPE", "notes": reason}]
                    self.run_manager.update_skill_progress(run_id, blocked, status="blocked", summary=reason)
                    self.run_manager.register_agent_session(
                        run_id, agent_id=f"{blocked}-scope-gate", skill=blocked,
                        parent_agent_id="coordinator", status="blocked_scope", model="policy-gate")
                    self._log_event(blocked, "BLOCKED_SCOPE", reason)
                logger.warning("Scope policy blocks active vulnerability skills; allowed stages: %s",
                               ", ".join(self.skills))
            if not self.scope_authorized:
                # Allow only passive recon without scope
                self.skills = [s for s in self.skills if s == "recon-subdomain"]
                if not self.skills:
                    logger.error("No skills can run without authorization. Aborting.")
                    self.run_manager.finish_run(run_id, status="failed", error="No authorization scope found")
                    return {"status": "FAILED", "failed_skills": [{"skill": "scope-check", "notes": "No authorization"}]}
                logger.warning("⚠️  Running in PASSIVE-ONLY mode (no scope-of-work)")

            # Step 2.5: WAF Detection & Adaptive Pacing
            try:
                from waf_detector import WafDetector
                from tech_profiler import TechProfiler
                probe_resp = self.runner.http.request(f"https://{self.target}/")
                if probe_resp.get("status") == "response":
                    waf_info = WafDetector().inspect_response(
                        probe_resp.get("status_code", 0),
                        probe_resp.get("headers", {}),
                        probe_resp.get("body", "")
                    )
                    if waf_info.get("waf_detected"):
                        detected_names = ", ".join(d["waf"] for d in waf_info["detected_wafs"])
                        logger.warning(f"🛡️  WAF Detected: {detected_names}. Applying adaptive evasion pacing ({waf_info['recommended_delay']}s delay).")
                        self.runner.http.delay_seconds = max(self.runner.http.delay_seconds, waf_info["recommended_delay"])
                        self.memory_manager.store_fact("waf", detected_names, category="infrastructure", source="waf_detector")

                    tech_info = TechProfiler().profile_target(
                        probe_resp.get("headers", {}),
                        probe_resp.get("body", "")
                    )
                    if tech_info.get("technologies"):
                        self.detected_technologies = list(tech_info["technologies"])
                        logger.info(f"🧩 Target Technologies: {', '.join(tech_info['technologies'])}")
                        self.memory_manager.store_fact("technologies", ", ".join(tech_info["technologies"]), category="infrastructure", source="tech_profiler")
                        if self.learning_engine is not None:
                            for tech_name in self.detected_technologies:
                                try:
                                    self.learning_engine.record_tech_fingerprint(
                                        target=self.target,
                                        technology=tech_name,
                                        run_id=run_id,
                                    )
                                except Exception as exc:
                                    logger.debug("LearningEngine record_tech_fingerprint error (non-fatal): %s", exc)
                        boosted = tech_info.get("prioritized_skills", [])
                        if boosted:
                            elevated = [s for s in self.skills if s in boosted]
                            remainder = [s for s in self.skills if s not in boosted]
                            self.skills = elevated + remainder
            except Exception as e:
                logger.debug(f"Target profiling non-fatal error: {e}")

            # Step 3: Validate dependencies & mark blocked skills
            blocked_skills = self.validate_dependencies()
            for b_skill, reason in blocked_skills.items():
                self.skill_results[b_skill] = [{"skill": b_skill, "status": "BLOCKED", "notes": reason}]
                self.run_manager.update_skill_progress(run_id, b_skill, status="blocked", summary=reason)
                self._log_event(b_skill, "BLOCKED", reason)

            # Step 4: Order skills according to dynamic dependency chain
            reg_order = SkillRegistry().get_execution_order(self.skills)
            ordered_skills = [s for s in reg_order if s in self.skills and s not in blocked_skills]
            for s in self.skills:
                if s not in ordered_skills and s not in blocked_skills and s not in ("review-skill", "report-conglomeration"):
                    ordered_skills.append(s)
            if "review-skill" in self.skills and "review-skill" not in ordered_skills and "review-skill" not in blocked_skills:
                ordered_skills.append("review-skill")
            if "report-conglomeration" in self.skills and "report-conglomeration" not in ordered_skills and "report-conglomeration" not in blocked_skills:
                ordered_skills.append("report-conglomeration")

            if self._resumed_completed_skills:
                pending_non_report = [
                    s for s in ordered_skills
                    if s != "report-conglomeration" and s not in self._resumed_completed_skills
                ]
                kept_skills = []
                for s in ordered_skills:
                    if s in self._resumed_completed_skills and not (s == "report-conglomeration" and pending_non_report):
                        logger.info(f"⏭️  Skipping completed skill on resume: {s}")
                        self._log_event(s, "SKIPPED_RESUMED", f"Already completed in run {run_id}")
                    else:
                        kept_skills.append(s)
                ordered_skills = kept_skills

            logger.info(f"Execution order: {' → '.join(ordered_skills)}")

            if self.learning_engine is not None:
                try:
                    with self._lock:
                        self.learning_context = self.learning_engine.before_recon(
                            self.target, techs=self.detected_technologies or None
                        ) or {}
                    recalled = self.learning_context.get("relevant_lessons", [])
                    if recalled:
                        logger.info("🧠 Recalled %d prior lesson(s) for %s", len(recalled), self.target)
                except Exception as exc:
                    logger.debug("LearningEngine before_recon error (non-fatal): %s", exc)
                try:
                    self.apply_advisory_prioritization(techs=self.detected_technologies)
                    advisory_order = self.advisory_prioritization.get("ordered_skills") or []
                    if advisory_order and ordered_skills:
                        order_idx = {s: idx for idx, s in enumerate(advisory_order)}
                        ordered_skills = self._preserve_dependency_order(
                            sorted(ordered_skills, key=lambda s: order_idx.get(s, len(advisory_order)))
                        )
                        logger.info(f"Advisory prioritized order: {' → '.join(ordered_skills)}")
                except Exception as exc:
                    logger.debug("Advisory prioritization error (non-fatal): %s", exc)

            # Step 5: Execute each scheduled skill (serial or parallel)
            serial_prereqs = {"recon-subdomain", "api-spec-discovery", "js-discover", "js-analyze", "content-discovery"}
            serial_finalizers = {"review-skill", "report-conglomeration"}

            if self.parallel:
                from concurrent.futures import ThreadPoolExecutor, as_completed

                prereq_skills = [s for s in ordered_skills if s in serial_prereqs]
                finalizer_skills = [s for s in ordered_skills if s in serial_finalizers]
                parallel_skills = [s for s in ordered_skills if s not in serial_prereqs and s not in serial_finalizers]

                # Phase A: Run prerequisite skills serially
                for skill_name in prereq_skills:
                    self._execute_skill_with_tracking(skill_name, run_id)

                # Phase B: Run independent vuln skills in parallel
                if parallel_skills:
                    logger.info(f"\n🔀 Running {len(parallel_skills)} skills in parallel: {', '.join(parallel_skills)}")
                    with ThreadPoolExecutor(max_workers=min(self.max_subagents, len(parallel_skills))) as executor:
                        futures = {
                            executor.submit(self._execute_skill_with_tracking, s, run_id): s
                            for s in parallel_skills
                        }
                        for future in as_completed(futures):
                            skill_name = futures[future]
                            try:
                                future.result()
                            except Exception as exc:
                                logger.error(f"Parallel skill '{skill_name}' raised: {exc}")

                # Phase B.5: Deterministic Phase 1 validation before finalizers/report-conglomeration
                if self.validate_candidates:
                    self.run_validation_stage()

                # Phase C: Run finalizers serially
                for skill_name in finalizer_skills:
                    self._execute_skill_with_tracking(skill_name, run_id)
            else:
                validated_before_report = False
                for skill_name in ordered_skills:
                    if self.validate_candidates and not validated_before_report and skill_name == "report-conglomeration":
                        self.run_validation_stage()
                        validated_before_report = True
                    self._execute_skill_with_tracking(skill_name, run_id)
                if self.validate_candidates and not validated_before_report:
                    self.run_validation_stage()

            # Step 6: Write orchestration log & finalize durable run
            self._write_scope_audit()
            policy_stop = bool(getattr(self.runner.http, "stop_requested", False))
            if self.scope_audit.get("stopped_by_policy") or self.scope_audit.get("deviation_detected"):
                policy_stop = True
            self._write_orchestration_log()
            final_status = "blocked" if policy_stop else ("failed" if self.failed_skills else "completed")
            if policy_stop:
                self._log_event("scope-check", "RUN_STOPPED", "A request or redirect violated the active scope policy; all later target requests were blocked.")
            self.run_manager.finish_run(run_id, status=final_status)

            try:
                self.cost_tracker.save_receipt()
            except Exception as exc:
                logger.debug("Cost receipt save error: %s", exc)

            if self.tracer and self.current_trace_id:
                try:
                    self.tracer.end_trace(self.current_trace_id)
                    self.tracer.export(self.current_trace_id)
                except Exception as exc:
                    logger.debug("Trace export error: %s", exc)

            for client in self.mcp_clients:
                try:
                    client.disconnect()
                except Exception:
                    pass

            # Step 7: Build Directed Attack Surface Graph
            try:
                from attack_graph import AttackGraphBuilder
                builder = AttackGraphBuilder(self.target, Path(self.target_dir))
                graph_data = builder.build_graph()
                logger.info("🗺️  Attack Graph generated at output/report/attack-graph.json")
                if self.learning_engine is not None and isinstance(graph_data, dict):
                    for chain in (graph_data.get("attack_chains") or []):
                        if not isinstance(chain, dict):
                            continue
                        try:
                            steps = chain.get("steps") or []
                            fids = [str(s.get("finding_id") or "") for s in steps if s.get("finding_id")]
                            self.learning_engine.record_attack_path(
                                target=self.target,
                                path_id=chain.get("chain_id"),
                                title=chain.get("name") or "attack chain",
                                steps=steps,
                                finding_ids=fids,
                                path_severity=str(chain.get("path_severity") or "medium").lower(),
                                path_risk_score=float(chain.get("path_risk_score") or 0.0),
                                verified=bool(chain.get("verified")),
                                review_status="verified" if chain.get("verified") else "inferred",
                                run_id=run_id,
                                evidence_ids=list(chain.get("evidence_ids") or []),
                                metadata={
                                    "step_count": chain.get("step_count", len(steps)),
                                    "missing_prerequisites": chain.get("missing_prerequisites", []),
                                },
                            )
                        except Exception as exc:
                            logger.debug("LearningEngine record_attack_path error (non-fatal): %s", exc)
            except Exception as e:
                logger.debug(f"Attack graph build non-fatal error: {e}")

            if self.learning_engine is not None:
                summary_res = {}
                distill_res = {}
                try:
                    with self._lock:
                        summary_res = self.learning_engine.before_summary(self._candidate_findings) or {}
                except Exception as exc:
                    logger.debug("LearningEngine before_summary error (non-fatal): %s", exc)
                try:
                    with self._lock:
                        distill_res = self.learning_engine.distill() or {}
                except Exception as exc:
                    logger.debug("LearningEngine distill error (non-fatal): %s", exc)
                self.learning_summary = {
                    "recon": self.learning_context,
                    "summary": summary_res,
                    "distill": distill_res,
                }

            if self.failed_skills:
                logger.error("\n❌ Orchestration finished with %d failed skill run(s).", len(self.failed_skills))
            else:
                logger.info("\n✅ Orchestration complete!")
            return {"status": "BLOCKED_SCOPE" if policy_stop else ("FAILED" if self.failed_skills else "SUCCESS"),
                    "run_id": run_id,
                    "resumed": bool(resumed_plan),
                    "trace_id": self.current_trace_id,
                    "cost_summary": self.cost_tracker.get_running_total(),
                    "failed_skills": self.failed_skills,
                    "scope_violations": getattr(self.runner.http, "policy_violations", [])}
        finally:
            if getattr(self, "_has_prev_moros_proxy", False):
                if self._prev_moros_proxy is None:
                    os.environ.pop("MOROS_PROXY", None)
                else:
                    os.environ["MOROS_PROXY"] = self._prev_moros_proxy
                self._has_prev_moros_proxy = False
            if self.learning_engine is not None:
                try:
                    self.learning_engine.close()
                except Exception as exc:
                    logger.debug("LearningEngine close error (non-fatal): %s", exc)
                self.learning_engine = None

    def _model_preflight(self) -> Optional[str]:
        """Require a responding LLM before the orchestrator can touch a target."""
        if not self.llm.is_available():
            return "No LLM provider is configured; connect a model before starting a scan."
        try:
            logger.info("Verifying model connection: %s/%s", self.llm.provider, self.llm.model)
            response = self.llm.complete(
                "Reply with exactly: READY",
                max_tokens=8,
                timeout=15,
            )
        except Exception as exc:
            detail = redact_secrets(str(exc))
            return f"Model connection check failed: {detail}"
        if not response:
            detail = redact_secrets(getattr(self.llm, "last_error", None) or "the provider returned no response")
            return f"Model connection check failed: {detail}"
        return None

    def _execute_skill_with_tracking(self, skill_name: str, run_id: str):
        """Execute a skill across configured models and track progress."""
        logger.info(f"\n{'='*40}")
        logger.info(f"STARTING SKILL: {skill_name}")
        logger.info(f"{'='*40}")

        # Check if dynamic predecessor failed in this run
        deps = SKILL_DEPENDENCIES.get(skill_name, [])
        with self._lock:
            failed_dep = next((d for d in deps if any(f["skill"] == d for f in self.failed_skills)), None)
        if failed_dep:
            reason = f"Prerequisite skill '{failed_dep}' failed earlier in this run."
            logger.warning(f"🚫 Skipping skill '{skill_name}': {reason}")
            with self._lock:
                self.skill_results[skill_name] = [{"skill": skill_name, "status": "BLOCKED", "notes": reason}]
                self.run_manager.update_skill_progress(run_id, skill_name, status="blocked", summary=reason)
                self._log_event(skill_name, "BLOCKED", reason)
            return

        # Run skill with each model
        for model in self.models:
            for run_num in range(1, self.runs_per_skill + 1):
                sub_run_id = f"{skill_name}_{model}_run{run_num}"
                logger.info(f"  Run: {sub_run_id}")
                with self._lock:
                    self.run_manager.update_skill_progress(run_id, skill_name, status="running")
                    if self.smart_routing and model in ("default", "auto"):
                        decision = self.model_router.select_model(skill_name)
                        self.llm = LLMClient(provider=decision.provider, model=decision.model)
                    else:
                        self.llm = self._llm_for_model(model)
                    self.runner.llm = self.llm

                result = self._execute_skill(skill_name, model, run_num)

                with self._lock:
                    if skill_name not in self.skill_results:
                        self.skill_results[skill_name] = []
                    self.skill_results[skill_name].append(result)

                    res_status = result.get("status", "COMPLETED")
                    if res_status in {"FAILED", "ERROR"}:
                        self.failed_skills.append({"skill": skill_name, "run_id": sub_run_id,
                                                   "notes": result.get("notes", "")})
                        self.run_manager.update_skill_progress(
                            run_id, skill_name, status="failed",
                            summary=result.get("notes", "")
                        )
                    else:
                        durable_status = "completed"
                        if res_status in {"BLOCKED", "BLOCKED_SCOPE"}:
                            durable_status = "blocked"
                        self.run_manager.update_skill_progress(
                            run_id, skill_name, status=durable_status,
                            summary=result.get("notes", "")
                        )

                # Run review-skill after each primary skill
                if (skill_name != "review-skill" and skill_name != "report-conglomeration"
                        and result.get("status") != "BLOCKED_SCOPE"):
                    self._run_review(skill_name, model, run_num)

    def _execute_skill(self, skill_name: str, model: str, run_num: int) -> dict:
        """Execute a tool-backed skill with real execution logic."""
        start_time = datetime.now(timezone.utc)
        agent_id = f"{skill_name}-{model}-r{run_num}"

        if self.current_run:
            self.run_manager.register_agent_session(
                self.current_run["run_id"],
                agent_id=agent_id,
                skill=skill_name,
                parent_agent_id="coordinator",
                status="running",
                model=model
            )
        review_agent_ids = []
        if self.current_run and skill_name == "report-conglomeration":
            for review_skill in ("evidence-integrity-review", "skeptical-false-positive-review"):
                review_id = f"{review_skill}-{model}-r{run_num}"
                review_agent_ids.append(review_id)
                self.run_manager.register_agent_session(
                    self.current_run["run_id"], agent_id=review_id,
                    skill=review_skill, parent_agent_id=agent_id,
                    status="running", model="deterministic-artifact-review",
                )

        result = {
            "skill": skill_name,
            "agent_id": agent_id,
            "model": model,
            "run_number": run_num,
            "start_time": start_time.isoformat(),
            "status": "PENDING",
            "notes": ""
        }

        self._log_event(skill_name, "STARTED",
                        f"Model: {model}, Run: {run_num}")

        if (getattr(self.runner.http, "stop_requested", False)
                and skill_name not in {"review-skill", "report-conglomeration"}):
            result["status"] = "BLOCKED_SCOPE"
            result["notes"] = "Skipped after the shared HTTP client stopped on a scope-policy violation."
            result["end_time"] = datetime.now(timezone.utc).isoformat()
            self._log_event(skill_name, result["status"], result["notes"])
            if self.current_run:
                self.run_manager.update_agent_session(
                    self.current_run["run_id"], agent_id=agent_id,
                    status="blocked_scope", summary=result["notes"],
                )
            return result

        skill_res = None
        try:
            if skill_name == "recon-subdomain":
                res = self.runner.run_recon_subdomain(
                    active_validation=self.scope_authorized,
                    max_active_hosts=self.active_host_limit,
                    root_only=self.root_only_active,
                    https_only=self.https_only,
                )
                skill_res = res
                result["status"] = res.get("status", "COMPLETED")
                result["notes"] = f"Found {res.get('subdomains', 0)} subdomains, {res.get('live_hosts', 0)} live hosts"
            elif skill_name == "deep-recon":
                res = self.runner.run_deep_recon(active_validation=self.scope_authorized)
                skill_res = res
                result["status"] = res.get("status", "COMPLETED")
                result["notes"] = (
                    f"Parallel deep-recon merged {res.get('subdomains', 0)} subdomains; "
                    f"WAF={res.get('wafs', [])}; Tech={res.get('technologies', [])}"
                )
            elif skill_name == "api-spec-discovery":
                if self.api_spec:
                    result.update(self._execute_api_spec())
                else:
                    res = self.runner.run_api_spec_discovery()
                    skill_res = res
                    result["status"] = res.get("status", "COMPLETED")
            elif skill_name == "js-discover":
                res = self.runner.run_js_discover()
                skill_res = res
                result["status"] = res.get("status", "COMPLETED")
                result["notes"] = f"Collected {res.get('files_collected', 0)} JS files"
            elif skill_name == "js-analyze":
                res = self.runner.run_js_analyze()
                skill_res = res
                result["status"] = res.get("status", "COMPLETED")
                result["notes"] = res.get("summary", "")
                result["findings_count"] = int(res.get("findings_count", 0))
            elif skill_name == "content-discovery":
                res = self.runner.run_content_discovery()
                skill_res = res
                result["status"] = res.get("status", "COMPLETED")
                result["findings_count"] = int(res.get("findings_count", 0))
                result["notes"] = (
                    f"Checked {res.get('paths_checked', 0)} safe paths; "
                    f"{res.get('findings_count', 0)} need manual review; "
                    f"{res.get('requests_used', 0)} target requests used."
                )
            elif skill_name in [
                "xss-reflected", "xss-stored", "xss-dom", "xss-blind",
                "ssrf-identify", "ssrf-post-exploit", "idp-race-condition",
                "auth-password-reset-bruteforce"
            ]:
                res = self.runner.run_vuln_skill(skill_name)
                skill_res = res
                result["status"] = res.get("status", "COMPLETED")
                result["notes"] = res.get(
                    "summary", f"Recorded {res.get('findings_count', 0)} candidate findings"
                )
                result["findings_count"] = int(res.get("findings_count", 0))
            elif skill_name == "report-conglomeration":
                self._write_scope_audit()
                res = self.runner.run_report_conglomeration()
                skill_res = res
                result["status"] = res.get("status", "COMPLETED")
                result["findings_count"] = int(res.get("findings_count", 0))
                result["notes"] = f"Generated report with {result['findings_count']} unique triage candidates"
            else:
                # Share remaining HTTP budget with custom skill runner if available
                if hasattr(self.runner, "http") and hasattr(self.runner.http, "max_requests"):
                    remaining_budget = max(0, self.runner.http.max_requests - self.runner.http.request_count)
                    os.environ["MOROS_HTTP_REQUESTS_REMAINING"] = str(remaining_budget)

                # Dynamic custom skill execution
                res = self.runner.run_custom_skill(skill_name)
                skill_res = res
                result["status"] = res.get("status", "COMPLETED")
                result["findings_count"] = int(res.get("findings_count", 0))
                result["notes"] = res.get("summary", f"Custom skill {skill_name} completed.")
        except Exception as e:
            logger.error(f"Error executing skill {skill_name}: {e}")
            result["status"] = "FAILED"
            result["notes"] = str(e)

        self._record_learning_findings(skill_name, result, skill_res)

        end_dt = datetime.now(timezone.utc)
        result["end_time"] = end_dt.isoformat()
        if self.learning_engine is not None and skill_name not in {"review-skill", "report-conglomeration"}:
            try:
                duration_ms = max(0.0, (end_dt - start_time).total_seconds() * 1000.0)
                with self._lock:
                    self.learning_engine.record_skill_telemetry(
                        target=self.target,
                        skill_id=skill_name,
                        status=str(result.get("status", "completed")).lower(),
                        duration_ms=duration_ms,
                        findings_count=int(result.get("findings_count", 0) or 0),
                        tech_stack=list(getattr(self, "detected_technologies", []) or []),
                        run_id=(self.current_run or {}).get("run_id"),
                    )
            except Exception as exc:
                logger.debug("LearningEngine record_skill_telemetry error (non-fatal): %s", exc)
        self._log_event(skill_name, result["status"], result.get("notes", ""))

        if self.current_run:
            review_summary = "Review stage did not produce a readable artifact."
            review_status = "failed"
            review_path = self.target_dir / "output" / "report" / "finding-review.json"
            if review_path.is_file():
                try:
                    review_data = json.loads(review_path.read_text(encoding="utf-8"))
                    count = int(review_data.get("unverified_candidates", 0))
                    review_status = "completed"
                    review_rows = review_data.get("findings", [])
                    hash_matches = sum(
                        1 for row in review_rows
                        if row.get("evidence_review", {}).get("sha256_matches") is True
                    )
                    for review_id in review_agent_ids:
                        if review_id.startswith("evidence-integrity-review-"):
                            summary = f"Checked source artifact integrity for {count} candidates; {hash_matches} supplied hashes matched."
                        else:
                            summary = f"Recorded skeptical objections for {count} candidates; none was proven false or promoted to validated."
                        self.run_manager.update_agent_session(
                            self.current_run["run_id"], agent_id=review_id,
                            status=review_status, summary=summary,
                        )
                except (OSError, ValueError, json.JSONDecodeError):
                    pass
            if review_status == "failed":
                for review_id in review_agent_ids:
                    self.run_manager.update_agent_session(
                        self.current_run["run_id"], agent_id=review_id,
                        status=review_status, summary=review_summary,
                    )
            self.run_manager.update_agent_session(
                self.current_run["run_id"],
                agent_id=agent_id,
                status=result["status"].lower(),
                summary=result.get("notes", ""),
                findings_count=result.get("findings_count", 0)
            )

        return result

    def _execute_api_spec(self) -> dict:
        """Import a local OpenAPI/Swagger file into the target inventory."""
        if self.api_spec is None:
            return {"status": "SKIPPED", "notes": "No --api-spec file was supplied."}
        if not self.api_spec.is_file():
            return {"status": "FAILED", "notes": f"API spec not found: {self.api_spec}"}

        try:
            from openapi_import import extract_endpoints, load_spec

            spec = load_spec(self.api_spec)
            if not isinstance(spec, dict) or not ("openapi" in spec or "swagger" in spec):
                raise ValueError("document does not declare an OpenAPI or Swagger version")
            endpoints = extract_endpoints(spec)
            output = self.target_dir / "output" / "api" / "endpoints.json"
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(
                json.dumps({
                    "target": self.target,
                    "source_file": str(self.api_spec),
                    "spec_version": spec.get("openapi", spec.get("swagger")),
                    "total_endpoints": len(endpoints),
                    "endpoints": endpoints,
                }, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            log = self.target_dir / "output" / "logs" / "api-spec-discovery" / "import.log"
            log.parent.mkdir(parents=True, exist_ok=True)
            log.write_text(
                f"Imported {len(endpoints)} endpoints from {self.api_spec}\nOutput: {output}\n",
                encoding="utf-8",
            )
            return {
                "status": "COMPLETED",
                "notes": f"Imported {len(endpoints)} endpoints",
                "artifact": str(output),
            }
        except Exception as exc:
            logger.exception("API specification import failed")
            return {"status": "FAILED", "notes": str(exc)}

    def _run_review(self, skill_name: str, model: str, run_num: int):
        """Run the review-skill to verify completion and fight completion bias (Section 6)."""
        logger.info(f"    Running review-skill for {skill_name} (run {run_num})")

        for retry in range(1, MAX_REVIEW_RETRIES + 1):
            rev = self.runner.run_review_skill(skill_name)
            status = rev.get("overall_status", "PASS")
            if status == "PASS":
                logger.info(f"    ✅ Review PASSED for {skill_name}: verified {rev.get('non_zero_logs_count', 0)} log artifacts")
                self._log_event("review-skill", "PASSED", f"Skill {skill_name} passed verification")
                break
            else:
                nudge = rev.get("nudge_prompt", "")
                logger.warning(f"    ⚠️ Review FAILED for {skill_name} (Attempt {retry}/{MAX_REVIEW_RETRIES}): {nudge}")
                self._log_event("review-skill", "FAILED", f"Attempt {retry} failed for {skill_name}")
                if retry < MAX_REVIEW_RETRIES:
                    logger.info(f"    Nudging skill {skill_name} to re-execute...")
                    self._execute_skill(skill_name, model, retry + 1)
                else:
                    logger.error(f"    ❌ CRITICAL SKILL FAILURE: {skill_name} failed all {MAX_REVIEW_RETRIES} verification attempts.")

    def _log_event(self, skill: str, status: str, details: str):
        """Log an orchestration event."""
        timestamp = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self.execution_log.append({
                "timestamp": timestamp,
                "skill": skill,
                "status": status,
                "details": details,
            })
            # Keep a human-readable agent timeline alongside the structured log.
            self.conversations.append(
                skill,
                "tool",
                f"[{status}] {details}" if details else f"[{status}]",
                source="orchestrator",
            )

    def _write_orchestration_log(self):
        """Write the full orchestration log to disk."""
        self._write_scope_audit()
        log_path = self.target_dir / "output" / "logs" / "orchestration-log.json"
        log_path.parent.mkdir(parents=True, exist_ok=True)

        log_data = {
            "target": self.target,
            "orchestration_time": datetime.now(timezone.utc).isoformat(),
            "skills_requested": self.skills,
            "models_used": self.models,
            "runs_per_skill": self.runs_per_skill,
            "status": (
                "BLOCKED_SCOPE"
                if self.scope_audit.get("stopped_by_policy") or self.scope_audit.get("deviation_detected")
                else ("FAILED" if self.failed_skills else "SUCCESS")
            ),
            "failed_skills": self.failed_skills,
            "scope_blocked_skills": self.scope_blocked_skills,
            "scope_violations": getattr(self.runner.http, "policy_violations", []),
            "scope_audit": self.scope_audit,
            "events": self.execution_log,
            "skill_results": self.skill_results,
        }

        log_path.write_text(json.dumps(log_data, indent=2, default=str), encoding="utf-8")
        logger.info(f"Orchestration log written to {log_path}")

    def _write_scope_audit(self):
        """Persist a run-specific view of observed hosts and enforced scope gates."""
        policy = getattr(self.scope_validator, "policy", {})
        host_counts = {}
        method_counts = {}
        request_observations = []
        traffic_path = self.target_dir / "output" / "js" / "traffic-log.json"
        started_at = (self.current_run or {}).get("started_at")
        try:
            run_started_epoch = datetime.fromisoformat(started_at.replace("Z", "+00:00")).timestamp() if started_at else 0
        except (ValueError, AttributeError):
            run_started_epoch = 0
        if traffic_path.is_file() and traffic_path.stat().st_mtime >= run_started_epoch:
            try:
                traffic = json.loads(traffic_path.read_text(encoding="utf-8"))
                request_observations.extend(row for row in traffic if isinstance(row, dict))
            except (OSError, json.JSONDecodeError):
                pass
        # The browser traffic log covers only browser-captured requests. Include
        # requests from the shared scoped client so GET/HEAD probes and blocked
        # before-navigation redirects are represented in the same audit.
        request_observations.extend(
            dict(row) for row in getattr(self.runner.http, "request_logs", [])
            if isinstance(row, dict)
        )
        for row in request_observations:
            parsed = urllib.parse.urlparse(str(row.get("url", "")))
            host = (parsed.hostname or "").lower().rstrip(".")
            method = str(row.get("method", "UNKNOWN")).upper()
            if host:
                host_counts[host] = host_counts.get(host, 0) + 1
            method_counts[method] = method_counts.get(method, 0) + 1
        out_of_scope_hosts = {
            host: count for host, count in host_counts.items()
            if not self.scope_validator.is_allowed(host)[0]
        }
        violations = list(getattr(self.runner.http, "policy_violations", []))
        out_of_policy_requests = [
            row for row in request_observations
            if (str(row.get("method", "")).upper() not in {"GET", "HEAD"}
                or not self.scope_validator.is_allowed(
                    urllib.parse.urlparse(str(row.get("url", ""))).hostname or ""
                )[0])
        ]
        audit = {
            "run_id": (self.current_run or {}).get("run_id"),
            "target": self.target,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "request_count": getattr(self.runner.http, "request_count", 0),
            "request_limit": getattr(self.runner.http, "max_requests", None),
            "minimum_delay_seconds": getattr(self.runner.http, "delay_seconds", None),
            "same_host_only": bool(policy.get("same_host_only")),
            "methods_observed": method_counts,
            "hosts_observed": host_counts,
            "out_of_scope_hosts": out_of_scope_hosts,
            "out_of_policy_requests": out_of_policy_requests,
            "request_observations": request_observations,
            "policy_violations": violations,
            # A redirect rejected before following is a safe block, not an
            # out-of-scope request. Keep the stop signal separate from a real
            # request that escaped host/method policy.
            "stopped_by_policy": bool(violations),
            "deviation_detected": bool(out_of_scope_hosts or out_of_policy_requests),
        }
        self.scope_audit = audit
        audit_path = self.target_dir / "output" / "logs" / "scope-audit-latest.json"
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        audit_path.write_text(json.dumps(audit, indent=2), encoding="utf-8")
        return audit


def main():
    parser = argparse.ArgumentParser(description="Hackbot Orchestrator")
    parser.add_argument("--target", required=True, help="Target domain")
    parser.add_argument("--target-dir", default=None,
                        help="Target directory (default: targets/<domain>)")
    parser.add_argument("--scope-file", default=None,
                        help="Path to scope-of-work file (for verification)")
    parser.add_argument("--skills", default="all",
                        help="Comma-separated skill list, or 'all'")
    parser.add_argument("--models", default="default",
                        help="Comma-separated model list")
    parser.add_argument("--runs-per-skill", type=int, default=1,
                        help="Number of runs per skill per model")
    parser.add_argument("--review-model", default=None,
                        help="Model to use for review-skill (default: same as skill)")
    parser.add_argument("--active-host-limit", type=int, default=20,
                        help="Maximum hosts for recon HEAD checks (default: 20)")
    parser.add_argument("--root-only-active", action="store_true",
                        help="Limit active recon checks to the exact target hostname")
    parser.add_argument("--https-only", action="store_true",
                        help="Do not fall back to plaintext HTTP during active recon")
    parser.add_argument("--max-http-requests", type=int, default=40,
                        help="Maximum same-host GET/HEAD requests per scan (default: 40)")
    parser.add_argument("--request-delay", type=float, default=0.4,
                        help="Minimum seconds between target requests (default: 0.4)")
    parser.add_argument("--parallel", action="store_true",
                        help="Execute independent skills in parallel using ThreadPoolExecutor")
    parser.add_argument("--max-subagents", type=int, default=5,
                        help="Maximum parallel workers/subagents (default: 5)")
    parser.add_argument("--validate", action="store_true",
                        help="Enable deterministic Phase 1 candidate validation before report assembly")

    args = parser.parse_args()

    target_dir = args.target_dir or f"targets/{args.target}"

    if args.skills == "all":
        skills = [s for s in SKILL_ORDER if s != "report-conglomeration"]
        skills.append("report-conglomeration")
    else:
        skills = [s.strip() for s in args.skills.split(",")]

    models = [m.strip() for m in args.models.split(",")]

    orchestrator = HackbotOrchestrator(
        target=args.target,
        target_dir=target_dir,
        skills=skills,
        models=models,
        runs_per_skill=args.runs_per_skill,
        review_model=args.review_model,
        parallel=args.parallel,
        max_subagents=args.max_subagents,
        validate_candidates=args.validate,
    )

    orchestrator.run()


if __name__ == "__main__":
    main()
