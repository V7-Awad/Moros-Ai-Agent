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
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import List

# Import LLM client and Skill execution runner
tools_dir = Path(__file__).parent.resolve()
if str(tools_dir) not in sys.path:
    sys.path.insert(0, str(tools_dir))

from llm_client import LLMClient
from skill_runner import SkillRunner
from conversation_store import ConversationStore
from run_manager import RunManager
from scope_validator import ScopeValidator

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S"
)
logger = logging.getLogger("hackbot-orchestrator")

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
    def __init__(self, target: str, target_dir: str, skills: list,
                 models: list = None, runs_per_skill: int = 1,
                 review_model: str = None, api_spec: str = None,
                 active_host_limit: int = 100, root_only_active: bool = False,
                 https_only: bool = False, max_http_requests: int = 150,
                 request_delay: float = 0.3, parallel: bool = False):
        self.target = target
        self.target_dir = Path(target_dir)
        self.skills = skills
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
        self.scope_authorized = False
        self.scope_blocked_skills: list = []
        self.scope_audit: dict = {}
        self._lock = threading.Lock()

        self.execution_log: list = []
        self.skill_results: dict = {}  # skill -> [run results]
        self.failed_skills: list = []

        # Ensure output directories
        output_base = self.target_dir / "output"
        for subdir in ["recon", "js", "content-discovery", "findings", "logs", "report", "api", "runs"]:
            (output_base / subdir).mkdir(parents=True, exist_ok=True)
        self.conversations = ConversationStore(self.target_dir)

        # Initialize durable run tracking.
        self.run_manager = RunManager(self.target_dir)
        self.current_run = None
        self.scope_validator = ScopeValidator(self.target, target_dir=self.target_dir)

        # "default" must auto-detect configured providers; model labels are not providers.
        self.llm = self._llm_for_model(self.models[0] if self.models else "default")
        self.runner = SkillRunner(self.target, self.target_dir, self.llm,
                                  max_http_requests=self.max_http_requests,
                                  request_delay=self.request_delay)
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
        for skill in self.skills:
            deps = SKILL_DEPENDENCIES.get(skill, [])
            for dep in deps:
                if dep not in self.skills:
                    if not self._check_dependency_artifact(dep):
                        reason = f"Prerequisite skill '{dep}' is missing from run schedule and required artifact was not found on disk."
                        blocked[skill] = reason
                        logger.warning(f"🚫 Skill '{skill}' is BLOCKED: {reason}")
                        break
        return blocked

    def run(self):
        """Execute the full orchestration pipeline."""
        logger.info("=" * 60)
        logger.info(f"HACKBOT ORCHESTRATOR — Target: {self.target}")
        logger.info(f"Skills: {', '.join(self.skills)}")
        logger.info(f"Models: {', '.join(self.models)}")
        logger.info(f"Runs per skill: {self.runs_per_skill}")
        logger.info("=" * 60)

        # Step 1: Initialize durable run
        self.current_run = self.run_manager.create_run(
            target=self.target,
            skills=self.skills,
            dry_run=False,
            models=",".join(self.models)
        )
        run_id = self.current_run["run_id"]
        try:
            self.runner.run_started_at = datetime.fromisoformat(
                self.current_run["started_at"].replace("Z", "+00:00")
            )
        except (ValueError, AttributeError, KeyError):
            self.runner.run_started_at = datetime.now(timezone.utc)

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

                tech_info = TechProfiler().profile_target(
                    probe_resp.get("headers", {}),
                    probe_resp.get("body", "")
                )
                if tech_info.get("technologies"):
                    logger.info(f"🧩 Target Technologies: {', '.join(tech_info['technologies'])}")
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
        logger.info(f"Execution order: {' → '.join(ordered_skills)}")

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
                with ThreadPoolExecutor(max_workers=min(4, len(parallel_skills))) as executor:
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

            # Phase C: Run finalizers serially
            for skill_name in finalizer_skills:
                self._execute_skill_with_tracking(skill_name, run_id)
        else:
            for skill_name in ordered_skills:
                self._execute_skill_with_tracking(skill_name, run_id)

        # Step 6: Write orchestration log & finalize durable run
        self._write_scope_audit()
        self._write_orchestration_log()
        policy_stop = bool(getattr(self.runner.http, "stop_requested", False))
        if self.scope_audit.get("deviation_detected"):
            policy_stop = True
        final_status = "blocked" if policy_stop else ("failed" if self.failed_skills else "completed")
        if policy_stop:
            self._log_event("scope-check", "RUN_STOPPED", "A request or redirect violated the active scope policy; all later target requests were blocked.")
        self.run_manager.finish_run(run_id, status=final_status)

        # Step 7: Build Directed Attack Surface Graph
        try:
            from attack_graph import AttackGraphBuilder
            builder = AttackGraphBuilder(self.target, Path(self.target_dir))
            builder.build_graph()
            logger.info("🗺️  Attack Graph generated at output/report/attack-graph.json")
        except Exception as e:
            logger.debug(f"Attack graph build non-fatal error: {e}")

        if self.failed_skills:
            logger.error("\n❌ Orchestration finished with %d failed skill run(s).", len(self.failed_skills))
        else:
            logger.info("\n✅ Orchestration complete!")
        return {"status": "BLOCKED_SCOPE" if policy_stop else ("FAILED" if self.failed_skills else "SUCCESS"),
                "run_id": run_id,
                "failed_skills": self.failed_skills,
                "scope_violations": getattr(self.runner.http, "policy_violations", [])}

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

        try:
            if skill_name == "recon-subdomain":
                res = self.runner.run_recon_subdomain(
                    active_validation=self.scope_authorized,
                    max_active_hosts=self.active_host_limit,
                    root_only=self.root_only_active,
                    https_only=self.https_only,
                )
                result["status"] = res.get("status", "COMPLETED")
                result["notes"] = f"Found {res.get('subdomains', 0)} subdomains, {res.get('live_hosts', 0)} live hosts"
            elif skill_name == "api-spec-discovery":
                if self.api_spec:
                    result.update(self._execute_api_spec())
                else:
                    res = self.runner.run_api_spec_discovery()
                    result["status"] = res.get("status", "COMPLETED")
            elif skill_name == "js-discover":
                res = self.runner.run_js_discover()
                result["status"] = res.get("status", "COMPLETED")
                result["notes"] = f"Collected {res.get('files_collected', 0)} JS files"
            elif skill_name == "js-analyze":
                res = self.runner.run_js_analyze()
                result["status"] = res.get("status", "COMPLETED")
                result["notes"] = res.get("summary", "")
                result["findings_count"] = int(res.get("findings_count", 0))
            elif skill_name == "content-discovery":
                res = self.runner.run_content_discovery()
                result["status"] = res.get("status", "COMPLETED")
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
                result["status"] = res.get("status", "COMPLETED")
                result["notes"] = res.get(
                    "summary", f"Recorded {res.get('findings_count', 0)} candidate findings"
                )
                result["findings_count"] = int(res.get("findings_count", 0))
            elif skill_name == "report-conglomeration":
                self._write_scope_audit()
                res = self.runner.run_report_conglomeration()
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
                result["status"] = res.get("status", "COMPLETED")
                result["notes"] = res.get("summary", f"Custom skill {skill_name} completed.")
        except Exception as e:
            logger.error(f"Error executing skill {skill_name}: {e}")
            result["status"] = "FAILED"
            result["notes"] = str(e)

        result["end_time"] = datetime.now(timezone.utc).isoformat()
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
            "status": "FAILED" if self.failed_skills else "SUCCESS",
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
        traffic_path = self.target_dir / "output" / "js" / "traffic-log.json"
        started_at = (self.current_run or {}).get("started_at")
        try:
            run_started_epoch = datetime.fromisoformat(started_at.replace("Z", "+00:00")).timestamp() if started_at else 0
        except (ValueError, AttributeError):
            run_started_epoch = 0
        if traffic_path.is_file() and traffic_path.stat().st_mtime >= run_started_epoch:
            try:
                traffic = json.loads(traffic_path.read_text(encoding="utf-8"))
                for row in traffic if isinstance(traffic, list) else []:
                    parsed = urllib.parse.urlparse(str(row.get("url", "")))
                    host = (parsed.hostname or "").lower().rstrip(".")
                    method = str(row.get("method", "UNKNOWN")).upper()
                    if host:
                        host_counts[host] = host_counts.get(host, 0) + 1
                    method_counts[method] = method_counts.get(method, 0) + 1
            except (OSError, json.JSONDecodeError):
                pass
        out_of_scope_hosts = {
            host: count for host, count in host_counts.items()
            if not self.scope_validator.is_allowed(host)[0]
        }
        violations = list(getattr(self.runner.http, "policy_violations", []))
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
            "policy_violations": violations,
            "deviation_detected": bool(out_of_scope_hosts or violations),
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
    )

    orchestrator.run()


if __name__ == "__main__":
    main()
