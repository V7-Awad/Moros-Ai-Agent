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
import time
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S"
)
logger = logging.getLogger("hackbot-orchestrator")

# Skill execution order (dependency chain)
SKILL_ORDER = [
    "recon-subdomain",         # 1. Discover attack surface
    "js-discover",             # 2. Collect all JavaScript
    "js-analyze",              # 3. Analyze JavaScript
    "content-discovery",       # 4. Find hidden files/dirs
    "xss-reflected",           # 5. Reflected XSS
    "xss-stored",              # 6. Stored XSS
    "xss-dom",                 # 7. DOM XSS
    "xss-blind",               # 8. Blind XSS
    "ssrf-identify",           # 9. SSRF identification
    "ssrf-post-exploit",       # 10. SSRF post-exploitation
    "idp-race-condition",      # 11. IdP redirect race
    "auth-password-reset-bruteforce",  # 12. Auth brute-force
    "report-conglomeration",   # 13. Final report (always last)
]

# Skills that require specific prior skills to have completed
SKILL_DEPENDENCIES = {
    "js-analyze": ["js-discover"],
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

# Skills that require human approval at certain checkpoints
HUMAN_CHECKPOINT_SKILLS = [
    "xss-stored",
    "xss-blind",
    "ssrf-post-exploit",
    "idp-race-condition",
    "auth-password-reset-bruteforce",
]

MAX_REVIEW_RETRIES = 3


class HackbotOrchestrator:
    def __init__(self, target: str, target_dir: str, skills: list,
                 models: list = None, runs_per_skill: int = 1,
                 review_model: str = None):
        self.target = target
        self.target_dir = Path(target_dir)
        self.skills = skills
        self.models = models or ["default"]
        self.runs_per_skill = runs_per_skill
        self.review_model = review_model

        self.execution_log: list = []
        self.skill_results: dict = {}  # skill -> [run results]

        # Ensure output directories
        output_base = self.target_dir / "output"
        for subdir in ["recon", "js", "content-discovery", "findings", "logs", "report"]:
            (output_base / subdir).mkdir(parents=True, exist_ok=True)

    def verify_scope(self) -> bool:
        """Check that scope-of-work authorization exists."""
        scope_files = list(self.target_dir.glob("scope-of-work.*"))
        if not scope_files:
            logger.error(f"❌ AUTHORIZATION FAILED: No scope-of-work file found in {self.target_dir}")
            logger.error("   Place scope-of-work.pdf or scope-of-work.md in the target directory.")
            self._log_event("scope-check", "FAILED", "No scope-of-work file found")
            return False

        logger.info(f"✅ Authorization verified: {scope_files[0]}")
        self._log_event("scope-check", "PASSED", f"Found {scope_files[0]}")
        return True

    def validate_dependencies(self) -> bool:
        """Verify that all skill dependencies are satisfied."""
        for skill in self.skills:
            deps = SKILL_DEPENDENCIES.get(skill, [])
            for dep in deps:
                if dep not in self.skills and dep != skill:
                    # Check if dependency was run in a previous session (output exists)
                    # For now, just warn
                    logger.warning(f"⚠️  Skill '{skill}' depends on '{dep}' which is not in this run")

        return True

    def run(self):
        """Execute the full orchestration pipeline."""
        logger.info("=" * 60)
        logger.info(f"HACKBOT ORCHESTRATOR — Target: {self.target}")
        logger.info(f"Skills: {', '.join(self.skills)}")
        logger.info(f"Models: {', '.join(self.models)}")
        logger.info(f"Runs per skill: {self.runs_per_skill}")
        logger.info("=" * 60)

        # Step 1: Verify scope
        if not self.verify_scope():
            # Allow only passive recon without scope
            self.skills = [s for s in self.skills if s == "recon-subdomain"]
            if not self.skills:
                logger.error("No skills can run without authorization. Aborting.")
                return
            logger.warning("⚠️  Running in PASSIVE-ONLY mode (no scope-of-work)")

        # Step 2: Validate dependencies
        self.validate_dependencies()

        # Step 3: Order skills according to dependency chain
        ordered_skills = [s for s in SKILL_ORDER if s in self.skills]
        logger.info(f"Execution order: {' → '.join(ordered_skills)}")

        # Step 4: Execute each skill
        for skill_name in ordered_skills:
            logger.info(f"\n{'='*40}")
            logger.info(f"STARTING SKILL: {skill_name}")
            logger.info(f"{'='*40}")

            # Check if this skill needs human approval
            if skill_name in HUMAN_CHECKPOINT_SKILLS:
                logger.info(f"⚠️  HUMAN CHECKPOINT: '{skill_name}' requires human approval")
                self._log_event(skill_name, "CHECKPOINT", "Awaiting human approval")

            # Run skill with each model
            for model in self.models:
                for run_num in range(1, self.runs_per_skill + 1):
                    run_id = f"{skill_name}_{model}_run{run_num}"
                    logger.info(f"  Run: {run_id}")

                    result = self._execute_skill(skill_name, model, run_num)

                    if skill_name not in self.skill_results:
                        self.skill_results[skill_name] = []
                    self.skill_results[skill_name].append(result)

                    # Run review-skill after each primary skill
                    if skill_name != "review-skill" and skill_name != "report-conglomeration":
                        self._run_review(skill_name, model, run_num)

        # Step 5: Write orchestration log
        self._write_orchestration_log()
        logger.info("\n✅ Orchestration complete!")

    def _execute_skill(self, skill_name: str, model: str, run_num: int) -> dict:
        """Execute a single skill run. Placeholder for actual agent invocation."""
        start_time = datetime.now(timezone.utc)

        result = {
            "skill": skill_name,
            "model": model,
            "run_number": run_num,
            "start_time": start_time.isoformat(),
            "status": "PENDING",
            "notes": "Skill execution placeholder — integrate with agent harness"
        }

        self._log_event(skill_name, "STARTED",
                        f"Model: {model}, Run: {run_num}")

        # TODO: Integrate with actual agent harness (Claude Code, Codex, OpenCode)
        # This is where the orchestrator would:
        # 1. Load the skill's SKILL.md
        # 2. Configure the model backend
        # 3. Invoke the agent with the skill instructions
        # 4. Monitor for completion
        # 5. Collect output artifacts

        logger.info(f"    [PLACEHOLDER] Would execute {skill_name} with {model}")

        result["end_time"] = datetime.now(timezone.utc).isoformat()
        result["status"] = "PLACEHOLDER"

        self._log_event(skill_name, "COMPLETED", f"Status: {result['status']}")
        return result

    def _run_review(self, skill_name: str, model: str, run_num: int):
        """Run the review-skill to verify completion."""
        logger.info(f"    Running review-skill for {skill_name} (run {run_num})")

        for retry in range(1, MAX_REVIEW_RETRIES + 1):
            review_result = self._execute_skill("review-skill", 
                                                 self.review_model or model,
                                                 retry)
            # TODO: Check review result and retry skill if needed
            # For now, just log the review attempt
            logger.info(f"    Review attempt {retry}/{MAX_REVIEW_RETRIES}")
            break  # Placeholder — real implementation checks pass/fail

    def _log_event(self, skill: str, status: str, details: str):
        """Log an orchestration event."""
        self.execution_log.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "skill": skill,
            "status": status,
            "details": details,
        })

    def _write_orchestration_log(self):
        """Write the full orchestration log to disk."""
        log_path = self.target_dir / "output" / "logs" / "orchestration-log.json"
        log_path.parent.mkdir(parents=True, exist_ok=True)

        log_data = {
            "target": self.target,
            "orchestration_time": datetime.now(timezone.utc).isoformat(),
            "skills_requested": self.skills,
            "models_used": self.models,
            "runs_per_skill": self.runs_per_skill,
            "events": self.execution_log,
            "skill_results": self.skill_results,
        }

        log_path.write_text(json.dumps(log_data, indent=2, default=str), encoding="utf-8")
        logger.info(f"Orchestration log written to {log_path}")


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
    )

    orchestrator.run()


if __name__ == "__main__":
    main()
