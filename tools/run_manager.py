#!/usr/bin/env python3
"""
run_manager.py — Durable Run Lifecycle & State Management for Moros AI.

Implements Priority 3 of the Moros AI Architecture:
- Durable run records under targets/<target>/output/runs/<run_id>/
- Run persistence surviving process restarts
- Event timeline stream in events.jsonl
- Artifact & Checkpoint manifests
- Safe resume, list, and abort capabilities
"""

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("run-manager")


class RunManager:
    def __init__(self, target_dir: Path):
        self.target_dir = Path(target_dir).resolve()
        self.runs_dir = self.target_dir / "output" / "runs"
        self.runs_dir.mkdir(parents=True, exist_ok=True)

    def _run_dir(self, run_id: str) -> Path:
        safe_id = "".join(c for c in run_id if c.isalnum() or c in "-_")
        return self.runs_dir / safe_id

    def create_run(self, target: str, skills: List[str], dry_run: bool = False,
                   models: str = "default") -> Dict[str, Any]:
        """Initialize a new durable run."""
        timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        rand_suffix = hashlib.sha256(os.urandom(8)).hexdigest()[:6]
        run_id = f"run-{timestamp_str}-{rand_suffix}"

        run_path = self._run_dir(run_id)
        run_path.mkdir(parents=True, exist_ok=True)

        record = {
            "run_id": run_id,
            "target": target,
            "status": "running",
            "dry_run": dry_run,
            "models": models,
            "pid": os.getpid(),
            "started_at": datetime.now(timezone.utc).isoformat(),
            "completed_at": None,
            "skills_requested": skills,
            "skills_completed": [],
            "skills_failed": [],
            "current_skill": skills[0] if skills else None,
            "error": None,
        }

        with open(run_path / "run.json", "w", encoding="utf-8") as f:
            json.dump(record, f, indent=2, ensure_ascii=False)

        self.log_event(run_id, "RUN_CREATED", {"target": target, "skills": skills, "dry_run": dry_run})
        logger.info(f"[RunManager] Created durable run {run_id} for target {target}")
        return record

    def log_event(self, run_id: str, event_type: str, details: Dict[str, Any] = None):
        """Append an event to events.jsonl."""
        run_path = self._run_dir(run_id)
        if not run_path.exists():
            return
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "run_id": run_id,
            "event": event_type,
            "details": details or {},
        }
        with open(run_path / "events.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def update_skill_progress(self, run_id: str, skill: str, status: str = "completed",
                              summary: str = "", findings_count: int = 0):
        """Update skill execution status in run.json."""
        run_path = self._run_dir(run_id)
        run_file = run_path / "run.json"
        if not run_file.is_file():
            return

        with open(run_file, "r", encoding="utf-8") as f:
            record = json.load(f)

        if status == "completed":
            if skill not in record.get("skills_completed", []):
                record.setdefault("skills_completed", []).append(skill)
        elif status == "failed":
            if skill not in record.get("skills_failed", []):
                record.setdefault("skills_failed", []).append(skill)

        # Set next current skill
        req = record.get("skills_requested", [])
        completed = record.get("skills_completed", []) + record.get("skills_failed", [])
        remaining = [s for s in req if s not in completed]
        record["current_skill"] = remaining[0] if remaining else None

        with open(run_file, "w", encoding="utf-8") as f:
            json.dump(record, f, indent=2, ensure_ascii=False)

        self.log_event(run_id, f"SKILL_{status.upper()}", {
            "skill": skill,
            "summary": summary,
            "findings_count": findings_count,
        })

    def finish_run(self, run_id: str, status: str = "completed", error: Optional[str] = None) -> Dict[str, Any]:
        """Mark a run as completed, failed, or aborted."""
        run_path = self._run_dir(run_id)
        run_file = run_path / "run.json"
        if not run_file.is_file():
            return {}

        with open(run_file, "r", encoding="utf-8") as f:
            record = json.load(f)

        record["status"] = status
        record["completed_at"] = datetime.now(timezone.utc).isoformat()
        record["current_skill"] = None
        if error:
            record["error"] = error

        with open(run_file, "w", encoding="utf-8") as f:
            json.dump(record, f, indent=2, ensure_ascii=False)

        self.log_event(run_id, f"RUN_{status.upper()}", {"error": error})
        logger.info(f"[RunManager] Run {run_id} finished with status '{status}'")
        return record

    def get_run(self, run_id: str) -> Optional[Dict[str, Any]]:
        run_file = self._run_dir(run_id) / "run.json"
        if not run_file.is_file():
            return None
        try:
            with open(run_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    def list_runs(self) -> List[Dict[str, Any]]:
        """List all durable runs sorted newest first."""
        results = []
        if not self.runs_dir.is_dir():
            return []

        for p in self.runs_dir.iterdir():
            if p.is_dir():
                rf = p / "run.json"
                if rf.is_file():
                    try:
                        with open(rf, "r", encoding="utf-8") as f:
                            data = json.load(f)
                            results.append(data)
                    except Exception:
                        continue

        results.sort(key=lambda r: r.get("started_at", ""), reverse=True)
        return results

    def get_latest_or_active_run(self) -> Optional[Dict[str, Any]]:
        runs = self.list_runs()
        # Prefer currently running
        for r in runs:
            if r.get("status") == "running":
                return r
        return runs[0] if runs else None
