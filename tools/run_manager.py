#!/usr/bin/env python3
"""
run_manager.py — Run Lifecycle & State Management for Moros.

Provides:
- Durable run records under targets/<target>/output/runs/<run_id>/
- Run persistence across process restarts
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

    def get_event_stream(self, run_id: str) -> List[Dict[str, Any]]:
        """Read and parse the event timeline stream from events.jsonl cleanly."""
        if not run_id:
            return []
        events_file = self._run_dir(str(run_id)) / "events.jsonl"
        if not events_file.is_file():
            return []
        events: List[Dict[str, Any]] = []
        try:
            with open(events_file, "r", encoding="utf-8") as f:
                for line in f:
                    raw = line.strip()
                    if not raw:
                        continue
                    try:
                        parsed = json.loads(raw)
                        if isinstance(parsed, dict):
                            events.append(parsed)
                    except json.JSONDecodeError:
                        continue
        except OSError:
            return []
        return events

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
            if skill in record.get("skills_failed", []):
                record["skills_failed"].remove(skill)
        elif status == "failed":
            if skill not in record.get("skills_failed", []):
                record.setdefault("skills_failed", []).append(skill)

        # Set next current skill
        req = record.get("skills_requested", [])
        completed = set(record.get("skills_completed", [])) | set(record.get("skills_failed", []))
        remaining = [s for s in req if s not in completed]
        if status == "running":
            record["current_skill"] = skill
        else:
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

    def register_agent_session(self, run_id: str, agent_id: str, skill: str,
                               parent_agent_id: str = "coordinator",
                               status: str = "running", model: str = "default") -> Dict[str, Any]:
        """Record child agent session in agents.jsonl."""
        run_path = self._run_dir(run_id)
        if not run_path.exists():
            return {}
        record = {
            "agent_id": agent_id,
            "parent_agent_id": parent_agent_id,
            "skill": skill,
            "status": status,
            "model": model,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "completed_at": None,
            "findings_count": 0,
            "summary": "",
        }
        with open(run_path / "agents.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
        return record

    def update_agent_session(self, run_id: str, agent_id: str, status: str = "completed",
                             summary: str = "", findings_count: int = 0):
        """Update child agent session status in agents.jsonl."""
        run_path = self._run_dir(run_id)
        agents_file = run_path / "agents.jsonl"
        if not agents_file.is_file():
            return
        updated_records = []
        with open(agents_file, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                    if rec.get("agent_id") == agent_id:
                        rec["status"] = status
                        rec["summary"] = summary
                        rec["findings_count"] = findings_count
                        rec["completed_at"] = datetime.now(timezone.utc).isoformat()
                    updated_records.append(rec)
                except Exception:
                    continue
        with open(agents_file, "w", encoding="utf-8") as f:
            for rec in updated_records:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def list_agent_sessions(self, run_id: str) -> List[Dict[str, Any]]:
        """List all child agent sessions for a run."""
        run_path = self._run_dir(run_id)
        agents_file = run_path / "agents.jsonl"
        if not agents_file.is_file():
            return []
        records = []
        with open(agents_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        records.append(json.loads(line))
                    except Exception:
                        pass
        return records

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

    RESUMABLE_STATUSES = frozenset({"running", "failed", "aborted"})

    def _is_resumable(self, record: Optional[Dict[str, Any]]) -> bool:
        """Return True when a run record can resume uncompleted requested skills."""
        if not isinstance(record, dict) or record.get("dry_run"):
            return False
        if record.get("status") not in self.RESUMABLE_STATUSES:
            return False
        requested = record.get("skills_requested") or []
        completed = set(record.get("skills_completed") or [])
        return any(skill not in completed for skill in requested)

    def get_latest_resumable_run(self) -> Optional[Dict[str, Any]]:
        """Return the most recent run eligible for resumption, or None."""
        for record in self.list_runs():
            if self._is_resumable(record):
                return record
        return None

    def prepare_resume_plan(self, run_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Build a resume plan for the given run_id or the most recent resumable run.
        Returns None when no matching resumable run with pending skills exists.
        """
        if run_id is None or str(run_id).strip().lower() == "latest":
            record = self.get_latest_resumable_run()
        else:
            candidate = self.get_run(str(run_id).strip())
            record = candidate if self._is_resumable(candidate) else None

        if not record:
            return None

        requested = list(record.get("skills_requested") or [])
        completed = list(record.get("skills_completed") or [])
        completed_set = set(completed)
        pending = [skill for skill in requested if skill not in completed_set]

        return {
            "run_id": record["run_id"],
            "target": record.get("target"),
            "status": record.get("status"),
            "models": record.get("models", "default"),
            "skills_requested": requested,
            "skills_completed": completed,
            "skills_failed": list(record.get("skills_failed") or []),
            "skills_pending": pending,
            "remaining_skills": pending,
            "run": record,
        }

    def mark_run_resumed(self, run_id: str) -> Dict[str, Any]:
        """Transition a resumable run back to running, refresh PID, and log RUN_RESUMED."""
        run_path = self._run_dir(run_id)
        run_file = run_path / "run.json"
        if not run_file.is_file():
            return {}

        with open(run_file, "r", encoding="utf-8") as f:
            record = json.load(f)

        prev_status = record.get("status")
        requested = list(record.get("skills_requested") or [])
        completed_set = set(record.get("skills_completed") or [])
        pending = [skill for skill in requested if skill not in completed_set]

        record["status"] = "running"
        record["pid"] = os.getpid()
        record["completed_at"] = None
        record["error"] = None
        record["resumed_at"] = datetime.now(timezone.utc).isoformat()
        record["current_skill"] = pending[0] if pending else None

        with open(run_file, "w", encoding="utf-8") as f:
            json.dump(record, f, indent=2, ensure_ascii=False)

        self.log_event(run_id, "RUN_RESUMED", {
            "previous_status": prev_status,
            "pid": record["pid"],
            "skills_completed": list(record.get("skills_completed") or []),
            "skills_pending": pending,
        })
        logger.info(f"[RunManager] Resumed run {run_id} (previous status: '{prev_status}')")
        return record
