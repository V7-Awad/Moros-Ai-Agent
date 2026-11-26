#!/usr/bin/env python3
"""
checkpoint_manager.py — Blocking Human-in-the-Loop (HITL) Engine for Moros.

Provides:
- Worker thread blocking before state-changing or high-impact actions
- Deterministic state machine:
  CREATED -> WAITING_APPROVAL -> APPROVED | REJECTED | TIMEOUT | CANCELLED
- Persistent checkpoint records under targets/<target>/output/logs/checkpoints.json
- Dashboard / CLI approval waking via thread events and durable file updates
"""

import hashlib
import json
import logging
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger("checkpoint-manager")

# Global event registry for active in-process checkpoints
_ACTIVE_EVENTS: Dict[str, threading.Event] = {}
_EVENTS_LOCK = threading.Lock()


class CheckpointManager:
    def __init__(self, target: str, target_dir: Path):
        self.target = target
        self.target_dir = Path(target_dir).resolve()
        self.output_dir = self.target_dir / "output"
        self.checkpoints_file = self.output_dir / "logs" / "checkpoints.json"
        self.checkpoints_file.parent.mkdir(parents=True, exist_ok=True)

    def _read_all(self) -> List[Dict[str, Any]]:
        if not self.checkpoints_file.is_file():
            return []
        try:
            with open(self.checkpoints_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except Exception:
            return []

    def _save_all(self, items: List[Dict[str, Any]]):
        temp_file = self.checkpoints_file.with_suffix(".tmp")
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(items, f, indent=2, ensure_ascii=False)
        temp_file.replace(self.checkpoints_file)

    def create_checkpoint(self, checkpoint_type: str, target_url: str, method: str = "ACTION",
                          reason: str = "", risk_level: str = "HIGH", agent: str = "coordinator") -> Dict[str, Any]:
        """Create a durable checkpoint and return its metadata."""
        identity = f"{self.target}|{checkpoint_type}|{target_url}|{method}"
        cp_id = "cp-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:12]
        now = datetime.now(timezone.utc).isoformat()

        all_cps = self._read_all()
        # Check if already exists
        for cp in all_cps:
            if cp.get("id") == cp_id:
                return cp

        record = {
            "id": cp_id,
            "target": self.target,
            "type": checkpoint_type,
            "target_url": target_url,
            "method": method,
            "reason": reason or f"Potential state-changing or high-impact action on {target_url}",
            "risk_level": risk_level,
            "status": "WAITING_APPROVAL",
            "agent": agent,
            "created_at": now,
            "decided_at": None,
            "decision_notes": "",
            "decided_by": None,
        }
        all_cps.insert(0, record)
        self._save_all(all_cps)
        return record

    def request_approval(self, checkpoint_type: str, target_url: str, method: str = "ACTION",
                         reason: str = "", risk_level: str = "HIGH", agent: str = "coordinator",
                         timeout_seconds: int = 300, poll_interval: float = 0.5,
                         blocking: bool = True) -> Dict[str, Any]:
        """
        Block the calling worker thread until human approval, rejection, or timeout.
        If blocking=False or timeout_seconds <= 0, registers checkpoint and returns immediately.
        Returns the finalized or current checkpoint state.
        """
        cp = self.create_checkpoint(checkpoint_type, target_url, method, reason, risk_level, agent)
        cp_id = cp["id"]

        # If already decided in previous session
        if cp.get("status") in ["APPROVED", "REJECTED"]:
            logger.info(f"[HITL] Checkpoint {cp_id} was previously decided: {cp['status']}")
            return cp

        if not blocking or timeout_seconds <= 0:
            return cp

        event = threading.Event()
        with _EVENTS_LOCK:
            _ACTIVE_EVENTS[cp_id] = event

        logger.warning(
            f"[HITL-BLOCKING] Worker waiting for human operator approval on checkpoint {cp_id} "
            f"({checkpoint_type}: {method} {target_url}) — timeout in {timeout_seconds}s."
        )

        start_time = time.time()
        try:
            while time.time() - start_time < timeout_seconds:
                # 1. Check in-process event
                if event.is_set():
                    break

                # 2. Check durable file update (in case decision came via separate server process)
                current_cps = self._read_all()
                for item in current_cps:
                    if item.get("id") == cp_id and item.get("status") in ["APPROVED", "REJECTED"]:
                        event.set()
                        return item

                time.sleep(poll_interval)

            # Check if finalized
            current_cps = self._read_all()
            for item in current_cps:
                if item.get("id") == cp_id:
                    if item.get("status") in ["APPROVED", "REJECTED"]:
                        return item

            # If loop exited without decision: Mark as TIMEOUT
            logger.warning(f"[HITL-TIMEOUT] Checkpoint {cp_id} timed out after {timeout_seconds}s.")
            return self.decide(cp_id, "reject", notes=f"Automated safety timeout after {timeout_seconds}s", decider="system_timeout")

        finally:
            with _EVENTS_LOCK:
                _ACTIVE_EVENTS.pop(cp_id, None)

    def decide(self, checkpoint_id: str, action: str, notes: str = "", decider: str = "operator") -> Dict[str, Any]:
        """
        Record approval or rejection decision and wake any blocked worker.
        action: 'approve' or 'reject'
        """
        action_clean = "APPROVED" if action.lower() in ["approve", "approved"] else "REJECTED"
        all_cps = self._read_all()
        target_cp = None

        for cp in all_cps:
            if cp.get("id") == checkpoint_id:
                cp["status"] = action_clean
                cp["decided_at"] = datetime.now(timezone.utc).isoformat()
                cp["decision_notes"] = notes
                cp["decided_by"] = decider
                target_cp = cp
                break

        if not target_cp:
            target_cp = {
                "id": checkpoint_id,
                "status": action_clean,
                "decided_at": datetime.now(timezone.utc).isoformat(),
                "decision_notes": notes,
                "decided_by": decider,
            }
            all_cps.insert(0, target_cp)

        self._save_all(all_cps)

        # Wake in-process thread if waiting
        with _EVENTS_LOCK:
            event = _ACTIVE_EVENTS.get(checkpoint_id)
            if event:
                event.set()

        logger.info(f"[HITL-DECIDED] Checkpoint {checkpoint_id} marked as {action_clean} by {decider}.")
        return target_cp

    def list_checkpoints(self) -> List[Dict[str, Any]]:
        return self._read_all()
