#!/usr/bin/env python3
"""
scheduler.py — Automations, Recurring Schedules & Webhook Triggers for Moros AI (P2-1).

Provides:
- Interval and cron-like recurring scan schedules
- Webhook event definitions and trigger dispatch (with optional HMAC-SHA256 verification)
- Persistence to targets/<target>/schedules.json
- Strict ScopeValidator and budget cap enforcement before queuing any run
"""

import hashlib
import hmac
import json
import logging
import re
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

try:
    from scope_validator import ScopeValidator
    from cost_tracker import CostTracker
    from run_manager import RunManager
except ImportError:
    from tools.scope_validator import ScopeValidator
    from tools.cost_tracker import CostTracker
    from tools.run_manager import RunManager

logger = logging.getLogger("scan-scheduler")

PROJECT_ROOT = Path(__file__).parent.parent.resolve()

CRON_ALIASES: Dict[str, str] = {
    "@yearly": "0 0 1 1 *",
    "@annually": "0 0 1 1 *",
    "@monthly": "0 0 1 * *",
    "@weekly": "0 0 * * 0",
    "@daily": "0 0 * * *",
    "@midnight": "0 0 * * *",
    "@hourly": "0 * * * *",
}


class SchedulerError(Exception):
    """Base error for ScanScheduler operations."""


class ScopeViolationError(SchedulerError, PermissionError):
    """Raised when a schedule or webhook target violates ScopeValidator rules."""


class BudgetCapExceededError(SchedulerError, ValueError):
    """Raised when a schedule or queued run exceeds configured budget caps."""


def _now_utc(now: Optional[datetime] = None) -> datetime:
    if now is None:
        return datetime.now(timezone.utc)
    if now.tzinfo is None:
        return now.replace(tzinfo=timezone.utc)
    return now.astimezone(timezone.utc)


def _parse_iso(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _sanitize_target_dirname(target: str) -> str:
    clean = re.sub(r"[^a-zA-Z0-9._-]", "_", (target or "").strip().lower()).strip("._")
    if not clean or clean in {".", ".."}:
        raise ValueError("Invalid target name for scheduler storage")
    return clean


def _parse_cron_field(field: str, min_val: int, max_val: int) -> Set[int]:
    """Parse a single 5-field cron token into a set of allowed integers."""
    values: Set[int] = set()
    parts = [p.strip() for p in field.split(",") if p.strip()]
    if not parts:
        raise ValueError(f"Empty cron field: {field!r}")

    for part in parts:
        step = 1
        if "/" in part:
            base, step_str = part.split("/", 1)
            if not step_str.isdigit() or int(step_str) <= 0:
                raise ValueError(f"Invalid cron step in {part!r}")
            step = int(step_str)
        else:
            base = part

        if base == "*":
            start, end = min_val, max_val
        elif "-" in base:
            start_s, end_s = base.split("-", 1)
            if not (start_s.isdigit() and end_s.isdigit()):
                raise ValueError(f"Invalid cron range in {part!r}")
            start, end = int(start_s), int(end_s)
            if start > end or start < min_val or end > max_val:
                raise ValueError(f"Cron range out of bounds ({min_val}-{max_val}): {part!r}")
        else:
            if not base.isdigit():
                raise ValueError(f"Invalid cron value in {part!r}")
            val = int(base)
            if val < min_val or val > max_val:
                raise ValueError(f"Cron value out of bounds ({min_val}-{max_val}): {part!r}")
            if "/" in part:
                start, end = val, max_val
            else:
                start, end = val, val

        values.update(range(start, end + 1, step))

    if not values:
        raise ValueError(f"Cron field matched no values: {field!r}")
    return values


def parse_cron_expression(expr: str) -> Dict[str, Set[int]]:
    """Validate and parse a 5-field cron expression (or @alias)."""
    raw = (expr or "").strip()
    normalized = CRON_ALIASES.get(raw.lower(), raw)
    fields = normalized.split()
    if len(fields) != 5:
        raise ValueError(f"Cron expression must have 5 fields, got {len(fields)}: {expr!r}")

    minutes = _parse_cron_field(fields[0], 0, 59)
    hours = _parse_cron_field(fields[1], 0, 23)
    days = _parse_cron_field(fields[2], 1, 31)
    months = _parse_cron_field(fields[3], 1, 12)
    # Support 7 as Sunday alias alongside 0
    raw_dow = _parse_cron_field(fields[4], 0, 7)
    weekdays = {0 if d == 7 else d for d in raw_dow}

    return {
        "minutes": minutes,
        "hours": hours,
        "days": days,
        "months": months,
        "weekdays": weekdays,
    }


def cron_matches(expr: str, dt: datetime) -> bool:
    """Return True if dt (UTC) matches the 5-field cron expression."""
    parsed = parse_cron_expression(expr)
    dt_utc = _now_utc(dt)
    # Python weekday(): Mon=0..Sun=6 -> cron Sun=0..Sat=6
    cron_dow = (dt_utc.weekday() + 1) % 7
    return (
        dt_utc.minute in parsed["minutes"]
        and dt_utc.hour in parsed["hours"]
        and dt_utc.day in parsed["days"]
        and dt_utc.month in parsed["months"]
        and cron_dow in parsed["weekdays"]
    )


def compute_next_cron_run(expr: str, after_dt: datetime, max_lookahead_minutes: int = 60 * 24 * 366) -> datetime:
    """Compute the next UTC minute strictly after after_dt matching expr."""
    parsed = parse_cron_expression(expr)
    cursor = _now_utc(after_dt).replace(second=0, microsecond=0) + timedelta(minutes=1)
    for _ in range(max_lookahead_minutes):
        cron_dow = (cursor.weekday() + 1) % 7
        if (
            cursor.month in parsed["months"]
            and cursor.day in parsed["days"]
            and cron_dow in parsed["weekdays"]
            and cursor.hour in parsed["hours"]
            and cursor.minute in parsed["minutes"]
        ):
            return cursor
        cursor += timedelta(minutes=1)
    raise ValueError(f"No matching cron timestamp found within lookahead for {expr!r}")


class ScanScheduler:
    """
    Persistent scan scheduler & webhook trigger manager for a Moros target.

    Persists schedule definitions and queued run records to
    `targets/<target>/schedules.json` while strictly enforcing ScopeValidator
    and budget caps before queuing any run.
    """

    def __init__(
        self,
        target: str = "",
        target_dir: Optional[Path] = None,
        max_budget_cap_usd: float = 50.0,
        total_budget_cap_usd: Optional[float] = None,
        scope_validator: Optional[ScopeValidator] = None,
        cost_tracker: Optional[CostTracker] = None,
        run_manager: Optional[RunManager] = None,
        on_queue: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        if target_dir is not None:
            self.target_dir = Path(target_dir).resolve()
            self.target = (target or self.target_dir.name).strip()
        elif target:
            self.target = target.strip()
            self.target_dir = (PROJECT_ROOT / "targets" / _sanitize_target_dirname(self.target)).resolve()
        else:
            raise ValueError("Either target or target_dir must be provided")

        if not self.target:
            raise ValueError("Target cannot be empty")
        if max_budget_cap_usd <= 0:
            raise ValueError("max_budget_cap_usd must be positive")
        if total_budget_cap_usd is not None and total_budget_cap_usd <= 0:
            raise ValueError("total_budget_cap_usd must be positive")

        self.target_dir.mkdir(parents=True, exist_ok=True)
        self.schedules_file = self.target_dir / "schedules.json"
        self.max_budget_cap_usd = float(max_budget_cap_usd)
        self.total_budget_cap_usd = float(total_budget_cap_usd) if total_budget_cap_usd is not None else None
        self.scope_validator = scope_validator or ScopeValidator(self.target, target_dir=self.target_dir)
        self.cost_tracker = cost_tracker
        self.run_manager = run_manager
        self.on_queue = on_queue
        self._lock = threading.Lock()

        if not self.schedules_file.exists():
            self._save_state({
                "version": 1,
                "target": self.target,
                "schedules": [],
                "queued_runs": [],
            })

    def _load_state(self) -> Dict[str, Any]:
        if not self.schedules_file.is_file():
            return {"version": 1, "target": self.target, "schedules": [], "queued_runs": []}
        try:
            data = json.loads(self.schedules_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {"version": 1, "target": self.target, "schedules": [], "queued_runs": []}
        if not isinstance(data, dict):
            return {"version": 1, "target": self.target, "schedules": [], "queued_runs": []}
        data.setdefault("version", 1)
        data.setdefault("target", self.target)
        data.setdefault("schedules", [])
        data.setdefault("queued_runs", [])
        return data

    def _save_state(self, state: Dict[str, Any]) -> None:
        self.schedules_file.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self.schedules_file.with_suffix(".json.tmp")
        tmp_path.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp_path.replace(self.schedules_file)

    @staticmethod
    def _public_schedule(schedule: Dict[str, Any]) -> Dict[str, Any]:
        """Return a copy of a schedule record without exposing raw webhook secrets."""
        copy = dict(schedule)
        has_secret = bool(copy.pop("secret", None))
        copy["has_secret"] = has_secret
        return copy

    def _validate_scope(self, target_host_or_url: Optional[str] = None) -> None:
        subject = (target_host_or_url or self.target).strip()
        allowed, reason = self.scope_validator.is_allowed(subject)
        if not allowed:
            raise ScopeViolationError(f"Scope validation failed for '{subject}': {reason}")

    def _validate_budget(self, budget_usd: float, state: Optional[Dict[str, Any]] = None) -> None:
        if budget_usd <= 0:
            raise BudgetCapExceededError(f"Schedule budget_usd must be positive, got {budget_usd}")
        if budget_usd > self.max_budget_cap_usd:
            raise BudgetCapExceededError(
                f"Requested budget ${budget_usd:.2f} exceeds per-run cap ${self.max_budget_cap_usd:.2f}"
            )

        if self.cost_tracker is not None:
            totals = self.cost_tracker.get_running_total()
            if self.cost_tracker.budget_exceeded:
                raise BudgetCapExceededError("CostTracker budget cap already exceeded")
            remaining = float(totals.get("budget_remaining_usd", 0.0))
            if budget_usd > remaining:
                raise BudgetCapExceededError(
                    f"Requested budget ${budget_usd:.2f} exceeds remaining CostTracker budget ${remaining:.2f}"
                )

        if self.total_budget_cap_usd is not None and state is not None:
            committed = sum(float(r.get("budget_usd", 0.0)) for r in state.get("queued_runs", []))
            if committed + budget_usd > self.total_budget_cap_usd:
                raise BudgetCapExceededError(
                    f"Cumulative queued budget ${committed + budget_usd:.2f} exceeds total cap ${self.total_budget_cap_usd:.2f}"
                )

    def create_schedule(
        self,
        name: str,
        skills: Optional[List[str]] = None,
        interval_seconds: Optional[float] = None,
        cron: Optional[str] = None,
        event_type: Optional[str] = None,
        budget_usd: float = 10.0,
        scan_mode: str = "full",
        target_override: Optional[str] = None,
        enabled: bool = True,
        secret: Optional[str] = None,
        run_immediately: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
        now: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Create and persist an interval, cron, or webhook-triggered scan schedule.
        """
        clean_name = (name or "").strip()
        if not clean_name:
            raise ValueError("Schedule name cannot be empty")

        modes = [bool(interval_seconds is not None), bool(cron), bool(event_type)]
        if sum(modes) != 1:
            raise ValueError("Specify exactly one of interval_seconds, cron, or event_type")

        if scan_mode not in {"quick", "deep", "full", "passive"}:
            raise ValueError(f"Unsupported scan_mode: {scan_mode}")

        effective_target = (target_override or self.target).strip()
        self._validate_scope(effective_target)

        now_dt = _now_utc(now)
        schedule_id = f"sched-{uuid.uuid4().hex[:10]}"

        if interval_seconds is not None:
            interval_val = float(interval_seconds)
            if interval_val <= 0:
                raise ValueError("interval_seconds must be positive")
            schedule_type = "interval"
            next_run = now_dt if run_immediately else (now_dt + timedelta(seconds=interval_val))
            next_run_iso: Optional[str] = next_run.isoformat()
        elif cron:
            parse_cron_expression(cron)
            schedule_type = "cron"
            interval_val = None
            if run_immediately and cron_matches(cron, now_dt):
                next_run = now_dt.replace(second=0, microsecond=0)
            else:
                next_run = compute_next_cron_run(cron, now_dt)
            next_run_iso = next_run.isoformat()
        else:
            clean_event = (event_type or "").strip()
            if not clean_event:
                raise ValueError("event_type cannot be empty")
            schedule_type = "webhook"
            interval_val = None
            next_run_iso = None

        with self._lock:
            state = self._load_state()
            self._validate_budget(float(budget_usd), state=state)

            record: Dict[str, Any] = {
                "schedule_id": schedule_id,
                "name": clean_name,
                "target": effective_target,
                "schedule_type": schedule_type,
                "interval_seconds": interval_val,
                "cron": cron.strip() if cron else None,
                "event_type": event_type.strip() if event_type else None,
                "skills": list(skills) if skills else ["all"],
                "scan_mode": scan_mode,
                "budget_usd": float(budget_usd),
                "enabled": bool(enabled),
                "secret": secret,
                "metadata": dict(metadata) if metadata else {},
                "created_at": now_dt.isoformat(),
                "last_run_at": None,
                "next_run_at": next_run_iso,
                "run_count": 0,
            }
            state["schedules"].append(record)
            self._save_state(state)

        logger.info("Created %s schedule '%s' (%s) for %s", schedule_type, clean_name, schedule_id, effective_target)
        return self._public_schedule(record)

    def list_schedules(
        self,
        include_disabled: bool = True,
        schedule_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List persisted schedules from targets/<target>/schedules.json."""
        with self._lock:
            state = self._load_state()
            schedules = state.get("schedules", [])

        results: List[Dict[str, Any]] = []
        for s in schedules:
            if not include_disabled and not s.get("enabled", True):
                continue
            if schedule_type and s.get("schedule_type") != schedule_type:
                continue
            results.append(self._public_schedule(s))
        return results

    def get_schedule(self, schedule_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single schedule by ID."""
        with self._lock:
            state = self._load_state()
            for s in state.get("schedules", []):
                if s.get("schedule_id") == schedule_id:
                    return self._public_schedule(s)
        return None

    def set_enabled(self, schedule_id: str, enabled: bool) -> Dict[str, Any]:
        """Enable or disable an existing schedule."""
        with self._lock:
            state = self._load_state()
            for s in state.get("schedules", []):
                if s.get("schedule_id") == schedule_id:
                    s["enabled"] = bool(enabled)
                    self._save_state(state)
                    return self._public_schedule(s)
        raise KeyError(f"Schedule not found: {schedule_id}")

    def delete_schedule(self, schedule_id: str) -> bool:
        """Delete a schedule by ID."""
        with self._lock:
            state = self._load_state()
            before = len(state.get("schedules", []))
            state["schedules"] = [s for s in state.get("schedules", []) if s.get("schedule_id") != schedule_id]
            if len(state["schedules"]) == before:
                return False
            self._save_state(state)
            return True

    def list_queued_runs(self) -> List[Dict[str, Any]]:
        """Return all queued scan run descriptors."""
        with self._lock:
            state = self._load_state()
            return [dict(r) for r in state.get("queued_runs", [])]

    def _enqueue_locked(
        self,
        state: Dict[str, Any],
        schedule: Dict[str, Any],
        trigger: str,
        now_dt: datetime,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Validate scope + budget caps and enqueue a run while holding self._lock."""
        # Re-validate both schedule target and any target/url override in event payload
        sched_target = schedule.get("target") or self.target
        self._validate_scope(sched_target)
        if payload:
            for key in ("target", "url", "host"):
                val = payload.get(key)
                if isinstance(val, str) and val.strip():
                    self._validate_scope(val.strip())

        budget_usd = float(schedule.get("budget_usd", 0.0))
        self._validate_budget(budget_usd, state=state)

        skills = list(schedule.get("skills") or ["all"])
        run_id: Optional[str] = None
        if self.run_manager is not None:
            run_rec = self.run_manager.create_run(target=sched_target, skills=skills)
            run_id = run_rec.get("run_id")

        queued = {
            "queue_id": f"qrun-{uuid.uuid4().hex[:10]}",
            "run_id": run_id,
            "schedule_id": schedule["schedule_id"],
            "schedule_name": schedule["name"],
            "target": sched_target,
            "skills": skills,
            "scan_mode": schedule.get("scan_mode", "full"),
            "budget_usd": budget_usd,
            "trigger": trigger,
            "payload": dict(payload) if payload else {},
            "status": "queued",
            "queued_at": now_dt.isoformat(),
        }
        state.setdefault("queued_runs", []).append(queued)

        schedule["last_run_at"] = now_dt.isoformat()
        schedule["run_count"] = int(schedule.get("run_count", 0)) + 1

        if schedule.get("schedule_type") == "interval" and schedule.get("interval_seconds"):
            schedule["next_run_at"] = (
                now_dt + timedelta(seconds=float(schedule["interval_seconds"]))
            ).isoformat()
        elif schedule.get("schedule_type") == "cron" and schedule.get("cron"):
            schedule["next_run_at"] = compute_next_cron_run(schedule["cron"], now_dt).isoformat()

        return queued

    def due_schedules(
        self,
        now: Optional[datetime] = None,
        queue: bool = False,
        strict: bool = False,
    ) -> List[Dict[str, Any]]:
        """
        Return interval/cron schedules that are due as of `now` (UTC).

        Enforces scope validation and budget caps before queuing runs (when queue=True)
        and filters out schedules that violate policy unless `strict=True` (which raises).
        """
        now_dt = _now_utc(now)
        due_items: List[Dict[str, Any]] = []

        with self._lock:
            state = self._load_state()
            changed = False

            for s in state.get("schedules", []):
                if not s.get("enabled", True):
                    continue
                stype = s.get("schedule_type")
                if stype not in ("interval", "cron"):
                    continue

                is_due = False
                next_dt = _parse_iso(s.get("next_run_at"))
                last_dt = _parse_iso(s.get("last_run_at"))

                if next_dt is not None:
                    is_due = now_dt >= next_dt
                elif stype == "interval" and s.get("interval_seconds"):
                    if last_dt is None:
                        is_due = True
                    else:
                        is_due = now_dt >= last_dt + timedelta(seconds=float(s["interval_seconds"]))
                elif stype == "cron" and s.get("cron"):
                    if cron_matches(s["cron"], now_dt):
                        if last_dt is None or last_dt.replace(second=0, microsecond=0) < now_dt.replace(second=0, microsecond=0):
                            is_due = True

                if not is_due:
                    continue

                try:
                    self._validate_scope(s.get("target") or self.target)
                    self._validate_budget(float(s.get("budget_usd", 0.0)), state=state)
                except SchedulerError:
                    if strict:
                        raise
                    logger.warning("Skipping due schedule %s: failed scope or budget validation", s.get("schedule_id"))
                    continue

                entry = self._public_schedule(s)
                if queue:
                    queued_run = self._enqueue_locked(state, s, trigger=stype, now_dt=now_dt)
                    entry["queued_run"] = queued_run
                    changed = True
                due_items.append(entry)

            if changed:
                self._save_state(state)

        if queue and self.on_queue is not None:
            for item in due_items:
                if "queued_run" in item:
                    self.on_queue(item["queued_run"])

        return due_items

    def trigger_webhook_event(
        self,
        event_type: str,
        payload: Optional[Dict[str, Any]] = None,
        signature: Optional[str] = None,
        raw_body: Optional[bytes] = None,
        now: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """
        Dispatch a webhook event to all matching enabled webhook schedules.

        Validates optional HMAC-SHA256 signatures, target/payload scope rules,
        and budget caps before queuing each run.
        """
        clean_event = (event_type or "").strip()
        if not clean_event:
            raise ValueError("event_type cannot be empty")

        now_dt = _now_utc(now)
        payload_dict = dict(payload) if payload else {}
        body_bytes = (
            raw_body
            if raw_body is not None
            else json.dumps(payload_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )

        queued_runs: List[Dict[str, Any]] = []
        with self._lock:
            state = self._load_state()
            matched = [
                s for s in state.get("schedules", [])
                if s.get("enabled", True)
                and s.get("schedule_type") == "webhook"
                and s.get("event_type") == clean_event
            ]

            for s in matched:
                secret = s.get("secret")
                if secret:
                    if not signature:
                        raise PermissionError(f"Missing webhook signature for schedule '{s['schedule_id']}'")
                    expected_hex = hmac.new(
                        str(secret).encode("utf-8"),
                        body_bytes,
                        hashlib.sha256,
                    ).hexdigest()
                    provided_hex = signature.removeprefix("sha256=").strip()
                    if not hmac.compare_digest(expected_hex, provided_hex):
                        raise PermissionError(f"Invalid webhook signature for schedule '{s['schedule_id']}'")

                queued = self._enqueue_locked(
                    state,
                    s,
                    trigger=f"webhook:{clean_event}",
                    now_dt=now_dt,
                    payload=payload_dict,
                )
                queued_runs.append(queued)

            if queued_runs:
                self._save_state(state)

        if self.on_queue is not None:
            for q in queued_runs:
                self.on_queue(q)

        return queued_runs
