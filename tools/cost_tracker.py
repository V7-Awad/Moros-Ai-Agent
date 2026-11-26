#!/usr/bin/env python3
"""
cost_tracker.py — Cost Transparency Engine for Moros.

Tracks token usage and estimated cost per LLM call, per skill, and
per scan session. Generates machine-readable receipts and human-
readable summaries. Designed to prevent cost surprises by surfacing
running totals before and after every step.
"""

import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger("cost-tracker")


class CostEntry:
    """Single LLM call cost record."""
    __slots__ = (
        "timestamp", "skill", "step", "provider", "model",
        "input_tokens", "output_tokens", "cost_usd", "duration_ms",
    )

    def __init__(self, skill: str, step: int, provider: str, model: str,
                 input_tokens: int, output_tokens: int, cost_usd: float,
                 duration_ms: float = 0.0):
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.skill = skill
        self.step = step
        self.provider = provider
        self.model = model
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens
        self.cost_usd = cost_usd
        self.duration_ms = duration_ms

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "skill": self.skill,
            "step": self.step,
            "provider": self.provider,
            "model": self.model,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cost_usd": round(self.cost_usd, 6),
            "duration_ms": round(self.duration_ms, 1),
        }


class CostTracker:
    """
    Thread-safe cost accumulator with per-skill breakdowns,
    running totals, and receipt generation.
    """

    def __init__(self, target_dir: Path = None, budget_cap_usd: float = 10.0):
        self._lock = threading.Lock()
        self._entries: List[CostEntry] = []
        self._skill_totals: Dict[str, Dict[str, Any]] = {}
        self._total_cost: float = 0.0
        self._total_input_tokens: int = 0
        self._total_output_tokens: int = 0
        self._budget_cap: float = budget_cap_usd
        self._started_at: str = datetime.now(timezone.utc).isoformat()
        self._target_dir = Path(target_dir) if target_dir else None

    def record(self, skill: str, step: int, provider: str, model: str,
               input_tokens: int, output_tokens: int, cost_usd: float,
               duration_ms: float = 0.0) -> Dict[str, Any]:
        """Record a single LLM call and return running totals."""
        entry = CostEntry(
            skill=skill, step=step, provider=provider, model=model,
            input_tokens=input_tokens, output_tokens=output_tokens,
            cost_usd=cost_usd, duration_ms=duration_ms,
        )

        with self._lock:
            self._entries.append(entry)
            self._total_cost += cost_usd
            self._total_input_tokens += input_tokens
            self._total_output_tokens += output_tokens

            # Per-skill accumulation
            if skill not in self._skill_totals:
                self._skill_totals[skill] = {
                    "calls": 0, "input_tokens": 0,
                    "output_tokens": 0, "cost_usd": 0.0,
                }
            st = self._skill_totals[skill]
            st["calls"] += 1
            st["input_tokens"] += input_tokens
            st["output_tokens"] += output_tokens
            st["cost_usd"] += cost_usd

            pct_used = (
                round(min(100.0, (self._total_cost / self._budget_cap) * 100), 1)
                if self._budget_cap > 0
                else (100.0 if self._total_cost > 0 else 0.0)
            )
            running = {
                "total_cost_usd": round(self._total_cost, 6),
                "budget_remaining_usd": round(max(0, self._budget_cap - self._total_cost), 6),
                "budget_pct_used": pct_used,
                "total_calls": len(self._entries),
            }

            # Persist entry to disk under lock to prevent concurrent write races
            if self._target_dir:
                self._persist_entry(entry)

        return running

    def _persist_entry(self, entry: CostEntry):
        """Append entry to cost log on disk."""
        try:
            cost_dir = self._target_dir / "output" / "costs"
            cost_dir.mkdir(parents=True, exist_ok=True)
            log_path = cost_dir / "cost-log.jsonl"
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry.to_dict(), ensure_ascii=False) + "\n")
        except OSError as exc:
            logger.warning("Failed to persist cost entry: %s", exc)

    @property
    def budget_exceeded(self) -> bool:
        with self._lock:
            return self._total_cost >= self._budget_cap

    def get_running_total(self) -> Dict[str, Any]:
        """Return current running totals."""
        with self._lock:
            return {
                "total_cost_usd": round(self._total_cost, 6),
                "total_input_tokens": self._total_input_tokens,
                "total_output_tokens": self._total_output_tokens,
                "total_calls": len(self._entries),
                "budget_cap_usd": self._budget_cap,
                "budget_remaining_usd": round(max(0, self._budget_cap - self._total_cost), 6),
                "per_skill": {k: {**v, "cost_usd": round(v["cost_usd"], 6)}
                              for k, v in self._skill_totals.items()},
            }

    def generate_receipt(self) -> Dict[str, Any]:
        """Generate a final cost receipt for the scan."""
        with self._lock:
            return {
                "receipt_generated_at": datetime.now(timezone.utc).isoformat(),
                "scan_started_at": self._started_at,
                "summary": {
                    "total_cost_usd": round(self._total_cost, 6),
                    "total_input_tokens": self._total_input_tokens,
                    "total_output_tokens": self._total_output_tokens,
                    "total_llm_calls": len(self._entries),
                    "budget_cap_usd": self._budget_cap,
                },
                "per_skill_breakdown": {
                    k: {**v, "cost_usd": round(v["cost_usd"], 6)}
                    for k, v in self._skill_totals.items()
                },
                "entries": [e.to_dict() for e in self._entries],
            }

    def save_receipt(self, output_path: Path = None) -> Path:
        """Write the receipt JSON to disk."""
        receipt = self.generate_receipt()
        if output_path is None:
            if self._target_dir:
                cost_dir = self._target_dir / "output" / "costs"
                cost_dir.mkdir(parents=True, exist_ok=True)
                output_path = cost_dir / "receipt.json"
            else:
                output_path = Path("cost-receipt.json")
        else:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(receipt, f, indent=2, ensure_ascii=False)
        logger.info("Cost receipt saved to %s", output_path)
        return output_path

    def format_human_summary(self) -> str:
        """Return a human-readable cost summary."""
        totals = self.get_running_total()
        lines = [
            f"Cost Summary — {totals['total_calls']} LLM calls",
            f"  Total: ${totals['total_cost_usd']:.4f} / ${totals['budget_cap_usd']:.2f} budget",
            f"  Tokens: {totals['total_input_tokens']:,} in / {totals['total_output_tokens']:,} out",
            "",
        ]
        for skill, data in totals.get("per_skill", {}).items():
            lines.append(
                f"  {skill}: ${data['cost_usd']:.4f} "
                f"({data['calls']} calls, {data['input_tokens']:,}+{data['output_tokens']:,} tokens)"
            )
        return "\n".join(lines)
