#!/usr/bin/env python3
"""Tests for cost_tracker.py — Cost Transparency Engine."""

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))
from cost_tracker import CostTracker, CostEntry


class TestCostEntry:
    def test_entry_creation(self):
        e = CostEntry(
            skill="xss-reflected", step=1, provider="openai", model="gpt-4o-mini",
            input_tokens=500, output_tokens=200, cost_usd=0.001,
        )
        assert e.skill == "xss-reflected"
        assert e.timestamp

    def test_entry_to_dict(self):
        e = CostEntry(
            skill="recon", step=2, provider="deepseek", model="deepseek-chat",
            input_tokens=1000, output_tokens=400, cost_usd=0.0003, duration_ms=150.5,
        )
        d = e.to_dict()
        assert d["provider"] == "deepseek"
        assert d["duration_ms"] == 150.5
        assert d["cost_usd"] == 0.0003


class TestCostTracker:
    def test_initial_state(self):
        ct = CostTracker(budget_cap_usd=5.0)
        totals = ct.get_running_total()
        assert totals["total_cost_usd"] == 0.0
        assert totals["total_calls"] == 0
        assert totals["budget_cap_usd"] == 5.0

    def test_record_accumulates(self):
        ct = CostTracker()
        ct.record("recon", 1, "openai", "gpt-4o-mini", 500, 200, 0.001)
        ct.record("recon", 2, "openai", "gpt-4o-mini", 600, 300, 0.002)
        totals = ct.get_running_total()
        assert totals["total_calls"] == 2
        assert totals["total_input_tokens"] == 1100
        assert totals["total_output_tokens"] == 500
        assert abs(totals["total_cost_usd"] - 0.003) < 0.0001

    def test_per_skill_breakdown(self):
        ct = CostTracker()
        ct.record("recon", 1, "openai", "gpt-4o", 500, 200, 0.01)
        ct.record("xss", 1, "deepseek", "chat", 300, 100, 0.001)
        totals = ct.get_running_total()
        assert "recon" in totals["per_skill"]
        assert "xss" in totals["per_skill"]
        assert totals["per_skill"]["recon"]["calls"] == 1
        assert totals["per_skill"]["xss"]["calls"] == 1

    def test_budget_exceeded(self):
        ct = CostTracker(budget_cap_usd=0.01)
        ct.record("test", 1, "openai", "gpt-4o", 10000, 5000, 0.015)
        assert ct.budget_exceeded

    def test_running_total_returns_budget_pct(self):
        ct = CostTracker(budget_cap_usd=10.0)
        running = ct.record("test", 1, "openai", "gpt-4o", 1000, 500, 1.0)
        assert running["budget_pct_used"] == 10.0

    def test_generate_receipt(self):
        ct = CostTracker()
        ct.record("recon", 1, "deepseek", "chat", 500, 200, 0.001)
        receipt = ct.generate_receipt()
        assert "summary" in receipt
        assert "entries" in receipt
        assert len(receipt["entries"]) == 1
        assert receipt["summary"]["total_llm_calls"] == 1

    def test_save_receipt_to_disk(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target_dir = Path(tmpdir) / "test-target"
            target_dir.mkdir()
            ct = CostTracker(target_dir=target_dir)
            ct.record("test", 1, "openai", "gpt-4o", 1000, 500, 0.01)
            path = ct.save_receipt()
            assert path.exists()
            data = json.loads(path.read_text())
            assert data["summary"]["total_llm_calls"] == 1

    def test_human_summary(self):
        ct = CostTracker(budget_cap_usd=5.0)
        ct.record("recon", 1, "openai", "gpt-4o", 1000, 500, 0.01)
        summary = ct.format_human_summary()
        assert "Cost Summary" in summary
        assert "recon" in summary

    def test_persistence_to_disk(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target_dir = Path(tmpdir) / "test-target"
            target_dir.mkdir()
            ct = CostTracker(target_dir=target_dir)
            ct.record("test", 1, "openai", "gpt-4o", 500, 200, 0.001)
            log_path = target_dir / "output" / "costs" / "cost-log.jsonl"
            assert log_path.exists()
            line = log_path.read_text().strip()
            data = json.loads(line)
            assert data["skill"] == "test"
