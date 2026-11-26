#!/usr/bin/env python3
"""Tests for model_router.py — Smart Model Router."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))
from model_router import (
    ModelRouter, RoutingDecision, BudgetState,
    COMPLEXITY_SIMPLE, COMPLEXITY_MEDIUM, COMPLEXITY_HARD, COMPLEXITY_FRONTIER,
    MODEL_COST_TABLE,
)


class TestBudgetState:
    def test_initial_state(self):
        b = BudgetState(max_budget_usd=10.0)
        assert b.remaining == 10.0
        assert not b.exhausted
        assert b.calls == 0

    def test_record_usage(self):
        b = BudgetState(max_budget_usd=5.0)
        b.record(1000, 500, 0.01)
        assert b.calls == 1
        assert b.total_input_tokens == 1000
        assert b.total_output_tokens == 500
        assert abs(b.spent_usd - 0.01) < 0.0001

    def test_budget_exhaustion(self):
        b = BudgetState(max_budget_usd=0.05)
        b.record(10000, 5000, 0.05)
        assert b.exhausted

    def test_to_dict(self):
        b = BudgetState(max_budget_usd=5.0)
        b.record(100, 50, 0.001)
        d = b.to_dict()
        assert "max_budget_usd" in d
        assert "remaining_usd" in d
        assert d["calls"] == 1


class TestModelRouter:
    def test_classify_simple(self):
        router = ModelRouter(available_providers=["deepseek"])
        assert router.classify_complexity("format the log output") == COMPLEXITY_SIMPLE

    def test_classify_medium(self):
        router = ModelRouter(available_providers=["deepseek"])
        assert router.classify_complexity("analyze the response headers") == COMPLEXITY_MEDIUM

    def test_classify_hard(self):
        router = ModelRouter(available_providers=["openai"])
        assert router.classify_complexity("audit this exploit chain") == COMPLEXITY_HARD

    def test_classify_frontier(self):
        router = ModelRouter(available_providers=["openai"])
        c = router.classify_complexity("exploit injection bypass and reverse the payload chain")
        assert c == COMPLEXITY_FRONTIER

    def test_select_model_returns_decision(self):
        router = ModelRouter(budget_usd=5.0, available_providers=["deepseek"])
        decision = router.select_model("format some text")
        assert isinstance(decision, RoutingDecision)
        assert decision.provider
        assert decision.model
        assert decision.complexity == COMPLEXITY_SIMPLE

    def test_select_model_no_providers(self):
        router = ModelRouter(available_providers=[])
        decision = router.select_model("do something")
        assert decision.provider == "auto"
        assert "No configured" in decision.reason

    def test_budget_forces_cheap(self):
        router = ModelRouter(budget_usd=0.05, available_providers=["deepseek", "openai"])
        router.budget.record(10000, 5000, 0.05)  # exhaust budget
        decision = router.select_model("exploit complex vulnerability chain")
        assert decision.complexity == COMPLEXITY_SIMPLE

    def test_estimate_scan_cost(self):
        router = ModelRouter(available_providers=["deepseek"])
        estimate = router.estimate_scan_cost(skill_count=10)
        assert "cost_low_usd" in estimate
        assert "cost_mid_usd" in estimate
        assert "cost_high_usd" in estimate
        assert estimate["cost_low_usd"] <= estimate["cost_mid_usd"] <= estimate["cost_high_usd"]

    def test_record_usage_updates_budget(self):
        router = ModelRouter(budget_usd=10.0, available_providers=["deepseek"])
        cost = router.record_usage(1000, 500, "deepseek", "deepseek-chat")
        assert cost >= 0
        assert router.budget.calls == 1
        assert router.budget.total_input_tokens == 1000

    def test_preferred_provider(self):
        router = ModelRouter(available_providers=["deepseek", "gemini"])
        decision = router.select_model("format text", preferred_provider="gemini")
        assert decision.provider == "gemini"

    def test_preferred_provider_even_when_more_expensive(self):
        router = ModelRouter(available_providers=["deepseek", "openai"])
        decision = router.select_model("format text", preferred_provider="openai")
        assert decision.provider == "openai"


class TestCostTable:
    def test_cost_table_has_entries(self):
        assert len(MODEL_COST_TABLE) > 10

    def test_all_entries_have_costs(self):
        for key, costs in MODEL_COST_TABLE.items():
            assert "input" in costs, f"Missing input cost for {key}"
            assert "output" in costs, f"Missing output cost for {key}"
            assert costs["input"] >= 0
            assert costs["output"] >= 0
