#!/usr/bin/env python3
"""
model_router.py — Intelligent Model Router for Moros.

Routes LLM calls to the cheapest provider that can handle the task
complexity. Simple steps (log formatting, text extraction) go to
fast/cheap models; complex steps (exploit analysis, code review) go
to frontier models. Tracks budget and prevents cost blowout.
"""

import logging
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

_tools_dir = Path(__file__).parent.resolve()
if str(_tools_dir) not in sys.path:
    sys.path.insert(0, str(_tools_dir))

logger = logging.getLogger("model-router")

# Cost per 1M tokens (input / output) in USD — Nov 2026 estimates.
# These are ballpark figures; real pricing may vary.
MODEL_COST_TABLE: Dict[str, Dict[str, float]] = {
    # Provider/model -> {input_per_1m, output_per_1m}
    "deepseek/deepseek-chat":     {"input": 0.14,  "output": 0.28},
    "groq/llama-3.3-70b":         {"input": 0.59,  "output": 0.79},
    "cerebras/llama3.3-70b":      {"input": 0.60,  "output": 0.80},
    "sambanova/llama-3.3-70b":    {"input": 0.60,  "output": 0.80},
    "together/llama-3.3-70b":     {"input": 0.88,  "output": 0.88},
    "fireworks/llama-3.3-70b":    {"input": 0.90,  "output": 0.90},
    "gemini/gemini-2.0-flash":    {"input": 0.10,  "output": 0.40},
    "gemini/gemini-2.5-flash":    {"input": 0.15,  "output": 0.60},
    "openai/gpt-4o-mini":         {"input": 0.15,  "output": 0.60},
    "mistral/mistral-small":      {"input": 0.10,  "output": 0.30},
    # Mid tier
    "openai/gpt-4o":              {"input": 2.50,  "output": 10.0},
    "anthropic/claude-sonnet":    {"input": 3.00,  "output": 15.0},
    "gemini/gemini-2.5-pro":      {"input": 1.25,  "output": 10.0},
    "mistral/mistral-large":      {"input": 2.00,  "output": 6.00},
    "deepseek/deepseek-reasoner": {"input": 0.55,  "output": 2.19},
    # Frontier tier
    "openai/o4-mini":             {"input": 1.10,  "output": 4.40},
    "anthropic/claude-opus":      {"input": 15.0,  "output": 75.0},
    "openai/o3":                  {"input": 10.0,  "output": 40.0},
    # Local (free)
    "ollama/llama3":              {"input": 0.0,   "output": 0.0},
}

# Step complexity tiers
COMPLEXITY_SIMPLE = "simple"
COMPLEXITY_MEDIUM = "medium"
COMPLEXITY_HARD = "hard"
COMPLEXITY_FRONTIER = "frontier"

# Keyword patterns that indicate step complexity.
_SIMPLE_KEYWORDS = {
    "format", "log", "extract", "parse", "list", "count", "summarize",
    "clean", "split", "join", "template", "normalize", "sort",
}
_MEDIUM_KEYWORDS = {
    "analyze", "classify", "compare", "correlate", "filter", "map",
    "detect", "scan", "enumerate", "discover", "crawl", "recon",
}
_HARD_KEYWORDS = {
    "exploit", "bypass", "inject", "reverse", "deobfuscate", "review",
    "audit", "vulnerability", "payload", "chain", "escalate", "pivot",
}

# Tier -> recommended model groups
TIER_MODEL_POOLS = {
    COMPLEXITY_SIMPLE: [
        "deepseek/deepseek-chat",
        "gemini/gemini-2.0-flash",
        "openai/gpt-4o-mini",
        "groq/llama-3.3-70b",
        "mistral/mistral-small",
    ],
    COMPLEXITY_MEDIUM: [
        "deepseek/deepseek-chat",
        "gemini/gemini-2.5-flash",
        "openai/gpt-4o-mini",
        "groq/llama-3.3-70b",
    ],
    COMPLEXITY_HARD: [
        "deepseek/deepseek-reasoner",
        "gemini/gemini-2.5-pro",
        "openai/gpt-4o",
        "anthropic/claude-sonnet",
    ],
    COMPLEXITY_FRONTIER: [
        "openai/o4-mini",
        "openai/o3",
        "anthropic/claude-opus",
    ],
}


@dataclass
class RoutingDecision:
    """Result of the routing decision."""
    provider: str
    model: str
    complexity: str
    estimated_cost_usd: float
    reason: str


@dataclass
class BudgetState:
    """Running budget for a scan session."""
    max_budget_usd: float = 5.0
    spent_usd: float = 0.0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    calls: int = 0

    @property
    def remaining(self) -> float:
        return max(0.0, self.max_budget_usd - self.spent_usd)

    @property
    def exhausted(self) -> bool:
        return self.remaining <= 0.001

    def record(self, input_tokens: int, output_tokens: int, cost_usd: float):
        self.total_input_tokens += input_tokens
        self.total_output_tokens += output_tokens
        self.spent_usd += cost_usd
        self.calls += 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "max_budget_usd": self.max_budget_usd,
            "spent_usd": round(self.spent_usd, 6),
            "remaining_usd": round(self.remaining, 6),
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "calls": self.calls,
        }


class ModelRouter:
    """
    Routes LLM calls to the cheapest model tier that meets complexity needs,
    while respecting the per-session cost budget.
    """

    def __init__(self, budget_usd: float = 5.0, available_providers: List[str] = None):
        self.budget = BudgetState(max_budget_usd=budget_usd)
        # Filter to only providers that have API keys configured.
        self._available = (
            available_providers
            if available_providers is not None
            else self._detect_available_providers()
        )

    @staticmethod
    def _detect_available_providers() -> List[str]:
        """Check which providers have API keys set in env."""
        from llm_client import KNOWN_PROVIDERS
        available = []
        for name, cfg in KNOWN_PROVIDERS.items():
            env_key = cfg.get("env_key", "")
            if not env_key:
                # Ollama — always considered available
                available.append(name)
            elif os.environ.get(env_key, "").strip():
                available.append(name)
        return available

    def classify_complexity(self, step_description: str) -> str:
        """
        Classify a step's complexity based on keyword analysis.
        Returns one of: simple, medium, hard, frontier.
        """
        if not step_description:
            return COMPLEXITY_SIMPLE
        text = step_description.lower()
        # Score each tier
        hard_score = sum(1 for kw in _HARD_KEYWORDS if kw in text)
        medium_score = sum(1 for kw in _MEDIUM_KEYWORDS if kw in text)

        if hard_score >= 4:
            return COMPLEXITY_FRONTIER
        if hard_score >= 1:
            return COMPLEXITY_HARD
        if medium_score >= 1:
            return COMPLEXITY_MEDIUM
        return COMPLEXITY_SIMPLE

    def select_model(self, step_description: str,
                     preferred_provider: str = None,
                     estimated_tokens: int = 2000) -> RoutingDecision:
        """
        Pick the best model for a given step, considering complexity,
        budget, and available providers.
        """
        estimated_tokens = max(0, estimated_tokens)
        complexity = self.classify_complexity(step_description)

        # If budget is almost gone, force cheapest tier
        if self.budget.remaining < 0.10:
            complexity = COMPLEXITY_SIMPLE

        candidates = TIER_MODEL_POOLS.get(complexity, TIER_MODEL_POOLS[COMPLEXITY_SIMPLE])

        # Filter by what's actually available
        filtered = []
        for model_key in candidates:
            provider = model_key.split("/")[0]
            if provider in self._available:
                filtered.append(model_key)

        # Preferred provider override: keep only preferred provider models if available in tier
        if preferred_provider and preferred_provider in self._available:
            pref_candidates = [
                k for k in filtered if k.startswith(preferred_provider + "/")
            ]
            if pref_candidates:
                filtered = pref_candidates

        if not filtered:
            # Fallback: cheapest available anything (preferring preferred_provider if available)
            sorted_models = sorted(MODEL_COST_TABLE.items(), key=lambda x: x[1]["input"])
            if preferred_provider and preferred_provider in self._available:
                for model_key, _ in sorted_models:
                    if model_key.startswith(preferred_provider + "/"):
                        filtered.append(model_key)
                        break
            if not filtered:
                for model_key, _ in sorted_models:
                    provider = model_key.split("/")[0]
                    if provider in self._available:
                        filtered.append(model_key)
                        break

        if not filtered:
            return RoutingDecision(
                provider="auto", model="default",
                complexity=complexity, estimated_cost_usd=0.0,
                reason="No configured providers; falling back to auto-detect."
            )

        # Pick cheapest from filtered
        best = min(filtered, key=lambda k: MODEL_COST_TABLE.get(k, {}).get("input", 999))
        provider, model = best.split("/", 1)
        cost_info = MODEL_COST_TABLE.get(best, {"input": 0.0, "output": 0.0})
        est_cost = (estimated_tokens * cost_info["input"] / 1_000_000) + \
                   (estimated_tokens * 0.5 * cost_info["output"] / 1_000_000)

        return RoutingDecision(
            provider=provider, model=model,
            complexity=complexity,
            estimated_cost_usd=round(est_cost, 6),
            reason=f"Classified as {complexity}; cheapest available in tier: {best}"
        )

    def estimate_scan_cost(self, skill_count: int, avg_steps_per_skill: int = 10,
                           avg_tokens_per_step: int = 3000) -> Dict[str, Any]:
        """
        Pre-execution cost estimate for a full scan.
        Returns range (low, mid, high) in USD.
        """
        skill_count = max(0, skill_count)
        avg_steps_per_skill = max(0, avg_steps_per_skill)
        avg_tokens_per_step = max(0, avg_tokens_per_step)
        total_steps = skill_count * avg_steps_per_skill
        total_tokens = total_steps * avg_tokens_per_step

        # Assume 60% simple, 30% medium, 10% hard
        cheap_rate = 0.15 / 1_000_000  # cheapest model per token
        mid_rate = 1.0 / 1_000_000
        expensive_rate = 5.0 / 1_000_000

        low = total_tokens * cheap_rate * 1.5  # input + output
        mid = (total_tokens * 0.6 * cheap_rate + total_tokens * 0.3 * mid_rate +
               total_tokens * 0.1 * expensive_rate) * 1.5
        high = total_tokens * expensive_rate * 1.5

        return {
            "skill_count": skill_count,
            "estimated_steps": total_steps,
            "estimated_tokens": total_tokens,
            "cost_low_usd": round(low, 4),
            "cost_mid_usd": round(mid, 4),
            "cost_high_usd": round(high, 4),
        }

    def record_usage(self, input_tokens: int, output_tokens: int,
                     provider: str = "", model: str = ""):
        """Record actual token usage and compute cost."""
        key = f"{provider}/{model}" if provider and model else ""
        cost_info = MODEL_COST_TABLE.get(key, {"input": 0.5, "output": 1.0})
        cost = (input_tokens * cost_info["input"] / 1_000_000) + \
               (output_tokens * cost_info["output"] / 1_000_000)
        self.budget.record(input_tokens, output_tokens, cost)
        return round(cost, 6)

    def get_budget_state(self) -> Dict[str, Any]:
        return self.budget.to_dict()
