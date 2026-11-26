#!/usr/bin/env python3
"""Tests for memory_manager.py — Tiered Memory System."""

import json
import sys
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))
from memory_manager import MemoryManager


@pytest.fixture
def memory(tmp_path):
    """Create a MemoryManager with a temp directory."""
    return MemoryManager(target_dir=tmp_path / "test-target")


class TestEpisodicMemory:
    def test_record_and_recall(self, memory):
        memory.record_event("tool_call", "Called http_get on /login", skill="xss-reflected")
        events = memory.recall_events()
        assert len(events) == 1
        assert events[0]["event_type"] == "tool_call"
        assert events[0]["skill"] == "xss-reflected"

    def test_filter_by_skill(self, memory):
        memory.record_event("tool_call", "Event A", skill="recon")
        memory.record_event("tool_call", "Event B", skill="xss")
        events = memory.recall_events(skill="recon")
        assert len(events) == 1
        assert "Event A" in events[0]["summary"]

    def test_filter_by_event_type(self, memory):
        memory.record_event("finding", "Found XSS", skill="xss")
        memory.record_event("error", "Timeout", skill="xss")
        events = memory.recall_events(event_type="finding")
        assert len(events) == 1

    def test_relevance_stored(self, memory):
        memory.record_event("note", "Important", relevance=0.9)
        events = memory.recall_events()
        assert events[0]["relevance"] == 0.9

    def test_details_stored(self, memory):
        memory.record_event("tool_call", "HTTP GET", details={"url": "/api", "status": 200})
        events = memory.recall_events()
        details = json.loads(events[0]["details"])
        assert details["url"] == "/api"


class TestSemanticMemory:
    def test_store_and_recall_fact(self, memory):
        memory.store_fact("waf", "cloudflare", category="infrastructure")
        facts = memory.recall_facts(category="infrastructure")
        assert len(facts) == 1
        assert facts[0]["value"] == "cloudflare"

    def test_get_fact_by_key(self, memory):
        memory.store_fact("tech_stack", "React + Node.js")
        value = memory.get_fact("tech_stack")
        assert value == "React + Node.js"

    def test_get_fact_missing(self, memory):
        value = memory.get_fact("nonexistent")
        assert value is None

    def test_upsert_fact(self, memory):
        memory.store_fact("waf", "cloudflare")
        memory.store_fact("waf", "akamai")
        value = memory.get_fact("waf")
        assert value == "akamai"

    def test_confidence_stored(self, memory):
        memory.store_fact("server", "nginx", confidence=0.85)
        facts = memory.recall_facts()
        assert facts[0]["confidence"] == 0.85


class TestProceduralMemory:
    def test_record_and_recall_technique(self, memory):
        memory.record_technique("sql_injection", "Found SQLi in /search", success=True)
        techniques = memory.recall_techniques()
        assert len(techniques) == 1
        assert techniques[0]["success"] == 1

    def test_filter_success_only(self, memory):
        memory.record_technique("xss", "No XSS found", success=False)
        memory.record_technique("ssrf", "SSRF confirmed", success=True)
        successes = memory.recall_techniques(success_only=True)
        assert len(successes) == 1
        assert successes[0]["technique"] == "ssrf"

    def test_filter_by_technique(self, memory):
        memory.record_technique("xss", "Reflected XSS found", success=True)
        memory.record_technique("sqli", "No SQLi", success=False)
        results = memory.recall_techniques(technique="xss")
        assert len(results) == 1


class TestCheckpoints:
    def test_save_and_load_checkpoint(self, memory):
        state = {"progress": 50, "urls_checked": ["/login", "/admin"]}
        memory.save_checkpoint("run-001", "xss-reflected", step=5, state=state)
        loaded = memory.load_checkpoint("run-001", "xss-reflected")
        assert loaded is not None
        assert loaded["step"] == 5
        assert loaded["state"]["progress"] == 50

    def test_load_missing_checkpoint(self, memory):
        loaded = memory.load_checkpoint("run-999", "nonexistent")
        assert loaded is None

    def test_checkpoint_upsert(self, memory):
        memory.save_checkpoint("run-001", "recon", step=3, state={"a": 1})
        memory.save_checkpoint("run-001", "recon", step=7, state={"a": 2})
        loaded = memory.load_checkpoint("run-001", "recon")
        assert loaded["step"] == 7
        assert loaded["state"]["a"] == 2

    def test_clear_checkpoints(self, memory):
        memory.save_checkpoint("run-001", "recon", step=3, state={})
        memory.save_checkpoint("run-001", "xss", step=5, state={})
        memory.clear_checkpoints("run-001")
        assert memory.load_checkpoint("run-001", "recon") is None
        assert memory.load_checkpoint("run-001", "xss") is None


class TestTargetContext:
    def test_build_context_with_data(self, memory):
        memory.store_fact("waf", "cloudflare", category="infrastructure")
        memory.record_technique("xss_reflected", "Found reflected XSS in /search", success=True)
        context = memory.build_target_context()
        assert "cloudflare" in context
        assert "xss_reflected" in context

    def test_build_context_empty(self, memory):
        context = memory.build_target_context()
        assert context == ""


class TestStats:
    def test_stats_counts(self, memory):
        memory.record_event("test", "event 1")
        memory.record_event("test", "event 2")
        memory.store_fact("key1", "val1")
        memory.record_technique("tech1", "outcome1", success=True)
        memory.save_checkpoint("run-1", "skill-1", 1, {})
        stats = memory.get_stats()
        assert stats["episodic_events"] == 2
        assert stats["semantic_facts"] == 1
        assert stats["procedural_steps"] == 1
        assert stats["active_checkpoints"] == 1
