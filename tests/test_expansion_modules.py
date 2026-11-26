#!/usr/bin/env python3
"""
test_expansion_modules.py — Unit tests for Moros AI expansion modules:
  1. tools/scheduler.py (P2-1 ScanScheduler)
  2. tools/a2a_server.py (P2-4 A2AAgentCard & A2ATaskHandler)
  3. tools/skill_learner.py (P3-1 SkillLearner)
"""

import hashlib
import hmac
import json
import sys
import threading
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import HTTPServer
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(PROJECT_ROOT / "tools"))

from cost_tracker import CostTracker
from memory_manager import MemoryManager
from run_manager import RunManager
from scope_validator import ScopeValidator
from skill_registry import SkillRegistry
from trace_logger import TraceLogger

from scheduler import (
    BudgetCapExceededError,
    ScanScheduler,
    ScopeViolationError,
    compute_next_cron_run,
    cron_matches,
    parse_cron_expression,
)
from a2a_server import (
    A2AAgentCard,
    A2ATaskHandler,
    ERR_INVALID_PARAMS,
    ERR_INVALID_REQUEST,
    ERR_METHOD_NOT_FOUND,
    ERR_PARSE,
    ERR_PERMISSION_DENIED,
    ERR_SCOPE_VIOLATION,
    ERR_TASK_NOT_CANCELABLE,
    ERR_TASK_NOT_FOUND,
    build_agent_card,
    make_a2a_http_handler,
)
from skill_learner import SkillLearner


# ══════════════════════════════════════════════════════════════════════
# 1. ScanScheduler Tests (tools/scheduler.py)
# ══════════════════════════════════════════════════════════════════════


class TestCronHelpers:
    def test_parse_and_match_cron(self):
        parsed = parse_cron_expression("*/15 2 * * 1-5")
        assert 0 in parsed["minutes"]
        assert 45 in parsed["minutes"]
        assert parsed["hours"] == {2}
        assert parsed["weekdays"] == {1, 2, 3, 4, 5}

        # 2026-11-26 is a Thursday (cron weekday 4)
        dt_match = datetime(2026, 11, 26, 2, 30, tzinfo=timezone.utc)
        dt_miss = datetime(2026, 11, 26, 2, 31, tzinfo=timezone.utc)
        assert cron_matches("*/15 2 * * 1-5", dt_match) is True
        assert cron_matches("*/15 2 * * 1-5", dt_miss) is False

    def test_cron_alias_and_next_run(self):
        base = datetime(2026, 11, 26, 10, 12, tzinfo=timezone.utc)
        nxt = compute_next_cron_run("@hourly", base)
        assert nxt == datetime(2026, 11, 26, 11, 0, tzinfo=timezone.utc)

    def test_invalid_cron_rejected(self):
        with pytest.raises(ValueError):
            parse_cron_expression("* * *")
        with pytest.raises(ValueError):
            parse_cron_expression("65 * * * *")
        with pytest.raises(ValueError):
            parse_cron_expression("*/0 * * * *")


class TestScanScheduler:
    def test_persistence_and_interval_schedule(self, tmp_path):
        target_dir = tmp_path / "targets" / "example.com"
        t0 = datetime(2026, 11, 26, 12, 0, 0, tzinfo=timezone.utc)
        scheduler = ScanScheduler(target="example.com", target_dir=target_dir, max_budget_cap_usd=25.0)

        created = scheduler.create_schedule(
            name="Hourly Surface Recon",
            skills=["recon-subdomain", "js-discover"],
            interval_seconds=3600,
            budget_usd=5.0,
            run_immediately=False,
            now=t0,
        )
        assert created["schedule_type"] == "interval"
        assert created["budget_usd"] == 5.0
        assert (target_dir / "schedules.json").is_file()

        # Reload from disk in fresh instance
        reloaded = ScanScheduler(target="example.com", target_dir=target_dir, max_budget_cap_usd=25.0)
        listed = reloaded.list_schedules()
        assert len(listed) == 1
        assert listed[0]["schedule_id"] == created["schedule_id"]

        # Not due yet at t0 + 30 min
        assert reloaded.due_schedules(now=t0 + timedelta(minutes=30)) == []

        # Due at t0 + 61 min and queued cleanly
        due = reloaded.due_schedules(now=t0 + timedelta(minutes=61), queue=True)
        assert len(due) == 1
        assert due[0]["queued_run"]["target"] == "example.com"
        assert len(reloaded.list_queued_runs()) == 1

        # Not due again immediately after queuing
        assert reloaded.due_schedules(now=t0 + timedelta(minutes=62)) == []

    def test_cron_schedule_due_and_advance(self, tmp_path):
        target_dir = tmp_path / "targets" / "example.com"
        t0 = datetime(2026, 11, 26, 1, 0, 0, tzinfo=timezone.utc)
        scheduler = ScanScheduler(target="example.com", target_dir=target_dir)
        scheduler.create_schedule(
            name="Nightly Deep Scan",
            skills=["xss-reflected"],
            cron="30 2 * * *",
            budget_usd=10.0,
            now=t0,
        )

        assert scheduler.due_schedules(now=datetime(2026, 11, 26, 2, 29, tzinfo=timezone.utc)) == []
        due = scheduler.due_schedules(now=datetime(2026, 11, 26, 2, 30, tzinfo=timezone.utc), queue=True)
        assert len(due) == 1
        assert due[0]["queued_run"]["trigger"] == "cron"
        # Next run advanced to next day
        assert scheduler.due_schedules(now=datetime(2026, 11, 26, 2, 35, tzinfo=timezone.utc)) == []

    def test_webhook_event_trigger_and_hmac_verification(self, tmp_path):
        target_dir = tmp_path / "targets" / "example.com"
        rm = RunManager(target_dir)
        scheduler = ScanScheduler(target="example.com", target_dir=target_dir, run_manager=rm)

        secret = "super-webhook-secret"
        sched = scheduler.create_schedule(
            name="Deploy Triggered API Scan",
            skills=["api-spec-discovery"],
            event_type="deployment.succeeded",
            budget_usd=4.0,
            secret=secret,
        )
        # Raw secret must never leak from list_schedules
        assert "secret" not in sched
        assert sched["has_secret"] is True

        payload = {"url": "https://api.example.com/v2", "release": "2026.11"}
        raw_body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        sig = "sha256=" + hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()

        with pytest.raises(PermissionError):
            scheduler.trigger_webhook_event("deployment.succeeded", payload=payload, signature="sha256=bad")

        queued = scheduler.trigger_webhook_event(
            "deployment.succeeded",
            payload=payload,
            signature=sig,
            raw_body=raw_body,
        )
        assert len(queued) == 1
        assert queued[0]["trigger"] == "webhook:deployment.succeeded"
        assert queued[0]["run_id"] is not None
        assert rm.get_run(queued[0]["run_id"]) is not None

    def test_scope_validation_blocks_out_of_scope_schedules_and_webhooks(self, tmp_path):
        target_dir = tmp_path / "targets" / "example.com"
        validator = ScopeValidator(
            target="example.com",
            in_scope=["example.com", "*.example.com"],
            out_of_scope=["blog.example.com", "evil.com"],
        )
        scheduler = ScanScheduler(
            target="example.com",
            target_dir=target_dir,
            scope_validator=validator,
        )

        # Cannot create schedule for out-of-scope host
        with pytest.raises(ScopeViolationError):
            scheduler.create_schedule(
                name="Out of scope blog",
                interval_seconds=600,
                target_override="blog.example.com",
                budget_usd=2.0,
            )

        # Valid webhook schedule cannot be triggered for out-of-scope URL in payload
        scheduler.create_schedule(
            name="Webhook Scan",
            event_type="push",
            budget_usd=2.0,
        )
        with pytest.raises(ScopeViolationError):
            scheduler.trigger_webhook_event("push", payload={"url": "https://evil.com/login"})

    def test_budget_caps_enforced_per_run_total_and_cost_tracker(self, tmp_path):
        target_dir = tmp_path / "targets" / "example.com"
        tracker = CostTracker(target_dir=target_dir, budget_cap_usd=6.0)
        tracker.record("recon", 1, "openai", "gpt-4o", 1000, 500, cost_usd=4.5)

        scheduler = ScanScheduler(
            target="example.com",
            target_dir=target_dir,
            max_budget_cap_usd=10.0,
            total_budget_cap_usd=5.0,
            cost_tracker=tracker,
        )

        # Exceeds per-run cap
        with pytest.raises(BudgetCapExceededError):
            scheduler.create_schedule(name="Too pricey", interval_seconds=300, budget_usd=12.0)

        # Exceeds CostTracker remaining ($1.50 left)
        with pytest.raises(BudgetCapExceededError):
            scheduler.create_schedule(name="Exceeds remaining", interval_seconds=300, budget_usd=2.0)

        # Valid small schedule succeeds once, then cumulative cap blocks second queued run
        scheduler.create_schedule(name="Small check", event_type="alert", budget_usd=1.0)
        queued = scheduler.trigger_webhook_event("alert")
        assert len(queued) == 1

        # Triggering again fails because cumulative budget would hit 2.0 > remaining 1.5
        tracker.record("xss", 1, "openai", "gpt-4o", 100, 100, cost_usd=0.8)
        with pytest.raises(BudgetCapExceededError):
            scheduler.trigger_webhook_event("alert")


# ══════════════════════════════════════════════════════════════════════
# 2. A2A Server & Protocol Tests (tools/a2a_server.py)
# ══════════════════════════════════════════════════════════════════════


class TestA2AAgentCard:
    def test_build_agent_card_metadata_and_skills(self, tmp_path):
        skills_dir = tmp_path / "skills"
        registry = SkillRegistry(skills_dir=skills_dir)
        registry.create_custom_skill(
            skill_id="api-idor-audit",
            title="API IDOR Audit",
            category="Authorization",
            description="Detects broken object-level authorization.",
        )

        card_builder = A2AAgentCard(skill_registry=registry)
        card = card_builder.build_agent_card("https://moros.local:8443/")

        assert card["name"] == "Moros AI"
        assert card["url"] == "https://moros.local:8443"
        assert card["protocolVersion"]
        assert card["capabilities"]["stateTransitionHistory"] is True
        assert "Bearer" in card["authentication"]["schemes"]
        assert len(card["skills"]) == 1
        assert card["skills"][0]["id"] == "api-idor-audit"

        # Class-level invocation also works
        static_card = A2AAgentCard.build_agent_card("http://127.0.0.1:8080")
        assert static_card["url"] == "http://127.0.0.1:8080"
        assert build_agent_card("http://localhost:8080")["name"] == "Moros AI"

    def test_invalid_base_url_rejected(self):
        with pytest.raises(ValueError):
            A2AAgentCard.build_agent_card("ftp://invalid.local")


class TestA2ATaskHandler:
    def test_tasks_send_get_cancel_lifecycle(self, tmp_path):
        validator = ScopeValidator(target="example.com", in_scope=["example.com"])
        handler = A2ATaskHandler(
            scope_validator=validator,
            storage_path=tmp_path / "a2a-tasks.json",
        )

        send_resp = handler.handle_request({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tasks/send",
            "params": {
                "id": "task-101",
                "message": {"role": "user", "parts": [{"type": "text", "text": "Scan example.com"}]},
                "metadata": {"target": "example.com", "skills": ["recon-subdomain"]},
            },
        })
        assert "result" in send_resp
        assert send_resp["result"]["id"] == "task-101"
        assert send_resp["result"]["status"]["state"] == "submitted"

        get_resp = handler.handle_request({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tasks/get",
            "params": {"id": "task-101"},
        })
        assert get_resp["result"]["id"] == "task-101"
        assert len(get_resp["result"]["history"]) == 1

        cancel_resp = handler.handle_request({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tasks/cancel",
            "params": {"id": "task-101"},
        })
        assert cancel_resp["result"]["status"]["state"] == "canceled"

        # Canceling again returns terminal state error
        cancel_again = handler.handle_request({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tasks/cancel",
            "params": {"id": "task-101"},
        })
        assert cancel_again["error"]["code"] == ERR_TASK_NOT_CANCELABLE

    def test_scoped_permissions_and_scope_validator_enforcement(self):
        validator = ScopeValidator(
            target="example.com",
            in_scope=["example.com", "api.example.com"],
            out_of_scope=["forbidden.example.com"],
        )
        handler = A2ATaskHandler(
            scope_validator=validator,
            api_tokens={
                "read-only-tok": ["tasks:read"],
                "runner-tok": ["tasks:read", "tasks:write"],
            },
            allowed_skills=["recon-subdomain", "xss-reflected"],
        )

        # Missing auth denied
        unauth = handler.handle_request({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tasks/send",
            "params": {
                "message": {"role": "user", "parts": [{"type": "text", "text": "Scan"}]},
                "metadata": {"target": "example.com"},
            },
        })
        assert unauth["error"]["code"] == ERR_PERMISSION_DENIED

        # Read-only token cannot invoke tasks/send
        read_only = handler.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tasks/send",
                "params": {
                    "message": {"role": "user", "parts": [{"type": "text", "text": "Scan"}]},
                    "metadata": {"target": "example.com"},
                },
            },
            headers={"Authorization": "Bearer read-only-tok"},
        )
        assert read_only["error"]["code"] == ERR_PERMISSION_DENIED

        # Out-of-scope target blocked even with runner token
        out_scope = handler.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tasks/send",
                "params": {
                    "message": {"role": "user", "parts": [{"type": "text", "text": "Scan"}]},
                    "metadata": {"target": "forbidden.example.com", "skills": ["recon-subdomain"]},
                },
            },
            headers={"Authorization": "Bearer runner-tok"},
        )
        assert out_scope["error"]["code"] == ERR_SCOPE_VIOLATION

        # Disallowed skill blocked
        bad_skill = handler.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tasks/send",
                "params": {
                    "message": {"role": "user", "parts": [{"type": "text", "text": "Scan"}]},
                    "metadata": {"target": "api.example.com", "skills": ["ssrf-post-exploit"]},
                },
            },
            headers={"Authorization": "Bearer runner-tok"},
        )
        assert bad_skill["error"]["code"] == ERR_PERMISSION_DENIED

        # Authorized scoped task succeeds
        ok = handler.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tasks/send",
                "params": {
                    "id": "task-auth-ok",
                    "message": {"role": "user", "parts": [{"type": "text", "text": "Run recon"}]},
                    "metadata": {"target": "api.example.com", "skills": ["recon-subdomain"]},
                },
            },
            headers={"Authorization": "Bearer runner-tok"},
        )
        assert ok["result"]["id"] == "task-auth-ok"

    def test_jsonrpc_error_handling(self):
        handler = A2ATaskHandler()
        assert handler.handle_json("{invalid json")["error"]["code"] == ERR_PARSE
        assert handler.handle_request({"jsonrpc": "1.0", "id": 1, "method": "tasks/get"})["error"]["code"] == ERR_INVALID_REQUEST
        assert handler.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tasks/unknown"})["error"]["code"] == ERR_METHOD_NOT_FOUND
        assert handler.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tasks/get", "params": {}})["error"]["code"] == ERR_INVALID_PARAMS
        assert handler.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tasks/get", "params": {"id": "missing"}})["error"]["code"] == ERR_TASK_NOT_FOUND

    def test_http_well_known_agent_card_and_jsonrpc_endpoint(self, tmp_path):
        skills_dir = tmp_path / "skills"
        registry = SkillRegistry(skills_dir=skills_dir)
        registry.create_custom_skill("jwt-audit", "JWT Audit", "Inspects JWT tokens.")
        card_builder = A2AAgentCard(skill_registry=registry)
        task_handler = A2ATaskHandler(
            task_executor=lambda task: {
                "state": "completed",
                "artifacts": [{"name": "summary", "parts": [{"type": "text", "text": "ok"}]}],
            }
        )

        server = HTTPServer(("127.0.0.1", 0), make_a2a_http_handler(card_builder, task_handler, "http://127.0.0.1"))
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/.well-known/agent.json", timeout=5) as resp:
                card_data = json.loads(resp.read().decode("utf-8"))
            assert card_data["skills"][0]["id"] == "jwt-audit"

            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/",
                data=json.dumps({
                    "jsonrpc": "2.0",
                    "id": "rpc-1",
                    "method": "tasks/send",
                    "params": {"message": {"role": "user", "parts": [{"type": "text", "text": "Go"}]}},
                }).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                rpc_data = json.loads(resp.read().decode("utf-8"))
            assert rpc_data["result"]["status"]["state"] == "completed"
            assert len(rpc_data["result"]["artifacts"]) == 1
        finally:
            server.shutdown()
            server.server_close()


# ══════════════════════════════════════════════════════════════════════
# 3. SkillLearner Tests (tools/skill_learner.py)
# ══════════════════════════════════════════════════════════════════════


class TestSkillLearner:
    def test_propose_skills_saves_unapproved_without_activating(self, tmp_path):
        target_dir = tmp_path / "targets" / "example.com"
        skills_dir = tmp_path / "skills"
        skills_dir.mkdir(parents=True)

        tracer = TraceLogger(target_dir=target_dir)
        trace_id = tracer.start_trace("scan-1")
        skill_span = tracer.start_span("graphql-introspection", trace_id, span_type="skill")
        tracer.record_tool_call(
            trace_id,
            parent_id=skill_span.span_id,
            tool_name="http_post",
            args_summary="url=https://example.com/graphql Authorization: Bearer secret123",
            result_summary="200 OK schema returned",
            success=True,
        )
        tracer.end_span(skill_span, status="ok")
        tracer.end_trace(trace_id)

        memory = MemoryManager(target_dir=target_dir)
        memory.record_technique(
            technique="graphql_introspection_bypass",
            outcome="Extracted full GraphQL schema via POST /graphql",
            success=True,
            target_context="Node.js Apollo API",
        )
        memory.record_technique(
            technique="failed_probe",
            outcome="Blocked by WAF",
            success=False,
        )

        learner = SkillLearner(
            target_dir=target_dir,
            skills_dir=skills_dir,
            trace_logger=tracer,
            memory_manager=memory,
        )
        proposals = learner.propose_skills()

        assert len(proposals) == 1
        prop = proposals[0]
        assert prop["approved"] is False
        assert prop["status"] == "pending"
        assert prop["skill_id"] == "graphql-introspection-bypass"

        # Saved under targets/<target>/output/skill-proposals/
        prop_md = Path(prop["skill_md_path"])
        assert prop_md.is_file()
        assert prop_md.is_relative_to(target_dir / "output" / "skill-proposals")
        md_text = prop_md.read_text(encoding="utf-8")
        assert "graphql-introspection-bypass" in md_text
        assert "secret123" not in md_text  # secrets must not leak

        # CRITICAL: Never auto-activated into skills/
        assert list(skills_dir.iterdir()) == []

    def test_approve_proposal_activates_and_reject_stays_inactive(self, tmp_path):
        target_dir = tmp_path / "targets" / "example.com"
        skills_dir = tmp_path / "skills"
        skills_dir.mkdir(parents=True)

        memory = MemoryManager(target_dir=target_dir)
        memory.record_technique("jwt_kid_traversal", "Signed token with /dev/null key", success=True)
        memory.record_technique("cors_null_origin", "Reflected null origin with credentials", success=True)

        learner = SkillLearner(
            target_dir=target_dir,
            skills_dir=skills_dir,
            memory_manager=memory,
        )
        proposals = learner.propose_skills()
        assert len(proposals) == 2

        by_skill = {p["skill_id"]: p for p in proposals}
        jwt_prop = by_skill["jwt-kid-traversal"]
        cors_prop = by_skill["cors-null-origin"]

        # Reject one proposal
        rejected = learner.reject_proposal(cors_prop["proposal_id"], reason="Duplicate of existing check")
        assert rejected["approved"] is False
        assert rejected["status"] == "rejected"
        assert not (skills_dir / "cors-null-origin").exists()

        # Cannot approve a rejected proposal
        with pytest.raises(ValueError):
            learner.approve_proposal(cors_prop["proposal_id"])

        # Explicit approval activates into skills/ and SkillRegistry discovers it
        approved = learner.approve_proposal(jwt_prop["proposal_id"], approved_by="security-lead", activate=True)
        assert approved["approved"] is True
        assert approved["status"] == "approved"
        assert approved["approved_by"] == "security-lead"

        registry = SkillRegistry(skills_dir=skills_dir)
        installed = registry.get_skill("jwt-kid-traversal")
        assert installed is not None
        assert installed["is_custom"] is True
        assert len(installed["checklist"]) >= 2

    def test_empty_memory_returns_no_proposals(self, tmp_path):
        target_dir = tmp_path / "targets" / "empty.com"
        learner = SkillLearner(target_dir=target_dir, skills_dir=tmp_path / "skills")
        assert learner.propose_skills() == []
        assert learner.list_proposals() == []
