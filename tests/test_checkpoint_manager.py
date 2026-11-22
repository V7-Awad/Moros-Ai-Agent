import threading
import time
import pytest
from pathlib import Path
from tools.checkpoint_manager import CheckpointManager


def test_checkpoint_creation_and_deterministic_id(tmp_path):
    cm = CheckpointManager(target="example.com", target_dir=tmp_path)
    cp = cm.create_checkpoint(
        checkpoint_type="State-Changing Endpoint Confirmation",
        target_url="https://example.com/api/delete-user",
        method="DELETE",
        reason="Human confirmation required before destructive call",
        risk_level="HIGH"
    )

    assert cp["id"].startswith("cp-")
    assert cp["target"] == "example.com"
    assert cp["status"] == "WAITING_APPROVAL"
    assert cp["method"] == "DELETE"

    # Determinism: creating again returns identical ID
    cp2 = cm.create_checkpoint(
        checkpoint_type="State-Changing Endpoint Confirmation",
        target_url="https://example.com/api/delete-user",
        method="DELETE"
    )
    assert cp2["id"] == cp["id"]


def test_checkpoint_approval_and_rejection(tmp_path):
    cm = CheckpointManager(target="example.com", target_dir=tmp_path)
    cp = cm.create_checkpoint(
        checkpoint_type="Race Condition Confirmation",
        target_url="https://example.com/oauth/callback",
        method="POST"
    )

    # Approve
    approved = cm.decide(cp["id"], "approve", notes="Operator authorized test", decider="admin")
    assert approved["status"] == "APPROVED"
    assert approved["decided_by"] == "admin"
    assert approved["decision_notes"] == "Operator authorized test"

    # Verify persistence
    all_cps = cm.list_checkpoints()
    assert len(all_cps) == 1
    assert all_cps[0]["status"] == "APPROVED"


def test_checkpoint_blocking_worker_wakes_on_decision(tmp_path):
    cm = CheckpointManager(target="example.com", target_dir=tmp_path)
    outcome = {}

    def worker():
        res = cm.request_approval(
            checkpoint_type="Password Reset Audit",
            target_url="https://example.com/reset-password",
            method="POST",
            timeout_seconds=5
        )
        outcome["status"] = res["status"]
        outcome["decided_by"] = res.get("decided_by")

    t = threading.Thread(target=worker)
    t.start()

    # Allow worker to enter wait state
    time.sleep(0.3)
    cps = cm.list_checkpoints()
    assert len(cps) == 1
    assert cps[0]["status"] == "WAITING_APPROVAL"

    # Human operator decides to approve
    cm.decide(cps[0]["id"], "approve", notes="Approved via dashboard", decider="operator_john")
    t.join(timeout=3)

    assert not t.is_alive()
    assert outcome.get("status") == "APPROVED"
    assert outcome.get("decided_by") == "operator_john"


def test_checkpoint_timeout_rejects(tmp_path):
    cm = CheckpointManager(target="example.com", target_dir=tmp_path)
    # Request approval with 1 second timeout and no decider
    res = cm.request_approval(
        checkpoint_type="Blind XSS Payload",
        target_url="https://example.com/feedback",
        method="POST",
        timeout_seconds=1,
        poll_interval=0.2
    )

    assert res["status"] == "REJECTED"
    assert "timeout" in res.get("decision_notes", "").lower()
